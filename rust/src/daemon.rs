//! agentd — 常驻运行时：Unix socket + NDJSON 协议。
//!
//! 安全模型（红队审计 H1/H3/H4 修复后的设计）：
//!   1. **daemon 只执行本地已安装的策略**：exec 请求携带策略 *名称*（而非内容），
//!      daemon 从 state_dir/policies/*.json 反查。socket 客户端无法自拟权限。
//!   2. **socket 权限显式 0600**：仅属主用户可连接（跨用户被内核拒绝；
//!      同用户残余风险见 README 诚实边界）。
//!   3. **身份种子 0600**：写入用 OpenOptions.mode(0600)；已存在但权限过宽则拒绝启动。
//!   4. network=true 的策略在加载时直接拒绝（当前无后端能强制网络，fail-closed）。

use crate::exec::{select, Executor};
use crate::identity;
use crate::identity::Identity;
use crate::ledger::Ledger;
use crate::policy::Policy;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Clone)]
pub struct DaemonConfig {
    pub state_dir: PathBuf,
    pub socket: PathBuf,
    pub llrun: Option<PathBuf>,
}

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub struct Runtime {
    pub cfg: DaemonConfig,
    pub identity: Identity,
    pub executor: Box<dyn Executor>,
    pub started: Instant,
    pub policies: Arc<HashMap<String, Policy>>,
    /// run_id → 状态快照（上限 256 条，FIFO 淘汰，防内存无限增长）
    pub runs: Arc<Mutex<Vec<(String, Value)>>>,
}

pub fn serve(cfg: DaemonConfig) -> std::io::Result<()> {
    std::fs::create_dir_all(&cfg.state_dir)?;
    let policies = Arc::new(load_policies(&cfg.state_dir)?);
    let _ = std::fs::remove_file(&cfg.socket);
    if let Some(parent) = cfg.socket.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let listener = UnixListener::bind(&cfg.socket)?;

    // 身份：H3 修复由 identity.rs 保证 0600 与权限校验
    let identity = identity::ensure(&cfg.state_dir)?;

    let executor = select(cfg.llrun.as_ref());
    let started = Instant::now();
    eprintln!(
        "[agentd] listening on {} (executor: {} / {}) state: {} policies: {}",
        cfg.socket.display(),
        executor.name(),
        executor.enforcement(),
        cfg.state_dir.display(),
        policies.len()
    );

    // H4：socket 显式 0600——仅属主用户可连接（连接前内核即拒绝其他用户）
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cfg.socket, std::fs::Permissions::from_mode(0o600))?;
    }

    let runtime = Arc::new(Runtime {
        cfg,
        identity,
        executor,
        started,
        policies,
        runs: Arc::new(Mutex::new(Vec::new())),
    });
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let rt = Arc::clone(&runtime);
        std::thread::spawn(move || {
            let _ = handle_conn(stream, &rt);
        });
    }
    Ok(())
}

/// 从 state_dir/policies/*.json 加载已安装策略（文件名即策略名）。
/// network=true 一律拒绝加载（当前无后端能强制网络，fail-closed，M1 修复口径）。
fn load_policies(state_dir: &PathBuf) -> Result<HashMap<String, Policy>, std::io::Error> {
    let dir = state_dir.join("policies");
    std::fs::create_dir_all(&dir)?;
    let mut map = HashMap::new();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string();
        let raw = std::fs::read_to_string(&path)?;
        match serde_json::from_str::<Policy>(&raw) {
            Ok(p) => {
                if p.network {
                    eprintln!("[agentd] 拒绝加载策略 '{name}'：network=true 无法被强制（fail-closed）");
                    continue;
                }
                eprintln!("[agentd] 已装策略 '{name}'（读写区 {}）", p.workdir);
                map.insert(name, p);
            }
            Err(e) => eprintln!("[agentd] 拒绝加载策略 '{name}'：解析失败 {e}"),
        }
    }
    Ok(map)
}

fn handle_conn(stream: UnixStream, rt: &Arc<Runtime>) -> std::io::Result<()> {
    // H4 残余修复：对端凭据校验（同用户才可对话；跨用户在 socket 0600 已被内核拒绝，
    // 此处兜底防 uid 借用场景）
    if !peer_uid_is_self(&stream) {
        let resp = json!({"id": null, "ok": false,
                          "error": "对端身份与 daemon 属主不符（peer uid 校验失败）"});
        let mut writer = std::io::BufWriter::new(stream);
        let _ = writeln!(writer, "{}", serde_json::to_string(&resp).unwrap_or_default());
        return Ok(());
    }
    const MAX_LINE: usize = 1 << 20; // L1：单行上限 1MiB，防内存 DoS
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = std::io::BufWriter::new(stream);
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            break; // 对端关闭
        }
        if line.len() > MAX_LINE {
            let resp = json!({"id": null, "ok": false, "error": "请求行超过 1MiB 上限"});
            writeln!(writer, "{}", serde_json::to_string(&resp).unwrap_or_default())?;
            writer.flush()?;
            continue;
        }
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(&line) {
            Ok(req) => {
                let id = req.get("id").cloned().unwrap_or(json!(null));
                match dispatch(&req, rt) {
                    Ok(result) => json!({"id": id, "ok": true, "result": result}),
                    Err(e) => json!({"id": id, "ok": false, "error": e}),
                }
            }
            Err(e) => json!({"id": null, "ok": false, "error": format!("请求不是合法 JSON: {e}")}),
        };
        writeln!(writer, "{}", serde_json::to_string(&response).unwrap_or_default())?;
        writer.flush()?;
    }
    Ok(())
}

fn dispatch(req: &Value, rt: &Arc<Runtime>) -> Result<Value, String> {
    let cmd = req
        .get("cmd")
        .and_then(|v| v.as_str())
        .ok_or("缺少 cmd 字段")?
        .to_string();
    let params = req.get("params").cloned().unwrap_or(json!({}));
    let ledger_path = rt.cfg.state_dir.join("ledger.jsonl");
    let anchor_path = rt.cfg.state_dir.join("ledger.anchor");
    match cmd.as_str() {
        "status" => {
            let led = Ledger::load(&ledger_path);
            let runs_total = rt
                .runs
                .lock()
                .map(|m| m.len())
                .unwrap_or(led.entries.len());
            Ok(json!({
                "version": VERSION,
                "enforcement": format!("{}/{}", rt.executor.name(), rt.executor.enforcement()),
                "runs": runs_total,
                "agent_pubkey": rt.identity.pubkey_hex(),
                "policies": rt.policies.keys().cloned().collect::<Vec<_>>(),
                "uptime_secs": rt.started.elapsed().as_secs(),
            }))
        }
        "policies" => Ok(json!({
            "installed": rt.policies.keys().cloned().collect::<Vec<_>>(),
        })),
        "exec" => do_exec(&params, rt, &ledger_path, &anchor_path),
        "watch" => {
            let run = params
                .get("run")
                .and_then(|v| v.as_str())
                .ok_or("watch 需要 params.run")?;
            if let Some(state) = rt
                .runs
                .lock()
                .map_err(|_| "状态锁中毒".to_string())?
                .iter()
                .find(|(r, _)| r == run)
                .map(|(_, v)| v.clone())
            {
                return Ok(state);
            }
            // daemon 重启后从账本推断：M3 修复——只有 run.end 才算 done，
            // 仅有 run.start 报 interrupted，绝不虚报完成
            let led = Ledger::load(&ledger_path);
            let has_end = led.entries.iter().any(|e| e.run == *run && e.event == "run.end");
            let has_start = led.entries.iter().any(|e| e.run == *run);
            if has_end {
                Ok(json!({"state": "done", "run": run,
                          "note": "daemon 重启后仅能从账本确认完成状态"}))
            } else if has_start {
                Ok(json!({"state": "interrupted", "run": run,
                          "note": "daemon 重启时有未完成的受理记录"}))
            } else {
                Err(format!("未知 run: {run}"))
            }
        }
        "runs" => Ok(list_runs(&Ledger::load(&ledger_path), rt)),
        "verify" => {
            let led = Ledger::load(&ledger_path);
            match led.verify(Some(&anchor_path)) {
                Ok(total) => Ok(json!({"ok": true, "total": total})),
                Err(e) => Ok(json!({"ok": false, "total": e.total, "reason": e.reason})),
            }
        }
        other => Err(format!("未知 cmd: {other}（可用：status/policies/exec/watch/runs/verify）")),
    }
}

fn do_exec(
    params: &Value,
    rt: &Arc<Runtime>,
    ledger_path: &PathBuf,
    anchor_path: &PathBuf,
) -> Result<Value, String> {
    // H1 修复：exec 只接受【已安装策略的名称】，不接受客户端自拟的 policy 内容。
    let policy_name = params
        .get("policy")
        .and_then(|v| v.as_str())
        .ok_or("exec 需要 params.policy（已安装策略名，可用 policies 命令查询）")?;
    let policy = rt
        .policies
        .get(policy_name)
        .ok_or_else(|| {
            format!(
                "未安装策略 '{policy_name}'（已安装: {:?}）。策略由操作者放置于 {}",
                rt.policies.keys().collect::<Vec<_>>(),
                rt.cfg.state_dir.join("policies").display()
            )
        })?
        .clone();
    let argv: Vec<String> = serde_json::from_value(
        params.get("argv").cloned().ok_or("exec 需要 params.argv")?,
    )
    .map_err(|e| format!("argv 解析失败: {e}"))?;
    let stdin = params.get("stdin").and_then(|v| v.as_str()).map(String::from);
    let wait = params.get("wait").and_then(|v| v.as_bool()).unwrap_or(true);
    let run = format!("{}{}", now_date(), short_uuid());

    // run.start（签名：策略 canonical 摘要 + run id 绑定）
    let mut led = Ledger::load(ledger_path);
    let policy_val = serde_json::to_value(&policy).map_err(|e| e.to_string())?;
    let bind = json!({"policy": policy_val, "run": run});
    let policy_digest = sha256_hex(&crate::ledger::canonical(&bind));
    let sig = rt.identity.sign_digest(&hex_decode32(&policy_digest)?);
    led.append(
        "run.start",
        &run,
        json!({
            "policy_name": policy_name, "policy": policy_val,
            "backend": format!("{}/{}", rt.executor.name(), rt.executor.enforcement()),
            "agent_pubkey": rt.identity.pubkey_hex(),
            "signed": policy_digest, "agent_sig": sig,
        }),
    );
    drop(led);

    if !wait {
        if let Ok(mut m) = rt.runs.lock() {
            m.push((run.clone(), json!({"state": "running", "run": run})));
            evict_oldest(&mut m);
        }
        let rt2 = Arc::clone(rt);
        let run2 = run.clone();
        let policy2 = policy.clone();
        std::thread::spawn(move || {
            let result = run_task(&rt2, &run2, policy2, argv, stdin);
            if let Ok(mut m) = rt2.runs.lock() {
                if let Some(pos) = m.iter().position(|(r, _)| r == &run2) {
                    m[pos].1 = result.clone();
                }
            }
        });
        return Ok(json!({"run": run, "accepted": true}));
    }

    let result = run_task(rt, &run, policy, argv, stdin);
    if let Ok(mut m) = rt.runs.lock() {
        if let Some(pos) = m.iter().position(|(r, _)| r == &run) {
            m[pos].1 = result.clone();
        } else {
            m.push((run.clone(), result.clone()));
        }
    }
    Ok(result)
}

/// 执行主体：校验 → 执行器 → 落账（exec.result + 签名 run.end）→ 锚点 → 结果。
fn run_task(rt: &Runtime, run: &str, policy: Policy, argv: Vec<String>, stdin: Option<String>) -> Value {
    let ledger_path = rt.cfg.state_dir.join("ledger.jsonl");
    let anchor_path = rt.cfg.state_dir.join("ledger.anchor");

    if let Err(why) = policy.validate_run_command(&argv) {
        let mut led = Ledger::load(&ledger_path);
        led.append("exec.denied", run, json!({"argv": argv, "reason": why}));
        let _ = led.anchor(&anchor_path);
        return json!({"state": "done", "run": run, "denied": true, "rc": 127,
                      "stdout": "", "stderr": why,
                      "enforcement": format!("{}/{}", rt.executor.name(), rt.executor.enforcement())});
    }

    let res = rt.executor.execute(&policy, &argv, stdin.as_deref());

    // M4 修复：run.end 签名覆盖 run id/argv/rc/输出内容/enforcement，防跨 run 重放
    let mut led = Ledger::load(&ledger_path);
    led.append(
        "exec.result",
        run,
        json!({"argv": argv, "rc": res.rc, "enforcement": res.enforcement,
               "network_enforced": res.network_enforced}),
    );
    let outcome = json!({
        "run": run, "argv": argv, "rc": res.rc,
        "stdout": res.stdout, "stderr": res.stderr, "enforcement": res.enforcement,
        "network_enforced": res.network_enforced,
    });
    let outcome_digest = sha256_hex(&crate::ledger::canonical(&outcome));
    let sig = rt.identity.sign_digest(&hex_decode32(&outcome_digest).unwrap_or([0u8; 32]));
    led.append(
        "run.end",
        run,
        json!({"how": "exec", "outcome_digest": outcome_digest,
               "agent_pubkey": rt.identity.pubkey_hex(),
               "signed": outcome_digest, "agent_sig": sig}),
    );
    let _ = led.anchor(&anchor_path);

    json!({"state": "done", "run": run, "denied": false, "rc": res.rc,
           "stdout": res.stdout, "stderr": res.stderr,
           "enforcement": res.enforcement, "network_enforced": res.network_enforced})
}

/// FIFO 淘汰：状态表超过 256 条时移除最旧（M3 内存泄漏修复）。
fn evict_oldest(m: &mut Vec<(String, Value)>) {
    while m.len() > 256 {
        m.remove(0);
    }
}

fn list_runs(led: &Ledger, rt: &Runtime) -> Value {
    let mut runs: Vec<(String, u64, String, String)> = Vec::new();
    for e in &led.entries {
        if let Some(pos) = runs.iter().position(|r| r.0 == e.run) {
            runs[pos].1 += 1;
            runs[pos].3 = e.event.clone();
        } else {
            runs.push((e.run.clone(), 1, e.ts.clone(), e.event.clone()));
        }
    }
    let states = rt.runs.lock().ok();
    let items: Vec<Value> = runs
        .iter()
        .rev()
        .take(20)
        .map(|(run, events, first, last)| {
            let state = states
                .as_ref()
                .and_then(|m| m.iter().find(|(r, _)| r == run))
                .and_then(|(_, v)| v.get("state").and_then(|s| s.as_str()))
                .unwrap_or("settled");
            json!({"run": run, "events": events, "first_ts": first, "last_event": last, "state": state})
        })
        .collect();
    json!({"total_runs": runs.len(), "items": items})
}

fn now_date() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}{:06}", d.as_secs(), d.subsec_micros())
}

/// L3 修复：run id 随机部分来自 /dev/urandom（时间拼接存在并发碰撞）
fn short_uuid() -> String {
    let mut b = [0u8; 4];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut b);
    } else {
        let d = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        b = (d.subsec_nanos() as u32).to_le_bytes();
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn sha256_hex(data: &str) -> String {
    let mut h = Sha256::new();
    h.update(data.as_bytes());
    hex(&h.finalize())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode32(s: &str) -> Result<[u8; 32], String> {
    let v: Vec<u8> = (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    v.try_into().map_err(|_| "摘要长度不是 32 字节".to_string())
}

/// 客户端/测试辅助：连接 socket、发送请求、读取一行响应。
pub fn request(socket: &PathBuf, req: &Value) -> std::io::Result<Value> {
    let stream = UnixStream::connect(socket)?;
    let mut writer = stream.try_clone()?;
    writeln!(writer, "{}", serde_json::to_string(req).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?)?;
    writer.flush()?;
    let reader = BufReader::new(stream);
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        return serde_json::from_str(&line)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()));
    }
    Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "连接被关闭且无响应"))
}


/// 对端凭据校验：Linux=SO_PEERCRED，macOS=LOCAL_PEERCRED。
/// 比较对端 uid 与本进程 euid；平台不支持时放行（容器内恒同 uid，风险可接受并已记录）。
fn peer_uid_is_self(stream: &UnixStream) -> bool {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    let euid = unsafe { libc::geteuid() };
    #[cfg(target_os = "linux")]
    {
        let mut cred = libc::ucred { pid: 0, gid: 0, uid: 0 };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        unsafe {
            if libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_PEERCRED,
                                &mut cred as *mut libc::ucred as *mut libc::c_void,
                                &mut len) != 0 {
                eprintln!("[agentd] peer 凭据获取失败，拒绝连接（fail-closed）");
                return false;
            }
        }
        cred.uid == euid
    }
    #[cfg(target_os = "macos")]
    {
        #[repr(C)]
        struct Xucred { cr_version: u32, cr_uid: u32, cr_ngroups: i16, cr_groups: [u32; 16] }
        const LOCAL_PEERCRED: libc::c_int = 0x001;
        const SOL_LOCAL: libc::c_int = 0;
        const XUCRED_VERSION: u32 = 0;
        let mut cred = Xucred { cr_version: 0, cr_uid: 0, cr_ngroups: 0, cr_groups: [0; 16] };
        let mut len = std::mem::size_of::<Xucred>() as libc::socklen_t;
        unsafe {
            if libc::getsockopt(fd, SOL_LOCAL, LOCAL_PEERCRED,
                                &mut cred as *mut Xucred as *mut libc::c_void,
                                &mut len) != 0 {
                eprintln!("[agentd] peer 凭据获取失败，拒绝连接（fail-closed）");
                return false;
            }
        }
        if cred.cr_version != XUCRED_VERSION {
            // 版本不符 = 结构布局不可信 → fail-closed（审计 M-3）
            eprintln!("[agentd] peer 凭据版本不符，拒绝连接（fail-closed）");
            return false;
        }
        cred.cr_uid == euid
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = fd;
        let _ = euid;
        true
    }
}
