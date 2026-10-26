//! agentd — 常驻运行时：Unix socket + NDJSON 协议。
//!
//! 协议（每连接一个请求）：
//!   请求: {"id":"...","cmd":"status|exec|runs|watch|verify","params":{...}}
//!   响应: {"id":"...","ok":true,"result":{...}} 或 {"id":"...","ok":false,"error":"..."}
//!
//! exec 两种模式：
//!   同步（默认）  —— params.wait 缺省/true：执行完返回 {"run","rc","stdout",...}
//!   异步          —— params.wait=false：立即返回 {"run","accepted":true}，
//!                    随后用 watch {"run"} 轮询 {"state":"running|done", ...}
//!
//! daemon 是"内核"——把命令放进策略笼子执行并记账；模型循环属于客户端。

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
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

#[derive(Clone)]
pub struct DaemonConfig {
    pub state_dir: PathBuf,
    pub socket: PathBuf,
    pub llrun: Option<PathBuf>,
}

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// daemon 运行时共享状态。
pub struct Runtime {
    pub cfg: DaemonConfig,
    pub identity: Identity,
    pub executor: Box<dyn Executor>,
    pub started: Instant,
    /// run_id → 状态快照 {"state":"running|done", "rc":..., "stdout":..., ...}
    pub runs: Arc<Mutex<HashMap<String, Value>>>,
}

pub fn serve(cfg: DaemonConfig) -> std::io::Result<()> {
    std::fs::create_dir_all(&cfg.state_dir)?;
    if let Some(parent) = cfg.socket.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(&cfg.socket);
    let listener = UnixListener::bind(&cfg.socket)?;
    let identity = identity::ensure(&cfg.state_dir)?;
    let executor = select(cfg.llrun.as_ref());
    let started = Instant::now();
    eprintln!(
        "[agentd] listening on {} (executor: {} / {}) state: {}",
        cfg.socket.display(),
        executor.name(),
        executor.enforcement(),
        cfg.state_dir.display()
    );
    let runtime = Arc::new(Runtime {
        cfg,
        identity,
        executor,
        started,
        runs: Arc::new(Mutex::new(HashMap::new())),
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

fn handle_conn(stream: UnixStream, rt: &Arc<Runtime>) -> std::io::Result<()> {
    let reader = BufReader::new(stream.try_clone()?);
    let mut writer = std::io::BufWriter::new(stream);
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
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
                "uptime_secs": rt.started.elapsed().as_secs(),
            }))
        }
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
                .get(run)
                .cloned()
            {
                return Ok(state);
            }
            // daemon 重启后内存态丢失：从账本推断（无结果详情）
            let led = Ledger::load(&ledger_path);
            let events = led.entries.iter().filter(|e| e.run == *run).count();
            if events > 0 {
                Ok(json!({"state": "done", "run": run, "events": events,
                          "note": "daemon 重启后仅能从账本确认完成状态"}))
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
        other => Err(format!("未知 cmd: {other}（可用：status/exec/watch/runs/verify）")),
    }
}

fn do_exec(params: &Value, rt: &Arc<Runtime>, ledger_path: &PathBuf, anchor_path: &PathBuf) -> Result<Value, String> {
    let policy: Policy = serde_json::from_value(
        params.get("policy").cloned().ok_or("exec 需要 params.policy")?,
    )
    .map_err(|e| format!("policy 解析失败: {e}"))?;
    let argv: Vec<String> = serde_json::from_value(
        params.get("argv").cloned().ok_or("exec 需要 params.argv")?,
    )
    .map_err(|e| format!("argv 解析失败: {e}"))?;
    let stdin = params.get("stdin").and_then(|v| v.as_str()).map(String::from);
    let wait = params.get("wait").and_then(|v| v.as_bool()).unwrap_or(true);
    let run = format!("{}{}", now_date(), short_uuid());

    // run.start（签名：策略 canonical 摘要）—— 同步/异步都在受理线程记账
    let mut led = Ledger::load(ledger_path);
    let policy_val = serde_json::to_value(&policy).map_err(|e| e.to_string())?;
    let policy_digest = sha256_hex(&crate::ledger::canonical(&policy_val));
    let sig = rt.identity.sign_digest(&hex_decode32(&policy_digest)?);
    led.append(
        "run.start",
        &run,
        json!({
            "policy": policy_val, "backend": format!("{}/{}", rt.executor.name(), rt.executor.enforcement()),
            "agent_pubkey": rt.identity.pubkey_hex(), "signed": policy_digest, "agent_sig": sig,
        }),
    );
    drop(led);

    if !wait {
        if let Ok(mut m) = rt.runs.lock() {
            m.insert(run.clone(), json!({"state": "running", "run": run}));
        }
        let rt2 = Arc::clone(rt);
        let run2 = run.clone();
        let argv2 = argv.clone();
        std::thread::spawn(move || {
            let result = run_task(&rt2, &run2, policy, argv2, stdin);
            if let Ok(mut m) = rt2.runs.lock() {
                m.insert(run2, result);
            }
        });
        return Ok(json!({"run": run, "accepted": true}));
    }

    let result = run_task(rt, &run, policy, argv, stdin);
    if let Ok(mut m) = rt.runs.lock() {
        m.insert(run.clone(), result.clone());
    }
    Ok(result)
}

/// 执行主体：执行器跑命令 → exec.result + run.end 落账 → 锚点 → 返回结果 JSON。
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

    let mut led = Ledger::load(&ledger_path);
    led.append(
        "exec.result",
        run,
        json!({"argv": argv, "rc": res.rc, "enforcement": res.enforcement}),
    );
    let report_digest = sha256_hex(&format!("exec|{}|{}", res.rc, res.stdout.len()));
    let sig = rt.identity.sign_digest(&hex_decode32(&report_digest).unwrap_or([0u8; 32]));
    led.append(
        "run.end",
        run,
        json!({"how": "exec", "rc": res.rc, "agent_pubkey": rt.identity.pubkey_hex(),
               "signed": report_digest, "agent_sig": sig}),
    );
    let _ = led.anchor(&anchor_path);

    json!({"state": "done", "run": run, "denied": false, "rc": res.rc,
           "stdout": res.stdout, "stderr": res.stderr,
           "enforcement": res.enforcement})
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
                .and_then(|m| m.get(run))
                .and_then(|v| v.get("state").and_then(|s| s.as_str()))
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

fn short_uuid() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{:08x}", (d.as_nanos() & 0xffff_ffff) as u32)
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

/// MutexGuard 的类型别名辅助（锁中毒转错误由调用方处理）。
pub fn lock_map<'a>(rt: &'a Runtime) -> Option<MutexGuard<'a, HashMap<String, Value>>> {
    rt.runs.lock().ok()
}
