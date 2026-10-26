//! agentd — 常驻运行时：Unix socket + NDJSON 协议。
//!
//! 协议（每连接一个请求）：
//!   请求: {"id":"...","cmd":"status|exec|runs|verify","params":{...}}
//!   响应: {"id":"...","ok":true,"result":{...}} 或 {"id":"...","ok":false,"error":"..."}
//!
//! exec 语义：daemon 是"内核"——把命令放进策略笼子执行并记账；
//! 模型循环属于客户端（如 Python harness）。run.start/run.end 由 daemon 身份签名，
//! Python 的 ledger.verify()/ed25519.checkvalid 可直接互验。

use crate::exec::{select, Executor};
use crate::identity::{self, Identity};
use crate::ledger::Ledger;
use crate::policy::Policy;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

#[derive(Clone)]
pub struct DaemonConfig {
    pub state_dir: PathBuf,
    pub socket: PathBuf,
    pub llrun: Option<PathBuf>,
}

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn serve(cfg: DaemonConfig) -> std::io::Result<()> {
    std::fs::create_dir_all(&cfg.state_dir)?;
    if let Some(parent) = cfg.socket.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(&cfg.socket);
    let listener = UnixListener::bind(&cfg.socket)?;
    let identity = Arc::new(identity::ensure(&cfg.state_dir)?);
    let executor = Arc::new(select(cfg.llrun.as_ref()));
    let started = Instant::now();
    eprintln!(
        "[agentd] listening on {} (executor: {} / {}) state: {}",
        cfg.socket.display(),
        executor.name(),
        executor.enforcement(),
        cfg.state_dir.display()
    );
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let cfg = cfg.clone();
        let identity = Arc::clone(&identity);
        let executor = Arc::clone(&executor);
        let started = started;
        std::thread::spawn(move || {
            let executor_ref: &dyn Executor = &**executor;
            let _ = handle_conn(stream, &cfg, &identity, executor_ref, started);
        });
    }
    Ok(())
}

fn handle_conn(
    stream: UnixStream,
    cfg: &DaemonConfig,
    identity: &Identity,
    executor: &dyn Executor,
    started: Instant,
) -> std::io::Result<()> {
    use std::io::{BufRead, Write};
    let reader = std::io::BufReader::new(stream.try_clone()?);
    let mut writer = std::io::BufWriter::new(stream);
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(&line) {
            Ok(req) => {
                let id = req.get("id").cloned().unwrap_or(json!(null));
                match dispatch(&req, cfg, identity, executor, started) {
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

fn dispatch(
    req: &Value,
    cfg: &DaemonConfig,
    identity: &Identity,
    executor: &dyn Executor,
    started: Instant,
) -> Result<Value, String> {
    let cmd = req
        .get("cmd")
        .and_then(|v| v.as_str())
        .ok_or("缺少 cmd 字段")?
        .to_string();
    let params = req.get("params").cloned().unwrap_or(json!({}));
    let ledger_path = cfg.state_dir.join("ledger.jsonl");
    let anchor_path = cfg.state_dir.join("ledger.anchor");
    match cmd.as_str() {
        "status" => {
            let led = Ledger::load(&ledger_path);
            Ok(json!({
                "version": VERSION,
                "enforcement": format!("{}/{}", executor.name(), executor.enforcement()),
                "runs": count_runs(&led),
                "agent_pubkey": identity.pubkey_hex(),
                "uptime_secs": started.elapsed().as_secs(),
            }))
        }
        "exec" => do_exec(&params, cfg, identity, executor, &ledger_path, &anchor_path),
        "runs" => Ok(list_runs(&Ledger::load(&ledger_path))),
        "verify" => {
            let led = Ledger::load(&ledger_path);
            match led.verify(Some(&anchor_path)) {
                Ok(total) => Ok(json!({"ok": true, "total": total})),
                Err(e) => Ok(json!({"ok": false, "total": e.total, "reason": e.reason})),
            }
        }
        other => Err(format!("未知 cmd: {other}（可用：status/exec/runs/verify）")),
    }
}

fn do_exec(
    params: &Value,
    cfg: &DaemonConfig,
    identity: &Identity,
    executor: &dyn Executor,
    ledger_path: &PathBuf,
    anchor_path: &PathBuf,
) -> Result<Value, String> {
    let policy: Policy = serde_json::from_value(
        params.get("policy").cloned().ok_or("exec 需要 params.policy")?,
    )
    .map_err(|e| format!("policy 解析失败: {e}"))?;
    let argv: Vec<String> = serde_json::from_value(
        params.get("argv").cloned().ok_or("exec 需要 params.argv")?,
    )
    .map_err(|e| format!("argv 解析失败: {e}"))?;
    let stdin = params.get("stdin").and_then(|v| v.as_str()).map(String::from);

    let run = format!("{}-{}", now_date(), short_uuid());
    let ledger_path = ledger_path.clone();
    let anchor_path = anchor_path.clone();

    // run.start（签名：策略 canonical 摘要）
    let mut led = Ledger::load(&ledger_path);
    let policy_val = serde_json::to_value(&policy).map_err(|e| e.to_string())?;
    let policy_digest = sha256_hex(&crate::ledger::canonical(&policy_val));
    let sig = identity.sign_digest(&hex_decode32(&policy_digest)?);
    led.append(
        "run.start",
        &run,
        json!({
            "policy": policy_val, "backend": format!("{}/{}", executor.name(), executor.enforcement()),
            "agent_pubkey": identity.pubkey_hex(), "signed": policy_digest, "agent_sig": sig,
        }),
    );
    drop(led);

    // 策略校验（H1 口径）：拒绝也入账
    if let Err(why) = policy.validate_run_command(&argv) {
        let mut led = Ledger::load(&ledger_path);
        led.append("exec.denied", &run, json!({"argv": argv, "reason": why}));
        led.anchor(&anchor_path);
        return Ok(json!({"run": run, "denied": true, "rc": 127, "stdout": "", "stderr": why,
                         "enforcement": format!("{}/{}", executor.name(), executor.enforcement())}));
    }

    let res = executor.execute(&policy, &argv, stdin.as_deref());

    let mut led = Ledger::load(&ledger_path);
    led.append(
        "exec.result",
        &run,
        json!({"argv": argv, "rc": res.rc, "enforcement": res.enforcement}),
    );
    let report_digest = sha256_hex(&format!("exec|{}|{}", res.rc, res.stdout.len()));
    let sig = identity.sign_digest(&hex_decode32(&report_digest)?);
    led.append(
        "run.end",
        &run,
        json!({"how": "exec", "rc": res.rc, "agent_pubkey": identity.pubkey_hex(),
               "signed": report_digest, "agent_sig": sig}),
    );
    led.anchor(&anchor_path);

    Ok(json!({"run": run, "denied": false, "rc": res.rc,
              "stdout": res.stdout, "stderr": res.stderr,
              "enforcement": res.enforcement}))
}

fn list_runs(led: &Ledger) -> Value {
    let mut runs: Vec<(String, u64, String, String)> = Vec::new();
    for e in &led.entries {
        if let Some(pos) = runs.iter().position(|r| r.0 == e.run) {
            runs[pos].1 += 1;
            runs[pos].3 = e.event.clone();
        } else {
            runs.push((e.run.clone(), 1, e.ts.clone(), e.event.clone()));
        }
    }
    let items: Vec<Value> = runs
        .iter()
        .rev()
        .take(20)
        .map(|(run, events, first, last)| {
            json!({"run": run, "events": events, "first_ts": first, "last_event": last})
        })
        .collect();
    json!({"total_runs": runs.len(), "items": items})
}

fn count_runs(led: &Ledger) -> usize {
    let mut runs: Vec<&str> = led.entries.iter().map(|e| e.run.as_str()).collect();
    runs.dedup();
    runs.len()
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

/// 客户端/测试辅助：连接 socket、发送请求、读取一行响应。
pub fn request(socket: &PathBuf, req: &Value) -> std::io::Result<Value> {
    let stream = UnixStream::connect(socket)?;
    let mut writer = stream.try_clone()?;
    writeln!(writer, "{}", serde_json::to_string(req).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?)?;
    writer.flush()?;
    let reader = std::io::BufReader::new(stream);
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
