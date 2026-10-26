//! agentctl — agentd 的最小客户端。
//! 用法：
//!   agentctl --socket <SOCK> status
//!   agentctl --socket <SOCK> runs
//!   agentctl --socket <SOCK> verify
//!   agentctl --socket <SOCK> exec --policy <policy.json> -- CMD [ARGS]...
//!   agentctl --socket <SOCK> exec --workdir <DIR> -- CMD [ARGS]...   （合成默认策略）

use agentos_core::daemon::request;
use serde_json::{json, Value};
use std::path::PathBuf;

fn main() {
    let mut socket = PathBuf::from("/tmp/agentos.sock");
    let mut argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.first().map(|s| s == "--socket").unwrap_or(false) {
        argv.remove(0);
        socket = argv.remove(0).into();
    }
    let Some(cmd) = argv.first().cloned() else {
        eprintln!("用法: agentctl --socket <SOCK> status|runs|verify|exec ...");
        std::process::exit(2);
    };
    let argv: Vec<String> = argv[1..].to_vec();

    let (req, result_only): (Value, bool) = match cmd.as_str() {
        "status" | "runs" | "verify" => (json!({"id": "ctl", "cmd": cmd, "params": {}}), false),
        "exec" => {
            let mut policy_file: Option<String> = None;
            let mut workdir: Option<String> = None;
            let mut rest: Vec<String> = Vec::new();
            let mut i = 0;
            while i < argv.len() {
                match argv[i].as_str() {
                    "--policy" if i + 1 < argv.len() => { policy_file = Some(argv[i + 1].clone()); i += 2; }
                    "--workdir" if i + 1 < argv.len() => { workdir = Some(argv[i + 1].clone()); i += 2; }
                    "--" => { rest = argv[i + 1..].to_vec(); break; }
                    t => { rest.push(t.to_string()); i += 1; }
                }
            }
            let policy = if let Some(f) = &policy_file {
                std::fs::read_to_string(f).unwrap_or_else(|e| {
                    eprintln!("[agentctl] 读 policy 失败: {e}");
                    std::process::exit(2);
                })
            } else if let Some(wd) = &workdir {
                serde_json::json!({
                    "schema": "agentos.policy.v0", "workdir": wd, "extra_read": [],
                    "allow_commands": ["ls","cat","head","tail","grep","wc","mkdir","mv","cp","echo"],
                    "network": false, "backend": "auto", "max_steps": 24
                }).to_string()
            } else {
                eprintln!("[agentctl] exec 需要 --policy <file> 或 --workdir <dir>");
                std::process::exit(2);
            };
            let policy: Value = serde_json::from_str(&policy).unwrap_or_else(|e| {
                eprintln!("[agentctl] policy 不是合法 JSON: {e}");
                std::process::exit(2);
            });
            (
                json!({"id": "ctl", "cmd": "exec", "params": {"policy": policy, "argv": rest}}),
                true,
            )
        }
        other => {
            eprintln!("未知命令: {other}");
            std::process::exit(2);
        }
    };

    match request(&socket, &req) {
        Ok(resp) => {
            let ok = resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
            if result_only {
                if let Some(r) = resp.get("result") {
                    if let Some(out) = r.get("stdout").and_then(|v| v.as_str()) {
                        print!("{out}");
                    }
                    if let Some(err) = r.get("stderr").and_then(|v| v.as_str()) {
                        if !err.is_empty() {
                            eprintln!("{err}");
                        }
                    }
                    if let Some(denied) = r.get("denied").and_then(|v| v.as_bool()) {
                        if denied {
                            eprintln!("[agentctl] 策略拒绝");
                        }
                    }
                    if let Some(rc) = r.get("rc").and_then(|v| v.as_i64()) {
                        std::process::exit(rc.clamp(0, 125) as i32);
                    }
                }
                std::process::exit(if ok { 0 } else { 1 });
            }
            match serde_json::to_string_pretty(&resp) {
                Ok(s) => println!("{s}"),
                Err(e) => { eprintln!("[agentctl] 序列化失败: {e}"); std::process::exit(1); }
            }
            if !ok {
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("[agentctl] 无法连接 {socket:?}: {e}");
            std::process::exit(1);
        }
    }
}
