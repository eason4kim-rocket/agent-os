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
        "watch" => {
            let Some(run) = argv.first() else {
                eprintln!("用法: agentctl watch <run> [--timeout S]");
                std::process::exit(2);
            };
            let timeout = argv
                .iter()
                .position(|a| a == "--timeout")
                .and_then(|i| argv.get(i + 1))
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(120);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout);
            loop {
                let resp = request(&socket, &json!({"id": "ctl", "cmd": "watch",
                                                    "params": {"run": run}}))
                    .unwrap_or_else(|e| {
                        eprintln!("[agentctl] 连接失败: {e}");
                        std::process::exit(1);
                    });
                let state = resp["result"]["state"].as_str().unwrap_or("");
                if state == "done" {
                    let r = &resp["result"];
                    if let Some(out) = r.get("stdout").and_then(|v| v.as_str()) {
                        print!("{out}");
                    }
                    if let Some(err) = r.get("stderr").and_then(|v| v.as_str()) {
                        if !err.is_empty() {
                            eprintln!("{err}");
                        }
                    }
                    let rc = r.get("rc").and_then(|v| v.as_i64()).unwrap_or(-1);
                    std::process::exit(rc.clamp(0, 125) as i32);
                }
                if std::time::Instant::now() >= deadline {
                    eprintln!("[agentctl] watch 超时（{timeout}s），任务仍在后台运行");
                    std::process::exit(124);
                }
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        }
        "exec" => {
            // H1 修复后的口径：--policy 是【已安装策略名】（不是文件/不是内容）——
            // 权限由操作者安装在 daemon state_dir/policies/ 下，客户端无法自拟。
            let mut policy_name = "default".to_string();
            let mut rest: Vec<String> = Vec::new();
            let mut i = 0;
            let mut wait = true;
            while i < argv.len() {
                match argv[i].as_str() {
                    "--policy" if i + 1 < argv.len() => { policy_name = argv[i + 1].clone(); i += 2; }
                    "--async" => { wait = false; i += 1; }
                    "--" => { rest = argv[i + 1..].to_vec(); break; }
                    t => { rest.push(t.to_string()); i += 1; }
                }
            }
            if rest.is_empty() {
                eprintln!("[agentctl] exec 需要 -- <命令...>");
                std::process::exit(2);
            }
            (
                json!({"id": "ctl", "cmd": "exec",
                       "params": {"policy": policy_name, "argv": rest, "wait": wait}}),
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
                    if r.get("accepted").and_then(|v| v.as_bool()).unwrap_or(false) {
                        if let Some(run) = r.get("run").and_then(|v| v.as_str()) {
                            println!("{run}");
                            println!("[agentctl] 已受理（异步），查看进度: agentctl watch {run}");
                        }
                        std::process::exit(0);
                    }
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
