//! agentd 集成测试：真实 Unix socket + NDJSON 协议往返（plain 执行器，跨平台）。

use agentos_core::daemon::{request, serve, DaemonConfig};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::Duration;

fn temp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("agentos-daemon-test-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn wait_socket(sock: &PathBuf) {
    for _ in 0..100 {
        if sock.exists() {
            std::thread::sleep(Duration::from_millis(50)); // 等 accept 循环就绪
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("socket 未创建: {}", sock.display());
}

fn setup(tag: &str) -> (DaemonConfig, PathBuf) {
    let state = temp_dir(tag);
    let work = temp_dir(&format!("{tag}-work"));
    std::fs::write(work.join("a.txt"), "hello").unwrap();
    let sock = PathBuf::from(format!("/tmp/agentos-test-{tag}.sock"));
    let _ = std::fs::remove_file(&sock);
    let cfg = DaemonConfig {
        state_dir: state.clone(),
        socket: sock.clone(),
        llrun: None,
    };
    let cfg_for_thread = cfg.clone();
    std::thread::spawn(move || {
        let _ = serve(cfg_for_thread);
    });
    wait_socket(&sock);
    (cfg, work)
}

fn req(sock: &PathBuf, cmd: &str, params: Value) -> Value {
    request(sock, &json!({"id": "t", "cmd": cmd, "params": params})).unwrap()
}

#[test]
fn daemon_status_exec_runs_verify() {
    let (cfg, work) = setup("full");

    // status
    let status = req(&cfg.socket, "status", json!({}));
    assert_eq!(status["ok"], true);
    assert!(status["result"]["agent_pubkey"].as_str().is_some());
    assert!(status["result"]["enforcement"].as_str().is_some());

    // exec：合法命令
    let policy = json!({
        "schema": "agentos.policy.v0", "workdir": work.to_str().unwrap(),
        "extra_read": [], "allow_commands": ["ls", "cat", "mkdir", "mv"],
        "network": false, "backend": "auto", "max_steps": 24,
    });
    let resp = req(&cfg.socket, "exec", json!({"policy": policy, "argv": ["cat", "a.txt"]}));
    assert_eq!(resp["ok"], true);
    let r = &resp["result"];
    assert_eq!(r["denied"], false);
    assert_eq!(r["rc"], 0);
    assert_eq!(r["stdout"].as_str().unwrap().trim(), "hello");
    assert!(r["run"].as_str().is_some());

    // exec：逃逸尝试（策略层拒绝，H1 口径）
    let resp = req(&cfg.socket, "exec", json!({"policy": policy, "argv": ["cat", "/etc/passwd"]}));
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["result"]["denied"], true);
    assert!(resp["result"]["stderr"].as_str().unwrap().contains("outside allowed roots"));

    // exec：异步受理 + watch 轮询到完成
    let resp = req(&cfg.socket, "exec", json!({"policy": policy, "argv": ["cat", "a.txt"], "wait": false}));
    assert_eq!(resp["result"]["accepted"], true);
    let run = resp["result"]["run"].as_str().unwrap().to_string();
    let mut done = false;
    for _ in 0..40 {
        let w = req(&cfg.socket, "watch", json!({"run": run}));
        if w["result"]["state"] == "done" {
            assert_eq!(w["result"]["rc"], 0);
            assert_eq!(w["result"]["stdout"].as_str().unwrap().trim(), "hello");
            done = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(done, "watch 轮询超时仍未完成");

    // runs
    let runs = req(&cfg.socket, "runs", json!({}));
    assert!(runs["result"]["total_runs"].as_u64().unwrap() >= 1);

    // verify：账本 + 锚点 + 签名
    let v = req(&cfg.socket, "verify", json!({}));
    assert_eq!(v["result"]["ok"], true, "verify: {}", v);
}
