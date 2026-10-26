//! agentd 集成测试（H1 修复后的协议）：exec 按【已安装策略名】引用。
//! 覆盖：未知策略拒绝、合法执行、逃逸拒绝、异步 watch、账本验签。

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
            std::thread::sleep(Duration::from_millis(50));
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("socket 未创建: {}", sock.display());
}

/// 启动 daemon 并安装 "default" 策略（读写区 = work，白名单含 tee 以覆盖写原语）。
fn setup(tag: &str) -> (DaemonConfig, PathBuf) {
    let state = temp_dir(tag);
    let work = temp_dir(&format!("{tag}-work"));
    std::fs::write(work.join("a.txt"), "hello").unwrap();

    // 安装策略（H1：策略由操作者放置，daemon 启动时加载）
    let policies = state.join("policies");
    std::fs::create_dir_all(&policies).unwrap();
    std::fs::write(
        policies.join("default.json"),
        json!({
            "schema": "agentos.policy.v0",
            "workdir": work.to_str().unwrap(),
            "extra_read": [],
            "allow_commands": ["ls", "cat", "mkdir", "mv", "tee"],
            "network": false,
            "backend": "auto",
            "max_steps": 24,
        })
        .to_string(),
    )
    .unwrap();

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
fn daemon_exec_by_installed_policy_name() {
    let (cfg, work) = setup("h1");

    // status：报告已装策略
    let status = req(&cfg.socket, "status", json!({}));
    assert_eq!(status["ok"], true);
    assert!(status["result"]["policies"].as_array().unwrap().iter().any(|p| p == "default"));

    // H1 正面：按名执行已安装策略
    let resp = req(&cfg.socket, "exec", json!({"policy": "default", "argv": ["cat", "a.txt"]}));
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["result"]["denied"], false);
    assert_eq!(resp["result"]["rc"], 0);
    assert_eq!(resp["result"]["stdout"].as_str().unwrap().trim(), "hello");

    // H1 反面 A：回传 policy【内容】（对象）→ 拒绝（协议只接受已安装策略名）
    let inline_policy = json!({
        "schema": "agentos.policy.v0", "workdir": "/", "extra_read": [],
        "allow_commands": ["bash", "cat"], "network": true, "backend": "auto",
    });
    let resp = req(&cfg.socket, "exec", json!({"policy": inline_policy, "argv": ["cat", "/etc/passwd"]}));
    assert_eq!(resp["ok"], false);
    assert!(resp["error"].as_str().unwrap().contains("params.policy"),
            "内联 policy 应被拒: {}", resp);

    // H1 反面 B：未安装的策略名 → 拒绝
    let resp = req(&cfg.socket, "exec", json!({"policy": "no-such-policy", "argv": ["ls"]}));
    assert_eq!(resp["ok"], false);
    assert!(resp["error"].as_str().unwrap().contains("未安装策略"));

    // H2 反面：.. 逃逸在策略层被拒（Rust 词法折叠）
    let resp = req(&cfg.socket, "exec", json!({"policy": "default", "argv": ["cat", "../../etc/passwd"]}));
    assert_eq!(resp["result"]["denied"], true);
    assert!(resp["result"]["stderr"].as_str().unwrap().contains("outside allowed roots"));

    // 异步 + watch
    let resp = req(&cfg.socket, "exec", json!({"policy": "default", "argv": ["cat", "a.txt"], "wait": false}));
    let run = resp["result"]["run"].as_str().unwrap().to_string();
    let mut done = false;
    for _ in 0..40 {
        let w = req(&cfg.socket, "watch", json!({"run": run}));
        if w["result"]["state"] == "done" {
            assert_eq!(w["result"]["stdout"].as_str().unwrap().trim(), "hello");
            done = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(done, "watch 轮询超时");

    // 未知 run 的 watch：不虚报 done
    let w = req(&cfg.socket, "watch", json!({"run": "no-such-run"}));
    assert_eq!(w["ok"], false);

    // verify：链 + 锚点 + 签名
    let v = req(&cfg.socket, "verify", json!({}));
    assert_eq!(v["result"]["ok"], true, "verify: {}", v);
}
