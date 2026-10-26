//! Conformance 案例（对照 conformance/cases.md 的 D 系列契约）。
//! 每个 test 名对应 cases.md 的编号，便于审计追溯。

use agentos_core::daemon::{request, serve, DaemonConfig};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::Duration;

fn temp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("agentos-conf-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn default_policy(work: &Path) -> Value {
    json!({
        "schema": "agentos.policy.v0",
        "workdir": work.to_str().unwrap(),
        "extra_read": [],
        "allow_commands": ["ls", "cat", "tee"],
        "network": false,
        "backend": "auto",
        "max_steps": 24,
    })
}

/// 启动 daemon；make_policies 收到 workdir 路径，返回 (名, 策略JSON) 列表（安装到 state_dir/policies）。
fn setup(
    tag: &str,
    make_policies: impl Fn(&Path) -> Vec<(String, Value)>,
    ledger_lines: Option<Vec<String>>,
) -> (PathBuf, PathBuf, PathBuf) {
    let state = temp_dir(tag);
    let work = temp_dir(&format!("{tag}-work"));
    std::fs::write(work.join("a.txt"), "hello").unwrap();

    let pdir = state.join("policies");
    std::fs::create_dir_all(&pdir).unwrap();
    for (name, policy) in make_policies(&work) {
        std::fs::write(pdir.join(format!("{name}.json")), policy.to_string()).unwrap();
    }
    let ledger_path = state.join("ledger.jsonl");
    if let Some(lines) = ledger_lines {
        std::fs::write(&ledger_path, lines.join("\n") + "\n").unwrap();
    }

    let sock = PathBuf::from(format!("/tmp/agentos-conf-{tag}.sock"));
    let _ = std::fs::remove_file(&sock);
    let cfg = DaemonConfig {
        state_dir: state.clone(),
        socket: sock.clone(),
        llrun: None,
    };
    let cfg2 = cfg.clone();
    std::thread::spawn(move || {
        let _ = serve(cfg2);
    });
    for _ in 0..100 {
        if sock.exists() {
            std::thread::sleep(Duration::from_millis(80));
            return (sock, state, work);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("socket 未创建");
}

fn req(sock: &PathBuf, cmd: &str, params: Value) -> Value {
    request(sock, &json!({"id": "c", "cmd": cmd, "params": params})).unwrap()
}

/// D3：network=true 的策略文件拒绝加载（fail-closed，M1 口径）
#[test]
fn d3_network_policy_rejected_at_load() {
    let (sock, _, work) = setup(
        "d3",
        |w| {
            vec![
                ("net".into(), json!({
                    "schema": "agentos.policy.v0", "workdir": w.to_str().unwrap(),
                    "extra_read": [], "allow_commands": ["curl"],
                    "network": true, "backend": "auto", "max_steps": 24})),
                ("ok".into(), default_policy(w)),
            ]
        },
        None,
    );
    let resp = req(&sock, "exec", json!({"policy": "net", "argv": ["curl", "http://x"]}));
    assert_eq!(resp["ok"], false);
    assert!(resp["error"].as_str().unwrap().contains("未安装策略"));
    let list = req(&sock, "policies", json!({}));
    let installed = list["result"]["installed"].as_array().unwrap();
    assert!(installed.iter().any(|p| p == "ok"));
    assert!(!installed.iter().any(|p| p == "net"));
}

/// D7：大输出（>64KiB 管道容量）正常返回，不得假超时（M2 回归）
#[test]
fn d7_large_output_no_fake_timeout() {
    let (sock, state, work) = setup("d7", |w| vec![("default".into(), default_policy(w))], None);
    let big = "x".repeat(2 * 1024 * 1024);
    std::fs::write(work.join("big.txt"), &big).unwrap();
    let resp = req(&sock, "exec", json!({"policy": "default", "argv": ["cat", "big.txt"]}));
    let r = &resp["result"];
    assert_eq!(r["rc"], 0, "大输出命令不得假超时: {}", resp);
    assert_eq!(r["stdout"].as_str().unwrap().len(), big.len());
}

/// D8：大 stdin（>64KiB）正常返回不挂死（M2 回归）
#[test]
fn d8_large_stdin_no_hang() {
    let (sock, state, work) = setup("d8", |w| vec![("default".into(), default_policy(w))], None);
    let big = "y".repeat(200 * 1024);
    let resp = req(
        &sock,
        "exec",
        json!({"policy": "default", "argv": ["cat"], "stdin": big}),
    );
    let r = &resp["result"];
    assert_eq!(r["rc"], 0);
    assert_eq!(r["stdout"].as_str().unwrap().len(), big.len());
}

/// D6：daemon 重启后，仅有 run.start 的 run → interrupted（不得虚报 done，M3 回归）
#[test]
fn d6_restart_interrupted_not_done() {
    let lines = vec![
        r#"{"schema":"agentos.ledger.v0","seq":1,"ts":"t","run":"orphan","event":"run.start","detail":{},"prev":"00","hash":"aa"}"#.to_string(),
    ];
    let (sock, state, _) = setup("d6", |w| vec![("default".into(), default_policy(w))], Some(lines));
    let w = req(&sock, "watch", json!({"run": "orphan"}));
    assert_eq!(w["result"]["state"], "interrupted", "不得虚报 done: {}", w);
    drop(state);
}

/// D10：run.end 签名绑定输出内容——同长度不同内容的两次 exec，摘要必须不同（M4 回归）
#[test]
fn d10_signature_binds_output_content() {
    let (sock, state, work) = setup("d10", |w| vec![("default".into(), default_policy(w))], None);
    std::fs::write(work.join("f1.txt"), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
    std::fs::write(work.join("f2.txt"), "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
    let r1 = req(&sock, "exec", json!({"policy": "default", "argv": ["cat", "f1.txt"]}));
    let r2 = req(&sock, "exec", json!({"policy": "default", "argv": ["cat", "f2.txt"]}));
    assert_eq!(
        r1["result"]["stdout"].as_str().unwrap().len(),
        r2["result"]["stdout"].as_str().unwrap().len()
    );
    let led = agentos_core::ledger::Ledger::load(&state.join("ledger.jsonl"));
    let mut digests: Vec<String> = Vec::new();
    for e in &led.entries {
        if e.event == "run.end" {
            if let Some(d) = e.detail.get("outcome_digest").and_then(|v| v.as_str()) {
                digests.push(d.to_string());
            }
        }
    }
    assert_eq!(digests.len(), 2);
    assert_ne!(digests[0], digests[1], "同长度不同输出的 run.end 摘要不应相同");
}
