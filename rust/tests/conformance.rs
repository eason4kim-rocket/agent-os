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

    let sock = PathBuf::from(format!("/tmp/agentos-conf-{}-{tag}.sock", std::process::id()));
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

fn hex_decode_rs(s: &str) -> Result<Vec<u8>, ()> {
    if s.len() % 2 != 0 { return Err(()); }
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2*i..2*i+2], 16).map_err(|_| ())).collect()
}

// ===== L 系列与 D9/P7（二审补齐） =====

use agentos_core::ledger::{canonical, Ledger, GENESIS};

/// D9/L5：换身份重建账本 → 锚点公钥集检测（无锚点时链+签名自洽可过——诚实边界）。
#[test]
fn d9_ledger_verify_rejects_forged_identity() {
    use agentos_core::ledger::{canonical, Ledger, GENESIS};
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

    let dir = std::env::temp_dir().join(format!("agentos-d9-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("ledger.jsonl");
    let anchor = dir.join("ledger.anchor");

    // 攻击者 B：自己的密钥、自己的 policy、正确计算哈希链（链内自洽）
    let attacker = SigningKey::from_bytes(&[9u8; 32]);
    let attacker_pk = hex(&attacker.verifying_key().to_bytes());
    let policy = json!({"schema": "agentos.policy.v0", "workdir": "/", "extra_read": [],
                        "allow_commands": ["bash"], "network": true, "backend": "auto", "max_steps": 24});
    let policy_digest = hex(&Sha256::digest(canonical(&policy).as_bytes()));
    let sig = attacker.sign(&hex_decode(&policy_digest).unwrap());
    let entry = json!({
        "schema": "agentos.ledger.v0", "seq": 1, "ts": "t", "run": "forged",
        "event": "run.start", "detail": {"policy": policy, "agent_pubkey": attacker_pk,
            "signed": policy_digest, "agent_sig": hex(&sig.to_bytes())},
        "prev": GENESIS, "hash": ""
    });
    let mut no_hash = entry.clone();
    if let Some(o) = no_hash.as_object_mut() {
        o.remove("hash");  // 哈希输入必须排除 hash 字段本身（与 verify 口径一致）
    }
    let mut hasher = Sha256::new();
    hasher.update(GENESIS.as_bytes());  // 首条 prev = GENESIS
    hasher.update(canonical(&no_hash).as_bytes());
    let hash = hex(&hasher.finalize());
    let mut entry = entry;
    entry["hash"] = json!(hash);
    std::fs::write(&path, canonical(&entry) + "\n").unwrap();

    // 无锚点：链+签名自洽，verify 通过（诚实边界——本地无外部信任基准时无法识破）
    assert!(Ledger::load(&path).verify(None).is_ok());

    // 有锚点（操作者记录的原始公钥集合不含攻击者）→ 必须拒绝
    let original_anchor = json!({
        "schema": "agentos.ledger.anchor.v0", "count": 1,
        "head": hash, "agent_pubkeys": ["aa".repeat(32)],
    });
    std::fs::write(&anchor, canonical(&original_anchor) + "\n").unwrap();
    let err = Ledger::load(&path)
        .verify(Some(&anchor))
        .expect_err("换身份重建的账本必须被锚点拒绝");
    assert!(err.reason.contains("签名身份不在锚点记录中"), "实际: {}", err.reason);
}

/// L1/L3/L4（Rust）：空账本、锚点截断、坏行
#[test]
fn l_series_ledger_edges_rust() {
    let dir = std::env::temp_dir().join(format!("agentos-l-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("ledger.jsonl");
    let anchor = dir.join("ledger.anchor");

    // L1：空账本
    assert!(Ledger::load(&path).verify(Some(&anchor)).is_err());

    // 写 3 条 + 锚点
    let mut led = Ledger::load(&path);
    for i in 0..3 {
        led.append("tool.result", "r", serde_json::json!({"i": i})).unwrap();
    }
    led.anchor(&anchor).unwrap();

    // L3：截断尾部 → 锚点核对失败
    let content = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    std::fs::write(&path, lines[..1].join("\n") + "\n").unwrap();
    let err = Ledger::load(&path).verify(Some(&anchor)).expect_err("截断应失败");
    assert!(err.reason.contains("截断"), "实际: {}", err.reason);

    // L4：坏行（断电半行）→ 失败不崩溃
    std::fs::write(&path, lines[..1].join("\n") + "\n" + "{\"schema\": \"agentos.led\n").unwrap();
    let err = Ledger::load(&path).verify(Some(&anchor)).expect_err("坏行应失败");
    assert!(err.reason.contains("解析失败"), "实际: {}", err.reason);
}

/// P7（Rust）：词法层不解析符号链接——笼内相对路径放行、笼外绝对路径拒绝；
/// 符号链接的最终语义由 Landlock 内核层兜底（README 已声明该边界）。
#[test]
fn p7_symlink_documented_boundary() {
    let tmp = temp_dir("p7");
    let work = tmp.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let p = agentos_core::policy::Policy {
        schema: agentos_core::policy::SCHEMA.into(),
        workdir: work.to_string_lossy().into(),
        extra_read: vec![],
        allow_commands: vec!["ls".into()],
        network: false,
        backend: "auto".into(),
        max_steps: 24,
    };
    assert!(p.path_allowed_read("a.txt").is_ok());
    assert!(p.path_allowed_read("/etc/passwd").is_err());
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    if s.len() % 2 != 0 {
        return Err(());
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| ()))
        .collect()
}
