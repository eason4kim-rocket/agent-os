//! Rust ↔ Python 互操作测试：验证 Python 参考实现生成的账本 fixture
//! （含 ed25519 签名），并证明 Rust 追加的事件能被 Python verify() 接受。

use agentos_core::ledger::Ledger;
use std::path::{Path, PathBuf};

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

#[test]
fn verify_python_generated_ledger() {
    let path = fixture_dir().join("ledger-sample.jsonl");
    let ledger = Ledger::load(&path);
    let total = ledger
        .verify(Some(&fixture_dir().join("ledger-sample.anchor")))
        .unwrap_or_else(|e| panic!("Python 生成的账本应通过 Rust 验证: {}", e.reason));
    assert_eq!(total, 7);
}

#[test]
fn tampered_python_ledger_detected() {
    let path = fixture_dir().join("ledger-sample.jsonl");
    let content = std::fs::read_to_string(&path).unwrap();
    // 篡改第一条 detail
    let tampered = content.replacen("整理发票", "被黑的发票", 1);
    let tmp = std::env::temp_dir().join("agentos-rs-tamper.jsonl");
    std::fs::write(&tmp, tampered).unwrap();
    let err = Ledger::load(&tmp)
        .verify(None)
        .expect_err("篡改必须被检出");
    assert!(err.reason.contains("篡改"), "实际: {}", err.reason);
    assert!(err.reason.contains("seq"), "必须指明行号: {}", err.reason);
}

#[test]
fn rust_signs_and_python_style_verify() {
    // Rust 侧：固定种子签名 → dalek 严格验证
    use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
    let seed = [7u8; 32];
    let sk = SigningKey::from_bytes(&seed);
    let vk = VerifyingKey::from(&sk);
    let digest = [42u8; 32];
    let sig: Signature = sk.sign(&digest);
    assert!(vk.verify_strict(&digest, &sig).is_ok());
    let bad = [43u8; 32];
    assert!(vk.verify_strict(&bad, &sig).is_err());
    // 字段十六进制与 Python hex() 对齐
    assert_eq!(agentos_core::ledger::hex(&digest), "2a".repeat(32));
}

#[test]
fn rust_written_ledger_file_layout() {
    // 反向互操作：Rust 追加的账本文件，由 Python harness.verify() 核验
    // （CI 的 python-interop job 执行真正的 Python 校验；此处断言文件形态）
    use agentos_core::ledger::Ledger;
    use ed25519_dalek::{Signer, SigningKey};
    let dir = std::env::temp_dir().join(format!("agentos-rs-ledger-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("ledger.jsonl");

    let seed = [7u8; 32];
    let sk = SigningKey::from_bytes(&seed);
    let pk_hex = hex(&ed25519_dalek::VerifyingKey::from(&sk).to_bytes());

    let mut led = Ledger::load(&path);
    let policy = serde_json::json!({
        "schema": "agentos.policy.v0", "workdir": "/tmp/work", "extra_read": [],
        "allow_commands": ["ls"], "network": false, "backend": "auto", "max_steps": 24,
    });
    let digest = sha256_hex(&serde_json::to_string(&policy).unwrap());
    let sig = sk.sign(&hex_decode(&digest));
    led.append("run.start", "rs-run-001", serde_json::json!({
        "policy": policy, "backend": "landlock/kernel-native",
        "agent_pubkey": pk_hex, "signed": digest, "agent_sig": hex(&sig.to_bytes()),
    })).unwrap();

    // canonical 形态与 Python 一致：sort_keys + 紧凑分隔符
    let first = std::fs::read_to_string(&path).unwrap().lines().next().unwrap().to_string();
    assert!(first.contains("\"schema\":\"agentos.ledger.v0\""));
    assert!(first.contains("\"seq\":1"));
    assert!(first.contains("agent_sig"));
    std::fs::write(std::env::temp_dir().join("agentos-rs-ledger-path"), path.to_str().unwrap()).ok();
}

fn sha256_hex(data: &str) -> String {
    use sha2::{Digest, Sha256};
    hex(&Sha256::digest(data.as_bytes()))
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
