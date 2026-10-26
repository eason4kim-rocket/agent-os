//! AgentOS core（协议资产 P1/P3 的 Rust 实现）。
//!
//! 与 Python 参考实现（../harness/）的互操作契约：
//! - 账本格式 `agentos.ledger.v0`：canonical JSON = 键排序 + 紧凑分隔符 + 保留 UTF-8
//! - 哈希 = sha256(prev_hex + canonical_json(entry_without_hash))
//! - 签名 = ed25519，签名对象为 32 字节摘要（见 harness/identity.py）
//!
//! 两个方向都必须通过测试：Rust 验 Python 生成的账本 fixture；
//! Python 的 harness.verify() 验 Rust 追加的账本（CI 中执行）。

pub mod ledger;
pub mod policy;

/// Landlock 强制仅存在于 Linux（macOS 上由容器后端兜底，见 harness/sandbox.py）。
#[cfg(target_os = "linux")]
pub mod landlock;
