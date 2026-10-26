//! 账本（agentos.ledger.v0）：哈希链 JSONL 的 Rust 读写与验证。
//!
//! 与 harness/ledger.py 的互操作契约（字段、哈希、锚点、签名）见 docs/ledger.format.md。

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    #[serde(default = "schema_name")]
    pub schema: String,
    pub seq: u64,
    pub ts: String,
    pub run: String,
    pub event: String,
    pub detail: serde_json::Value,
    pub prev: String,
    pub hash: String,
}

fn schema_name() -> String {
    "agentos.ledger.v0".into()
}

/// canonical JSON：键排序 + 紧凑分隔符 + 保留 UTF-8（与 Python ensure_ascii=False 对齐）。
pub fn canonical<T: Serialize>(value: &T) -> String {
    // serde_json::Value 的对象默认按 BTreeMap 排序输出（preserve_order feature 未开）
    let v = serde_json::to_value(value).expect("serialize to value");
    serde_json::to_string(&v).expect("canonical string")
}

fn digest(prev: &str, entry_without_hash: &serde_json::Value) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev.as_bytes());
    hasher.update(_canonical_raw(entry_without_hash).as_bytes());
    hex(&hasher.finalize())
}

/// 对任意 serde 序列化值做 canonical 字符串（等价于 canonical() 但避免双重转换）。
fn _canonical_raw(value: &serde_json::Value) -> String {
    serde_json::to_string(value).expect("canonical string")
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub struct Ledger {
    pub path: PathBuf,
    pub entries: Vec<Entry>,
    /// 无法解析的尾部行（模拟断电）；verify 会报错。
    corrupt_tail: Option<String>,
}

#[derive(Debug)]
pub struct VerifyError {
    pub total: usize,
    pub reason: String,
}

impl Ledger {
    pub fn load(path: &Path) -> Self {
        let mut entries = Vec::new();
        let mut corrupt_tail = None;
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                match serde_json::from_str::<Entry>(line) {
                    Ok(e) => entries.push(e),
                    Err(_) => {
                        // 只容忍文件末尾的半行（部分写入）；中间坏行同样标记
                        corrupt_tail = Some(line.chars().take(200).collect());
                        break;
                    }
                }
            }
        }
        Self { path: path.to_path_buf(), entries, corrupt_tail }
    }

    /// 追加事件。锁内以文件尾为准（防并发断链）。
    pub fn append(&mut self, event: &str, run: &str, detail: serde_json::Value) -> Result<Entry, String> {
        use std::fs::OpenOptions;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&self.path)
            .map_err(|e| e.to_string())?;
        // 简化版互斥：真实多进程场景由调用方持锁；与 Python 一致在锁内重读文件尾
        #[cfg(unix)]
        unsafe {
            libc::flock(f.as_raw_fd(), libc::LOCK_EX);
        }
        f.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        let mut last_hash = GENESIS.to_string();
        let mut last_seq = 0u64;
        for line in BufReader::new(&f).lines() {
            let line = line.map_err(|e| e.to_string())?;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(e) = serde_json::from_str::<Entry>(line) {
                last_hash = e.hash;
                last_seq = e.seq;
            }
        }
        let mut entry = Entry {
            schema: "agentos.ledger.v0".into(),
            seq: last_seq + 1,
            ts: now_iso(),
            run: run.into(),
            event: event.into(),
            detail,
            prev: last_hash.clone(),
            hash: String::new(),
        };
        // 哈希输入必须排除 hash 字段本身（与 Python verify 的重算口径一致）
        let mut without_hash = serde_json::to_value(&entry).map_err(|e| e.to_string())?;
        if let Some(obj) = without_hash.as_object_mut() {
            obj.remove("hash");
        }
        let hash = digest(&last_hash, &without_hash);
        entry.hash = hash;
        let mut f2 = f;
        writeln!(f2, "{}", canonical(&entry)).map_err(|e| e.to_string())?;
        f2.flush().map_err(|e| e.to_string())?;
        #[cfg(unix)]
        unsafe {
            libc::flock(f2.as_raw_fd(), libc::LOCK_UN);
        }
        self.entries.push(entry.clone());
        Ok(entry)
    }

    /// 写锚点（防截断/重放/换身份重建）。
    pub fn anchor(&self, anchor_path: &Path) -> Result<serde_json::Value, String> {
        let head = self.entries.last().map(|e| e.hash.clone()).unwrap_or(GENESIS.into());
        let mut pubkeys: Vec<String> = self
            .entries
            .iter()
            .filter_map(|e| e.detail.get("agent_pubkey").and_then(|v| v.as_str()).map(String::from))
            .collect();
        pubkeys.sort();
        pubkeys.dedup();
        let anchor = serde_json::json!({
            "schema": "agentos.ledger.anchor.v0",
            "count": self.entries.len(),
            "head": head,
            "agent_pubkeys": pubkeys,
        });
        if let Some(parent) = anchor_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(anchor_path, canonical(&anchor) + "\n").map_err(|e| e.to_string())?;
        Ok(anchor)
    }

    /// 重算全链 + 锚点 + 身份签名。
    pub fn verify(&self, anchor_path: Option<&Path>) -> Result<usize, VerifyError> {
        if let Some(tail) = &self.corrupt_tail {
            return Err(VerifyError {
                total: self.entries.len(),
                reason: format!("行解析失败（部分写入或损坏）: {tail}"),
            });
        }
        let mut prev = GENESIS.to_string();
        for e in &self.entries {
            let without_hash = serde_json::to_value(EntryNoHash::from(e)).map_err(|e: serde_json::Error| {
                VerifyError { total: self.entries.len(), reason: e.to_string() }
            })?;
            if e.prev != prev {
                return Err(VerifyError {
                    total: self.entries.len(),
                    reason: format!("seq {}: prev-hash 链断裂", e.seq),
                });
            }
            if e.hash != digest(&prev, &without_hash) {
                return Err(VerifyError {
                    total: self.entries.len(),
                    reason: format!("seq {}: 内容哈希不匹配（事件被篡改）", e.seq),
                });
            }
            // P2 身份签名核验
            if let Some(sig_hex) = e.detail.get("agent_sig").and_then(|v| v.as_str()) {
                let signed = e
                    .detail
                    .get("signed")
                    .and_then(|v| v.as_str())
                    .ok_or(VerifyError { total: self.entries.len(), reason: format!("seq {}: 缺少 signed 摘要", e.seq) })?;
                let pubkey = e
                    .detail
                    .get("agent_pubkey")
                    .and_then(|v| v.as_str())
                    .ok_or(VerifyError { total: self.entries.len(), reason: format!("seq {}: 缺少 agent_pubkey", e.seq) })?;
                let ok: Result<bool, ()> = (|| {
                    let sig_bytes = hex_decode(sig_hex).ok_or(())?;
                    let msg = hex_decode(signed).ok_or(())?;
                    let pk_bytes = hex_decode(pubkey).ok_or(())?;
                    let vk = VerifyingKey::from_bytes(&pk_bytes.try_into().map_err(|_| ())?).map_err(|_| ())?;
                    let sig = Signature::from_slice(&sig_bytes).map_err(|_| ())?;
                    Ok(vk.verify_strict(&msg, &sig).is_ok())
                })();
                match ok {
                    Ok(true) => {}
                    Ok(false) => {
                        return Err(VerifyError {
                            total: self.entries.len(),
                            reason: format!("seq {}: 身份签名不匹配（伪造的 Agent 身份）", e.seq),
                        });
                    }
                    Err(()) => {
                        return Err(VerifyError {
                            total: self.entries.len(),
                            reason: format!("seq {}: 签名字段损坏", e.seq),
                        });
                    }
                }
            }
            prev = e.hash.clone();
        }
        if let Some(anchor_path) = anchor_path {
            if let Ok(content) = std::fs::read_to_string(anchor_path) {
                let anchor: serde_json::Value = serde_json::from_str(&content).map_err(|e: serde_json::Error| {
                    VerifyError { total: self.entries.len(), reason: format!("锚点文件损坏: {e}") }
                })?;
                let n = anchor["count"].as_u64().unwrap_or(0) as usize;
                let head = anchor["head"].as_str().unwrap_or(GENESIS);
                if self.entries.len() < n {
                    return Err(VerifyError {
                        total: self.entries.len(),
                        reason: format!("账本被截断：锚点记录 {n} 条，现存 {} 条", self.entries.len()),
                    });
                }
                if n > 0 && self.entries[n - 1].hash != head {
                    return Err(VerifyError {
                        total: self.entries.len(),
                        reason: format!("锚点核对失败：第 {n} 条哈希与锚点不符（前缀被重放/重建）"),
                    });
                }
                if let Some(known) = anchor["agent_pubkeys"].as_array() {
                    let known: Vec<&str> = known.iter().filter_map(|v| v.as_str()).collect();
                    for e in self.entries.iter().take(n) {
                        if let Some(pk) = e.detail.get("agent_pubkey").and_then(|v| v.as_str()) {
                            if !pk.is_empty() && !known.contains(&pk) {
                                return Err(VerifyError {
                                    total: self.entries.len(),
                                    reason: format!("seq {}: 签名身份不在锚点记录中（换身份重建账本）", e.seq),
                                });
                            }
                        }
                    }
                }
            }
        }
        if self.entries.is_empty() {
            return Err(VerifyError { total: 0, reason: "空账本（无事件可验）".into() });
        }
        Ok(self.entries.len())
    }
}

/// 不含 hash 字段的入口视图（用于哈希计算）。
#[derive(Serialize)]
struct EntryNoHash<'a> {
    schema: &'a str,
    seq: u64,
    ts: &'a str,
    run: &'a str,
    event: &'a str,
    detail: &'a serde_json::Value,
    prev: &'a str,
}

impl<'a> From<&'a Entry> for EntryNoHash<'a> {
    fn from(e: &'a Entry) -> Self {
        EntryNoHash {
            schema: &e.schema,
            seq: e.seq,
            ts: &e.ts,
            run: &e.run,
            event: &e.event,
            detail: &e.detail,
            prev: &e.prev,
        }
    }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok())
        .collect()
}

fn now_iso() -> String {
    // 阶段 1 不引 chrono：秒级 ISO 由调用方传入或使用 unix 时间戳。
    // 这里保持与 Python 侧字段兼容：用系统 date 命令不可取，改为毫秒 unix 时间戳字符串。
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}.{:03}Z", d.as_secs(), d.subsec_millis())
}
