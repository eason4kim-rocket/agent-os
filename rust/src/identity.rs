//! Agent 身份（P2 v0 的 Rust 侧）：ed25519 密钥对，文件布局与 Python 互通。
//! identity/agent.seed（32 字节，0600）= 私钥种子；agent.pub = 公钥。
//!
//! H3 修复：seed 写入显式 mode(060)（红队实测 fs::write 默认落 0644）；
//! 已存在但权限过宽的 seed 拒绝加载（fail-closed）；身份目录 0700。

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub struct Identity {
    signing: SigningKey,
    pubkey_hex: String,
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 加载或生成身份。已存在的 seed 权限过宽（组/其他人可读）时拒绝加载。
pub fn ensure(state_dir: &Path) -> std::io::Result<Identity> {
    let d = state_dir.join("identity");
    std::fs::create_dir_all(&d)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700))?;
    }
    let seed_file = d.join("agent.seed");
    let pub_file = d.join("agent.pub");
    let seed: [u8; 32] = if seed_file.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&seed_file)?.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "身份种子权限过宽（{:03o}），拒绝加载；请 chmod 600 后重试",
                        mode
                    ),
                ));
            }
        }
        let raw = std::fs::read(&seed_file)?;
        raw.try_into().map_err(|v: Vec<u8>| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("身份文件损坏（{} 字节，应为 32）", v.len()),
            )
        })?
    } else {
        let mut seed = [0u8; 32];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut seed)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .write(true)
                .open(&seed_file)?
                .write_all(&seed)?;
        }
        #[cfg(not(unix))]
        std::fs::write(&seed_file, seed)?;
        seed
    };
    let signing = SigningKey::from_bytes(&seed);
    let pubkey_hex = hex(&VerifyingKey::from(&signing).to_bytes());
    std::fs::write(&pub_file, &pubkey_hex)?;
    Ok(Identity { signing, pubkey_hex })
}

impl Identity {
    pub fn pubkey_hex(&self) -> &str {
        &self.pubkey_hex
    }

    /// 对 32 字节摘要签名（与 Python sign_digest 语义一致）。
    pub fn sign_digest(&self, digest32: &[u8; 32]) -> String {
        hex(&self.signing.sign(digest32).to_bytes())
    }

    /// 验证摘要签名（Python 侧可用 ed25519.checkvalid 互验）。
    pub fn verify_digest(pk_hex: &str, sig_hex: &str, digest32: &[u8; 32]) -> bool {
        let (Ok(pk_bytes), Ok(sig_bytes)) = (hex_decode(pk_hex), hex_decode(sig_hex)) else {
            return false;
        };
        let Ok(pk_arr) = <[u8; 32]>::try_from(pk_bytes.as_slice()) else { return false };
        let Ok(vk) = VerifyingKey::from_bytes(&pk_arr) else { return false };
        let Ok(sig) = Signature::from_slice(&sig_bytes) else { return false };
        vk.verify_strict(digest32, &sig).is_ok()
    }
}

fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    if s.len() % 2 != 0 {
        return Err(());
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| ()))
        .collect()
}

/// 便捷：返回身份文件路径（用于文档/诊断）。
pub fn seed_path(state_dir: &Path) -> PathBuf {
    state_dir.join("identity").join("agent.seed")
}
