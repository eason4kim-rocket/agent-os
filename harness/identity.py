"""Agent 身份（P2 v0）：ed25519 密钥对，绑定策略与动作。

身份文件存放在 Home 状态目录（identity/agent.seed，0600）。
种子即身份：谁持有 seed，谁就是该 Agent。
"""

from __future__ import annotations

import secrets
from pathlib import Path

from . import ed25519


def ensure_identity(state_dir: Path) -> tuple[bytes, bytes]:
    """加载或生成 Agent 身份。返回 (seed私钥, 公钥)。"""
    d = Path(state_dir) / "identity"
    seed_file = d / "agent.seed"
    pub_file = d / "agent.pub"
    if seed_file.exists():
        seed = seed_file.read_bytes()
        if len(seed) != 32:
            raise ValueError(f"身份文件损坏（{len(seed)} 字节，应为 32）")
    else:
        seed = secrets.token_bytes(32)
        d.mkdir(parents=True, exist_ok=True)
        seed_file.write_bytes(seed)
        seed_file.chmod(0o600)
    pub_file.write_bytes(ed25519.publickey(seed))
    return seed, ed25519.publickey(seed)


def load_public_only(state_dir: Path) -> bytes | None:
    pub_file = Path(state_dir) / "identity" / "agent.pub"
    if pub_file.exists():
        return pub_file.read_bytes()
    return None


def sign_digest(seed: bytes, digest32: bytes) -> bytes:
    """对 32 字节摘要（如 sha256 输出）签名。"""
    if len(digest32) != 32:
        raise ValueError("签名对象必须是 32 字节摘要")
    return ed25519.signature(digest32, seed, ed25519.publickey(seed))


def verify_digest(pk: bytes, sig: bytes, digest32: bytes) -> bool:
    return ed25519.checkvalid(sig, digest32, pk)
