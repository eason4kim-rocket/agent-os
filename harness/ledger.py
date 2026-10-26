"""账本（Ledger）：哈希链 JSONL。协议资产 P3 的 v0 草案。

诚实的安全边界（docs/ledger.format.md 同步声明）：
- 哈希链防"原地篡改任意一行"——改任何字节都会断链
- 哈希链不防"整文件重放/替换"和"删除尾部"——那需要外部锚点（anchor）或签名（v1）
- anchor() 在每次 run 结束时把 (count, head_hash) 写到账本之外；verify() 会核对锚点
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
from datetime import datetime
from pathlib import Path

GENESIS = "0" * 64


def _canonical(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _digest(prev: str, entry: dict) -> str:
    return hashlib.sha256((prev + _canonical(entry)).encode("utf-8")).hexdigest()


class Ledger:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.entries: list[dict] = self._load()

    def _load(self) -> list[dict]:
        entries = []
        if not self.path.exists():
            return entries
        with self.path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    entries.append({"seq": len(entries) + 1, "corrupt": True, "raw": line[:200]})
        return entries

    def _next_seq(self) -> int:
        return (self.entries[-1]["seq"] + 1) if self.entries else 1

    def append(self, event: str, run: str, **detail) -> dict:
        """追加事件。文件锁防并发断链（锁内以文件尾为准），fsync 降低撕裂概率。"""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a+", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            f.seek(0)
            last_hash, last_seq = GENESIS, 0
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                    last_hash = e.get("hash", last_hash)
                    last_seq = int(e.get("seq", last_seq + 1))
                except json.JSONDecodeError:
                    continue
            entry = {
                "schema": "agentos.ledger.v0",
                "seq": last_seq + 1,
                "ts": datetime.now().astimezone().isoformat(timespec="milliseconds"),
                "run": run,
                "event": event,
                "detail": detail,
                "prev": last_hash,
            }
            entry["hash"] = _digest(last_hash, entry)
            f.write(_canonical(entry) + "\n")
            f.flush()
            os.fsync(f.fileno())
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        self.entries.append(entry)
        return entry

    def anchor(self, anchor_path: Path) -> dict:
        """把链头 (count, hash) 与出现过的 Agent 公钥写到账本之外的锚点文件。

        锚点防"整体重放/截断/换身份重建"；锚点文件本身由操作者保管（可再签名/上链）。
        """
        head = self.entries[-1]["hash"] if self.entries else GENESIS
        pubkeys = sorted({e["detail"]["agent_pubkey"] for e in self.entries
                          if "agent_pubkey" in e.get("detail", {})})
        anchor = {"schema": "agentos.ledger.anchor.v0",
                  "count": len(self.entries), "head": head, "agent_pubkeys": pubkeys}
        anchor_path.parent.mkdir(parents=True, exist_ok=True)
        anchor_path.write_text(_canonical(anchor) + "\n", encoding="utf-8")
        return anchor

    def verify(self, anchor_path: Path | None = None) -> tuple[bool, int, str]:
        """重算全链 + 核对锚点 + 验证身份签名。返回 (是否完整, 总条数, 首个坏点描述)。"""
        from . import ed25519
        prev = GENESIS
        for i, e in enumerate(self.entries):
            if e.get("corrupt"):
                return False, len(self.entries), f"seq {e.get('seq')}: 行解析失败（部分写入或损坏）"
            expect = {k: v for k, v in e.items() if k != "hash"}
            if e.get("prev") != prev:
                return False, len(self.entries), f"seq {e.get('seq')}: prev-hash 链断裂"
            if e.get("hash") != _digest(prev, expect):
                return False, len(self.entries), f"seq {e.get('seq')}: 内容哈希不匹配（事件被篡改）"
            d = e.get("detail", {})
            if "agent_sig" in d:  # P2 身份签名核验（v0：签名对象为 signed 摘要字段）
                try:
                    if not ed25519.checkvalid(bytes.fromhex(d["agent_sig"]),
                                              bytes.fromhex(d["signed"]),
                                              bytes.fromhex(d["agent_pubkey"])):
                        return False, len(self.entries), \
                            f"seq {e.get('seq')}: 身份签名不匹配（伪造的 Agent 身份）"
                except (KeyError, ValueError):
                    return False, len(self.entries), f"seq {e.get('seq')}: 签名字段损坏"
            prev = e["hash"]
        if anchor_path is not None and Path(anchor_path).exists():
            try:
                anchor = json.loads(Path(anchor_path).read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                return False, len(self.entries), "锚点文件损坏"
            n, head = anchor.get("count"), anchor.get("head")
            if len(self.entries) < n:
                return False, len(self.entries), f"账本被截断：锚点记录 {n} 条，现存 {len(self.entries)} 条"
            if n and self.entries[n - 1].get("hash") != head:
                return False, n, f"锚点核对失败：第 {n} 条哈希与锚点不符（前缀被重放/重建）"
            known = set(anchor.get("agent_pubkeys") or [])
            if known:
                for e in self.entries[:n]:
                    pk = e.get("detail", {}).get("agent_pubkey")
                    if pk and pk not in known:
                        return False, len(self.entries), \
                            f"seq {e.get('seq')}: 签名身份不在锚点记录中（换身份重建账本）"
        if not self.entries:
            return False, 0, "空账本（无事件可验）"
        return True, len(self.entries), ""
