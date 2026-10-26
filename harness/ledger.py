"""账本（Ledger）：防篡改的哈希链 JSONL。协议资产 P3 的 v0 草案。

格式（agentos.ledger.v0）：
  每行一个 JSON 事件：
    { seq, ts, run, event, detail, prev, hash }
  hash = sha256( prev + canonical_json(entry_without_hash) )
  首事件 prev 为 64 个 "0"。

账本只追加（append-only）；verify() 重算全链，任何一处改动都会被察觉。
账本存放在工作目录之外（工作目录会被回滚，账本不能跟着回滚）。
"""

from __future__ import annotations

import hashlib
import json
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
        self.entries: list[dict] = []
        if self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    self.entries.append(json.loads(line))

    def _next_seq(self) -> int:
        return (self.entries[-1]["seq"] + 1) if self.entries else 1

    def append(self, event: str, run: str, **detail) -> dict:
        entry = {
            "schema": "agentos.ledger.v0",
            "seq": self._next_seq(),
            "ts": datetime.now().astimezone().isoformat(timespec="milliseconds"),
            "run": run,
            "event": event,
            "detail": detail,
        }
        prev = self.entries[-1]["hash"] if self.entries else GENESIS
        entry["prev"] = prev
        entry["hash"] = _digest(prev, entry)
        self.entries.append(entry)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(_canonical(entry) + "\n")
        return entry

    def verify(self) -> tuple[bool, int, str]:
        """重算全链。返回 (是否完整, 事件数, 首个坏点描述)。"""
        prev = GENESIS
        for i, e in enumerate(self.entries):
            expect = {k: v for k, v in e.items() if k != "hash"}
            if e.get("prev") != prev:
                return False, i, f"seq {e.get('seq')}: prev-hash 链断裂"
            if e.get("hash") != _digest(prev, expect):
                return False, i, f"seq {e.get('seq')}: 内容哈希不匹配（事件被篡改）"
            prev = e["hash"]
        return True, len(self.entries), ""
