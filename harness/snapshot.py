"""快照（Snapshot）：任务开跑前存档，随时读档。四件套之三。

存放在 state_root（工作目录之外），带 MANIFEST（逐文件 sha256）。
restore 时校验 MANIFEST、校验 sid 合法性（防路径穿越）；symlink 不跟随。
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from datetime import datetime
from pathlib import Path

SID_PATTERN = re.compile(r"^\d{8}-\d{6}(\.\d+)?[a-z0-9]*$")


class SnapshotManager:
    def __init__(self, workdir: Path, state_root: Path):
        self.workdir = Path(workdir).resolve()
        self.snap_root = Path(state_root) / "snapshots"

    def _snap_dir(self, sid: str) -> Path:
        if not SID_PATTERN.match(sid):
            raise ValueError(f"非法快照 id: {sid!r}")
        p = (self.snap_root / sid).resolve()
        if self.snap_root.resolve() not in p.parents:
            raise ValueError(f"快照 id 越界: {sid!r}")
        return p

    def create(self, run: str) -> str:
        sid = datetime.now().strftime("%Y%m%d-%H%M%S.%f")
        dest = self._snap_dir(sid)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(self.workdir, dest, symlinks=True)
        manifest = {"schema": "agentos.snapshot.v0", "run": run, "created": sid, "files": {}}
        for p in sorted(dest.rglob("*")):
            if p.is_file():
                rel = p.relative_to(dest).as_posix()
                manifest["files"][rel] = hashlib.sha256(p.read_bytes()).hexdigest()
        (dest / "MANIFEST.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8")
        return sid

    def list(self) -> list[str]:
        if not self.snap_root.exists():
            return []
        return sorted(p.name for p in self.snap_root.iterdir() if p.is_dir())

    def restore(self, sid: str) -> dict:
        src = self._snap_dir(sid)
        if not src.is_dir():
            raise FileNotFoundError(f"快照不存在: {sid}")
        # 校验 MANIFEST（防快照内容被篡改后静默恢复）
        manifest_file = src / "MANIFEST.json"
        manifest = json.loads(manifest_file.read_text(encoding="utf-8")) if manifest_file.exists() else None
        bad = []
        if manifest:
            for rel, digest in manifest["files"].items():
                f = src / rel
                if not f.is_file() or hashlib.sha256(f.read_bytes()).hexdigest() != digest:
                    bad.append(rel)
        if bad:
            raise ValueError(f"快照校验失败（内容与 MANIFEST 不符）: {bad[:3]}")
        shutil.rmtree(self.workdir)
        shutil.copytree(src, self.workdir, symlinks=True,
                        ignore=shutil.ignore_patterns("MANIFEST.json"))
        return manifest or {}
