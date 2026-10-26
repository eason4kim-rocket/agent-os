"""快照（Snapshot）：任务开跑前存档，随时读档。四件套之三。

存放在 state_root（工作目录之外），带 MANIFEST（逐文件 sha256）。
"""

from __future__ import annotations

import hashlib
import json
import shutil
from datetime import datetime
from pathlib import Path


class SnapshotManager:
    def __init__(self, workdir: Path, state_root: Path):
        self.workdir = Path(workdir).resolve()
        self.snap_root = Path(state_root) / "snapshots"

    def _snap_dir(self, sid: str) -> Path:
        return self.snap_root / sid

    def create(self, run: str) -> str:
        sid = datetime.now().strftime("%Y%m%d-%H%M%S")
        dest = self._snap_dir(sid)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(self.workdir, dest)
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

    def restore(self, sid: str) -> None:
        src = self._snap_dir(sid)
        if not src.is_dir():
            raise FileNotFoundError(f"快照不存在: {sid}")
        shutil.rmtree(self.workdir)
        shutil.copytree(src, self.workdir, ignore=shutil.ignore_patterns("MANIFEST.json"))
