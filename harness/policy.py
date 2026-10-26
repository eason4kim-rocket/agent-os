"""策略（Policy）：任务声明"我要什么"，引擎决定"给什么"。

这是协议资产 P1（统一策略格式）的 v0 草案核心：
- Policy 对象是机器可读的策略声明（未来对应 schemas/policy.schema.json）
- 路径/命令的软件层强制检查，所有后端共用（内核强制之外的第二道闸）
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


DEFAULT_ALLOW_COMMANDS = (
    "ls", "cat", "head", "tail", "grep", "find",
    "mkdir", "mv", "cp", "echo", "wc",
)


@dataclass
class Policy:
    """一个任务的权限声明。v0：单工作目录读写 + 只读附加区 + 命令白名单。"""

    workdir: Path                     # 读写区（任务的工作目录）
    extra_read: tuple[Path, ...] = () # 只读区（可读不可写）
    allow_commands: tuple[str, ...] = DEFAULT_ALLOW_COMMANDS
    network: bool = False             # 沙箱内一律禁网（模型调用发生在笼外）
    backend: str = "auto"             # auto | plain | docker | srt
    max_steps: int = 24               # 模型回合预算（防失控）

    def resolved_workdir(self) -> Path:
        return self.workdir.resolve()

    # ---- 软件层强制（所有后端共享的最低保障） ----------------------------

    def _inside(self, p: Path, root: Path) -> bool:
        try:
            p.resolve().relative_to(root)
            return True
        except (ValueError, OSError):
            return False

    def path_allowed_read(self, raw: str | Path) -> tuple[bool, str]:
        p = Path(raw).expanduser()
        if not p.is_absolute():
            p = self.resolved_workdir() / p
        if self._inside(p, self.resolved_workdir()):
            return True, "workdir"
        for r in self.extra_read:
            if self._inside(p, Path(r).resolve()):
                return True, "extra_read"
        return False, f"path outside allowed roots: {p}"

    def path_allowed_write(self, raw: str | Path) -> tuple[bool, str]:
        p = Path(raw).expanduser()
        if not p.is_absolute():
            p = self.resolved_workdir() / p
        if self._inside(p, self.resolved_workdir()):
            return True, "workdir"
        return False, f"write outside workdir: {p}"

    def command_allowed(self, argv: list[str]) -> tuple[bool, str]:
        if not argv:
            return False, "empty command"
        cmd = Path(argv[0]).name
        if cmd in self.allow_commands:
            return True, "whitelisted"
        return False, f"command '{cmd}' not in allow_commands"

    # ---- 序列化（账本/未来的 schema 双向使用） --------------------------

    def to_dict(self) -> dict:
        return {
            "schema": "agentos.policy.v0",
            "workdir": str(self.resolved_workdir()),
            "extra_read": [str(Path(r).resolve()) for r in self.extra_read],
            "allow_commands": list(self.allow_commands),
            "network": self.network,
            "max_steps": self.max_steps,
        }
