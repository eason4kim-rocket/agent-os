"""策略（Policy）：任务声明"我要什么"，引擎决定"给什么"。

协议资产 P1（统一策略格式）的 v0 草案核心：
- Policy 对象是机器可读的策略声明（对应 schemas/policy.schema.json）
- 软件层强制（所有后端共用的最低保障）：
  * 文件工具：路径 resolve() 归一化白名单
  * run_command：命令白名单 + **操作数路径检查**（H1 修复：plain 后端也校验参数）
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


# find 自带 -delete/-exec，具备破坏性，默认白名单不含
DEFAULT_ALLOW_COMMANDS = (
    "ls", "cat", "head", "tail", "grep", "wc",
    "mkdir", "mv", "cp", "echo",
)

# 这些命令的目的地操作数会写入文件系统（最后一个非选项参数）
WRITE_DEST_COMMANDS = {"mkdir", "mv", "cp", "tee"}

# 任何参数中出现即拒绝的危险选项（防破坏性内置动作）
DENIED_OPTION_FRAGMENTS = ("-delete", "-exec", "-fprintf", "-fls", "-ok")


@dataclass
class Policy:
    """一个任务的权限声明。v0：单工作目录读写 + 只读附加区 + 命令白名单。"""

    workdir: Path                     # 读写区（任务的工作目录）
    extra_read: tuple[Path, ...] = () # 只读区（可读不可写）
    allow_commands: tuple[str, ...] = DEFAULT_ALLOW_COMMANDS
    network: bool = False             # 沙箱内一律禁网（模型调用发生在笼外）
    backend: str = "auto"             # auto | plain | docker | landlock | srt
    max_steps: int = 24               # 模型回合预算（防失控）

    def resolved_workdir(self) -> Path:
        return self.workdir.resolve()

    # ---- 路径强制 --------------------------------------------------------

    def _inside(self, p: Path, root: Path) -> bool:
        try:
            p.resolve().relative_to(root)
            return True
        except (ValueError, OSError):
            return False

    def _resolve_token(self, raw: str) -> Path:
        p = Path(raw).expanduser()
        if not p.is_absolute():
            p = self.resolved_workdir() / p
        return p

    def path_allowed_read(self, raw: str | Path) -> tuple[bool, str]:
        p = self._resolve_token(str(raw))
        if self._inside(p, self.resolved_workdir()):
            return True, "workdir"
        for r in self.extra_read:
            if self._inside(p, Path(r).resolve()):
                return True, "extra_read"
        return False, f"path outside allowed roots: {p}"

    def path_allowed_write(self, raw: str | Path) -> tuple[bool, str]:
        p = self._resolve_token(str(raw))
        if self._inside(p, self.resolved_workdir()):
            return True, "workdir"
        return False, f"write outside workdir: {p}"

    # ---- 命令强制 --------------------------------------------------------

    def command_allowed(self, argv: list[str]) -> tuple[bool, str]:
        if not argv:
            return False, "empty command"
        cmd = Path(argv[0]).name
        if cmd in self.allow_commands:
            return True, "whitelisted"
        return False, f"command '{cmd}' not in allow_commands"

    def validate_run_command(self, argv: list[str]) -> tuple[bool, str]:
        """run_command 的完整软件层校验：白名单 + 危险选项 + 操作数路径。

        容器后端另有内核/挂载层强制；此处保证 plain 后端不因"只看 argv[0]"而逃逸。
        """
        ok, why = self.command_allowed(argv)
        if not ok:
            return ok, why
        cmd = Path(argv[0]).name

        for tok in argv[1:]:
            if tok.startswith("-") and any(f in tok for f in DENIED_OPTION_FRAGMENTS):
                return False, f"forbidden option: {tok}"

        operands = [t for t in argv[1:] if not t.startswith("-")]
        # 写入型命令：最后一个操作数是目的地，必须可写
        for i, tok in enumerate(operands):
            last = i == len(operands) - 1
            if cmd in WRITE_DEST_COMMANDS and last:
                ok, why = self.path_allowed_write(tok)
            else:
                p = self._resolve_token(tok)
                if not p.exists() and not p.is_absolute():
                    continue  # 尚不存在的新相对路径（如 grep 的模式误判），放行给后端裁决
                ok, why = self.path_allowed_read(tok)
            if not ok:
                return False, f"{cmd}: {why}"
        return True, "ok"

    # ---- 序列化 ----------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "schema": "agentos.policy.v0",
            "workdir": str(self.resolved_workdir()),
            "extra_read": [str(Path(r).resolve()) for r in self.extra_read],
            "allow_commands": list(self.allow_commands),
            "network": self.network,
            "backend": self.backend,
            "max_steps": self.max_steps,
        }
