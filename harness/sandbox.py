"""沙箱（Sandbox）：笼子。协议 P1 的执行侧，后端可插拔。

enforcement 分级（账本会如实记录每一级）：
  software        —— 软件层强制（策略预检），无内核隔离（macOS 今日的兜底）
  kernel-container —— Linux 容器隔离（namespace/cgroups，macOS 上经 Docker VM 亦属此类）
  kernel-native   —— Landlock/seccomp 原生强制（Linux 目标形态；srt/OpenShell）

历史注记（2026-10-26 实测）：macOS 27 的 sandbox-exec(Seatbelt) 已被系统禁用
（任何 profile 均 SIGABRT），故 macOS 上原生内核强制不可用，属预期降级。
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .policy import Policy


@dataclass
class SandboxResult:
    rc: int
    stdout: str
    stderr: str
    denied: bool = False
    reason: str = ""


class Sandbox:
    name = "base"
    enforcement = "software"

    def available(self) -> bool:
        return True

    def _precheck(self, argv: list[str], policy: Policy) -> SandboxResult | None:
        ok, why = policy.command_allowed(argv)
        if not ok:
            return SandboxResult(rc=127, stdout="", stderr=why, denied=True, reason=why)
        return None

    def execute(self, argv: list[str], policy: Policy, stdin: str | None = None) -> SandboxResult:
        raise NotImplementedError


class PlainSandbox(Sandbox):
    """软件层强制：策略预检 + 直接执行。无内核隔离，账本如实标注。"""

    name = "plain"
    enforcement = "software"

    def execute(self, argv, policy, stdin=None):
        blocked = self._precheck(argv, policy)
        if blocked:
            return blocked
        proc = subprocess.run(
            argv, cwd=policy.resolved_workdir(), input=stdin,
            capture_output=True, text=True, timeout=60,
        )
        return SandboxResult(proc.returncode, proc.stdout, proc.stderr)


class DockerSandbox(Sandbox):
    """容器强制：Linux namespace/cgroups（macOS 上经由 Docker Desktop 的 VM）。

    --network none（断网）、--read-only（只读根）、资源限额、工作目录唯一挂载。
    """

    name = "docker"
    enforcement = "kernel-container"
    IMAGE = "alpine:3.20"

    def available(self) -> bool:
        if not shutil.which("docker"):
            return False
        try:
            subprocess.run(["docker", "info"], capture_output=True, timeout=15, check=True)
            subprocess.run(["docker", "image", "inspect", self.IMAGE],
                           capture_output=True, timeout=15, check=True)
            return True
        except (subprocess.SubprocessError, OSError):
            return False

    def execute(self, argv, policy, stdin=None):
        blocked = self._precheck(argv, policy)
        if blocked:
            return blocked
        docker_argv = [
            "docker", "run", "--rm",
            "--network", "none",
            "--read-only", "--tmpfs", "/tmp",
            "--memory", "512m", "--cpus", "1",
            "--security-opt", "no-new-privileges",
            "-v", f"{policy.resolved_workdir()}:/work",
            "-w", "/work",
            self.IMAGE,
        ] + argv
        proc = subprocess.run(docker_argv, input=stdin,
                              capture_output=True, text=True, timeout=120)
        return SandboxResult(proc.returncode, proc.stdout, proc.stderr)


class SrtSandbox(Sandbox):
    """内核原生强制：Anthropic sandbox-runtime（Linux=Bubblewrap+Landlock）。

    依赖 `srt` CLI 在 PATH 中。仅在 Linux 上达到 kernel-native；
    macOS 上 srt 同样走 Seatbelt（本机已验证不可用），故 available() 返回 False。
    """

    name = "srt"
    enforcement = "kernel-native"

    def available(self) -> bool:
        if not shutil.which("srt"):
            return False
        import platform
        return platform.system() == "Linux"

    def execute(self, argv, policy, stdin=None):
        blocked = self._precheck(argv, policy)
        if blocked:
            return blocked
        # srt 的具体 CLI 以其文档为准；此处为最小封装点，接口已隔离。
        srt_argv = ["srt", "run",
                    "--allow-read", str(policy.resolved_workdir()),
                    "--allow-write", str(policy.resolved_workdir()),
                    "--"] + argv
        proc = subprocess.run(srt_argv, cwd=policy.resolved_workdir(), input=stdin,
                              capture_output=True, text=True, timeout=120)
        return SandboxResult(proc.returncode, proc.stdout, proc.stderr)


class LandlockSandbox(Sandbox):
    """内核原生强制（Landlock）：自研 llandlock 编译策略，容器内 VM 原生文件系统上执行。

    背景（2026-10-26 实测）：Docker Desktop 的 macOS 绑定挂载（VirtioFS）与 Landlock
    不兼容——规则不生效。改用命名卷（VM 内 ext4）作为笼内工作区：
      begin()    把工作目录内容种入卷
      execute()  每条命令 = llandlock 策略编译 + 容器执行
      end()      卷内容导出回工作目录，卷销毁
    在原生 Linux 上，同一份 llandlock 可脱离容器直接使用（真正的 kernel-native）。
    """

    name = "landlock"
    enforcement = "kernel-native"
    IMAGE = "agentos-sandbox:latest"
    VOLUME = "agentos-work"

    def __init__(self):
        self._started = False

    # ---- 生命周期 --------------------------------------------------------

    def available(self) -> bool:
        try:
            subprocess.run(["docker", "image", "inspect", self.IMAGE],
                           capture_output=True, timeout=15, check=True)
            return True
        except (subprocess.SubprocessError, OSError):
            return False

    def begin(self, policy: Policy) -> None:
        subprocess.run(["docker", "volume", "rm", "-f", self.VOLUME],
                       capture_output=True, timeout=30)
        subprocess.run(["docker", "volume", "create", self.VOLUME],
                       capture_output=True, timeout=30, check=True)
        # 种入工作目录内容（alpine + 两挂载点之间 cp，全程不经 Landlock）
        subprocess.run([
            "docker", "run", "--rm", "-v", f"{self.VOLUME}:/work",
            "-v", f"{policy.resolved_workdir()}:/seed:ro", "alpine:3.20",
            "sh", "-c", "cp -a /seed/. /work/",
        ], capture_output=True, timeout=120, check=True)
        self._started = True

    def end(self, policy: Policy, export: bool = True) -> None:
        if not self._started:
            return
        if export:
            subprocess.run([
                "docker", "run", "--rm", "-v", f"{self.VOLUME}:/work",
                "-v", f"{policy.resolved_workdir()}:/out", "alpine:3.20",
                "sh", "-c", "find /out -mindepth 1 -delete && cp -a /work/. /out/",
            ], capture_output=True, timeout=120, check=True)
        subprocess.run(["docker", "volume", "rm", self.VOLUME],
                       capture_output=True, timeout=30)
        self._started = False

    # ---- 执行 ------------------------------------------------------------

    def available_paths(self, policy: Policy) -> list[str]:
        rox = ["--rox", "/bin", "--rox", "/usr/bin", "--rox", "/lib",
               "--rox", "/usr/lib", "--rox", "/lib64"]
        return rox

    def execute(self, argv, policy, stdin=None):
        blocked = self._precheck(argv, policy)
        if blocked:
            return blocked
        docker_argv = [
            "docker", "run", "--rm", "--network", "none",
            "--read-only", "--tmpfs", "/tmp",
            "--memory", "512m", "--cpus", "1",
            "--security-opt", "no-new-privileges",
            "-v", f"{self.VOLUME}:/work",
            "-w", "/work",
        ]
        # 策略编译（P1 的编译目标之一）：workdir→rw、extra_read→ro、执行器路径→rox
        docker_argv += ["--entrypoint", "/usr/local/bin/llandlock", self.IMAGE,
                        "--rw", "/work"] + self.available_paths(policy)
        for r in policy.extra_read:
            name = "/extra-" + Path(str(r)).name
            docker_argv += ["-v", f"{Path(str(r)).resolve()}:{name}:ro",
                            "--ro", name]
        docker_argv += ["--"] + argv
        proc = subprocess.run(docker_argv, input=stdin,
                              capture_output=True, text=True, timeout=120)
        return SandboxResult(proc.returncode, proc.stdout, proc.stderr)


def select_backend(policy: Policy) -> Sandbox:
    """auto：优先内核原生，其次容器，最后软件层。选择结果如实入账本。"""
    order: list[type[Sandbox]] = [SrtSandbox, LandlockSandbox, DockerSandbox, PlainSandbox]
    if policy.backend != "auto":
        order = [b for b in order if b.name == policy.backend] or [PlainSandbox]
    for cls in order:
        sb = cls()
        if sb.available():
            return sb
    return PlainSandbox()
