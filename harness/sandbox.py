"""沙箱（Sandbox）：笼子。协议 P1 的执行侧，后端可插拔。

enforcement 分级（账本如实记录每一级）：
  software         —— 软件层强制（策略预检），无内核隔离
  kernel-container —— Linux 容器隔离（namespace/cgroups）
  kernel-native    —— Landlock/seccomp 原生强制

历史注记（2026-10-26 实测）：macOS 27 已禁用 sandbox-exec(Seatbelt)；Docker Desktop
的 macOS 绑定挂载（VirtioFS）上 Landlock 规则不生效——故 landlock 后端经由命名卷。
"""

from __future__ import annotations

import os
import shutil
import signal
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


def _run_pguarded(argv: list[str], cwd: str | None, stdin: str | None,
                  timeout: int) -> tuple[int, str, str]:
    """进程组托管执行：超时杀整组（含孙进程），异常转 rc=124。"""
    proc = subprocess.Popen(
        argv, cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        out, err = proc.communicate(input=stdin, timeout=timeout)
        return proc.returncode, out, err
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
        out, err = proc.communicate()
        return 124, out, (err or "") + "\n[harness] 执行超时被强制终止"
    except OSError as e:
        return 127, "", f"[harness] 执行失败: {e}"


class Sandbox:
    name = "base"
    enforcement = "software"

    def available(self) -> bool:
        return True

    def _precheck(self, argv: list[str], policy: Policy,
                  internal: bool = False) -> SandboxResult | None:
        """命令白名单预检。internal=True 用于工具内部原语（如 write_file 的 tee），
        跳过用户白名单（路径策略仍由各后端/调用方强制）。"""
        if internal:
            return None
        ok, why = policy.command_allowed(argv)
        if not ok:
            return SandboxResult(rc=127, stdout="", stderr=why, denied=True, reason=why)
        return None

    def execute(self, argv: list[str], policy: Policy, stdin: str | None = None,
                internal: bool = False) -> SandboxResult:
        raise NotImplementedError


class PlainSandbox(Sandbox):
    """软件层强制：策略预检（含 run_command 操作数检查，见 policy.validate_run_command）。"""

    name = "plain"
    enforcement = "software"

    def execute(self, argv, policy, stdin=None, internal=False):
        blocked = self._precheck(argv, policy, internal)
        if blocked:
            return blocked
        rc, out, err = _run_pguarded(argv, cwd=str(policy.resolved_workdir()),
                                     stdin=stdin, timeout=60)
        return SandboxResult(rc, out, err)


class DockerSandbox(Sandbox):
    """容器强制：namespace/cgroups。工作目录绑定挂载（容器内文件系统与宿主隔离）。"""

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

    def execute(self, argv, policy, stdin=None, internal=False):
        blocked = self._precheck(argv, policy, internal)
        if blocked:
            return blocked
        docker_argv = [
            "docker", "run", "--rm", "--network", "none",
            "--read-only", "--tmpfs", "/tmp",
            "--memory", "512m", "--cpus", "1",
            "--security-opt", "no-new-privileges",
            "-v", f"{policy.resolved_workdir()}:/work",
            "-w", "/work", self.IMAGE,
        ] + argv
        rc, out, err = _run_pguarded(docker_argv, cwd=None, stdin=stdin, timeout=120)
        return SandboxResult(rc, out, err)


class LandlockSandbox(Sandbox):
    """内核原生强制（Landlock）：自研 llandlock 编译策略，容器内 VM 原生文件系统上执行。

    背景（2026-10-26 实测）：Docker Desktop 的 macOS 绑定挂载（VirtioFS）与 Landlock
    不兼容——规则不生效。改用命名卷（VM 内 ext4）作为笼内工作区：
      begin(run)  卷名带 run id（并发安全），种入工作目录内容
      execute()   每条命令 = llandlock 策略编译 + 容器执行
      end(run)    卷内容镜像导出回工作目录，卷销毁
    在原生 Linux 上，同一份 llandlock 可脱离容器直接使用（真正的 kernel-native）。
    """

    name = "landlock"
    enforcement = "kernel-native"
    IMAGE = "agentos-sandbox:latest"

    def __init__(self):
        self._volume: str | None = None

    # ---- 生命周期 --------------------------------------------------------

    def available(self) -> bool:
        try:
            subprocess.run(["docker", "image", "inspect", self.IMAGE],
                           capture_output=True, timeout=15, check=True)
            return True
        except (subprocess.SubprocessError, OSError):
            return False

    def begin(self, policy: Policy, run: str = "") -> None:
        self._volume = f"agentos-work-{run or 'default'}"
        subprocess.run(["docker", "volume", "rm", "-f", self._volume],
                       capture_output=True, timeout=30)
        subprocess.run(["docker", "volume", "create", self._volume],
                       capture_output=True, timeout=30, check=True)
        subprocess.run([
            "docker", "run", "--rm", "-v", f"{self._volume}:/work",
            "-v", f"{policy.resolved_workdir()}:/seed:ro", "alpine:3.20",
            "sh", "-c", "cp -a /seed/. /work/",
        ], capture_output=True, timeout=120, check=True)
        # 内核 Landlock 可用性探针（不可用则 fail fast，不静默空转）
        probe = self.execute(["true"], policy, internal=True)
        if probe.rc == 126:
            self.end(policy, export=False)
            raise RuntimeError("内核 Landlock 不可用（探针 rc=126），请换用 docker/plain 后端")

    def end(self, policy: Policy, export: bool = True, run: str = "") -> None:
        volume = self._volume or f"agentos-work-{run or 'default'}"
        if export:
            subprocess.run([
                "docker", "run", "--rm", "-v", f"{volume}:/work",
                "-v", f"{policy.resolved_workdir()}:/out", "alpine:3.20",
                "sh", "-c", "find /out -mindepth 1 -delete && cp -a /work/. /out/",
            ], capture_output=True, timeout=120, check=True)
        subprocess.run(["docker", "volume", "rm", "-f", volume],
                       capture_output=True, timeout=30)
        self._volume = None

    # ---- 执行 ------------------------------------------------------------

    def _rox_args(self) -> list[str]:
        return ["--rox", "/bin", "--rox", "/usr/bin", "--rox", "/lib",
                "--rox", "/usr/lib", "--rox", "/lib64"]

    def execute(self, argv, policy, stdin=None, internal=False):
        blocked = self._precheck(argv, policy, internal)
        if blocked:
            return blocked
        if not self._volume:
            return SandboxResult(126, "", "[landlock] 卷未初始化（begin 未调用）", denied=True,
                                 reason="volume not initialized")
        docker_argv = [
            "docker", "run", "--rm", "--network", "none",
            "--read-only", "--tmpfs", "/tmp",
            "--memory", "512m", "--cpus", "1",
            "--security-opt", "no-new-privileges",
            "-v", f"{self._volume}:/work", "-w", "/work",
            "--entrypoint", "/usr/local/bin/llandlock", self.IMAGE,
            "--rw", "/work",
        ] + self._rox_args()
        for r in policy.extra_read:
            name = "/extra-" + Path(str(r)).resolve().name
            docker_argv += ["-v", f"{Path(str(r)).resolve()}:{name}:ro", "--ro", name]
        docker_argv += ["--"] + argv
        rc, out, err = _run_pguarded(docker_argv, cwd=None, stdin=stdin, timeout=120)
        return SandboxResult(rc, out, err)


class SrtSandbox(Sandbox):
    """内核原生强制：Anthropic sandbox-runtime（Linux=bwrap+Landlock，macOS=Seatbelt）。

    2026-10-26 在 Ubuntu 24.04（colima VM，内核 6.8）实测校准的真实接口：
      - 入口是 `srt-py`（pip 包 sandbox-runtime 0.2.0），不是 `srt`
      - 权限走 `-s <settings.json>`，JSON 为 **camelCase**：
        {"filesystem": {"allowWrite": ["/work"], "denyRead": []}, "network": {"allowedDomains": []}}
      - 读默认放行（deny_read 例外）、写默认拒绝（allow_write 白名单）
      - 依赖：ripgrep、bubblewrap、socat；Ubuntu 24.04 需
        `sysctl kernel.apparmor_restrict_unprivileged_userns=0`
    """

    name = "srt"
    enforcement = "kernel-native"
    SRT = "srt-py"  # venv 中的入口；部署时把 venv/bin 加入 PATH

    def available(self) -> bool:
        import platform
        return platform.system() == "Linux" and shutil.which(self.SRT) is not None

    def execute(self, argv, policy, stdin=None, internal=False):
        blocked = self._precheck(argv, policy, internal)
        if blocked:
            return blocked
        import json
        import tempfile
        workdir = policy.resolved_workdir()
        settings = {
            "filesystem": {
                "allowWrite": [str(workdir)],
                "denyRead": [],
            },
            "network": {"allowedDomains": []},
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(settings, f)
            settings_path = f.name
        srt_argv = [self.SRT, "-s", settings_path] + argv
        rc, out, err = _run_pguarded(srt_argv, cwd=str(workdir), stdin=stdin, timeout=120)
        os.unlink(settings_path)
        return SandboxResult(rc, out, err)


class AgentdSandbox(Sandbox):
    """经由常驻 agentd（Rust 守护进程）执行——"客户端大脑 + 内核执行"架构。

    协议：Unix socket NDJSON（见 rust/src/daemon.rs）。工具调用逐条发给 daemon：
    {"cmd":"exec","params":{"policy":..., "argv":..., "stdin":...,"wait":true}}
    daemon 侧独立记账并按其执行器（llrun/Landlock 或 plain）强制。

    注：写原语 tee 需出现在 allow_commands 中（客户端声明、daemon 内核强制）——
    cli 在 agentd 后端会自动附加。
    """

    name = "agentd"
    enforcement = "via-agentd"  # 实际级别由 daemon 返回并记入账本

    def __init__(self, socket_path: Path):
        self.socket = Path(socket_path)

    def available(self) -> bool:
        return self.socket.exists()

    def execute(self, argv, policy, stdin=None, internal=False):
        blocked = self._precheck(argv, policy, internal)
        if blocked:
            return blocked
        import json as _json
        import socket as _socket
        req = {
            "id": "harness",
            "cmd": "exec",
            "params": {
                "policy": policy.to_dict(),
                "argv": argv,
                "wait": True,
            },
        }
        if stdin is not None:
            req["params"]["stdin"] = stdin
        try:
            s = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
            s.settimeout(180)
            s.connect(str(self.socket))
            with s:
                s.sendall((_json.dumps(req) + "\n").encode("utf-8"))
                buf = b""
                while b"\n" not in buf:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
        except OSError as e:
            return SandboxResult(125, "", f"[agentd] 连接失败: {e}")
        try:
            resp = _json.loads(buf.decode("utf-8").splitlines()[0])
        except (json.JSONDecodeError, IndexError):
            return SandboxResult(125, "", "[agentd] daemon 响应无法解析")
        if not resp.get("ok"):
            return SandboxResult(125, "", f"[agentd] {resp.get('error', '未知错误')}")
        r = resp.get("result", {})
        denied = bool(r.get("denied"))
        return SandboxResult(
            rc=int(r.get("rc", -1)),
            stdout=str(r.get("stdout", "")),
            stderr=str(r.get("stderr", "")),
            denied=denied,
            reason=str(r.get("stderr", "")) if denied else "",
        )


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
