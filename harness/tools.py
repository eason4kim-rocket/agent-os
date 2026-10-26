"""工具（Tools）：模型可调用的动作。全部经过沙箱/策略强制，全部入账本。"""

from __future__ import annotations

import shlex
from pathlib import Path

from .policy import Policy
from .sandbox import Sandbox, SandboxResult

TOOL_SCHEMAS = [
    {"type": "function", "function": {
        "name": "list_dir",
        "description": "列出工作目录（或其子目录）的内容",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string", "description": "相对工作目录的路径，默认 ."}},
            "required": []}}},
    {"type": "function", "function": {
        "name": "read_file",
        "description": "读取一个文本文件的内容",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string"}}, "required": ["path"]}}},
    {"type": "function", "function": {
        "name": "write_file",
        "description": "把文本写入工作目录内的一个文件（覆盖）",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string"}, "content": {"type": "string"}},
            "required": ["path", "content"]}}},
    {"type": "function", "function": {
        "name": "run_command",
        "description": "在工作目录内执行一条白名单 shell 命令（如 mkdir/mv/ls）",
        "parameters": {"type": "object", "properties": {
            "command": {"type": "string"}}, "required": ["command"]}}},
    {"type": "function", "function": {
        "name": "finish",
        "description": "宣布任务完成并提交验收报告",
        "parameters": {"type": "object", "properties": {
            "report": {"type": "string", "description": "做了什么、结果如何、自查结论"}},
            "required": ["report"]}}},
]


def _fmt(res: SandboxResult) -> str:
    if res.denied:
        return f"[策略拒绝] {res.reason}"
    out = (res.stdout or "").strip()
    err = (res.stderr or "").strip()
    if res.rc != 0:
        return f"[退出码 {res.rc}] {err or out or '(无输出)'}"
    return out or "(空)"


def dispatch(name: str, args: dict, policy: Policy, sb: Sandbox,
             on_event) -> tuple[str, bool]:
    """执行一个工具调用。返回 (给模型的文本, 是否为 finish)。所有事件经 on_event 入账。"""
    if name == "finish":
        report = str(args.get("report", "")).strip()
        on_event("tool.finish", tool="finish", report=report)
        return "任务已提交验收。", True

    if name == "list_dir":
        raw = args.get("path", ".")
        ok, why = policy.path_allowed_read(raw)
        if not ok:
            on_event("tool.denied", tool=name, target=raw, reason=why)
            return f"[策略拒绝] {why}", False
        base = policy.resolved_workdir() / Path(raw)
        items = []
        for p in sorted(base.iterdir()):
            items.append(("d " if p.is_dir() else "f ") + p.name)
        res = SandboxResult(0, "\n".join(items) or "(空目录)", "")
        on_event("tool.result", tool=name, target=str(raw), lines=len(items))
        return _fmt(res), False

    if name == "read_file":
        raw = args.get("path", "")
        ok, why = policy.path_allowed_read(raw)
        if not ok:
            on_event("tool.denied", tool=name, target=raw, reason=why)
            return f"[策略拒绝] {why}", False
        res = sb.execute(["cat", str(raw)], policy)
        on_event("tool.result", tool=name, target=str(raw), rc=res.rc, denied=res.denied)
        return _fmt(res), False

    if name == "write_file":
        raw = args.get("path", "")
        ok, why = policy.path_allowed_write(raw)
        if not ok:
            on_event("tool.denied", tool=name, target=raw, reason=why)
            return f"[策略拒绝] {why}", False
        res = sb.execute(["tee", str(raw)], policy, stdin=str(args.get("content", "")))
        on_event("tool.result", tool=name, target=str(raw), rc=res.rc, bytes=len(str(args.get("content", ""))))
        return ("写入成功" if res.rc == 0 else _fmt(res)), False

    if name == "run_command":
        raw = str(args.get("command", ""))
        argv = shlex.split(raw)
        res = sb.execute(argv, policy)
        on_event("tool.result", tool="run_command", command=raw, rc=res.rc,
                 denied=res.denied, reason=res.reason if res.denied else None)
        return _fmt(res), False

    return f"[未知工具] {name}", False
