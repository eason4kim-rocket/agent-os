"""Agent 循环：模型 ↔ 工具的回合制，全程过笼子、全程入账本。"""

from __future__ import annotations

import json
import sys
import uuid
from datetime import datetime

from .ledger import Ledger
from .model import GLMModel, MockModel, Reply
from .policy import Policy
from .sandbox import Sandbox
from .snapshot import SnapshotManager
from .tools import TOOL_SCHEMAS, dispatch


class AgentRunner:
    def __init__(self, policy: Policy, sb: Sandbox, ledger: Ledger, snaps: SnapshotManager,
                 model, verbose: bool = True):
        self.policy, self.sb, self.ledger, self.snaps, self.model = policy, sb, ledger, snaps, model
        self.verbose = verbose

    def _say(self, text: str) -> None:
        if self.verbose:
            print(text)

    def _event(self, event: str, run: str, **detail):
        self.ledger.append(event, run, **detail)
        if self.verbose and event.startswith("tool."):
            if event == "tool.result" and detail.get("rc", 0) != 0:
                icon = "✘"
            else:
                icon = {"tool.call": "▶", "tool.result": "✔", "tool.denied": "⛔",
                        "tool.finish": "🏁"}.get(event, "·")
            parts = [f"  {icon} {detail.get('tool', event)}"]
            for key in ("path", "target", "command"):
                if detail.get(key):
                    parts.append(str(detail[key]))
            if event == "tool.denied":
                parts.append(f"—— {detail.get('reason', '拒绝')}")
            self._say(" ".join(parts))

    def run(self, task_text: str, verifier: str | None = None) -> str:
        run = datetime.now().strftime("%Y%m%d") + "-" + uuid.uuid4().hex[:8]
        backend = f"{self.sb.name}/{self.sb.enforcement}"

        self._event("run.start", run, task=task_text[:200], policy=self.policy.to_dict(),
                    backend=backend)
        self._say(f"[笼子] {backend}｜读写区 {self.policy.resolved_workdir()}｜"
                  f"命令白名单 {len(self.policy.allow_commands)} 项｜断网")
        if hasattr(self.sb, "begin"):
            self.sb.begin(self.policy)
        sid = self.snaps.create(run)
        self._event("snapshot.created", run, snapshot=sid)
        self._say(f"[存档] 快照 {sid} 已保存")

        messages = [{
            "role": "system",
            "content": (
                "你是一个在严格沙箱中干活的 Agent。规则：\n"
                "1. 只能使用提供的工具；工作目录之外的路径会被策略拒绝。\n"
                "2. 完成任务后必须调用 finish 提交验收报告（做了什么/结果/自查）。\n"
                "3. 遇到拒绝不要绕过，调整方案或在报告中如实说明。"
            ),
        }, {"role": "user", "content": task_text}]

        report = ""
        for _ in range(self.policy.max_steps):
            reply: Reply = self.model.chat(messages, TOOL_SCHEMAS)
            if not reply.tool_calls:
                report = reply.content
                self._event("run.end", run, how="model_final_text", report=report[:500])
                break
            messages.append({"role": "assistant",
                             "content": reply.content or None,
                             "tool_calls": [
                                 {"id": f"c{i}", "type": "function",
                                  "function": {"name": c["name"],
                                               "arguments": json.dumps(c["arguments"],
                                                                       ensure_ascii=False)}}
                                 for i, c in enumerate(reply.tool_calls)]})
            done = False
            for i, call in enumerate(reply.tool_calls):
                self._event("tool.call", run, tool=call["name"], **{
                    k: v for k, v in call["arguments"].items() if k in ("path", "command")})
                result, done = dispatch(call["name"], call["arguments"],
                                        self.policy, self.sb,
                                        on_event=lambda e, **d: self._event(e, run, **d))
                messages.append({"role": "tool", "tool_call_id": f"c{i}", "content": result})
                if done:
                    report = str(call["arguments"].get("report", ""))
                    self._event("run.end", run, how="finish", report=report[:500])
            if done:
                break

        self._say(f"[完成] {report or '(无报告)'}")
        if hasattr(self.sb, "end"):
            self.sb.end(self.policy)
        if verifier:
            import subprocess
            req = json.dumps({"task_file": task_text[:1000], "workdir": str(self.policy.resolved_workdir()),
                              "report": report})
            proc = subprocess.run([sys.executable, verifier], input=req,
                                  capture_output=True, text=True, timeout=60)
            try:
                verdict = json.loads(proc.stdout or "{}")
            except json.JSONDecodeError:
                verdict = {"passed": False, "details": {"error": proc.stderr[:300]}}
            self._event("verifier.verdict", run, verifier=verifier,
                        passed=bool(verdict.get("passed")), detail=verdict.get("details"))
            self._say(f"[验收] {'✔ 通过' if verdict.get('passed') else '✘ 未通过'} {verdict.get('details', '')}")
            if not verdict.get("passed"):
                report = ""
        return report
