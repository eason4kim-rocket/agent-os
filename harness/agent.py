"""Agent 循环：模型 ↔ 工具的回合制，全程过笼子、全程入账本。

异常安全承诺：无论循环正常结束、预算耗尽、模型出错还是工具异常，
run.end 都会落账，沙箱后端的生命周期钩子（begin/end）都会配对执行。
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import uuid
from datetime import datetime

from . import identity as ident
from .ledger import Ledger
from .model import Reply
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
            if event in ("tool.denied",) or (event == "tool.result" and detail.get("rc", 0) != 0):
                if detail.get("reason") or detail.get("stderr"):
                    parts.append(f"—— {(detail.get('reason') or detail.get('stderr') or '').strip()[:120]}")
            self._say(" ".join(parts))

    def run(self, task_text: str, verifier: str | None = None) -> str:
        run = datetime.now().strftime("%Y%m%d") + "-" + uuid.uuid4().hex[:8]
        backend = f"{self.sb.name}/{self.sb.enforcement}"

        # P2 身份签名 v0：Agent 私钥对策略摘要签名，公钥与签名入 run.start
        seed, pk = ident.ensure_identity(self.ledger.path.parent)
        policy_digest = __import__("hashlib").sha256(
            json.dumps(self.policy.to_dict(), sort_keys=True, ensure_ascii=False,
                       separators=(",", ":")).encode("utf-8")).hexdigest()
        policy_sig = ident.sign_digest(seed, bytes.fromhex(policy_digest))
        self._event("run.start", run, task=task_text[:200], policy=self.policy.to_dict(),
                    backend=backend, agent_pubkey=pk.hex(),
                    signed=policy_digest, agent_sig=policy_sig.hex())
        self._say(f"[笼子] {backend}｜读写区 {self.policy.resolved_workdir()}｜"
                  f"命令白名单 {len(self.policy.allow_commands)} 项｜断网")
        if hasattr(self.sb, "begin"):
            self.sb.begin(self.policy, run=run)
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
        ended = {"flag": False}

        def end_run(how: str, **extra):
            if not ended["flag"]:
                ended["flag"] = True
                report_digest = hashlib.sha256(f"{how}|{report}".encode("utf-8")).hexdigest()
                sig = ident.sign_digest(seed, bytes.fromhex(report_digest))
                self._event("run.end", run, how=how, report=report[:500],
                            agent_pubkey=pk.hex(), signed=report_digest,
                            agent_sig=sig.hex(), **extra)

        try:
            for _ in range(self.policy.max_steps):
                try:
                    reply: Reply = self.model.chat(messages, TOOL_SCHEMAS)
                except Exception as e:  # 模型网络/协议错误也要落账收尾
                    end_run("model_error", error=str(e)[:300])
                    self._say(f"[错误] 模型调用失败：{e}")
                    break
                if not reply.tool_calls:
                    report = reply.content
                    end_run("model_final_text")
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
                    if done:  # finish 之后同回合的调用一律拒绝（M5）
                        self._event("tool.denied", run, tool=call["name"],
                                    reason="run already finished in this turn")
                        messages.append({"role": "tool", "tool_call_id": f"c{i}",
                                         "content": "[策略拒绝] 任务已结束"})
                        continue
                    self._event("tool.call", run, tool=call["name"], **{
                        k: v for k, v in call["arguments"].items() if k in ("path", "command")})
                    result, done = dispatch(call["name"], call["arguments"],
                                            self.policy, self.sb,
                                            on_event=lambda e, **d: self._event(e, run, **d))
                    messages.append({"role": "tool", "tool_call_id": f"c{i}", "content": result})
                    if done:
                        report = str(call["arguments"].get("report", ""))
                        end_run("finish")
                if done:
                    break
            else:
                end_run("budget_exhausted")
        finally:
            end_run("error")  # 若上面已 end_run 则此调用是空操作
            if hasattr(self.sb, "end"):
                self.sb.end(self.policy, run=run)

        self._say(f"[完成] {report or '(无报告)'}")

        if verifier and ended["flag"] and not ended.get("skip"):
            self._verify(verifier, run, task_text, report)
        return report

    def _verify(self, verifier: str, run: str, task_text: str, report: str) -> None:
        req = json.dumps({"task_file": task_text[:1000],
                          "workdir": str(self.policy.resolved_workdir()),
                          "report": report})
        try:
            proc = subprocess.run([sys.executable, verifier], input=req,
                                  capture_output=True, text=True, timeout=60)
            verdict = json.loads(proc.stdout or "{}")
        except (subprocess.SubprocessError, json.JSONDecodeError) as e:
            verdict = {"passed": False, "details": {"error": str(e)[:300]}}
        self._event("verifier.verdict", run, verifier=verifier,
                    passed=bool(verdict.get("passed")), detail=verdict.get("details"))
        self._say(f"[验收] {'✔ 通过' if verdict.get('passed') else '✘ 未通过'} "
                  f"{verdict.get('details', '')}")
