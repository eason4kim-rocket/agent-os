"""模型适配层：GLM（OpenAI 兼容）与 Mock 双模式。

- GLMModel：任何 OpenAI 兼容端点。Z.ai 编码套餐默认
  base=https://api.z.ai/api/paas/v4，也可指向 open.bigmodel.cn。
  环境变量：AGENTOS_API_BASE / AGENTOS_API_KEY / AGENTOS_MODEL
- MockModel：确定性脚本，无 key 也能演示全流程（含一次故意越界以展示笼子）。
"""

from __future__ import annotations

import json
import os
import urllib.request
from dataclasses import dataclass, field


@dataclass
class Reply:
    content: str = ""
    tool_calls: list[dict] = field(default_factory=list)  # [{name, arguments(dict)}]


class GLMModel:
    def __init__(self):
        self.base = os.environ.get("AGENTOS_API_BASE", "https://api.z.ai/api/paas/v4").rstrip("/")
        self.key = os.environ.get("AGENTOS_API_KEY", "")
        self.model = os.environ.get("AGENTOS_MODEL", "glm-4.6")
        if not self.key:
            raise SystemExit("未设置 AGENTOS_API_KEY。开发测试可用 --mock 免 key 运行。")

    def chat(self, messages: list[dict], tools: list[dict]) -> Reply:
        body = json.dumps({"model": self.model, "messages": messages, "tools": tools,
                           "temperature": 0.2}).encode("utf-8")
        req = urllib.request.Request(
            self.base + "/chat/completions", data=body,
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {self.key}"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        msg = data["choices"][0]["message"]
        calls = []
        for c in msg.get("tool_calls") or []:
            fn = c["function"]
            calls.append({"name": fn["name"],
                          "arguments": json.loads(fn.get("arguments") or "{}")})
        return Reply(content=msg.get("content") or "", tool_calls=calls)


class MockModel:
    """确定性剧本：读目录 → 读文件 → 试探笼外（被拒）→ 建目录 → 归位 → 汇报。

    顺序驱动，不解析真实文件内容——只演示完整的"循环+笼子+账本"机制。
    """

    SCRIPT: list[dict] = [
        {"name": "list_dir", "arguments": {"path": "."}},
        {"name": "read_file", "arguments": {"path": "发票_2026-01-05_餐饮_88元.txt"}},
        {"name": "read_file", "arguments": {"path": "../secret.txt"}},   # 越界，策略层拒绝
        {"name": "run_command", "arguments": {"command": "cat /etc/passwd"}},  # 笼内越界，内核层拒绝
        {"name": "run_command", "arguments": {"command": "mkdir -p 2026-01 2026-02 2026-03"}},
        {"name": "run_command", "arguments": {"command": "mv 发票_2026-01-05_餐饮_88元.txt 2026-01/"}},
        {"name": "run_command", "arguments": {"command": "mv 发票_2026-01-19_交通_30元.txt 2026-01/"}},
        {"name": "run_command", "arguments": {"command": "mv 发票_2026-02-03_住宿_320元.txt 2026-02/"}},
        {"name": "run_command", "arguments": {"command": "mv 发票_2026-02-14_餐饮_56元.txt 2026-02/"}},
        {"name": "run_command", "arguments": {"command": "mv 发票_2026-03-01_办公用品_120元.txt 2026-03/"}},
        {"name": "list_dir", "arguments": {"path": "."}},
        {"name": "finish", "arguments": {"report":
            "已把 5 张发票按月份归入 2026-01 / 2026-02 / 2026-03 三个子目录。"
            "期间两次越界被拒：读 ../secret.txt 与读 /etc/passwd "
            "（分别由策略层/内核层拦截，具体层级取决于所用后端）——符合预期。"}},
    ]

    def __init__(self):
        self._step = 0

    def chat(self, messages: list[dict], tools: list[dict]) -> Reply:
        if self._step >= len(self.SCRIPT):
            return Reply(content="（剧本已尽，未收到 finish——回合预算或工具异常。）")
        call = self.SCRIPT[self._step]
        self._step += 1
        return Reply(tool_calls=[{"name": call["name"], "arguments": call["arguments"]}])
