#!/usr/bin/env python3
"""示例验收器（P4 验收协议 v0）：检查"发票整理"任务的真实完成情况。

契约：从 stdin 读 {"task_file": str, "workdir": str, "report": str}，
向 stdout 输出 {"passed": bool, "details": {...}}，退出码 0（判定结果看 passed）。
"""
import json
import sys
from pathlib import Path


def main() -> int:
    req = json.loads(sys.stdin.read())
    wd = Path(req["workdir"])
    months = ["2026-01", "2026-02", "2026-03"]
    checks = {}

    for m in months:
        checks[f"dir:{m}"] = wd.joinpath(m).is_dir()

    loose = [p.name for p in wd.iterdir() if p.is_file() and p.name.startswith("发票")]
    checks["no_loose_invoices"] = not loose

    filed = sum(1 for m in months for p in wd.joinpath(m).glob("发票*.txt")) if wd.is_dir() else 0
    checks["filed_count"] = filed
    checks["expected_count"] = 5

    passed = all(v is True for k, v in checks.items() if isinstance(v, bool)) and filed == 5
    print(json.dumps({"passed": passed,
                      "details": {"checks": checks, "loose": loose}},
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
