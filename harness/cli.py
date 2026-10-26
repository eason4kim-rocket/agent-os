"""agentos 命令行入口：run / snapshots / rollback / verify"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .agent import AgentRunner
from .ledger import Ledger
from .model import GLMModel, MockModel
from .policy import Policy
from .sandbox import select_backend
from .snapshot import SnapshotManager


def _paths(workdir: str):
    wd = Path(workdir).resolve()
    state = wd.parent / f".{wd.name}.agentos"
    return wd, state


def cmd_run(args):
    wd, state = _paths(args.workdir)
    if not wd.is_dir():
        raise SystemExit(f"工作目录不存在: {wd}")
    task = Path(args.task).read_text(encoding="utf-8") if args.task else "整理当前目录的文件。"
    policy = Policy(workdir=wd, backend=args.backend, max_steps=args.max_steps)
    sb = select_backend(policy)
    if args.backend != "auto" and sb.name != args.backend:
        raise SystemExit(f"后端 '{args.backend}' 不可用（当前回退为 '{sb.name}'）。"
                         f"请安装对应依赖或改用 --backend auto/plain。")
    ledger = Ledger(state / "ledger.jsonl")
    snaps = SnapshotManager(wd, state)
    model = MockModel() if (args.mock or not os.environ.get("AGENTOS_API_KEY")) else GLMModel()
    mode = "mock" if isinstance(model, MockModel) else model.model
    print(f"=== Agent OS harness｜模式: {mode}｜后端: {sb.name} ({sb.enforcement})｜任务: {args.task or '(默认)'} ===")
    AgentRunner(policy, sb, ledger, snaps, model).run(task, verifier=args.verifier)
    ledger.anchor(state / "ledger.anchor")


def cmd_explain(args):
    wd, _ = _paths(args.workdir)
    policy = Policy(workdir=wd, backend=args.backend if hasattr(args, "backend") else "auto")
    sb = select_backend(policy)
    cmds = "、".join(policy.allow_commands)
    print("┌─ 权限确认卡（agentos.policy.v0 → 人话）")
    print(f"│ 读写区   {policy.resolved_workdir()}")
    print(f"│          ↑ 只有这个目录允许改动（含子目录）")
    extra = "、".join(str(Path(r).resolve()) for r in policy.extra_read) or "（无）"
    print(f"│ 只读区   {extra}")
    print(f"│ 允许命令 {cmds}（共 {len(policy.allow_commands)} 项；白名单之外一律拒绝）")
    print(f"│ 网络     {'允许' if policy.network else '禁止'}（模型调用发生在笼外，不受影响）")
    print(f"│ 回合预算 最多 {policy.max_steps} 步，防失控")
    print(f"│ 强制后端 {sb.name}（{sb.enforcement}）")
    print("└─ 默认拒绝：读写区之外的一切、白名单之外的命令，全部拒绝并记入账本")


def cmd_snapshots(args):
    wd, state = _paths(args.workdir)
    ids = SnapshotManager(wd, state).list()
    if not ids:
        print("(无快照——先跑一次 run)")
        return
    latest = ids[-1]
    for sid in ids:
        mark = "  ← 最新（rollback 默认目标）" if sid == latest else ""
        print(f"{sid}{mark}")
    print(f"共 {len(ids)} 个快照；选择恢复：./bin/agentos rollback --id <id>")


def cmd_rollback(args):
    wd, state = _paths(args.workdir)
    snaps = SnapshotManager(wd, state)
    sid = args.id
    if sid == "last":
        ids = snaps.list()
        if not ids:
            raise SystemExit("没有可用快照")
        sid = ids[-1]
    try:
        snaps.restore(sid)  # 先恢复，成功才记账（M7：不让账本记"已恢复"的假话）
    except (FileNotFoundError, ValueError) as e:
        raise SystemExit(f"[读档失败] {e}")
    Ledger(state / "ledger.jsonl").append("snapshot.restored", run="manual", snapshot=sid)
    print(f"[读档] 已恢复到快照 {sid}（账本在 {state / 'ledger.jsonl'}，不受回滚影响）")


def cmd_verify(args):
    wd, state = _paths(args.workdir)
    ok, count, first_bad = Ledger(state / "ledger.jsonl").verify(state / "ledger.anchor")
    if ok:
        print(f"[账本] ✔ 完整：{count} 条事件，哈希链无断裂，锚点核对一致")
    else:
        print(f"[账本] ✘ 存疑：共 {count} 条，首个问题 → {first_bad}")
        sys.exit(1)


def main():
    ap = argparse.ArgumentParser(prog="agentos", description="Agent OS 阶段0 harness")
    ap.add_argument("--workdir", default="workspace/demo", help="任务工作目录")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser("run", help="运行一个任务")
    p_run.add_argument("--task", help="任务书 markdown 文件")
    p_run.add_argument("--verifier", help="验收器脚本（读 stdin JSON，输出 passed 判定）")
    p_run.add_argument("--backend", default="auto",
                       choices=["auto", "plain", "docker", "landlock", "srt"])
    p_run.add_argument("--mock", action="store_true", help="免 key 剧本模式")
    p_run.add_argument("--max-steps", type=int, default=24)

    sub.add_parser("explain", help="把策略翻译成人类的确认卡（硬问题#1 第一刀）")

    sub.add_parser("snapshots", help="列出快照")
    p_rb = sub.add_parser("rollback", help="回滚工作目录")
    p_rb.add_argument("--id", default="last", help="快照 id 或 last")
    sub.add_parser("verify", help="校验账本哈希链")

    # 容忍从文档复制来的行内注释：丢弃 # 开头的参数（值位除外）
    value_flags = {"--task", "--workdir", "--id", "--backend", "--max-steps"}
    argv: list[str] = []
    expect_value = False
    for a in sys.argv[1:]:
        if not expect_value and a.startswith("#"):
            continue
        argv.append(a)
        expect_value = a in value_flags

    # --workdir 既可放全局位置也可放子命令之后
    for sub in (p_run, sub.choices["snapshots"], p_rb, sub.choices["verify"]):
        sub.add_argument("--workdir", dest="workdir_sub", default=None,
                         help="任务工作目录（覆盖全局 --workdir）")

    args = ap.parse_args(argv)
    args.workdir = getattr(args, "workdir_sub", None) or args.workdir
    {"run": cmd_run, "snapshots": cmd_snapshots, "explain": cmd_explain,
     "rollback": cmd_rollback, "verify": cmd_verify}[args.cmd](args)


if __name__ == "__main__":
    main()
