# Agent OS — 阶段 0 harness

给 AI Agent 立规矩的最小参考实现：**笼子（沙箱）+ 存档（快照）+ 行车记录仪（哈希链账本）+ 验收单（finish 报告）**。
定位与路线图见 [PLAN.md](PLAN.md)，行业调研见 [RESEARCH.md](RESEARCH.md)。

## 快速开始（免 key）

在仓库根目录执行（`bin/agentos` 也会自动切到根目录）：

```sh
./bin/agentos run --task tasks/demo-organize.md --mock
./bin/agentos run --task tasks/demo-organize.md --backend landlock --verifier verifiers/demo_organization.py
                              # ↑ 内核级 Landlock 强制 + 独立验收判定（阶段1 双后端实证）
./bin/agentos explain         # 把策略翻译成人类的确认卡
./bin/agentos verify          # 校验账本哈希链
./bin/agentos snapshots       # 列出存档（标出最新；rollback 默认恢复它）
./bin/agentos rollback        # 读档：工作目录恢复到开跑前的乱序状态
```

> **出厂状态说明**：`workspace/demo` 初始为 5 张乱放的发票。`run` 会把它们整理进月份子目录，
> `rollback` 把它们放回乱放状态——来回对比才能看见效果。想从头再来：删掉
> `workspace/.demo.agentos/`（账本+快照），再把 `workspace/demo` 手动还原即可。
> Mock 模式是确定性剧本，动作总是"成功"，仅供机制演示；真实效果请用 GLM 模式。

**自定义工作目录**：`--workdir` 放全局或子命令后均可，账本/快照按目录隔离：
`./bin/agentos run --workdir ./my-dir --task tasks/demo-organize.md`

## 真实模型模式

```sh
export AGENTOS_API_KEY=你的_Z.ai_key        # 或 bigmodel 的 key
export AGENTOS_API_BASE=https://api.z.ai/api/paas/v4   # 可选，默认 Z.ai
export AGENTOS_MODEL=glm-4.6                # 可选
./bin/agentos run --task tasks/demo-organize.md
```

## 沙箱后端（可插拔，run 时自动选择）

| 后端 | 强制级别 | 现状 |
|---|---|---|
| `landlock` | **内核原生**：自研 [llandlock](sandbox/llandlock.c)（~100 行 C）编译策略，Docker Desktop 命名卷（VM 内 ext4）上执行；原生 Linux 上可脱容器直用 | ✅ 已验证（macOS 容器内 + colima Ubuntu 6.8 真机，含内核级拒绝） |
| `srt` | **内核原生**：Anthropic sandbox-runtime（Linux=bwrap+Landlock） | ✅ 已验证（colima Ubuntu 24.04 端到端）。依赖：`pip install sandbox-runtime` + ripgrep/bubblewrap/socat；Ubuntu 24.04 需 `sysctl kernel.apparmor_restrict_unprivileged_userns=0`；settings 为 camelCase JSON |
| `docker` | namespace/cgroups 容器 | ✅ 已验证 |
| `plain` | 软件层策略预检（含 run_command 操作数检查） | 永远可用（macOS 27 已禁用 Seatbelt） |

> `plain` 的诚实边界：它挡得住"AI 走 harness 调工具"，挡不住"进程自己绕过 harness"。
> 需要对抗性隔离时请用 docker/srt 后端。

账本会如实记录每次运行实际使用的强制级别——**声明是什么样，就记什么样**。

## 目录

- `harness/` 核心实现（纯标准库，无第三方依赖）
- `schemas/` **协议草案**：`policy.schema.json`（P1 统一策略格式）、`capability.schema.json`（P2 身份/能力模型）
- `docs/ledger.format.md` **协议草案**（P3 哈希链账本格式）
- `tasks/` 任务书 ｜ `workspace/demo` 演示工作区
- 运行状态在 `workspace/.demo.agentos/`（账本 + 快照，刻意放在工作目录外——回滚不能烧掉账本）

一致性检验已通过：`harness/policy.py` 的实际输出符合 `policy.schema.json`（这是"协议与实现同步演进"的最低保障，阶段 1 会升级为正式 conformance 测试套件）。
