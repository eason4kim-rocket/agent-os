# 安全审计 2026-10-26（第二轮）：agentd 运行时（PR #2/#3/#4）与修复

> 审核方式：零上下文红队子 Agent，逐行 + PoC 实证。原始评分 3/10。
> 审计对象：PR #2（daemon）/ #3（async）/ #4（AgentdSandbox）。

## 已修复（本轮 fix/security-hardening）

- **H1（设计缺陷）**：daemon 完全信任客户端提交的 policy 内容 →
  exec 改为只接受【已安装策略的名称】，策略由操作者放置于
  `state_dir/policies/*.json`；network=true 的策略拒绝加载（fail-closed）。
  内联 policy 对象/未知名称均被拒（回归测试覆盖）。
- **H2（已实证逃逸）**：Rust `starts_with` 不折叠 `..` →
  新增 `normalize_lexical()` 词法折叠；`cat ../../etc/passwd` 回归测试。
- **H3**：seed 文件实际 0644 且 /tmp 可预测目录可被抢占 →
  写入显式 mode(0600)、已存在但权限过宽拒绝加载、目录 0700、
  默认 state_dir 移至 `$HOME/.local/state/agentos`；账本/锚点 O_NOFOLLOW + 0600。
- **H4**：socket 从不设权限 → 显式 0600（仅属主可连接）。
- **M2**：管道死锁（大输出假超时/大 stdin 挂死）→ 三线程并发排空 + 写完即 drop stdin。
- **M3**：runs 表无限增长 + watch 对未完成 run 谎报 done →
  FIFO 淘汰（上限 256）；watch 区分 done/interrupted/unknown。
- **M4**：run.end 签名不绑定内容可跨 run 重放 →
  签名覆盖 canonical(run, argv, rc, stdout, stderr, enforcement)。
- **M5**：harness 账本记 "via-agentd" 丢弃真实级别 →
  SandboxResult 增加 enforcement 字段，daemon 返回的真实级别回写任务账本。
- **M6**：超时只杀直接子进程 → 进程组托管（process_group(0) + kill(-pgid)）。
- **L1/L3**：协议行上限 1MiB；run id 随机部分改 /dev/urandom。

## 已知未修（记录在案）

- **M1**：network=true 语义未被任何后端强制（已 fail-closed：拒载此类策略）；
  Landlock ABI v4 网络限制待实现
- H4 残余：同用户进程仍可连 socket（peer uid 校验待做；0600 已挡跨用户）
- 词法折叠不解析符号链接（plain 后端的符号链接残余风险；Landlock 后端内核侧无此问题）
- llandlock IOCTL_DEV（ABI v5）未入 handled
- anchor 写入的单调性互斥未做（并发 run 可能互相覆盖旧锚点）
- canonical JSON 浮点序列化跨语言字节一致性问题（阶段 2 conformance 套件固化）

## 经验

本次审计直接证明了两层防线的价值：红队抓到的 H2（两侧行为分叉）正是
AGENTS.md 硬规则 1（三者一致）定义的 bug；而修复的回归测试已进入
`rust/tests/daemon.rs`（含内联 policy 拒绝、未知策略拒绝、`..` 逃逸拒绝）。
