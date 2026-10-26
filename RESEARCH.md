# 调研报告：开放的原生 Agent Linux 发行版（2026-10）

> 调研方式：4 路并行子 Agent（Docker/容器生态、西方 OS 层、内核隔离实现、国内深水区），
> 全部结论基于可验证来源，标注【事实】/【推测】。

## 一句话结论

**"开放（开源+不绑云）+ 原生（为 Agent 而造）+ Linux 发行版（可装机）"三者同时满足的项目，
截至 2026-10 全球仍然空缺。** 但每个单项都有强势玩家入场，窗口期估计 12-18 个月。

---

## 全球格局（按层）

### L0 内核隔离层 —— NVIDIA 已下场标准化，勿重复造

| 项目 | 技术 | 状态 |
|---|---|---|
| **NVIDIA OpenShell** | Landlock(ABI3+/Linux6.2+) + seccomp + Supervisor/Sentry + 策略文件；Apache-2.0；不强制 NVIDIA 硬件（支持 Linux/macOS/WSL2）【事实】 | 2026-09 v0.1；被 Ubuntu/SUSE/Red Hat OpenShift AI 3.5 集成 |
| **Anthropic sandbox-runtime (srt)** | macOS=Seatbelt，Linux=**Bubblewrap+Landlock**，Windows WFP alpha；Apache-2.0【事实】 | 2026-10 开源，6.6k stars |
| **OpenAI codex linux-sandbox** | Landlock ABI4 + seccomp 拦 socket() + eBPF 回退；Apache-2.0 全开源【事实】 | 随 codex CLI 持续维护 |
| microsandbox | libkrun microVM 本地沙箱【事实】 | 8.8k stars，beta |
| landlock 官方生态 | island（官方工具）、landrun（免 root CLI）【事实】 | 成熟可用 |
| eBPF 阵营 | Tetragon、KubeArmor（强制）；ActPlane（agent 声明式内核策略，arXiv 2606.25189）；AgentSight（观测）【事实】 | 生产可用 |

**关键事实：三大 AI 巨头（NVIDIA/Anthropic/OpenAI）的沙箱全部收敛到 Landlock+seccomp。**
**关键空缺：各家策略格式互不兼容——统一策略格式 + agent 身份/能力模型是公认空白【推测，基于上述事实】。**

### L1 发行版层 —— 占位者盘点

| 项目 | 实质 | 与"开放原生"的距离 |
|---|---|---|
| **Omarchy**（DHH） | Arch 系，自定位 "agentic Linux"，45.7k★，$18.5M 融资（阿里投了 $3M）【事实】 | 唯一可装机+官方自称 agentic 的发行版，但实质是 Arch+预配置，非架构级原生 |
| **阿里 ANOLISA**（github.com/alibaba/anolisa） | 已开源 Apache-2.0：Copilot Shell(cosh/基于 Qwen Code)、AgentSecCore、AgentSight(eBPF)、SkillFS(FUSE 挂载 SKILL.md+签名)、namespace/cgroup/seccomp 隔离【事实】 | 开源但 x86-only、面向阿里云镜像、Skill 协议绑定 Qwen 生态 |
| **openEuler 26.09** | 明确 Agent Runtime/系统级沙箱/Agent Infra 路线【事实】 | 全开源社区底座，最有潜力承接，但尚无 agent 原生发行版整包 |
| SLES 16 / Ubuntu 26.04 | 传统发行版+agent 加固+OpenShell 集成【事实】 | 厂商驱动，"删掉 Agent 看不出为 Agent 而造" |
| Herald-OS | 自称 agent-native OS，562★ 个人项目【事实】 | 极早期 |
| NixOS 生态 | llm-agents.nix 等工具 + "agentic control layer" 提案（2026-05 Discourse）【事实】 | 无整包发行版，但声明式底座最契合 |

### L2 沙箱基础设施 —— 最卷，红海

- Docker：本地 microVM 沙箱（sbx）+ Cloud Sandboxes（2026-09）+ **Sandbox Kit 规范已提交 CNCF**（2026-10）【事实】——Docker 在抢执行层标准席位
- K8s：kagent 入 CNCF Sandbox；kubernetes-sigs/agent-sandbox CRD（gVisor/Kata）；Red Hat 商业 Agent Sandbox（2026-07）【事实】
- 云沙箱：E2B、Daytona、Modal、Cloudflare、Vercel、Fly Sprites 混战【事实】
- **判断：容器/云生态全部停留在"隔离执行单元"，无人做 OS 级整合【事实+推测】**

### L3 国内补充

- 腾讯云 AGS runtime（Cube microVM，60ms 冷启动）【事实】
- DeepSeek Harness（dsh，"一切皆插件"，TypeScript）开源【事实】
- 华为 HarmonyOS 7 Agent 亲和架构 + HMAF 2.0；阶跃星辰 Step AOS、讯飞玲珑、联想天禧 Claw、荣耀 MagicOS【事实】——终端/行业向，均绑生态
- 百度"产业智能体操作系统"（2026-09 提法，理念+平台，非 OS 产品）【事实】

### 学术界

AIOS（Rutgers，COLM 2025）、Sandlock（Rust+Landlock，arXiv 2605.26298）、ERA（microVM）、AgentBay（混合沙箱）——均带开源实现，原型级【事实】。

---

## 修正后的机会判断

1. **笼子层（内核隔离）：放弃自研。** Landlock+seccomp 已被三大巨头收敛为事实标准，参考实现全开放源（srt、codex-sandbox、island、landrun）。正确姿势：直接复用/封装。
2. **协议层（真正的空位）：统一策略格式 + Agent 身份/能力模型 + 账本格式 + 验收协议。**
   OpenShell 有自己的 Policy Schema、srt 有自己的配置、codex 有自己的 profile、ANOLISA 有 SKILL.md——
   **互不兼容，且全是单家私货。谁来定开放协议，谁就是"Agent 时代的 POSIX"。【推测】**
3. **发行版层（可装机载体）：两条候选路线**
   - openEuler 路线：国内全开源社区底座 + Agent Runtime 路线图，做"第一个 agent 原生的 openEuler remix"
   - NixOS 路线：声明式+原子回滚与"能力即文件"哲学同构，国际上无竞品
4. **差异化三板斧不变**：本地优先 / 模型无关 / 任何机器可装——上表所有玩家共同的盲区。
5. **窗口期**：Docker 在抢 CNCF 标准、NVIDIA 在收编发行版、阿里已开源占位——**12-18 个月内协议站队完毕。**

## 对阶段 0 的直接指导

- 沙箱后端：macOS 上对接 **Anthropic srt（Seatbelt）**，Linux 上对接 **srt(Bubblewrap+Landlock) 或 codex linux-sandbox**，不自己写内核胶水
- 账本/策略：从第一天按"未来开放协议"设计（哈希链账本、声明式策略、能力=带签名的文件），格式稳定性优先于功能
- 参考阅读：OpenShell 的 Policy Schema、ANOLISA 的 SKILL.md、srt 的配置格式——做兼容性映射表

---
*调研执行：2026-10-26，4 路并行子 Agent；来源 URL 已内联于正文。*
