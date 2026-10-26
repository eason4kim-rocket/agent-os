# AGENTS.md — AI 编码助手须知

## 文档与代码冲突（实证依据：arXiv 2610.30571）

If the docs and the existing code disagree, follow the existing code, and list
every mismatch in your final reply.

适用对象：README.md、PLAN.md、docs/、schemas/、代码注释。发现漂移时：

1. 以现有代码行为为准实现/修改
2. 在最终回复里逐条列出文档与代码的不一致
3. 不要顺手改文档——先报告，由人决定是"文档过时"还是"代码错了"

## 本项目硬规则

1. **三者一致**：协议工件（`schemas/`、`docs/ledger.format.md`）与参考实现
   （`harness/`、`rust/`）与测试（`tests/`、`rust/tests/`）必须同步——不一致 = bug
2. **账本只追加**：`agentos.ledger.v0` 已发布字段冻结，新信息用新事件类型
3. **安全边界要诚实**：每个后端挡什么/不挡什么，README、代码注释、账本记录三者一致
4. **校验器只能由人签名安装**（`schemas/capability.schema.json` 的 kind=human 规则）
5. canonical JSON = 键排序 + 紧凑分隔符 + 保留 UTF-8；Python 与 Rust 实现必须字节级一致

## 改完必须跑

```sh
python3 -m unittest discover tests -v        # Python 回归（16 例）
cd rust && cargo test                        # Rust 回归 + 互操作
actionlint .github/workflows/ci.yml          # workflow 语法
```
