# 贡献指南

## 铁律
1. **协议工件**（schemas/、docs/ledger.format.md、conformance/）是产品本体：
   改动必须同步参考实现与测试套件，三者不一致 = bug。
2. **账本格式只增不破**：`agentos.ledger.v0` 已发布的事件字段冻结，新字段加新事件类型。
3. **安全边界要诚实**：每个后端"挡什么/不挡什么"必须在 README 与代码注释中保持一致，
   账本如实记录实际使用的 enforcement 级别。
4. **校验器只能由人签名安装**（capability.schema.json 的 kind=human 规则）。

## 提交
- `python3 -m unittest discover tests` 必须全绿
- 演示命令行内注释是合法的（CLI 会忽略 `#` 开头参数）

## 安全披露
发现安全问题请勿公开 issue，联系仓库所有者私下披露。
