# NixOS 打包实验（阶段 2 / NixOS 路线）

## 内容

- `agentos.nix` — 运行时打包表达式（mkDerivation 打包预构建 bins）
- `agentos-module.nix` — NixOS 服务模块（systemd 加固矩阵与 deb unit 同源）

## 用法（VM 实验环境）

```sh
# VM 内先构建二进制
cd ~/agentos-src/rust && cargo build --release --bins
# nix 打包（预构建产物路线）
nix-build nix/agentos.nix
./result/bin/agentctl --socket /var/lib/agentos/agentd.sock status
```

## 已知局限（诚实记录）

1. **产物打包，非纯源码构建**：rustPlatform.buildRustPackage + cargoLock 在
   nixpkgs 24.05（rust 1.79）上解析 lock v4 失败。升级 nixpkgs rust 后可切换。
2. **glibc 依赖**：二进制动态链接 Ubuntu glibc；NixOS 上需 autoPatchelfHook
   或改用 nixpkgs stdenv 构建同源二进制。
3. **完整 NixOS VM 测试未做**：module 通过 nix-instantiate --parse 语法验证，
   systemd 语义与 deb unit 同源但未在真 NixOS 上 boot 验证。

## 二进制/服务模块对照

| 能力 | deb/install.sh | NixOS module |
|---|---|---|
| 加固矩阵 | ProtectSystem=strict 等全套 | 同源（NixOS 语义） |
| socket | /run/agentos → 改 /var/lib/agentos/agentd.sock | /run/agentos（RuntimeDirectory） |
| 策略 | /var/lib/agentos/policies root:agentos 0640 | StateDirectory + 同布局 |
| SystemCallFilter | 已移除（255 @system-service EACCES 拒启动） | 保留（NixOS 无此问题的前提下按同集合配置，待实测） |
