# AgentOS 运行时的 Nix 打包（阶段 2 发行版实验 / NixOS 路线）
#
# 用法（VM 内，nix 单用户安装；需先在 VM 里 cargo build --release --bins）：
#   nix-build nix/agentos.nix
#   ./result/bin/agentd --version
#
# 已知局限（诚实记录）：
#   - 打包的是【预构建产物】（本机构建后拷入），不是纯 nix 源码构建。
#     纯源码路线（rustPlatform.buildRustPackage + cargoLock）在 nixpkgs 24.05
#     的 rust 1.79 上解析 lock v4 失败，已记录；升级 nixpkgs 的 rust 版本后
#     可切回纯源码路线。
#   - 二进制动态链接 Ubuntu 的 glibc，在 NixOS 上需 patchelf/autoPatchelfHook
#     或改用构建机一致的 nixpkgs stdenv.mkDerivation 源码构建。本表达式用于
#     "产物打包 + 服务模块"的实验验证。

{
  pkgs ? import <nixpkgs> {},
}:

pkgs.stdenv.mkDerivation {
  pname = "agentos-runtime";
  version = "0.1.0";

  # 预构建产物目录（宿主 cargo build --release --bins 的输出）
  src = ../rust/target/release;

  dontBuild = true;
  dontFixup = true;

  installPhase = ''
    runHook preInstall
    install -d $out/bin
    for b in agentd agentctl llrun ledger-verify; do
      install -m 0755 $b $out/bin/$b
    done
    runHook postInstall
  '';

  meta = with pkgs.lib; {
    description = "AgentOS runtime — policy-enforced exec + signed ledger for AI agents";
    homepage = "https://github.com/eason4kim-rocket/agent-os";
    license = licenses.mit;
    platforms = platforms.linux;
    mainProgram = "agentd";
  };
}
