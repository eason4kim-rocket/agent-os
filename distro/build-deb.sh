#!/bin/bash
# AgentOS deb 打包器：在目标 Linux 机器上构建 .deb（需要 cargo + dpkg-deb + python3）
# 用法: ./build-deb.sh [--source <仓库根>] [--out <目录>]
set -euo pipefail

SOURCE="$(pwd)"
OUT="$(pwd)/distro/out"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --source) SOURCE="$2"; shift 2 ;;
    --out)    OUT="$2"; shift 2 ;;
    *) echo "未知参数: $1"; exit 2 ;;
  esac
done
command -v cargo >/dev/null || { echo "需要 cargo（先 source $HOME/.cargo/env）"; exit 2; }
command -v dpkg-deb >/dev/null || { echo "需要 dpkg-deb"; exit 2; }
command -v python3 >/dev/null || { echo "需要 python3"; exit 2; }

# 版本单一来源：rust/Cargo.toml（避免三处硬编码漂移）
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$SOURCE/rust/Cargo.toml" | head -1)"
ARCH="$(dpkg --print-architecture)"   # H-1：按构建机构架渲染，不再硬编码 arm64
PKG="agentos-runtime_${VERSION}_${ARCH}"
STAGE="$(mktemp -d)/${PKG}"

echo "== [1/3] cargo release 构建 =="
( cd "$SOURCE/rust" && cargo build --locked --release --bins )

echo "== [2/3] 组装包树 =="
install -d "$STAGE/DEBIAN" \
  "$STAGE/usr/bin" \
  "$STAGE/usr/lib/tmpfiles.d" \
  "$STAGE/usr/lib/systemd/system" \
  "$STAGE/usr/share/agentos/policies" \
  "$STAGE/var/lib/agentos/policies" \
  "$STAGE/var/lib/agentos/work"

for f in control postinst prerm postrm; do
  install -m 0644 "$SOURCE/distro/deb/$f" "$STAGE/DEBIAN/$f"
done
chmod 0755 "$STAGE/DEBIAN/postinst" "$STAGE/DEBIAN/prerm" "$STAGE/DEBIAN/postrm"
# H-1 修复：control 的 @ARCH@/@VERSION@ 按构建机与 Cargo.toml 渲染，
# 杜绝"文件名 amd64 / 声明 arm64"的静默坏包。渲染必须在拷贝之后。
python3 - "$SOURCE/distro/deb/control" "$STAGE/DEBIAN/control" "$ARCH" "$VERSION" <<'PY'
import sys
src, dst, arch, ver = sys.argv[1:5]
s = open(src, encoding="utf-8").read()
s = s.replace("@ARCH@", arch).replace("@VERSION@", ver)
open(dst, "w", encoding="utf-8").write(s)
PY
install -m 0755 "$SOURCE/rust/target/release/agentd"        "$STAGE/usr/bin/agentd"
install -m 0755 "$SOURCE/rust/target/release/agentctl"      "$STAGE/usr/bin/agentctl"
install -m 0755 "$SOURCE/rust/target/release/llrun"         "$STAGE/usr/bin/llrun"
install -m 0755 "$SOURCE/rust/target/release/ledger-verify" "$STAGE/usr/bin/ledger-verify"
install -m 0644 "$SOURCE/distro/deb/agentos-agentd.service" "$STAGE/usr/lib/systemd/system/agentos-agentd.service"
install -m 0644 "$SOURCE/distro/deb/tmpfiles.conf"          "$STAGE/usr/lib/tmpfiles.d/agentos.conf"
install -m 0644 "$SOURCE/policies/default.example.json"     "$STAGE/usr/share/agentos/policies/default.json"

echo "== [3/3] dpkg-deb 构建 =="
mkdir -p "$OUT"
rm -f "$OUT/$PKG.deb"
dpkg-deb --build --root-owner-group "$STAGE" "$OUT/$PKG.deb"
echo "完成: $OUT/$PKG.deb"
dpkg-deb --info "$OUT/$PKG.deb" | head -12
