#!/bin/bash
# AgentOS Linux 运行时安装器（阶段2 发行版实验）
# 用法: ./install.sh --source <仓库根> [--prefix /usr/local] [--user <服务运行用户>] [--workdir <DIR>]
# 注意：不要用 sudo 运行本脚本（构建需用户工具链）；脚本内部会在安装步骤自动提权。
set -euo pipefail

SOURCE="" ; PREFIX="/usr/local" ; RUN_USER="$(id -un)" ; WORKDIR=""
SUDO=""; [[ $(id -u) -ne 0 ]] && SUDO="sudo"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --source)  SOURCE="$2"; shift 2 ;;
    --prefix)  PREFIX="$2"; shift 2 ;;
    --user)    RUN_USER="$2"; shift 2 ;;
    --workdir) WORKDIR="$2"; shift 2 ;;
    *) echo "未知参数: $1"; exit 2 ;;
  esac
done
[[ -n "$SOURCE" ]] || { echo "需要 --source <仓库根>"; exit 2; }

BIN="$PREFIX/bin"
STATE="/var/lib/agentos"
SOCKET="/run/agentos/agentd.sock"
UNIT="/etc/systemd/system/agentos-agentd.service"

echo "== [1/5] 编译（release bins） =="
( cd "$SOURCE/rust" && cargo build --locked --release --bins )

echo "== [2/5] 安装二进制 → $BIN =="
sudo install -m 0755 "$SOURCE/rust/target/release/agentd"        "$BIN/agentd"
sudo install -m 0755 "$SOURCE/rust/target/release/agentctl"      "$BIN/agentctl"
sudo install -m 0755 "$SOURCE/rust/target/release/llrun"         "$BIN/llrun"
sudo install -m 0755 "$SOURCE/rust/target/release/ledger-verify" "$BIN/ledger-verify"

echo "== [3/5] 状态目录 + 示例策略 =="
sudo install -d -m 0750 -o "$RUN_USER" "$STATE"
sudo install -d -m 0750 -o "$RUN_USER" "$STATE/policies"
if [[ ! -f "$STATE/policies/default.json" ]]; then
  sudo install -m 0644 -o "$RUN_USER" "$SOURCE/policies/default.example.json" "$STATE/policies/default.json"
  # 示例的 workdir 是占位：指向 --workdir 或提醒手改
  if [[ -n "$WORKDIR" ]]; then
    python3 - "$STATE/policies/default.json" "$WORKDIR" <<'PY'
import json, sys
p = sys.argv[1]; w = sys.argv[2]
d = json.load(open(p)); d["workdir"] = w
json.dump(d, open(p, "w"), ensure_ascii=False, indent=1)
PY
  fi
fi

echo "== [4/5] 安装 systemd 服务 =="
sudo install -m 0644 "$SOURCE/distro/agentos-agentd.service" "$UNIT"
sudo sed -i "s|@USER@|$RUN_USER|g; s|@BIN@|$BIN|g; s|@STATE@|$STATE|g; s|@SOCKET@|/run/agentos/agentd.sock|g; s|@WORK@|${WORKDIR:-$STATE}|g" "$UNIT"
sudo systemctl daemon-reload

echo "== [5/5] 启动 =="
sudo systemctl enable --now agentos-agentd.service
sleep 1
systemctl --no-pager --lines=3 status agentos-agentd.service || true

cat <<TIP

安装完成。
  冒烟:   $BIN/agentctl --socket $SOCKET status          （以服务用户身份运行）
  执行:   $BIN/agentctl --socket $SOCKET exec --policy default -- <命令...>
  账本:   $STATE/ledger.jsonl（签名哈希链）
  策略:   $STATE/policies/（编辑后 systemctl restart agentos-agentd）
  日志:   journalctl -u agentos-agentd
TIP
