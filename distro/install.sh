#!/bin/bash
# AgentOS Linux 运行时安装器（阶段2 发行版实验）
# 用法: ./install.sh --source <仓库根> [--prefix /usr/local] [--user <服务运行用户>] [--workdir <DIR>]
# 注意：
#   1. 不要用 sudo 运行本脚本（构建需用户工具链）；脚本内部会在安装步骤自动提权
#   2. 请在无 AI agent 会话的独立终端运行（避免 sudo 凭据窗口与 agent 共享）
#   3. 结束时自动 sudo -k 清除凭据缓存
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
id -u "$RUN_USER" 2>/dev/null | grep -qv "^0$" || { echo "服务运行用户不能是 root"; exit 2; }
[[ $EUID -ne 0 ]] || { echo "请勿以 root 运行本脚本（服务运行用户用 --user 指定）"; exit 2; }
command -v python3 >/dev/null || { echo "需要 python3"; exit 2; }
[[ -f "$HOME/.cargo/env" ]] && source "$HOME/.cargo/env"
command -v cargo >/dev/null || { echo "需要 cargo（rust 工具链）"; exit 2; }

# workdir 必填（systemd ReadWritePaths 需要绝对已存在路径；同时防 unit 注入，审计 H-1）
if [[ -z "$WORKDIR" ]]; then
  echo "需要 --workdir <绝对路径>（任务的读写区，会被加入写白名单）"; exit 2
fi
[[ "$WORKDIR" = /* ]] || { echo "workdir 必须是绝对路径: $WORKDIR"; exit 2; }
[[ "$WORKDIR" == *$'\n'* || "$WORKDIR" == *$'\r'* ]] && { echo "workdir 含换行"; exit 2; }
[[ "$WORKDIR" =~ [[:cntrl:]] ]] && { echo "workdir 含控制字符"; exit 2; }

BIN="$PREFIX/bin"
STATE="/var/lib/agentos"
SOCKET="/run/agentos/agentd.sock"
UNIT="/etc/systemd/system/agentos-agentd.service"

echo "== [1/5] 编译（release bins，用户工具链） =="
( cd "$SOURCE/rust" && cargo build --locked --release --bins )

echo "== [1b/5] 产物 sha256（请留存比对） =="
for b in agentd agentctl llrun ledger-verify; do
  sha256sum "$SOURCE/rust/target/release/$b"
done

echo "== [2/5] 安装二进制 → $BIN =="
for b in agentd agentctl llrun ledger-verify; do
  sudo install -m 0755 "$SOURCE/rust/target/release/$b" "$BIN/$b"
done

echo "== [3/5] 状态目录 + socket 目录 + 策略 =="
sudo install -d -m 0750 -o "$RUN_USER" "$STATE"
sudo install -d -m 0750 -o "$RUN_USER" "$STATE/policies"
# socket 目录：namespace 挂载前必须已存在；tmpfiles.d 保证重启后自动重建
RUN_GROUP="$(id -gn "$RUN_USER")"
sudo install -d -m 0700 -o "$RUN_USER" -g "$RUN_GROUP" /run/agentos
echo "d /run/agentos 0700 $RUN_USER $RUN_GROUP -" | sudo tee /etc/tmpfiles.d/agentos.conf >/dev/null
if [[ -n "$WORKDIR" ]]; then
  sudo install -d -m 0750 -o "$RUN_USER" "$WORKDIR"
fi
POLICY_FILE="$STATE/policies/default.json"
if [[ -f "$POLICY_FILE" ]]; then
  # 已有策略：不覆盖；若安装时指定了 workdir 且与策略内不一致 → 明确提示（M-3）
  if [[ -n "$WORKDIR" ]] && grep -q "\"workdir\"" "$POLICY_FILE" \
     && ! grep -q "\"workdir\": *\"$WORKDIR\"" "$POLICY_FILE"; then
    echo "提示: 策略内 workdir 与 --workdir 不一致。改策略 workdir 后必须同步"
    echo "      更新 unit 的 ReadWritePaths 并 daemon-reload + restart（见 unit 头注）。"
  fi
else
  sudo install -m 0644 -o "$RUN_USER" "$SOURCE/policies/default.example.json" "$POLICY_FILE"
  if [[ -n "$WORKDIR" ]]; then
    sudo python3 - "$POLICY_FILE" "$WORKDIR" <<'PY'
import json, sys
p, w = sys.argv[1], sys.argv[2]
d = json.load(open(p)); d["workdir"] = w
json.dump(d, open(p, "w"), ensure_ascii=False, indent=1)
PY
    sudo chown "$RUN_USER" "$POLICY_FILE"
  else
    echo "警告: 未传 --workdir，策略内 workdir 为示例占位值——exec 会失败（rc=127）。"
    echo "      请编辑 $POLICY_FILE 的 workdir，并同步 unit 的 ReadWritePaths。"
  fi
fi

echo "== [4/5] 安装 systemd 服务 =="
sudo install -m 0644 "$SOURCE/distro/agentos-agentd.service" "$UNIT"
sudo python3 - "$UNIT" "$RUN_USER" "$BIN" "$STATE" "$WORKDIR" "$SOCKET" <<'PY'
# H-1 修复：模板渲染用 python 逐键替换（不用 sed，杜绝 workdir 注入 unit）
import sys
unit_path, user, bin_dir, state, work, sock = sys.argv[1:7]
work_rw = work
s = open(unit_path, encoding="utf-8").read()
for k, v in {"@USER@": user, "@BIN@": bin_dir, "@STATE@": state,
             "@WORK@": work_rw, "@SOCKET@": sock}.items():
    s = s.replace(k, v)
bad = [t for t in ("@USER@", "@BIN@", "@STATE@", "@WORK@", "@SOCKET@") if t in s]
assert not bad, f"存在未替换的占位符: {bad}"
open(unit_path, "w", encoding="utf-8").write(s)
PY
sudo systemctl daemon-reload

echo "== [5/5] 启动与验证 =="
sudo systemctl enable --now agentos-agentd.service
sleep 1
if ! sudo systemctl is-active --quiet agentos-agentd.service; then
  echo "服务未启动！排查: journalctl -u agentos-agentd -n 20"
  exit 1
fi
systemctl --no-pager --lines=3 status agentos-agentd.service || true
sudo -k

cat <<TIP

安装完成 ✅（以下命令以服务运行用户身份执行）
  冒烟:   $BIN/agentctl --socket $SOCKET status
  执行:   $BIN/agentctl --socket $SOCKET exec --policy default -- <命令...>
  账本:   $STATE/ledger.jsonl（签名哈希链）  策略: $STATE/policies/
  日志:   journalctl -u agentos-agentd
TIP
