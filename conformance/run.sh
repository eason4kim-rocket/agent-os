#!/bin/sh
# AgentOS 一致性运行器：Python 套件 + Rust 套件（含 conformance 案例）+ 双向互操作。
# 任何一项失败即整体失败。CI 与本地均以此为准。
set -eu
cd "$(dirname "$0")/.."

echo "== [1/3] Python 回归 =="
python3 -m unittest discover tests -v 2>&1 | tail -3

echo "== [2/3] Rust 套件（含 D 系列 conformance 案例） =="
(cd rust && cargo test --locked 2>&1 | grep -E "test result" )

echo "== [3/3] 双向互操作 =="
(cd rust && cargo test --locked interop 2>&1 | grep -E "test result")
L=$(find "${TMPDIR:-/tmp}" /tmp -maxdepth 3 -name "ledger.jsonl" -path "*agentos-rs-ledger*" 2>/dev/null | tail -1)
if [ -n "$L" ]; then
  python3 - "$L" <<'PYEOF'
import json, os, sys
sys.path.insert(0, '.')
from harness.ledger import Ledger
from harness import ed25519
from pathlib import Path
led = Ledger(Path(sys.argv[1]))
d = led.entries[-1]['detail']
assert ed25519.checkvalid(bytes.fromhex(d['agent_sig']), bytes.fromhex(d['signed']), bytes.fromhex(d['agent_pubkey']))
ok, n, bad = led.verify()
assert ok, bad
print(f'I2: Python 验 Rust 账本 {n} 条 ✅')
PYEOF
else
  echo "I2: 跳过（未找到 Rust 写的账本——先跑 cargo test interop）"
fi

echo "conformance: 全部通过 ✅"
