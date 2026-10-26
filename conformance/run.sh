#!/bin/bash
# AgentOS 一致性运行器：任何一项失败即整体失败（pipefail 防管道吞错）。
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== [1/4] Python 回归 =="
python3 -m unittest discover tests -v 2>&1 | tail -5

echo "== [2/4] Rust 套件（含 D 系列 conformance 案例） =="
(cd rust && cargo test --locked)

echo "== [3/4] 双向互操作 =="
(cd rust && cargo test --locked --test interop)
L=$( { find "${TMPDIR:-/tmp}" -maxdepth 3 -name "ledger.jsonl" -path "*agentos-rs-ledger*" 2>/dev/null || true; } | tail -1 )
test -n "$L" || { echo "I2 失败：未找到 Rust 写的账本"; exit 1; }
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

echo "== [4/4] Rust bin 验签口径 =="
(cd rust && cargo run --locked --quiet --bin ledger-verify -- "$L")

echo "conformance: 全部通过 ✅"
