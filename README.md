# AgentOS

> An open agent-capability protocol and its reference implementation:
> **rules for AI agents** — a pluggable cage (sandbox: Landlock / bwrap / container /
> software), snapshots (rollback), a tamper-evident ledger (signed hash chain),
> and independent acceptance (verifiers).

One policy declaration (`agentos.policy.v0`) compiles to four enforcement
backends. Every run is recorded to the ledger, signed with the agent's
ed25519 identity, and anchored against replay. See [PLAN.md](PLAN.md) for the
roadmap and [RESEARCH.md](RESEARCH.md) for the 2026 landscape survey.

**Status**: Phase 1 complete (protocol v0 drafts + four backends verified on
macOS and native Ubuntu), Phase 2 started (`agentd` resident runtime in
`rust/`). Research preview — formats may evolve.

## Quick start (no API key needed)

```sh
./bin/agentos run --task tasks/demo-organize.md --mock
./bin/agentos run --task tasks/demo-organize.md --backend landlock --verifier verifiers/demo_organization.py
                              # kernel-enforced Landlock + independent acceptance
./bin/agentos explain         # translate the policy into a human confirmation card
./bin/agentos verify          # verify the ledger hash chain + anchors + signatures
./bin/agentos snapshots       # list snapshots (latest is the rollback default)
./bin/agentos rollback        # restore the working directory from the snapshot
```

## Real-model mode

```sh
export AGENTOS_API_KEY=your_zai_key           # or a bigmodel key
export AGENTOS_API_BASE=https://api.z.ai/api/paas/v4   # optional, Z.ai default
export AGENTOS_MODEL=glm-4.6                  # optional
./bin/agentos run --task tasks/demo-organize.md
```

## Enforcement backends (pluggable, auto-selected per run)

| Backend | Enforcement | Status |
|---|---|---|
| `landlock` | **kernel-native**: our [llandlock](sandbox/llandlock.c) (~100 lines of C) compiles the policy; runs on a Docker Desktop named volume (VM-native ext4) on macOS, bare on native Linux | ✅ verified (macOS container + colima Ubuntu 6.8, kernel-level denials demoed) |
| `srt` | **kernel-native**: Anthropic sandbox-runtime (Linux=bwrap+Landlock) | ✅ verified end-to-end on Ubuntu 24.04. Deps: `pip install sandbox-runtime` + ripgrep/bubblewrap/socat; Ubuntu 24.04 needs `sysctl kernel.apparmor_restrict_unprivileged_userns=0`; settings JSON is camelCase |
| `docker` | namespace/cgroups container | ✅ verified |
| `plain` | software-level policy checks (incl. run_command operand validation) | always available (macOS 27 removed Seatbelt) |

> The ledger honestly records the enforcement level actually used for every run.
> Known boundaries (honest, recorded in every ledger entry): `plain` does not
> resolve symlinks in command operands and does not isolate the network (use
> `landlock`/`srt`/`docker` backends for adversarial workloads). `landlock`
> enforces **TCP bind/connect deny-all** when the kernel exposes Landlock
> ABI >= 4 (UDP, ICMP and unix sockets are outside this layer — pair with a
> network-less container for full isolation), and reports
> `network_enforced: false` honestly otherwise. All backends refuse policies
> with `network: true` until a network-enforcing backend exists (fail-closed).
> Daemon sockets are 0600 and peer-uid-checked (fail-closed on credential
> errors).

## Rust core (`rust/`)

`agentos-core` is the Phase-2 foundation: the same protocol, compiled natively.

- `policy.rs` — parse + software-level validation for `agentos.policy.v0`
- `ledger.rs` — chain/anchor/signature verification and append for
  `agentos.ledger.v0`
- `landlock.rs` + `llrun` — the Rust port of `llandlock.c` (Linux-only)

**Bidirectional interop is tested**: Rust verifies the Python-generated signed
ledger fixture; Python verifies the Rust-written ledger (dalek signatures,
canonical JSON, anchors). CI runs both directions.

```sh
cd rust && cargo test
cargo run --bin ledger-verify -- <ledger.jsonl> [ledger.anchor]
```

## agentd (Phase 2, in progress)

A resident runtime speaking newline-delimited JSON over a Unix socket — the
"kernel" that executes commands under a policy while the ledger records
everything.

```sh
cd rust
cargo run --bin agentd -- --state-dir /tmp/agentos-state --socket /tmp/agentos.sock
# another terminal
cargo run --bin agentctl -- --socket /tmp/agentos.sock status
```

## Protocol artifacts

- [`schemas/policy.schema.json`](schemas/policy.schema.json) — P1 unified policy format
- [`docs/ledger.format.md`](docs/ledger.format.md) — P3 hash-chain ledger format
- [`schemas/capability.schema.json`](schemas/capability.schema.json) — P2 identity/capability model
- [`docs/AUDIT-2026-10-26.md`](docs/AUDIT-2026-10-26.md) — red-team audit and fix log

## Repository layout

- `harness/` Python reference implementation (stdlib only)
- `rust/` Rust core (`agentos-core` + `agentd`/`agentctl`/`llrun`/`ledger-verify` bins)
- `sandbox/` llandlock.c + sandbox image
- `tasks/` task briefs ｜ `workspace/demo` demo working directory
- Run state lives in `workspace/.demo.agentos/` (ledger + snapshots — outside the
  working directory on purpose: rollback must never burn the ledger)

## License

MIT. Security issues: see [CONTRIBUTING.md](CONTRIBUTING.md) for private disclosure.
