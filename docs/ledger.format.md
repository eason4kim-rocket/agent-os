# AgentOS Ledger Format v0

> Protocol asset P3. Goal: an agent-action ledger recorded by any conforming implementation
> can be independently verified by any conforming tool.
> Reference implementation: `harness/ledger.py` (~60 lines, stdlib only).

## Design principles

1. **Append-only**: entries are never modified or deleted; rolling back the working
   directory never touches the ledger
2. **Self-verifying**: each entry embeds the hash of the previous one — any single
   tampered byte breaks the whole chain
3. **Dependency-free**: UTF-8 text file, one JSON object per line; sha256 is the only
   cryptographic requirement
4. **Ledger lives in protected state**: implementations MUST place the ledger outside
   the task working directory (the working directory is subject to rollback; the ledger is not)

## Line format

One JSON object per line, serialized in canonical form (sorted keys, no whitespace):

```json
{
  "schema": "agentos.ledger.v0",
  "seq": 8,
  "ts": "2026-10-26T11:03:14.449+08:00",
  "run": "20261026-a1b2c3d4",
  "event": "tool.denied",
  "detail": {
    "tool": "read_file",
    "target": "../secret.txt",
    "reason": "path outside allowed roots: ..."
  },
  "prev": "0000...0000",
  "hash": "9f1c...e7"
}
```

| Field | Meaning |
| --- | --- |
| `seq` | Monotonic line number starting at 1 |
| `ts` | RFC3339 timestamp with timezone |
| `run` | Run identifier (shared by all events of one run) |
| `event` | Event type (see table below) |
| `detail` | Event payload (free-form; per-event schemas specified separately) |
| `prev` | `hash` of the previous line; `"0" * 64` for the first line |
| `hash` | `sha256( prev + canonical(entry_without_hash) )`, lowercase hex |

## Standard event types (v0)

| event | meaning |
| --- | --- |
| `run.start` | Run begins; detail MUST include the policy snapshot and the actual enforcement level |
| `snapshot.created` / `snapshot.restored` | Snapshot taken / restored |
| `tool.call` | Model initiated a tool call |
| `tool.result` | Tool finished (includes exit code) |
| `tool.denied` | Policy denial (MUST include reason) |
| `tool.finish` | Agent submitted its acceptance report |
| `run.end` | Run ended (how: finish / model_final_text / budget_exhausted) |

## Verification

```
For every line: sha256(prev + canonical(line_without_hash)) MUST equal hash,
and prev MUST equal the previous line's hash.
Any mismatch → the ledger is suspect; everything from that line on is untrusted.
```

## v1 outlook (Phase 1)

- The first event of each run carries the agent identity (ed25519 public key) and a
  **signature** over the policy digest
- `tool.result` records only sha256 for large payloads; content goes to a
  content-addressed blob store
- Ledger sharding: one file per run, chain-head hash carried across files

---

> Chinese-language documentation is planned under `docs/zh/` (to be added with the Phase 1 docs site).
> Canonical language for protocol artifacts is **English**; local demo materials may stay Chinese.
