# Integrity operator workflow

Integrity controls are additive to the existing event verification commands. The API and browser require the configured RAVEN admin credential; set it with `--admin-token` or `RAVEN_ADMIN_TOKEN`. The browser keeps a credential in memory only.

```sh
export RAVEN_ADMIN_TOKEN='your-local-admin-token'
raven integrity status
raven integrity verify --type fast
raven integrity verify --type deep --wait
raven integrity verify --type ledger --wait
```

`verify` returns the durable run ID immediately. `--wait` polls until completion (30 seconds by default); exit status is 0 for a pass, 1 for an integrity mismatch, and 2 for unavailable, incomplete, or timed-out work. Set `--wait-timeout 2m` to extend the wait. `--ui http://127.0.0.1:9090` selects another management API address.

Open the console's **Integrity** tab for local/witness/chain heads, audit freshness, backlog, audit progress, and proof inspection by evidence sequence. A pending proof means the batch has not been witnessed; a witness signature alone is not a chain confirmation.

The management API contract is [`api/integrity.openapi.yaml`](api/integrity.openapi.yaml). All four `/api/v1/integrity/*` routes require management admin authentication. To enable witness status, ledger audit scheduling, and witness proof details, set both `RAVEN_WITNESS_URL` and the separate `RAVEN_WITNESS_ADMIN_TOKEN` for the RAVEN process. The witness producer token is never reused for these admin operations. Without a witness, its heads remain zero and ledger scheduling returns `503`.

Integrity remains opt-in. If it is disabled, status is still readable and reports `enabled: false`; starting an audit returns `409`. Existing `-verify` and `-verify-event` command flags are unchanged.
