# RAVEN Analysis configuration

Analysis inventory and rules are local YAML resources. The `examples/` directory is reference material and is **not loaded automatically**. To try it, copy files into the active directories:

```sh
mkdir -p analysis/devices analysis/rules
cp analysis/examples/devices/*.yaml analysis/devices/
cp analysis/examples/rules/*.yaml analysis/rules/
raven analysis validate --analysis-dir analysis
raven -analysis-dir analysis
```

The runtime defaults to `-analysis-dir analysis`. A missing or empty directory leaves Analysis disabled. Use `-analysis-dir none` to disable it explicitly. Invalid files are reported as warnings and disable Analysis while the normal Raven pipeline continues. A config reload must validate completely before it replaces the active immutable snapshot; for the CLI, restart Raven after editing files.

Use schema contracts at `schemas/device.schema.json` and `schemas/analysis-rule.schema.json`. Runtime validation is stricter than the JSON schemas where cross-file checks are needed: duplicate IDs and aliases, heartbeat references, durations, source categories, and compiled RE2 patterns are validated as one snapshot.

The v1 rule language is intentionally small. Field conditions in one rule are ANDed; use another rule for an alternative. `eq`, `in`, `gt`, `gte`, `lt`, `lte`, `contains`, and Go RE2 `regex` are accepted. Expressions only refer to normalized fields; raw payload paths and arbitrary scripts are rejected.

## Read-only telemetry API

When Analysis has a valid non-empty inventory, the UI management API exposes these read-only endpoints (default address `http://127.0.0.1:9090`):

```text
GET /api/v1/analysis/status
GET /api/v1/analysis/devices?limit=100&offset=0
GET /api/v1/analysis/sources?resolution=unassigned&limit=100&offset=0
```

The status response reports configuration/worker state (`disabled`, `running`, `delayed`, `degraded`, or `invalid_configuration`), checkpoint, backlog count and oldest age. Device pages include configured devices even when they have never been observed, state and explanation, last received/normalized/quarantined/matching-heartbeat timestamps and ages, active maintenance deadline, lifetime counters, five-minute rates, normalization ratio (`normalized / (normalized + quarantined)`), and identity confidence. `limit` is 1–500; `offset` is 0–1,000,000,000. The sources endpoint defaults to both `unknown` and `ambiguous`; `resolution=unknown` and `resolution=ambiguous` filter them separately. All routes are GET-only and do not mutate analysis or ingestion state.

The device status rules are conservative:

- `disabled` means the inventory disables the device, or its configured heartbeat is inside a maintenance window.
- `green` means an event-only device has a successful normalized event inside its configured `freshnessAfter`, or a heartbeat event actually matched its configured heartbeat rule within the warning deadline.
- `yellow` means its latest completed event was quarantined, or a matching heartbeat passed its warning deadline.
- `red` means a configured, matching heartbeat passed its critical deadline.
- `unknown` means the device has no valid health signal yet, has no freshness boundary, or its event-only signal is stale. Silence from an event-only device never means it is down.

The v9 migration backfills lifetime counters from existing A-02 observations; heartbeat times and five-minute rates start accumulating after the upgrade because earlier records did not store matched-heartbeat signals or rate buckets. During active processing, one-minute rate buckets are asynchronously retained for about one hour. A-03 exposes telemetry only: event findings/rule lifecycle and a dedicated analysis dashboard are later phases. Existing `/api/v1/sources`, stats, health, and event JSON contracts are unchanged.

A sender-IP-only alias has weak identity confidence; hostname aliases are strong. Exact alias conflicts are rejected while loading inventory.
