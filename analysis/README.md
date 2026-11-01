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

Preview an event rule against one normalized-event JSON file without opening or writing the RAVEN database:

```sh
raven analysis test -rule interface-down -sample analysis/examples/samples/interface-down.json
```

An event rule evaluates only the normalized OCSF fields (plus the normalized source category filter). All `match.fields` conditions must match. A match opens or updates a finding using the rule's separate finding severity/state/title; it does not change the OCSF event. All `clear` conditions must match to start the configured `clearAfter` hold-down. The same rule and owner have a stable finding ID across rule versions. Resolved findings remain available in the history; replayed observations do not increment or append a second transition.

## Rolling and missing-report rules

`window` rules count normalized events in a rolling interval. The `match.fields` conditions select counted events; optional `sourceCategory` narrows them, and `groupBy` separates findings by normalized fields such as `src_endpoint.ip`. The latest `consecutive` window observations must also match (default `1`). `finding.for` delays opening until that latest consecutive streak has lasted long enough. `countAtLeast` opens or updates; `clearBelow` starts recovery only after the count drops to that lower threshold. Counts between the two thresholds preserve the current finding state. A `clearAfter` hold-down controls resolution.

To count a severity, match its normalized severity field (for example `severity_id`) in the same rule; it uses the same rolling event counter.

```yaml
spec:
  kind: window
  match:
    fields:
      - {path: activity_name, op: eq, value: authentication_failure}
  window:
    signal: event_count
    duration: 5m
    groupBy: [src_endpoint.ip]
    countAtLeast: 5
    clearBelow: 2
    consecutive: 2
  finding:
    severity: high
    state: yellow
    title: Repeated authentication failures
    for: 30s
    clearAfter: 1m
```

`quality` rules calculate the recent quarantine ratio from completed normalized and quarantined outcomes for each resolved owner (device when matched, source identity otherwise). They do not accept a source-category filter or `groupBy`, since quarantined records have no normalized category. `ratioAtLeast` triggers and `clearRatio` begins recovery; values between those thresholds retain the current state. See [`examples/rules/repeated-auth-failures.yaml`](examples/rules/repeated-auth-failures.yaml) and [`examples/rules/quarantine-ratio.yaml`](examples/rules/quarantine-ratio.yaml).

Heartbeat missing-report findings use a device's configured `reporting.warningAfter` and `criticalAfter` deadlines plus its named heartbeat rule. A shared worker sweep checks devices in bounded pages; there is no goroutine per device. An active maintenance window suppresses the deadline finding and resolves an existing one; stale devices are evaluated again when maintenance ends. Devices without a configured heartbeat are never marked down from silence alone.

Rolling windows use Raven's durable observation receive/processing time and observation ID as a stable tie-breaker. Source-provided timestamps do not reorder or age these rules; late normalization is evaluated when its outcome reaches the analysis worker. This avoids letting a device's incorrect clock distort alert windows. The current pipeline does not estimate source clock offset, so source-clock skew itself is not reported as a separate metric. Window samples are indexed and retained for 30 days, then pruned in bounded batches during evaluation; a long quiet period can therefore require a few worker pages before all old groups are revisited.

## Read-only telemetry API

When Analysis has a valid non-empty inventory, the UI management API exposes these read-only endpoints (default address `http://127.0.0.1:9090`):

```text
GET /api/v1/analysis/status
GET /api/v1/analysis/devices?state=yellow&category=network_device&site=hq&device=edge&window=24h&limit=100&offset=0
GET /api/v1/analysis/sources?resolution=unassigned&limit=100&offset=0
GET /api/v1/analysis/findings?status=open&rule_id=interface-down&device=edge-router-01&window=24h&limit=100&offset=0
GET /api/v1/analysis/findings/{finding_id}?limit=100&offset=0
```

The status response reports configuration/worker state (`disabled`, `running`, `delayed`, `degraded`, or `invalid_configuration`), checkpoint, backlog count and oldest age. Device pages include configured devices even when they have never been observed, state and explanation, inventory labels, last received/normalized/quarantined/matching-heartbeat timestamps, active finding count, lifetime counters, five-minute rates, normalization ratio (`normalized / (normalized + quarantined)`), and identity confidence. Device filters support exact `state` and `category`, case-insensitive partial `site` matching against `labels.site`, case-insensitive partial `device` matching against ID/display name, and a last-activity `window` of `1h`, `24h`, or `7d`. Finding filters support `status` (`open`, `clearing`, `resolved`, or `all`), exact `rule_id`, exact device ID, and `window` based on last update. `limit` is 1–500; `offset` is 0–1,000,000,000. The sources endpoint defaults to both `unknown` and `ambiguous`; `resolution=unknown` and `resolution=ambiguous` filter them separately. All routes are GET-only and do not mutate analysis or ingestion state.

The device status rules are conservative:

- `disabled` means the inventory disables the device, or its configured heartbeat is inside a maintenance window.
- `green` means an event-only device has a successful normalized event inside its configured `freshnessAfter`, or a heartbeat event actually matched its configured heartbeat rule within the warning deadline.
- `yellow` means its latest completed event was quarantined, or a matching heartbeat passed its warning deadline.
- `red` means a configured, matching heartbeat passed its critical deadline.
- `unknown` means the device has no valid health signal yet, has no freshness boundary, or its event-only signal is stale. Silence from an event-only device never means it is down.

The v9 migration backfills lifetime counters from existing A-02 observations; heartbeat times and five-minute rates start accumulating after the upgrade because earlier records did not store matched-heartbeat signals or rate buckets. During active processing, one-minute rate buckets are retained for about one hour. Schema v11 adds current findings plus append-only transition history; schema v13 adds a finding/device index for dashboard counts. The worker commits findings with identity projection/checkpoint progress. The read-only dashboard links to event trace/verification and raw evidence; quarantined evidence opens the existing quarantine queue. Existing `/api/v1/sources`, stats, health, normalized event JSON/hash, and event verification contracts are unchanged.

A sender-IP-only alias has weak identity confidence; hostname aliases are strong. Exact alias conflicts are rejected while loading inventory.
