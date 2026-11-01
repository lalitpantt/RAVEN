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

For event-only devices, silence becomes `unknown` after `freshnessAfter` and never means down. Only heartbeat reporting may produce a missed-report state. A sender-IP-only alias has weak identity confidence; hostname aliases are strong. Exact alias conflicts are rejected while loading inventory.
