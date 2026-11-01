# RAVEN CLI reference

Run commands from the repository root or an extracted release folder. Source-build examples use ./bin/raven (PowerShell: .\bin\raven.exe); release archives keep the binary at their root, so use ./raven (PowerShell: raven.exe) there. The binary includes the web UI and does not need Go or Node.js at runtime. Use raven -h for startup flags and raven --version to identify the build.

## Start and configure RAVEN

Running `raven` starts RAVEN in the foreground. Listener defaults bind to loopback. Marketplace access is **off by default** and does not affect ingestion. When enabled, RAVEN makes network requests only for explicit marketplace actions; it does not poll in the background.

| Argument | Default | Purpose |
|---|---|---|
| `-db <file>` | `data/raven.db` | SQLite database for raw events, normalized events, quarantine, and delivery state. |
| `-integrity-stream-id <hex>` | unset | Opt in to a fresh evidence stream; accepts a 32-byte hex identity. Defaults from `RAVEN_STREAM_ID`. |
| `-integrity-installation-epoch <hex>` | unset | Installation epoch paired with the stream ID when enabling evidence journaling on a fresh database. Defaults from `RAVEN_INSTALLATION_EPOCH`. |
| `-packs-dir <dir>` | `packs` | Active YAML parser packs and their hidden `.marketplace/` cache/management files. Paths are relative to the process working directory unless absolute. |
| `-sources-dir <dir>` | `sources` | YAML source adapter definitions. |
| `-sinks-dir <dir>` | `sinks` | YAML output adapter definitions. |
| `-analysis-dir <dir>` | `analysis` | Analysis device inventory and rules. Use `none` to disable explicitly; a missing or empty configuration leaves Analysis off. |
| `-workers <n>` | `4` | Processing worker count. |
| `-file <file>` | off | Read one file on startup. RAVEN exits after processing only when other inputs are disabled. |
| `-stdin` | `false` | Read stdin; piped input is also detected automatically. |
| `-stdin-framing line\|ndjson\|document` | `line` | Treat each line as a record or the complete bounded input as one document. |
| `-syslog-udp <address>` | `127.0.0.1:1514` | Syslog UDP listener. Use `none` to disable or an explicit interface address to accept remote senders. |
| `-syslog-tcp <address>` | `127.0.0.1:1514` | Syslog TCP listener. Use `none` to disable. |
| `-syslog-tls <address>` | `none` | Syslog TLS listener; requires `-tls-cert` and `-tls-key`. |
| `-tls-cert <file>` | unset | PEM server certificate for Syslog TLS. |
| `-tls-key <file>` | unset | Matching TLS private key. Keep it private. |
| `-tls-client-ca <file>` | unset | Client CA; enables required client-certificate verification (mTLS). |
| `-http <address>` | `127.0.0.1:8080` | HTTP ingestion API (`POST /api/v1/ingest`, `GET /api/v1/health`). `none` disables it. |
| `-http-key <token>` | unset | Require this key on HTTP ingest requests. |
| `-inbox <dir>` | `data/inbox` | Watched file-drop folder. `none` disables it. |
| `-output-file <file>` | `data/output/normalized.ndjson` | Normalized NDJSON file output. `none` disables it. |
| `-stdout[=true\|false]` | `true` | Print normalized NDJSON to the terminal. |
| `-ui <address>` | `127.0.0.1:9090` | Unauthenticated web UI and management API. `none` disables live management. Keep it on loopback or a trusted private network. |
| `--marketplace-online` | off | Allow explicit catalog refresh and missing-artifact downloads. No internet request is made without this option. |
| `--marketplace-url <url>` | `https://ashokkmt.github.io/raven` | Marketplace registry root. Do not append `catalog.json`; RAVEN adds it. |
| `-d` | foreground | Start detached and write `data/raven.pid` and `data/raven.log`. |
| `-stop` / `raven stop` | — | Stop a detached RAVEN process. |
| `-status` / `raven status` | — | Show daemon and control API status. |
| `-replay <id\|all\|list>` | — | List quarantine records or replay one/all through the running management API. `raven replay` is the short form. |
| `-replay-all` | false | Alias for replaying all eligible quarantine records. |
| `-verify <raw-id>` | — | Recompute and compare the stored raw-payload SHA-256. |
| `-verify-event <event-id>` | — | Check normalized-event integrity and raw-event lineage. |
| `-v`, `--version`, `-h` | — | Print version or built-in flag help. |

Use the startup arguments once when starting the service. For example, the official online registry needs no custom URL:

```sh
# Local listeners, web UI, and explicit marketplace access
./bin/raven -syslog-udp 127.0.0.1:1514 -syslog-tcp 127.0.0.1:1514 \
  -http 127.0.0.1:8080 -ui 127.0.0.1:9090 \
  --marketplace-online

# Same RAVEN without marketplace network access
./bin/raven -syslog-udp 127.0.0.1:1514 -syslog-tcp 127.0.0.1:1514 \
  -http 127.0.0.1:8080 -ui 127.0.0.1:9090
```

To use a different static registry, add `--marketplace-url https://registry.example/root`. Management actions do not require an application token; keep the UI/API bound to loopback or a trusted private network.

Other useful modes:

```sh
# One-shot file, with all long-running listeners disabled
./bin/raven -file testdata/sources/network-device-firewall/valid_session.log \
  -syslog-udp none -syslog-tcp none -syslog-tls none -http none -ui none -inbox none

# Detached service and later status/stop
./bin/raven -d --marketplace-online
./bin/raven status
./bin/raven stop

# Standard-input processing
cat sample.log | ./bin/raven -stdin -syslog-udp none -syslog-tcp none -http none -ui none -inbox none
```

## Evidence integrity and blockchain simulation

Integrity mode appends evidence facts transactionally with RAVEN's existing SQLite writes. Entries cover raw-log arrival, normalized event versions, quarantine changes, and replay outcomes. A batch seals at 5,000 entries maximum or after roughly five seconds, whichever occurs first. RAVEN sends the ordered manifest and Merkle root to the separate witness; the witness retains it and submits the batch commitment to the configured EVM chain. Raw log bytes and normalized event payloads stay in RAVEN's database. The chain receives commitments and sequence metadata only.

Check the evidence heads and run audits through the management API:

```sh
raven integrity status
raven integrity verify --type fast --wait
raven integrity verify --type deep --wait --wait-timeout 2m
raven integrity verify --type ledger --wait --wait-timeout 2m
```

| Audit | Checks |
|---|---|
| `fast` | Walk the local evidence journal and verify its links to current raw and normalized data. |
| `deep` | Perform a full bounded reconciliation of evidence history and database projections at a fixed snapshot. New writes during a scan can make that run incomplete; pause ingestion and retry for a stable snapshot. |
| `ledger` | Walk retained witness manifests and sequential chain history, checking batch and block continuity. |

`raven integrity status` shows the local journal head, witness receipt head, chain-confirmed head, and pending backlog. These heads may temporarily differ while anchoring catches up. `--wait` polls the durable audit result; exit status is 0 for passed, 1 for a detected mismatch, and 2 for unavailable or incomplete work. `--ui <address>` selects another management API address.

Integrity is disabled unless a new stream ID and installation epoch are configured on a fresh RAVEN database. Witness and chain settings are provided by the local lab/service configuration, not by a separate `raven` CLI subcommand. The Anvil configuration in this repository is a development simulation; it is not a public-network deployment. See [plans/final-run.md](plans/final-run.md) for the complete native and Docker commands, dashboard, scans, and simulator.

The GitHub release archives contain the RAVEN executable, not separate `raven-witness`, Anvil, Forge, Solidity contracts, or local blockchain secrets/configuration. The integrity CLI/API/UI are part of the RAVEN executable and remain disabled until configured. CI builds and tests the contract without attaching contract artifacts to release assets.

## Analysis inventory and configuration

Analysis is opt-in. Put device resources in `analysis/devices/` and rule resources in `analysis/rules/`; examples under `analysis/examples/` are not loaded automatically. Validate the complete snapshot before starting RAVEN:

```sh
raven analysis validate
raven analysis validate --analysis-dir ./my-analysis
raven analysis test -rule interface-down -sample analysis/examples/samples/interface-down.json
raven -analysis-dir ./my-analysis
```

The validator checks strict YAML fields, resource IDs and versions, source categories, unique aliases, heartbeat rule references, bounded durations, and Go RE2 expressions. Event rules match individual normalized events; window rules count matching events with configurable grouping, thresholds, and hold-downs; quality rules track recent quarantine ratios; and configured heartbeat devices create missing-report findings after warning/critical deadlines, with maintenance suppression. `analysis test` previews an event rule against one normalized-event JSON sample and makes no database writes. Invalid Analysis configuration is reported and disables Analysis while normal ingestion continues. Use `-analysis-dir none` to disable it explicitly. See [analysis/README.md](analysis/README.md) for the resource format and examples.

With a valid inventory loaded, the management API serves read-only telemetry at `GET /api/v1/analysis/status`, `GET /api/v1/analysis/devices`, `GET /api/v1/analysis/sources`, and `GET /api/v1/analysis/findings`. Finding details at `/api/v1/analysis/findings/{finding_id}` include paginated transition history and links to the existing Events, Trace, Verify, and Raw views. List endpoints support `limit` (1–500) and `offset`; finding status can be `open` (the default), `clearing`, `resolved`, or `all`. Source resolution can be `unknown`, `ambiguous`, or `unassigned` (the default). The Analysis dashboard is available in the UI navigation.

## Decoded formats

Transport and decoded format are separate: HTTP, Syslog, files, and stdin carry bytes; RAVEN's decoder reads the syntax. The current decoder families are:

| Format | Behavior |
|---|---|
| Syslog | RFC 5424 and RFC 3164 envelopes; their bodies can contain another supported format. |
| JSON | Objects and bounded arrays/NDJSON records, depending on intake framing. |
| XML | Documents and bounded repeated child records selected by a pack. |
| CSV | Header/row parsing with pack-specific field mapping. |
| CEF | CEF headers and extension fields. |
| LEEF | LEEF 1.0/2.0 headers and attributes, direct or Syslog-wrapped. |
| Text | Proprietary/application text extracted through declarative pack rules. |

Decoding establishes syntax, not source meaning. A parser pack still needs to match the source and map its fields. Unknown, malformed, or ambiguous input can be quarantined instead of guessed.

## Packs, sources, and sinks

### Parser packs

Packs define how RAVEN recognizes and normalizes a decoded log. The ordinary file workflow is:

```sh
raven packs list
raven packs get network-device-firewall
raven packs validate -f packs/new-device.yaml
raven packs test -f packs/new-device.yaml -sample sample.log
raven packs apply -f packs/new-device.yaml
raven packs rollback
```

`apply` normally asks the running management API to validate and activate the pack. Use `--local` with `--packs-dir <dir>` only when that installation is stopped; the change will load on its next startup. Live operations use the default API at port 9090; pack commands accept `--ui <address>` when RAVEN listens elsewhere. Do not run local changes against a directory owned by a running process.

Marketplace commands are separate from authoring and applying arbitrary local YAML:

```sh
# Search the catalog cached under ./packs; filters can be combined
raven marketplace search firewall
raven marketplace search --vendor Cisco --product ASA --model 5500 --format syslog
raven marketplace search --installed
raven marketplace show network-device-asa

# These use the running RAVEN management API
raven marketplace refresh
raven marketplace fetch network-device-asa@1.0.3
raven packs fetch network-device-asa@1.0.3
raven packs install network-device-asa@1.0.3
raven packs outdated
raven packs upgrade network-device-asa
raven packs upgrade --all
raven packs remove network-device-asa
raven packs rollback
```

Search and `show` read the local signed catalog/cache under `-packs-dir`; they do not contact the server or internet. `refresh` updates that instance's cache. `fetch` downloads verified bytes without activating them. `install` validates and activates a pack on the running RAVEN. `remove` deactivates only marketplace-managed or bundled packs from that installation. Ordinary upgrades stay within the current major version and skip pinned packs; choose an exact version to pin it. `raven packs rollback` undoes the most recent pack transaction.

To change a stopped installation explicitly, supported pack mutation commands accept `--local`. For example:

```sh
raven marketplace import --dir ./offline-snapshot --packs-dir ./packs
raven packs fetch network-device-asa@1.0.3 --local --packs-dir ./packs
raven packs install network-device-asa@1.0.3 --local --packs-dir ./packs
```

Local `fetch` can contact the configured registry only when both `--marketplace-online` and `--marketplace-url` are provided to that command; usually it is simpler to let the running server perform downloads. Offline local install requires that the artifact has already been fetched or imported. `--local` changes files and reports that the pack is available on next startup.

Marketplace options:

| Command | Effect |
|---|---|
| `raven marketplace search [text] [filters]` | Search cached catalog. Filters: `--vendor`, `--product`, `--model`, `--category`, `--format`; `--installed` and `--json` are supported. |
| `raven marketplace show <name>` | Print cached catalog details and releases. |
| `raven marketplace refresh` | Fetch and verify the latest signed catalog through the daemon. |
| `raven marketplace fetch <name>[@version]` | Download and verify without activation. |
| `raven marketplace export --dir <dir>` | Export catalog and cached artifacts for offline transfer. |
| `raven marketplace import --dir <dir>` | Verify and import an offline snapshot into the selected packs directory. |

`--ui <address>` selects the management API for supported daemon commands; it does not open a browser and is not the marketplace URL. The default is port 9090, so omit it when RAVEN uses that port. CLI `search` and `show` currently read `-packs-dir` in the CLI's working context; pass `--packs-dir` if the catalog is in a non-default location.

### Sources, sinks, and replay

Sources describe where RAVEN reads logs; sinks describe where normalized events go. Both support `list`, `get`, `validate -f`, `test -f`, `apply -f`, and `rollback`:

```sh
raven sources list
raven sources get aws-cloudtrail-pull
raven sources validate -f sources/cloud-pull.yaml
raven sources test -f sources/cloud-pull.yaml
raven sources apply -f sources/cloud-pull.yaml
raven sources rollback

raven sinks list
raven sinks get siem-events
raven sinks validate -f sinks/http-siem.yaml
raven sinks test -f sinks/http-siem.yaml
raven sinks apply -f sinks/http-siem.yaml
raven sinks rollback
```

`apply` and `rollback` contact the running management API on port 9090. Management actions do not prompt for an admin token; keep this API private. Source/sink manifests may connect to external services when tested or enabled; use trusted files and configure secrets through `secretRef` and the documented secret environment/file mechanism.

Unknown, malformed, or ambiguous logs remain in quarantine with their raw bytes. After adding and activating parser knowledge:

```sh
raven replay                  # list quarantine records
raven replay QUARANTINE_ID    # replace with an ID from `raven replay`
raven replay all              # retry all eligible records
```

Replay uses the current parser snapshot and retains the original raw-event link. Inspect its result in the UI or database. Pack activation can also request reconciliation, so review its reported result before asking for another replay.

## Log simulator and Docker

`logsim` creates sample logs without needing a real device. Build it from source and send a bounded set to a local RAVEN HTTP listener:

```sh
mkdir -p bin
go build -o bin/logsim ./cmd/logsim
./bin/logsim --source app --scenario mixed --format http-post \
  --target http://127.0.0.1:8080/api/v1/ingest --rate 5 --count 50
```

For the complete simulator fleet, native RAVEN plus Docker simulators, and the air-gap image bundle, see the current commands in [README.md](README.md#docker-and-simulation).

## Other documentation

[MARKETPLACE.md](MARKETPLACE.md) explains the marketplace purpose, owner publishing workflow, signing keys, and customer install flow. [SECURITY.md](SECURITY.md) covers deployment boundaries, credentials, and integrity limits.
