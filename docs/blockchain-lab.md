# Repeatable local blockchain lab

The B-09 lab is opt-in and isolated under `data/blockchain-dev/`. It creates a fresh RAVEN evidence database and witness database there, deploys the pinned `LogAnchorLedger` contract to local Anvil, and stores throwaway credentials only in the mode-0600 `lab.env`. It does not use the normal `data/` database or the default Compose project.

## Requirements and pins

- Go 1.25.0 (the module toolchain), Node/npm and Python 3 for the embedded UI build and monotonic measurements, and `jq`, `openssl`, `xxd`, `shasum`, and `curl`.
- Foundry v1.8.6, Anvil, Forge, and cast. Solidity 0.8.37, Prague EVM, and optimizer settings are pinned in `contracts/foundry.toml`.
- Optional Compose path: Docker Engine with Compose v2. The witness image pins Go 1.25.0/Alpine 3.22; the Anvil image pins Foundry v1.8.6.

## Native run

From the repository root:

```sh
scripts/run-blockchain-dev.sh init
scripts/run-blockchain-dev.sh native-up
scripts/run-blockchain-dev.sh status
scripts/run-blockchain-dev.sh benchmark 1000
scripts/run-blockchain-dev.sh stop
```

`init` creates random stream/epoch IDs, independent Raven and witness credentials, and a one-time Ed25519 receipt key. `native-up` starts Anvil only on loopback, deploys/registers the stream on first run, pins the chain/deployment/code identity in `deployment.json`, builds the UI and local binaries, then starts the witness and RAVEN against lab-only databases. It starts RAVEN with the six-device/five-rule demo in `analysis/demo/` and verifies that Analysis is active. The Analysis dashboard is at `http://127.0.0.1:19090` under **Analysis**; `status` prints its worker/config state as well as health and integrity. It refuses to silently repin a changed Anvil genesis or a missing pinned contract. Use `reset --yes` only when deliberately discarding this lab and its state.

The demo inventory and rules produce green device health from normalized logs, a red heartbeat timeout after the one-shot heartbeat stops, red firewall findings, yellow SSH/quarantine findings, a grey disabled spare, and unknown unassigned sources. Seed and continuous all-source Docker simulator commands are in [the Analysis demo runbook](../plans/final-run.md#analysis-demo-with-the-blockchain-lab). The heartbeat scenario is excluded from mixed traffic so the deadline transition remains observable.

The local Raven UI is at `http://127.0.0.1:19090`; HTTP ingest is `http://127.0.0.1:18080/api/v1/ingest`. The witness is bound to `127.0.0.1:19091`. The development Anvil account private key is public and disposable; never reuse it outside this local simulation.

## Compose run

With Docker Engine running:

```sh
scripts/run-blockchain-dev.sh compose-up
scripts/run-blockchain-dev.sh status
scripts/run-blockchain-dev.sh stop
```

This uses only `docker-compose.blockchain.yaml` and Compose project `raven-blockchain-dev`; its ports bind to loopback. The runner marks an active Compose project so reset must stop that project first. Each lab directory is pinned to either native or Compose chain state; run `stop` and `reset --yes` before switching backends. The regular `docker-compose.yaml` is not part of this lab.

## Checks and measurements

`scripts/run-blockchain-dev.sh test` runs Go tests and vet, the UI production build, demo Analysis YAML validation, the tagged live Anvil recovery test, Forge build/tests, Compose config parsing, and the runner shell parser. The tagged test exercises recovery and reset detection:

```sh
GOCACHE=/private/tmp/raven-gocache go test -tags blockchain_integration ./internal/witness -run TestAnchorerAnvilRecoveryAndResetDetection -count=1
```

`benchmark [count]` sends the requested number of synthetic HTTP events from four concurrent producers, samples Raven's peak RSS, waits until the sealed backlog is anchored and clear, and records throughput, SQLite/WAL size, catch-up time, and fast-audit duration as JSON lines in the lab directory. Results depend on host hardware and are observations, not capacity promises. Run the B-09 S-01–S-12 matrix in `plans/saarthi/blockchain_addition.md` for replay, tamper, deletion, outage, reorg, audit, and reset scenarios; automated unit/integration coverage does not substitute for those scenarios or repeated host resource measurements.

Reset removes only the exact `data/blockchain-dev` directory after stopping owned native processes and, when marked active, the isolated Compose project. Existing operational data is outside this path.
