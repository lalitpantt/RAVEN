#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LAB="$ROOT/data/blockchain-dev"
export PATH="$HOME/.foundry/bin:$PATH"
PROJECT=raven-blockchain-dev
fail() { echo "error: $*" >&2; exit 1; }
init() {
  mkdir -p "$LAB"/{anvil,raven,witness,bin,contracts/src,contracts/script,inbox}
  if [[ ! -f "$LAB/lab.env" ]]; then
    stream="$(openssl rand -hex 32)"; epoch="$(openssl rand -hex 32)"
    genesis="$( { printf 'RAVEN-GENESIS\000\001'; printf '%s' "$stream$epoch" | xxd -r -p; } | shasum -a 256 | awk '{print $1}')"
    cat > "$LAB/lab.env" <<EOF
RAVEN_STREAM_ID=$stream
RAVEN_INSTALLATION_EPOCH=$epoch
RAVEN_GENESIS_HASH=$genesis
RAVEN_ADMIN_TOKEN=$(openssl rand -hex 32)
RAVEN_WITNESS_TOKEN=$(openssl rand -hex 32)
RAVEN_WITNESS_ADMIN_TOKEN=$(openssl rand -hex 32)
RAVEN_ANCHOR_PRIVATE_KEY=ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
RAVEN_ANCHOR_ADDRESS=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
RAVEN_UID=$(id -u)
RAVEN_GID=$(id -g)
EOF
    chmod 600 "$LAB/lab.env"
  fi
  set -a; source "$LAB/lab.env"; set +a
  [[ -f "$LAB/witness/receipt-key.b64" ]] || (cd "$ROOT"; go run ./cmd/raven-witness keygen -private-key "$LAB/witness/receipt-key.b64" -public-key "$LAB/witness/receipt-key.pub")
}
select_mode() {
  if [[ -f "$LAB/lab.mode" && "$(cat "$LAB/lab.mode")" != "$1" ]]; then
    fail "lab is pinned to $(cat "$LAB/lab.mode"); use reset --yes before switching chain backends"
  fi
  printf '%s\n' "$1" > "$LAB/lab.mode"
}
deploy() {
  local rpc="$1" genesis addr block blockhash codehash tx file
  cp "$ROOT/contracts/foundry.toml" "$LAB/contracts/"
  cp "$ROOT/contracts/src/LogAnchorLedger.sol" "$LAB/contracts/src/"
  cp "$ROOT/contracts/script/Deploy.s.sol" "$LAB/contracts/script/"
  genesis="$(cast block 0 --rpc-url "$rpc" --json | jq -er .data.hash)"
  if [[ -f "$LAB/deployment.json" ]]; then
    [[ "$(jq -r .chain_genesis_block_hash "$LAB/deployment.json")" == "$genesis" ]] || fail "Anvil identity changed; reset disposable lab"
    addr="$(jq -r .contract_address "$LAB/deployment.json")"; block="$(jq -r .deployment_block "$LAB/deployment.json")"
    blockhash="$(jq -r .deployment_block_hash "$LAB/deployment.json")"; codehash="$(jq -r .runtime_code_hash "$LAB/deployment.json")"
    [[ "$(cast code "$addr" --block "$block" --rpc-url "$rpc")" != 0x ]] || fail "pinned contract missing"
  else
    (cd "$LAB/contracts"; RAVEN_ANCHOR_ADDRESS="$RAVEN_ANCHOR_ADDRESS" RAVEN_STREAM_ID="0x$RAVEN_STREAM_ID" RAVEN_GENESIS_HASH="0x$RAVEN_GENESIS_HASH" forge script script/Deploy.s.sol:DeployScript --rpc-url "$rpc" --broadcast --private-key "$RAVEN_ANCHOR_PRIVATE_KEY" >/dev/null)
    file="$LAB/contracts/broadcast/Deploy.s.sol/31337/run-latest.json"
    addr="$(jq -r '.transactions[] | select(.contractName=="LogAnchorLedger") | .contractAddress' "$file" | tail -1)"
    tx="$(jq -r '.transactions[] | select(.contractName=="LogAnchorLedger") | .hash' "$file" | tail -1)"
    block="$(cast to-dec "$(cast receipt "$tx" --rpc-url "$rpc" --json | jq -er .blockNumber)")"
    blockhash="$(cast block "$block" --rpc-url "$rpc" --json | jq -er .data.hash)"
    codehash="$(cast code "$addr" --block "$block" --rpc-url "$rpc" | xargs cast keccak)"
    jq -n --arg genesis "$genesis" --arg addr "$addr" --arg block "$block" --arg bh "$blockhash" --arg ch "$codehash" '{chain_genesis_block_hash:$genesis,contract_address:$addr,deployment_block:($block|tonumber),deployment_block_hash:$bh,runtime_code_hash:$ch}' > "$LAB/deployment.json"
    chmod 600 "$LAB/deployment.json"
  fi
  export RAVEN_CHAIN_GENESIS_BLOCK_HASH="$genesis" RAVEN_CONTRACT_ADDRESS="$addr" RAVEN_DEPLOYMENT_BLOCK="$block" RAVEN_DEPLOYMENT_BLOCK_HASH="$blockhash" RAVEN_RUNTIME_CODE_HASH="$codehash"
  for mode in native compose; do
    if [[ "$mode" == native ]]; then listen=127.0.0.1:19091; db="$LAB/witness/witness.db"; key="$LAB/witness/receipt-key.b64"; rpcurl=http://127.0.0.1:8545
    else listen=0.0.0.0:9091; db=/lab/witness/witness.db; key=/lab/witness/receipt-key.b64; rpcurl=http://anvil:8545; fi
    cat > "$LAB/witness/witness-$mode.yaml" <<EOF
listen_address: $listen
database_path: $db
stream_id: 0x$RAVEN_STREAM_ID
genesis_hash: 0x$RAVEN_GENESIS_HASH
key_id: raven-local-witness-v1
private_key_path: $key
producer_token_env: RAVEN_WITNESS_TOKEN
admin_token_env: RAVEN_WITNESS_ADMIN_TOKEN
rpc_url: $rpcurl
chain_id: 31337
chain_genesis_block_hash: $genesis
contract_address: $addr
deployment_block: $block
deployment_block_hash: $blockhash
runtime_code_hash: $codehash
anchor_private_key_env: RAVEN_ANCHOR_PRIVATE_KEY
EOF
    chmod 600 "$LAB/witness/witness-$mode.yaml"
  done
}
native_up() {
  init
  select_mode native
  if [[ ! -f "$LAB/anvil.pid" ]] || ! kill -0 "$(cat "$LAB/anvil.pid")" 2>/dev/null; then
    if [[ -s "$LAB/anvil/state.json" ]]; then
      anvil --host 127.0.0.1 --port 8545 --chain-id 31337 --load-state "$LAB/anvil/state.json" --dump-state "$LAB/anvil/state.json" --preserve-historical-states > "$LAB/anvil/anvil.log" 2>&1 &
    else
      rm -f "$LAB/anvil/state.json"
      anvil --host 127.0.0.1 --port 8545 --chain-id 31337 --dump-state "$LAB/anvil/state.json" --preserve-historical-states > "$LAB/anvil/anvil.log" 2>&1 &
    fi
    echo $! > "$LAB/anvil.pid"
  fi
  for _ in $(seq 1 60); do cast chain-id --rpc-url http://127.0.0.1:8545 >/dev/null 2>&1 && break; sleep 1; done
  cast chain-id --rpc-url http://127.0.0.1:8545 >/dev/null || fail "Anvil failed; inspect $LAB/anvil/anvil.log"
  deploy http://127.0.0.1:8545
  (cd "$ROOT/web" && npm ci && npm run build)
  (cd "$ROOT" && go build -o "$LAB/bin/raven" ./cmd/raven && go build -o "$LAB/bin/raven-witness" ./cmd/raven-witness && go build -o "$LAB/bin/logsim" ./cmd/logsim)
  if [[ ! -f "$LAB/witness.pid" ]] || ! kill -0 "$(cat "$LAB/witness.pid")" 2>/dev/null; then
    (cd "$ROOT"; set -a; source "$LAB/lab.env"; set +a; "$LAB/bin/raven-witness" -config "$LAB/witness/witness-native.yaml" > "$LAB/witness/witness.log" 2>&1) & echo $! > "$LAB/witness.pid"
  fi
  if [[ ! -f "$LAB/raven.pid" ]] || ! kill -0 "$(cat "$LAB/raven.pid")" 2>/dev/null; then
    mkdir -p "$LAB/raven/inbox" "$LAB/raven/output"
    (cd "$ROOT"; set -a; source "$LAB/lab.env"; set +a; export RAVEN_WITNESS_URL=http://127.0.0.1:19091 RAVEN_WITNESS_PUBLIC_KEY="$LAB/witness/receipt-key.pub"; "$LAB/bin/raven" -db "$LAB/raven/raven.db" -inbox "$LAB/raven/inbox" -output-file "$LAB/raven/output/normalized.ndjson" -syslog-udp none -syslog-tcp none -http 127.0.0.1:18080 -ui 127.0.0.1:19090) > "$LAB/raven/raven.log" 2>&1 & echo $! > "$LAB/raven.pid"
  fi
  for _ in $(seq 1 60); do curl -fsS http://127.0.0.1:18080/api/v1/health >/dev/null 2>&1 && break; sleep 1; done
  curl -fsS http://127.0.0.1:18080/api/v1/health >/dev/null || fail "RAVEN failed; inspect $LAB/raven/raven.log"
  set -a; source "$LAB/lab.env"; set +a
  for _ in $(seq 1 60); do curl -fsS -H "Authorization: Bearer $RAVEN_WITNESS_ADMIN_TOKEN" "http://127.0.0.1:19091/v1/streams/0x$RAVEN_STREAM_ID/status" >/dev/null 2>&1 && break; sleep 1; done
  curl -fsS -H "Authorization: Bearer $RAVEN_WITNESS_ADMIN_TOKEN" "http://127.0.0.1:19091/v1/streams/0x$RAVEN_STREAM_ID/status" >/dev/null || fail "witness failed; inspect $LAB/witness/witness.log"
  for _ in $(seq 1 60); do curl -fsS -H "Authorization: Bearer $RAVEN_ADMIN_TOKEN" http://127.0.0.1:19090/api/v1/integrity/status 2>/dev/null | jq -e --arg id "0x$RAVEN_STREAM_ID" '.stream_id == $id' >/dev/null && break; sleep 1; done
  curl -fsS -H "Authorization: Bearer $RAVEN_ADMIN_TOKEN" http://127.0.0.1:19090/api/v1/integrity/status | jq -e --arg id "0x$RAVEN_STREAM_ID" '.stream_id == $id' >/dev/null || fail "RAVEN integrity stream differs from the isolated lab configuration"
}
stop() {
  if [[ -f "$LAB/compose-active" ]]; then
    docker info >/dev/null 2>&1 || fail "Compose lab marker exists but Docker is unavailable; stop project $PROJECT before reset"
    docker compose --env-file "$LAB/lab.env" -p raven-blockchain-dev -f "$ROOT/docker-compose.blockchain.yaml" down --remove-orphans || fail "could not stop isolated Compose project"
    rm -f "$LAB/compose-active"
  fi
  for f in "$LAB/raven.pid" "$LAB/witness.pid" "$LAB/anvil.pid"; do
    [[ -f "$f" ]] || continue; pid="$(cat "$f")"
    if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
      kill -TERM "$pid" 2>/dev/null || true
      for _ in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
    fi
    rm -f "$f"
  done
}
case "${1:-help}" in
  init) init; echo "Initialized isolated lab at $LAB" ;;
  native-up) native_up; echo "Native lab ready: http://127.0.0.1:19090" ;;
  compose-up)
    init; select_mode compose; docker info >/dev/null 2>&1 || fail "Docker daemon unavailable; use native-up"
    touch "$LAB/compose-active"
    docker compose --env-file "$LAB/lab.env" -p raven-blockchain-dev -f "$ROOT/docker-compose.blockchain.yaml" up -d anvil
    for _ in $(seq 1 60); do cast chain-id --rpc-url http://127.0.0.1:18545 >/dev/null 2>&1 && break; sleep 1; done
    deploy http://127.0.0.1:18545
    (cd "$ROOT/web" && npm ci && npm run build)
    docker compose --env-file "$LAB/lab.env" -p raven-blockchain-dev -f "$ROOT/docker-compose.blockchain.yaml" up -d --build witness raven ;;
  status) set -a; source "$LAB/lab.env"; set +a; curl -fsS http://127.0.0.1:18080/api/v1/health; echo; curl -fsS -H "Authorization: Bearer $RAVEN_ADMIN_TOKEN" http://127.0.0.1:19090/api/v1/integrity/status; echo ;;
  stop) stop ;;
  reset) [[ "${2:-}" == --yes ]] || fail "usage: $0 reset --yes (removes only $LAB)"; [[ "$LAB" == "$ROOT/data/blockchain-dev" && ! -L "$LAB" ]] || fail "refusing unsafe reset"; stop; rm -rf -- "$LAB"; echo "Removed $LAB" ;;
  benchmark)
    native_up; set -a; source "$LAB/lab.env"; set +a; count="${2:-1000}"
    [[ "$count" =~ ^[1-9][0-9]*$ ]] || fail "count must be positive"
    raven_pid="$(lsof -ti tcp:19090 | head -1)"; : > "$LAB/rss-samples-kb.txt"
    (while kill -0 "$raven_pid" 2>/dev/null; do ps -o rss= -p "$raven_pid" 2>/dev/null | awk 'NF {print $1}'; sleep 0.1; done) >> "$LAB/rss-samples-kb.txt" & sampler=$!
    started_ns="$(python3 -c 'import time; print(time.monotonic_ns())')"; per_job=$((count / 4)); extra=$((count % 4)); pids=()
    for job in 1 2 3 4; do job_count="$per_job"; [[ "$job" -le "$extra" ]] && job_count=$((job_count + 1)); [[ "$job_count" -gt 0 ]] || continue
      "$LAB/bin/logsim" --source app --scenario mixed --format http-post --target http://127.0.0.1:18080/api/v1/ingest --rate 0 --count "$job_count" --seed "$job" > "$LAB/logsim-$job.log" 2>&1 & pids+=("$!")
    done
    for pid in "${pids[@]}"; do wait "$pid" || fail "a concurrent synthetic producer failed; inspect $LAB/logsim-*.log"; done
    ingest_done_ns="$(python3 -c 'import time; print(time.monotonic_ns())')"
    ingest_ms=$(( (ingest_done_ns - started_ns) / 1000000 )); kill "$sampler" 2>/dev/null || true; wait "$sampler" 2>/dev/null || true
    max_rss_kb="$(sort -n "$LAB/rss-samples-kb.txt" | tail -1)"; max_rss_kb="${max_rss_kb:-0}"
    for _ in $(seq 1 90); do
      lab_status="$(curl -fsS -H "Authorization: Bearer $RAVEN_ADMIN_TOKEN" http://127.0.0.1:19090/api/v1/integrity/status 2>/dev/null || true)"
      echo "$lab_status" | jq -e '.local_head.batch_id > 0 and .chain_head.batch_id >= .local_head.batch_id and .backlog_count == 0' >/dev/null 2>&1 && break
      sleep 1
    done
    echo "$lab_status" | jq -e '.local_head.batch_id > 0 and .chain_head.batch_id >= .local_head.batch_id and .backlog_count == 0' >/dev/null || fail "sealed backlog did not reach the anchored chain before timeout"
    anchored_ns="$(python3 -c 'import time; print(time.monotonic_ns())')"
    catchup_ms=$(( (anchored_ns - ingest_done_ns) / 1000000 ))
    db="$(stat -f %z "$LAB/raven/raven.db" 2>/dev/null || echo 0)"; wal="$(stat -f %z "$LAB/raven/raven.db-wal" 2>/dev/null || echo 0)"
    audit_started_ns="$(python3 -c 'import time; print(time.monotonic_ns())')"
    "$LAB/bin/raven" integrity verify --ui http://127.0.0.1:19090 --admin-token "$RAVEN_ADMIN_TOKEN" --type fast --wait
    audit_ms=$(( ($(python3 -c 'import time; print(time.monotonic_ns())') - audit_started_ns) / 1000000 ))
    throughput="$(awk -v n="$count" -v ms="$ingest_ms" 'BEGIN { printf "%.3f", n*1000/(ms>0?ms:1) }')"
    printf '{"events":%s,"concurrent_producers":4,"ingest_seconds":%.3f,"events_per_second":%s,"max_raven_rss_kb":%s,"sqlite_bytes":%s,"wal_bytes":%s,"backlog_catchup_seconds":%.3f,"fast_audit_seconds":%.3f}\n' "$count" "$(awk -v ms="$ingest_ms" 'BEGIN { printf "%.3f", ms/1000 }')" "$throughput" "$max_rss_kb" "$db" "$wal" "$(awk -v ms="$catchup_ms" 'BEGIN { printf "%.3f", ms/1000 }')" "$(awk -v ms="$audit_ms" 'BEGIN { printf "%.3f", ms/1000 }')" | tee -a "$LAB/benchmark.jsonl" ;;
  test)
    (cd "$ROOT" && npm run build --prefix web && go test ./... && go vet ./... && go test -tags blockchain_integration ./internal/witness -run TestAnchorerAnvilRecoveryAndResetDetection -count=1)
    (cd "$ROOT/contracts" && forge build && forge test)
    docker compose -f "$ROOT/docker-compose.blockchain.yaml" config --quiet
    bash -n "$0" ;;
  *) echo "Usage: $0 {init|native-up|compose-up|status|stop|reset --yes|benchmark [count]|test}" ;;
esac

