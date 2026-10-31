# Local contract and witness (B-05/B-06)

The witness is an optional, separate process with its own SQLite file. It validates the frozen evidence codec, recomputes every entry leaf, the ordered Merkle root, and the ABI descriptor hash, then atomically retains the manifest and queues it before returning a signed acknowledgement. It does not receive raw payloads. B-06 adds a single durable transaction worker: it pins the Anvil/contract identity, persists nonce and exact signed bytes before broadcast, reconciles saved transactions after restart, and confirms only a successful canonical receipt with the expected event and contract descriptor. An RPC outage leaves queued manifests retained and the witness API available.

## Start the witness

1. Copy `config/blockchain-dev/witness.yaml.example` to a private local config file and replace `stream_id` and `genesis_hash` with the selected RAVEN stream identity. Set the database and key paths inside the disposable `data/blockchain-dev/witness/` directory.
2. Generate the receipt identity once. The command refuses to overwrite either file:

   ```sh
   go run ./cmd/raven-witness keygen \
     -private-key data/blockchain-dev/witness/receipt-key.b64 \
     -public-key data/blockchain-dev/witness/receipt-key.pub
   ```

   The private file is created with mode `0600`; the public file can be pinned by a RAVEN producer. Keep both files outside version control.
3. Start the pinned local Anvil chain and deploy/register `LogAnchorLedger` using the disposable Anvil anchor key. Fill in the chain and deployment identity fields in the witness config example. Capture chain ID with `cast chain-id`; the genesis and deployment block hashes with `cast block`; the contract address and deployment block from the Forge deployment output/receipt; and the runtime code hash with `cast keccak "$(cast code <address> --block <deployment-block> --rpc-url http://127.0.0.1:8545)"`. Keep the deployment block hash and runtime code hash fixed in the witness config.

4. Supply independent credentials through the environment. Each value must contain at least 32 bytes:

   ```sh
   export RAVEN_WITNESS_TOKEN="$(openssl rand -hex 32)"
   export RAVEN_WITNESS_ADMIN_TOKEN="$(openssl rand -hex 32)"
   go run ./cmd/raven-witness -config config/blockchain-dev/witness.yaml
   ```

The producer credential can submit manifests. The separate admin credential can read retained batches and witness status. The anchor worker reads the development EVM key from the configured `RAVEN_ANCHOR_PRIVATE_KEY` environment variable. A wrong-stream request returns `404`; malformed input returns `400`; an oversized body returns `413`; a skipped sequence or equivocation returns `409`; a SQLite failure returns `503` without an acknowledgement. Chain identity changes and reorgs become persistent findings; the worker does not repin or silently replace a prior baseline.

## Build and test the contract

The contract uses the frozen Solidity `0.8.37`, Prague EVM, optimizer 200, and no external Solidity library. With Foundry `v1.8.6` installed:

```sh
cd contracts
forge test
anvil --chain-id 31337
```

In another terminal, use a disposable Anvil account and stream identity to deploy/register the first stream:

```sh
export RAVEN_STREAM_ID=0x...
export RAVEN_GENESIS_HASH=0x...
export RAVEN_ANCHOR_ADDRESS=0x...
forge script script/Deploy.s.sol:DeployScript \
  --rpc-url http://127.0.0.1:8545 --broadcast \
  --private-key "$RAVEN_ANCHOR_PRIVATE_KEY"
```

Use only Anvil's throwaway key. Do not use a funded or production wallet.

## Recovery behavior

The database stores chain identity, checkpoints, signed transaction bytes, nonce, transaction hash, receipt, attempt count, and failures. After an uncertain send or restart, the worker checks receipt, transaction lookup, contract batch/head, and pending nonce before reuse; if a saved transaction must be resent, it sends the same signed bytes. A confirmed receipt is rechecked against the canonical block and contract event/state. An Anvil reset marks affected acknowledgements failed with a `reorged` receipt and removes them from the confirmed head. RAVEN uploads each sealed manifest with its producer credential, verifies the Ed25519 receipt against the configured public key, then polls the retained batch with the separate `RAVEN_WITNESS_ADMIN_TOKEN` until the anchor outcome is durable. B-08 exposes management status, audit scheduling/status, and inclusion-proof endpoints. Do not treat a signed witness acknowledgement as a blockchain confirmation.

For the isolated native and Compose lab, use [the blockchain lab runbook](blockchain-lab.md). It confines generated databases, keys, state, and reset behavior to `data/blockchain-dev/`.

Run unit tests with `go test ./internal/witness ./cmd/raven-witness`. Run the local chain recovery test with `go test -tags blockchain_integration ./internal/witness -run TestAnchorerAnvilRecoveryAndResetDetection -count=1`; it requires Forge and Anvil on the machine and uses a disposable in-memory chain plus the public Anvil development key only.
