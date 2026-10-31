package witness

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"raven/internal/integrity"
)

const ledgerABI = `[{"type":"function","name":"anchorBatch","inputs":[{"name":"d","type":"tuple","components":[{"name":"codecVersion","type":"uint32"},{"name":"streamId","type":"bytes32"},{"name":"batchId","type":"uint64"},{"name":"firstSeq","type":"uint64"},{"name":"lastSeq","type":"uint64"},{"name":"leafCount","type":"uint32"},{"name":"merkleRoot","type":"bytes32"},{"name":"prevBatchHash","type":"bytes32"}]}],"outputs":[{"name":"batchHash","type":"bytes32"}],"stateMutability":"nonpayable"},{"type":"function","name":"getBatch","inputs":[{"name":"streamId","type":"bytes32"},{"name":"batchId","type":"uint64"}],"outputs":[{"name":"","type":"tuple","components":[{"name":"firstSeq","type":"uint64"},{"name":"lastSeq","type":"uint64"},{"name":"leafCount","type":"uint32"},{"name":"merkleRoot","type":"bytes32"},{"name":"prevBatchHash","type":"bytes32"},{"name":"batchHash","type":"bytes32"}]}],"stateMutability":"view"},{"type":"function","name":"getHead","inputs":[{"name":"streamId","type":"bytes32"}],"outputs":[{"name":"","type":"tuple","components":[{"name":"batchId","type":"uint64"},{"name":"lastSeq","type":"uint64"},{"name":"batchHash","type":"bytes32"}]}],"stateMutability":"view"},{"type":"function","name":"genesisHashes","inputs":[{"name":"","type":"bytes32"}],"outputs":[{"name":"","type":"bytes32"}],"stateMutability":"view"},{"type":"function","name":"anchorAddresses","inputs":[{"name":"","type":"bytes32"}],"outputs":[{"name":"","type":"address"}],"stateMutability":"view"},{"type":"event","name":"BatchAnchored","anonymous":false,"inputs":[{"name":"streamId","type":"bytes32","indexed":true},{"name":"batchId","type":"uint64","indexed":true},{"name":"codecVersion","type":"uint32","indexed":false},{"name":"firstSeq","type":"uint64","indexed":false},{"name":"lastSeq","type":"uint64","indexed":false},{"name":"leafCount","type":"uint32","indexed":false},{"name":"merkleRoot","type":"bytes32","indexed":false},{"name":"prevBatchHash","type":"bytes32","indexed":false},{"name":"batchHash","type":"bytes32","indexed":false}]}]`

type AnchorConfig struct {
	RPCURL        string
	Identity      ChainIdentity
	PrivateKeyHex string
}

type chainDescriptor struct {
	CodecVersion  uint32
	StreamId      [32]byte
	BatchId       uint64
	FirstSeq      uint64
	LastSeq       uint64
	LeafCount     uint32
	MerkleRoot    [32]byte
	PrevBatchHash [32]byte
}

type chainBatch struct {
	FirstSeq      uint64   `json:"firstSeq"`
	LastSeq       uint64   `json:"lastSeq"`
	LeafCount     uint32   `json:"leafCount"`
	MerkleRoot    [32]byte `json:"merkleRoot"`
	PrevBatchHash [32]byte `json:"prevBatchHash"`
	BatchHash     [32]byte `json:"batchHash"`
}

type chainHead struct {
	BatchID   uint64   `json:"batchId"`
	LastSeq   uint64   `json:"lastSeq"`
	BatchHash [32]byte `json:"batchHash"`
}

var ErrAnchorAlreadyOnChain = errors.New("batch is already present in contract state but its transaction receipt is unavailable")
var ErrAnchorReceiptMismatch = errors.New("anchor receipt mismatch")

type Anchorer struct {
	store       *Store
	stream      integrity.Hash
	genesis     integrity.Hash
	config      AnchorConfig
	client      *ethclient.Client
	parsed      abi.ABI
	key         *ecdsa.PrivateKey
	identityErr error
}

var ErrChainIdentity = errors.New("ethereum identity divergence")

func StartAnchorer(ctx context.Context, store *Store, stream, genesis integrity.Hash, cfg AnchorConfig) (*Anchorer, error) {
	if cfg.RPCURL == "" || cfg.Identity.ChainID != 31337 || !common.IsHexAddress(cfg.Identity.ContractAddress) || cfg.Identity.DeploymentBlockHash == "" || cfg.Identity.RuntimeCodeHash == "" || cfg.Identity.GenesisBlockHash == "" || cfg.PrivateKeyHex == "" {
		return nil, errors.New("anchoring requires pinned local chain identity and RAVEN_ANCHOR_PRIVATE_KEY")
	}
	keyHex := strings.TrimPrefix(strings.TrimSpace(cfg.PrivateKeyHex), "0x")
	key, err := crypto.HexToECDSA(keyHex)
	if err != nil {
		return nil, fmt.Errorf("decode anchor private key: %w", err)
	}
	parsed, err := abi.JSON(strings.NewReader(ledgerABI))
	if err != nil {
		return nil, err
	}
	a := &Anchorer{store: store, stream: stream, genesis: genesis, config: cfg, parsed: parsed, key: key}
	if err := store.PinChainIdentity(ctx, cfg.Identity); err != nil {
		a.identityErr = err
	}
	return a, nil
}

func (a *Anchorer) Close() {
	if a.client != nil {
		a.client.Close()
	}
}

func (a *Anchorer) verifyIdentity(ctx context.Context) error {
	chainID, err := a.client.ChainID(ctx)
	if err != nil {
		return err
	}
	if chainID.Uint64() != a.config.Identity.ChainID {
		_ = a.store.MarkReorg(ctx, 0, "configured chain ID no longer matches the connected chain")
		return fmt.Errorf("%w: chain ID mismatch: got %s", ErrChainIdentity, chainID)
	}
	zero, err := a.client.HeaderByNumber(ctx, big.NewInt(0))
	if err != nil {
		return err
	}
	if !strings.EqualFold(zero.Hash().Hex(), a.config.Identity.GenesisBlockHash) {
		_ = a.store.MarkReorg(ctx, 0, "connected chain genesis differs from the retained baseline")
		return fmt.Errorf("%w: Ethereum genesis block hash differs from pinned identity", ErrChainIdentity)
	}
	deployment, err := a.client.HeaderByNumber(ctx, new(big.Int).SetUint64(a.config.Identity.DeploymentBlock))
	if errors.Is(err, ethereum.NotFound) {
		latest, headErr := a.client.HeaderByNumber(ctx, nil)
		if headErr != nil {
			return headErr
		}
		if latest.Number.Uint64() < a.config.Identity.DeploymentBlock {
			_ = a.store.MarkReorg(ctx, a.config.Identity.DeploymentBlock, "chain head regressed below the pinned contract deployment")
			return fmt.Errorf("%w: chain head regressed below contract deployment", ErrChainIdentity)
		}
		return errors.New("ethereum history is unavailable at pinned contract deployment block")
	}
	if err != nil {
		return err
	}
	if !strings.EqualFold(deployment.Hash().Hex(), a.config.Identity.DeploymentBlockHash) {
		_ = a.store.MarkReorg(ctx, a.config.Identity.DeploymentBlock, "pinned contract deployment block hash changed")
		return fmt.Errorf("%w: contract deployment block hash differs from pinned identity", ErrChainIdentity)
	}
	address := common.HexToAddress(a.config.Identity.ContractAddress)
	code, err := a.client.CodeAt(ctx, address, new(big.Int).SetUint64(a.config.Identity.DeploymentBlock))
	if err != nil {
		return err
	}
	if !strings.EqualFold(crypto.Keccak256Hash(code).Hex(), a.config.Identity.RuntimeCodeHash) {
		return fmt.Errorf("%w: contract runtime code differs from pinned identity", ErrChainIdentity)
	}
	latestCode, err := a.client.CodeAt(ctx, address, nil)
	if err != nil {
		return err
	}
	if !strings.EqualFold(crypto.Keccak256Hash(latestCode).Hex(), a.config.Identity.RuntimeCodeHash) {
		return fmt.Errorf("%w: contract code at chain head differs from pinned identity", ErrChainIdentity)
	}
	var streamID, configuredGenesis [32]byte
	copy(streamID[:], a.stream[:])
	copy(configuredGenesis[:], a.genesis[:])
	genesisOut, err := a.call(ctx, "genesisHashes", streamID)
	if err != nil {
		return err
	}
	if len(genesisOut) != 1 || genesisOut[0].([32]byte) != configuredGenesis {
		return fmt.Errorf("%w: contract stream genesis differs from witness stream", ErrChainIdentity)
	}
	anchorOut, err := a.call(ctx, "anchorAddresses", streamID)
	if err != nil {
		return err
	}
	if len(anchorOut) != 1 || anchorOut[0].(common.Address) != crypto.PubkeyToAddress(a.key.PublicKey) {
		return fmt.Errorf("%w: contract anchor address differs from configured signing key", ErrChainIdentity)
	}
	return a.verifyCheckpoints(ctx)
}

func (a *Anchorer) call(ctx context.Context, method string, args ...any) ([]any, error) {
	return a.callAt(ctx, nil, method, args...)
}

func (a *Anchorer) callAt(ctx context.Context, block *big.Int, method string, args ...any) ([]any, error) {
	data, err := a.parsed.Pack(method, args...)
	if err != nil {
		return nil, err
	}
	result, err := a.client.CallContract(ctx, ethereum.CallMsg{To: ptrAddress(common.HexToAddress(a.config.Identity.ContractAddress)), Data: data}, block)
	if err != nil {
		return nil, err
	}
	return a.parsed.Unpack(method, result)
}

func (a *Anchorer) verifyCheckpoints(ctx context.Context) error {
	rows, err := a.store.db.QueryContext(ctx, `SELECT block_number,block_hash FROM witness_chain_checkpoints ORDER BY block_number`)
	if err != nil {
		return err
	}
	type checkpoint struct {
		height uint64
		hash   []byte
	}
	var checkpoints []checkpoint
	for rows.Next() {
		var height uint64
		var expected []byte
		if err := rows.Scan(&height, &expected); err != nil {
			rows.Close()
			return err
		}
		checkpoints = append(checkpoints, checkpoint{height, append([]byte(nil), expected...)})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, checkpoint := range checkpoints {
		header, e := a.client.HeaderByNumber(ctx, new(big.Int).SetUint64(checkpoint.height))
		if errors.Is(e, ethereum.NotFound) {
			latest, latestErr := a.client.HeaderByNumber(ctx, nil)
			if latestErr != nil {
				return latestErr
			}
			if latest.Number.Uint64() < checkpoint.height {
				_ = a.store.MarkReorg(ctx, checkpoint.height, fmt.Sprintf("chain head regressed below previously confirmed block %d", checkpoint.height))
				return fmt.Errorf("chain head regressed below pinned checkpoint block %d", checkpoint.height)
			}
			return fmt.Errorf("ethereum history is unavailable at pinned checkpoint block %d", checkpoint.height)
		}
		if e != nil {
			return e
		}
		if !bytesEqual(header.Hash().Bytes(), checkpoint.hash) {
			_ = a.store.MarkReorg(ctx, checkpoint.height, fmt.Sprintf("canonical hash changed at previously confirmed block %d", checkpoint.height))
			return fmt.Errorf("pinned Ethereum checkpoint mismatch at block %d", checkpoint.height)
		}
	}
	return nil
}

// RunOnce submits or reconciles only the oldest outstanding batch for this stream.
func (a *Anchorer) RunOnce(ctx context.Context) error {
	if a.identityErr != nil {
		return a.identityErr
	}
	if a.client == nil {
		client, err := ethclient.DialContext(ctx, a.config.RPCURL)
		if err != nil {
			return fmt.Errorf("connect to Anvil RPC: %w", err)
		}
		a.client = client
	}
	if err := a.verifyIdentity(ctx); err != nil {
		if errors.Is(err, ErrChainIdentity) {
			_ = a.store.AddChainFinding(ctx, "chain_identity_divergence", err.Error())
		}
		return err
	}
	p, err := a.store.NextAnchor(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if p.State == "failed" {
		return fmt.Errorf("batch %d has a permanently failed anchor transaction", p.BatchID)
	}
	manifest, err := decodeManifest(p.Manifest)
	if err != nil {
		return err
	}
	if p.BatchID != manifest.Descriptor.BatchID {
		return errors.New("queued batch identity differs from retained manifest")
	}
	var rawTx types.Transaction
	if len(p.TxBytes) == 0 {
		return a.createAndSend(ctx, p, manifest)
	}
	if err := rawTx.UnmarshalBinary(p.TxBytes); err != nil {
		return fmt.Errorf("decode persisted signed transaction: %w", err)
	}
	if rawTx.Hash().Bytes() == nil || !bytesEqual(rawTx.Hash().Bytes(), p.TxHash) {
		return errors.New("persisted transaction bytes do not match stored hash")
	}
	if err := a.verifyPersistedTx(&rawTx, p, manifest); err != nil {
		_ = a.store.AddChainFinding(ctx, "persisted_transaction_mismatch", err.Error())
		_ = a.store.FailAnchor(ctx, p.BatchID, "persisted signed transaction does not match retained descriptor")
		return err
	}
	receipt, err := a.client.TransactionReceipt(ctx, rawTx.Hash())
	if errors.Is(err, ethereum.NotFound) {
		known, _, lookupErr := a.client.TransactionByHash(ctx, rawTx.Hash())
		if lookupErr == nil && known != nil {
			if err := a.verifyContractPosition(ctx, manifest); err != nil && !errors.Is(err, ErrAnchorAlreadyOnChain) {
				return err
			}
			return nil
		}
		if lookupErr != nil && !errors.Is(lookupErr, ethereum.NotFound) {
			return lookupErr
		}
		if err := a.verifyContractPosition(ctx, manifest); err != nil {
			return err
		}
		pending, nonceErr := a.client.PendingNonceAt(ctx, crypto.PubkeyToAddress(a.key.PublicKey))
		if nonceErr != nil {
			return nonceErr
		}
		if p.Nonce.Valid && pending > uint64(p.Nonce.Int64) {
			detail := "persisted anchor nonce was consumed but its transaction, receipt, and contract batch are unavailable"
			_ = a.store.AddChainFinding(ctx, "anchor_nonce_conflict", detail)
			_ = a.store.FailAnchor(ctx, p.BatchID, detail)
			return errors.New(detail)
		}
		if sendErr := a.client.SendTransaction(ctx, &rawTx); sendErr != nil && !strings.Contains(strings.ToLower(sendErr.Error()), "already known") && !strings.Contains(strings.ToLower(sendErr.Error()), "known transaction") {
			return fmt.Errorf("rebroadcast persisted transaction: %w", sendErr)
		}
		return nil
	}
	if err != nil {
		return err
	}
	err = a.verifyAndConfirm(ctx, p.BatchID, manifest, &rawTx, receipt)
	if errors.Is(err, ErrAnchorReceiptMismatch) {
		_ = a.store.AddChainFinding(ctx, "anchor_receipt_mismatch", err.Error())
		_ = a.store.FailAnchor(ctx, p.BatchID, err.Error())
	}
	return err
}

func (a *Anchorer) verifyPersistedTx(tx *types.Transaction, p PendingAnchor, m validatedManifest) error {
	if p.Nonce.Valid && tx.Nonce() != uint64(p.Nonce.Int64) {
		return errors.New("persisted transaction nonce differs from witness journal")
	}
	if tx.To() == nil || *tx.To() != common.HexToAddress(a.config.Identity.ContractAddress) || tx.ChainId().Uint64() != a.config.Identity.ChainID {
		return errors.New("persisted transaction chain or contract differs from pinned identity")
	}
	sender, err := types.Sender(types.LatestSignerForChainID(new(big.Int).SetUint64(a.config.Identity.ChainID)), tx)
	if err != nil {
		return err
	}
	if sender != crypto.PubkeyToAddress(a.key.PublicKey) {
		return errors.New("persisted transaction signer differs from configured anchor key")
	}
	d := chainDescriptor{CodecVersion: m.Descriptor.CodecVersion, BatchId: m.Descriptor.BatchID, FirstSeq: m.Descriptor.FirstSeq, LastSeq: m.Descriptor.LastSeq, LeafCount: m.Descriptor.LeafCount}
	copy(d.StreamId[:], m.Descriptor.StreamID[:])
	copy(d.MerkleRoot[:], m.Descriptor.MerkleRoot[:])
	copy(d.PrevBatchHash[:], m.Descriptor.PrevBatchHash[:])
	expected, err := a.parsed.Pack("anchorBatch", d)
	if err != nil {
		return err
	}
	if !bytes.Equal(tx.Data(), expected) {
		return errors.New("persisted transaction calldata differs from retained descriptor")
	}
	return nil
}

func (a *Anchorer) createAndSend(ctx context.Context, p PendingAnchor, m validatedManifest) error {
	if err := a.verifyContractPosition(ctx, m); err != nil {
		return err
	}
	d := chainDescriptor{CodecVersion: m.Descriptor.CodecVersion, BatchId: m.Descriptor.BatchID, FirstSeq: m.Descriptor.FirstSeq, LastSeq: m.Descriptor.LastSeq, LeafCount: m.Descriptor.LeafCount}
	copy(d.StreamId[:], m.Descriptor.StreamID[:])
	copy(d.MerkleRoot[:], m.Descriptor.MerkleRoot[:])
	copy(d.PrevBatchHash[:], m.Descriptor.PrevBatchHash[:])
	data, err := a.parsed.Pack("anchorBatch", d)
	if err != nil {
		return err
	}
	nonce, err := a.client.PendingNonceAt(ctx, crypto.PubkeyToAddress(a.key.PublicKey))
	if err != nil {
		return err
	}
	price, err := a.client.SuggestGasPrice(ctx)
	if err != nil {
		return err
	}
	to := common.HexToAddress(a.config.Identity.ContractAddress)
	gas, err := a.client.EstimateGas(ctx, ethereum.CallMsg{From: crypto.PubkeyToAddress(a.key.PublicKey), To: &to, GasPrice: price, Data: data})
	if err != nil {
		return err
	}
	unsigned := types.NewTransaction(nonce, to, big.NewInt(0), gas, price, data)
	signed, err := types.SignTx(unsigned, types.LatestSignerForChainID(new(big.Int).SetUint64(a.config.Identity.ChainID)), a.key)
	if err != nil {
		return err
	}
	raw, err := signed.MarshalBinary()
	if err != nil {
		return err
	}
	if err := a.store.PersistAnchorTx(ctx, p.BatchID, nonce, raw, signed.Hash().Bytes()); err != nil {
		return fmt.Errorf("persist signed anchor transaction before broadcast: %w", err)
	}
	if err := a.client.SendTransaction(ctx, signed); err != nil {
		if !strings.Contains(strings.ToLower(err.Error()), "already known") {
			return fmt.Errorf("send signed anchor transaction: %w", err)
		}
	}
	return nil
}

func (a *Anchorer) verifyContractPosition(ctx context.Context, m validatedManifest) error {
	stream := [32]byte(m.Descriptor.StreamID)
	values, err := a.call(ctx, "getBatch", stream, m.Descriptor.BatchID)
	if err != nil {
		return err
	}
	if len(values) != 1 {
		return errors.New("contract returned an invalid batch descriptor")
	}
	batch := *abi.ConvertType(values[0], new(chainBatch)).(*chainBatch)
	if batch.BatchHash != ([32]byte{}) {
		if batch.FirstSeq != m.Descriptor.FirstSeq || batch.LastSeq != m.Descriptor.LastSeq || batch.LeafCount != m.Descriptor.LeafCount || batch.MerkleRoot != [32]byte(m.Descriptor.MerkleRoot) || batch.PrevBatchHash != [32]byte(m.Descriptor.PrevBatchHash) || batch.BatchHash != [32]byte(m.BatchHash) {
			_ = a.store.AddChainFinding(ctx, "contract_conflict", fmt.Sprintf("contract batch %d conflicts with retained witness descriptor", m.Descriptor.BatchID))
			_ = a.store.FailAnchor(ctx, m.Descriptor.BatchID, "contract batch conflicts with retained witness descriptor")
			return errors.New("contract batch conflicts with retained witness descriptor")
		}
		return ErrAnchorAlreadyOnChain
	}
	values, err = a.call(ctx, "getHead", stream)
	if err != nil {
		return err
	}
	if len(values) != 1 {
		return errors.New("contract returned an invalid stream head")
	}
	head := *abi.ConvertType(values[0], new(chainHead)).(*chainHead)
	if head.BatchID >= m.Descriptor.BatchID || head.BatchID+1 != m.Descriptor.BatchID || head.LastSeq+1 != m.Descriptor.FirstSeq || head.BatchHash != [32]byte(m.Descriptor.PrevBatchHash) {
		_ = a.store.AddChainFinding(ctx, "contract_head_divergence", fmt.Sprintf("contract head does not precede retained batch %d", m.Descriptor.BatchID))
		_ = a.store.FailAnchor(ctx, m.Descriptor.BatchID, "contract head diverges from retained batch continuity")
		return errors.New("contract head diverges from retained batch continuity")
	}
	return nil
}

func (a *Anchorer) verifyAndConfirm(ctx context.Context, batch uint64, m validatedManifest, tx *types.Transaction, r *types.Receipt) error {
	if r == nil || r.BlockNumber == nil || r.TxHash != tx.Hash() || tx.To() == nil || *tx.To() != common.HexToAddress(a.config.Identity.ContractAddress) {
		return fmt.Errorf("%w: transaction hash or destination differs", ErrAnchorReceiptMismatch)
	}
	header, err := a.client.HeaderByNumber(ctx, r.BlockNumber)
	if err != nil {
		return err
	}
	if header.Hash() != r.BlockHash {
		_ = a.store.MarkReorg(ctx, r.BlockNumber.Uint64(), "submitted anchor receipt is not in the canonical block")
		return fmt.Errorf("%w: receipt block is not canonical", ErrAnchorReceiptMismatch)
	}
	if r.Status != types.ReceiptStatusSuccessful {
		record := map[string]any{"chain_id": a.config.Identity.ChainID, "contract_address": strings.ToLower(a.config.Identity.ContractAddress), "tx_hash": tx.Hash().Hex(), "block_number": r.BlockNumber.Uint64(), "block_hash": r.BlockHash.Hex(), "batch_hash": formatHash(m.BatchHash), "status": "failed"}
		encoded, err := json.Marshal(record)
		if err != nil {
			return err
		}
		if err := a.store.FailAnchorReceipt(ctx, batch, encoded, r.BlockNumber.Uint64(), r.BlockHash.Bytes()); err != nil {
			return err
		}
		return errors.New("anchor transaction reverted")
	}
	event := a.parsed.Events["BatchAnchored"]
	matched := false
	for _, log := range r.Logs {
		if log.Address != common.HexToAddress(a.config.Identity.ContractAddress) || len(log.Topics) != 3 || log.Topics[0] != event.ID || log.Topics[1] != common.Hash(m.Descriptor.StreamID) || new(big.Int).SetBytes(log.Topics[2].Bytes()).Uint64() != batch {
			continue
		}
		vals, e := a.parsed.Unpack("BatchAnchored", log.Data)
		if e != nil {
			return e
		}
		if len(vals) != 7 || vals[0].(uint32) != m.Descriptor.CodecVersion || vals[1].(uint64) != m.Descriptor.FirstSeq || vals[2].(uint64) != m.Descriptor.LastSeq || vals[3].(uint32) != m.Descriptor.LeafCount || vals[4].([32]byte) != [32]byte(m.Descriptor.MerkleRoot) || vals[5].([32]byte) != [32]byte(m.Descriptor.PrevBatchHash) || vals[6].([32]byte) != [32]byte(m.BatchHash) {
			return errors.New("anchor event descriptor differs from retained manifest")
		}
		matched = true
	}
	if !matched {
		return fmt.Errorf("%w: successful receipt lacks the expected BatchAnchored event", ErrAnchorReceiptMismatch)
	}
	stored, err := a.call(ctx, "getBatch", [32]byte(m.Descriptor.StreamID), batch)
	if err != nil {
		return err
	}
	if len(stored) != 1 {
		return errors.New("contract returned invalid batch state")
	}
	got := *abi.ConvertType(stored[0], new(chainBatch)).(*chainBatch)
	if got.FirstSeq != m.Descriptor.FirstSeq || got.LastSeq != m.Descriptor.LastSeq || got.LeafCount != m.Descriptor.LeafCount || got.MerkleRoot != [32]byte(m.Descriptor.MerkleRoot) || got.PrevBatchHash != [32]byte(m.Descriptor.PrevBatchHash) || got.BatchHash != [32]byte(m.BatchHash) {
		return fmt.Errorf("%w: contract state differs from retained manifest", ErrAnchorReceiptMismatch)
	}
	record := map[string]any{"chain_id": a.config.Identity.ChainID, "contract_address": strings.ToLower(a.config.Identity.ContractAddress), "tx_hash": tx.Hash().Hex(), "block_number": r.BlockNumber.Uint64(), "block_hash": r.BlockHash.Hex(), "batch_hash": formatHash(m.BatchHash), "status": "confirmed"}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return a.store.ConfirmAnchor(ctx, batch, encoded, r.BlockNumber.Uint64(), r.BlockHash.Bytes())
}

func (a *Anchorer) Start(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Second
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			callCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
			err := a.RunOnce(callCtx)
			cancel()
			if err != nil {
				if p, e := a.store.NextAnchor(context.Background()); e == nil {
					_ = a.store.AnchorError(context.Background(), p.BatchID, err.Error())
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func ptrAddress(a common.Address) *common.Address { return &a }
