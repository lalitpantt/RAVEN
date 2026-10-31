package witness

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"raven/internal/integrity"
)

const ledgerAuditBudget = 30 * time.Second

type AuditRun struct {
	RunID          string      `json:"run_id"`
	Type           string      `json:"type"`
	State          string      `json:"state"`
	Result         string      `json:"result"`
	StartedAt      string      `json:"started_at"`
	CompletedAt    *string     `json:"completed_at"`
	Target         AuditTarget `json:"target"`
	VerifiedPrefix AuditPrefix `json:"verified_prefix"`
	FailureClass   *string     `json:"failure_class"`
	FindingCount   int         `json:"finding_count"`
}

type AuditTarget struct {
	BatchID     *uint64 `json:"batch_id"`
	BlockNumber *uint64 `json:"block_number"`
	BlockHash   *string `json:"block_hash"`
}

type AuditPrefix struct {
	BatchID     uint64 `json:"batch_id"`
	EntrySeq    uint64 `json:"entry_seq"`
	BlockNumber uint64 `json:"block_number"`
}

type LedgerAuditor struct {
	store        *Store
	anchorer     *Anchorer
	public       ed25519.PublicKey
	mu           sync.Mutex
	active       string
	ctx          context.Context
	stop         context.CancelFunc
	activeCancel context.CancelFunc
	wg           sync.WaitGroup
}

func NewLedgerAuditor(store *Store, anchorer *Anchorer, signer ReceiptSigner) *LedgerAuditor {
	return &LedgerAuditor{store: store, anchorer: anchorer, public: signer.Key.Public().(ed25519.PublicKey)}
}

func (a *LedgerAuditor) Start(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	a.mu.Lock()
	a.ctx, a.stop = context.WithCancel(ctx)
	base := a.ctx
	a.wg.Add(1)
	a.mu.Unlock()
	go func() {
		defer a.wg.Done()
		_, _ = a.Schedule(base)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-base.Done():
				return
			case <-ticker.C:
				_, _ = a.Schedule(base)
			}
		}
	}()
}

func (a *LedgerAuditor) Stop() {
	a.mu.Lock()
	if a.stop != nil {
		a.stop()
	}
	if a.activeCancel != nil {
		a.activeCancel()
	}
	a.mu.Unlock()
	a.wg.Wait()
}

func (a *LedgerAuditor) Schedule(ctx context.Context) (AuditRun, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.active != "" {
		return a.store.GetAudit(ctx, a.active)
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return AuditRun{}, err
	}
	id := hex.EncodeToString(raw[:])
	if err := a.store.CreateAudit(ctx, id); err != nil {
		return AuditRun{}, err
	}
	a.active = id
	base := a.ctx
	if base == nil {
		base = context.Background()
	}
	jobCtx, cancel := context.WithTimeout(base, ledgerAuditBudget)
	a.activeCancel = cancel
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		defer cancel()
		a.run(jobCtx, id)
		a.mu.Lock()
		if a.active == id {
			a.active = ""
			a.activeCancel = nil
		}
		a.mu.Unlock()
	}()
	return a.store.GetAudit(ctx, id)
}

func (a *LedgerAuditor) run(ctx context.Context, id string) {
	result, target, prefix, failure, finding := "unavailable", AuditTarget{}, AuditPrefix{}, "chain_unavailable", ""
	if a.anchorer == nil {
	} else if err := a.scan(ctx, id, &target, &prefix); err != nil {
		failure, finding = "chain_unavailable", err.Error()
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			result, failure = "incomplete", "scan_interrupted"
		}
		if errors.Is(err, ethereum.NotFound) {
			failure = "history_unavailable"
		}
		if errors.Is(err, ErrChainIdentity) || strings.Contains(strings.ToLower(err.Error()), "mismatch") || strings.Contains(strings.ToLower(err.Error()), "conflict") || strings.Contains(strings.ToLower(err.Error()), "missing") {
			result, failure = "failed", "integrity_mismatch"
		}
	} else {
		result, failure = "passed", ""
	}
	if err := a.store.FinishAudit(context.Background(), id, result, target, prefix, failure, finding); err != nil {
		_ = a.store.AddChainFinding(context.Background(), "audit_persist_failure", err.Error())
	}
}

func (a *LedgerAuditor) scan(ctx context.Context, runID string, target *AuditTarget, prefix *AuditPrefix) error {
	chain := a.anchorer
	if err := chain.verifyIdentity(ctx); err != nil {
		return fmt.Errorf("chain identity unavailable: %w", err)
	}
	head, err := chain.client.HeaderByNumber(ctx, nil)
	if err != nil {
		return fmt.Errorf("read fixed chain target: %w", err)
	}
	blockTarget, batchTarget := head.Number.Uint64(), uint64(0)
	values, err := chain.callAt(ctx, head.Number, "getHead", [32]byte(a.store.streamID))
	if err != nil {
		return fmt.Errorf("read contract stream head: %w", err)
	}
	if len(values) != 1 {
		return errors.New("contract returned invalid stream head")
	}
	contractHead := *abi.ConvertType(values[0], new(chainHead)).(*chainHead)
	batchTarget = contractHead.BatchID
	blockHash := head.Hash().Hex()
	*target = AuditTarget{BatchID: &batchTarget, BlockNumber: &blockTarget, BlockHash: &blockHash}
	if err := a.store.SetAuditTarget(ctx, runID, batchTarget, blockTarget, head.Hash().Bytes()); err != nil {
		return err
	}
	var previous common.Hash
	for height := uint64(0); height <= blockTarget; height++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		h, e := chain.client.HeaderByNumber(ctx, new(big.Int).SetUint64(height))
		if e != nil {
			return fmt.Errorf("read historical block %d: %w", height, e)
		}
		if h.Number.Uint64() != height || (height > 0 && h.ParentHash != previous) {
			return fmt.Errorf("block continuity mismatch at block %d", height)
		}
		previous = h.Hash()
		prefix.BlockNumber = height
		if err := a.store.UpdateAuditPrefix(ctx, runID, *prefix); err != nil {
			return err
		}
		if height == ^uint64(0) {
			break
		}
	}
	rows, err := a.store.db.QueryContext(ctx, `SELECT b.batch_id,b.manifest_json,b.ack_json,b.ack_hash,q.state,q.receipt_json FROM witness_batches b JOIN witness_anchor_queue q USING(stream_id,batch_id) WHERE b.stream_id=? AND b.batch_id<=? ORDER BY b.batch_id`, a.store.streamID[:], batchTarget)
	if err != nil {
		return err
	}
	type retained struct {
		id                  uint64
		manifest, ack, hash []byte
		state               string
		receipt             []byte
	}
	var batches []retained
	for rows.Next() {
		var v retained
		if err := rows.Scan(&v.id, &v.manifest, &v.ack, &v.hash, &v.state, &v.receipt); err != nil {
			rows.Close()
			return err
		}
		batches = append(batches, v)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	var previousBatch, lastSeq uint64
	prevHash := a.store.genesis
	var previousAck integrity.Hash
	for _, row := range batches {
		if err := ctx.Err(); err != nil {
			return err
		}
		if row.id != previousBatch+1 {
			return fmt.Errorf("missing witness manifest for batch %d", previousBatch+1)
		}
		m, err := decodeManifest(row.manifest)
		if err != nil {
			return fmt.Errorf("batch %d manifest mismatch: %w", row.id, err)
		}
		if m.Descriptor.StreamID != a.store.streamID || m.Descriptor.BatchID != row.id || m.Descriptor.FirstSeq != lastSeq+1 || m.Descriptor.PrevBatchHash != prevHash {
			return fmt.Errorf("batch %d descriptor continuity mismatch", row.id)
		}
		var ack Acknowledgement
		if err := json.Unmarshal(row.ack, &ack); err != nil {
			return fmt.Errorf("batch %d acknowledgement mismatch: %w", row.id, err)
		}
		ack.AnchorState = row.state
		if len(row.receipt) == 0 {
			ack.AnchorReceipt = json.RawMessage("null")
		} else {
			ack.AnchorReceipt = row.receipt
		}
		batchHash, err := parseHash(ack.BatchHash)
		if err != nil {
			return err
		}
		streamID, err := parseHash(ack.StreamID)
		if err != nil {
			return err
		}
		prevAck, err := parseHash(ack.PreviousAckHash)
		if err != nil {
			return err
		}
		when, err := time.Parse(time.RFC3339Nano, ack.ReceivedAt)
		if err != nil {
			return err
		}
		sig, err := base64.StdEncoding.DecodeString(ack.Signature)
		if err != nil {
			return err
		}
		signed := integrity.SignedAcknowledgement{Acknowledgement: integrity.WitnessAcknowledgement{StreamID: streamID, BatchID: ack.BatchID, BatchHash: batchHash, PreviousAckHash: prevAck, WitnessKeyID: ack.KeyID, ReceivedAtNS: when.UnixNano()}, Signature: sig}
		if ack.BatchID != row.id || batchHash != m.BatchHash || streamID != a.store.streamID || prevAck != previousAck || integrity.VerifyAcknowledgement(signed, a.public) != nil {
			return fmt.Errorf("batch %d acknowledgement signature or chain mismatch", row.id)
		}
		ackHash, err := integrity.AcknowledgementHash(signed)
		if err != nil || !bytesEqual(row.hash, ackHash[:]) {
			return fmt.Errorf("batch %d acknowledgement digest mismatch", row.id)
		}
		if row.id <= contractHead.BatchID {
			if err := chain.verifyAuditedBatch(ctx, m, ack, head.Number); err != nil {
				return fmt.Errorf("batch %d anchor mismatch: %w", row.id, err)
			}
		}
		previousBatch, lastSeq, prevHash, previousAck = row.id, m.Descriptor.LastSeq, m.BatchHash, ackHash
		prefix.BatchID, prefix.EntrySeq = row.id, lastSeq
		if err := a.store.UpdateAuditPrefix(ctx, runID, *prefix); err != nil {
			return err
		}
	}
	if previousBatch < batchTarget {
		return fmt.Errorf("missing witness manifest for contract batch %d", previousBatch+1)
	}
	if contractHead.LastSeq != lastSeq || contractHead.BatchHash != [32]byte(prevHash) {
		return errors.New("contract head mismatch with audited witness batches")
	}
	current, err := chain.client.HeaderByNumber(ctx, new(big.Int).SetUint64(blockTarget))
	if err != nil || current.Hash() != head.Hash() {
		return errors.New("fixed target block hash changed during audit")
	}
	return ctx.Err()
}

func (a *Anchorer) verifyAuditedBatch(ctx context.Context, m validatedManifest, ack Acknowledgement, target *big.Int) error {
	if ack.AnchorState != "confirmed" {
		return errors.New("contract head includes a batch without a confirmed witness receipt")
	}
	values, err := a.callAt(ctx, target, "getBatch", [32]byte(m.Descriptor.StreamID), m.Descriptor.BatchID)
	if err != nil {
		return err
	}
	if len(values) != 1 {
		return errors.New("invalid contract batch")
	}
	b := *abi.ConvertType(values[0], new(chainBatch)).(*chainBatch)
	if b.FirstSeq != m.Descriptor.FirstSeq || b.LastSeq != m.Descriptor.LastSeq || b.LeafCount != m.Descriptor.LeafCount || b.MerkleRoot != [32]byte(m.Descriptor.MerkleRoot) || b.PrevBatchHash != [32]byte(m.Descriptor.PrevBatchHash) || b.BatchHash != [32]byte(m.BatchHash) {
		return errors.New("contract descriptor mismatch")
	}
	var receipt struct {
		TxHash      string `json:"tx_hash"`
		BlockNumber uint64 `json:"block_number"`
		BlockHash   string `json:"block_hash"`
		Status      string `json:"status"`
	}
	if err := json.Unmarshal(ack.AnchorReceipt, &receipt); err != nil {
		return err
	}
	if receipt.Status != "confirmed" || receipt.TxHash == "" || receipt.BlockHash == "" {
		return errors.New("confirmed batch has no valid receipt")
	}
	txHash := common.HexToHash(receipt.TxHash)
	r, err := a.client.TransactionReceipt(ctx, txHash)
	if err != nil {
		return err
	}
	if r == nil || r.TxHash != txHash || r.Status != types.ReceiptStatusSuccessful || r.BlockNumber.Uint64() != receipt.BlockNumber || r.BlockNumber.Cmp(target) > 0 || !strings.EqualFold(r.BlockHash.Hex(), receipt.BlockHash) {
		return errors.New("receipt identity mismatch")
	}
	h, err := a.client.HeaderByNumber(ctx, r.BlockNumber)
	if err != nil {
		return err
	}
	if h.Hash() != r.BlockHash {
		return errors.New("receipt block canonicality mismatch")
	}
	tx, _, err := a.client.TransactionByHash(ctx, txHash)
	if err != nil {
		return err
	}
	if err := a.verifyPersistedTx(tx, PendingAnchor{BatchID: m.Descriptor.BatchID}, m); err != nil {
		return fmt.Errorf("receipt transaction identity mismatch: %w", err)
	}
	event := a.parsed.Events["BatchAnchored"]
	found := false
	for _, log := range r.Logs {
		if log.Address != common.HexToAddress(a.config.Identity.ContractAddress) || len(log.Topics) != 3 || log.Topics[0] != event.ID || log.Topics[1] != common.Hash(m.Descriptor.StreamID) || new(big.Int).SetBytes(log.Topics[2].Bytes()).Uint64() != m.Descriptor.BatchID {
			continue
		}
		values, e := a.parsed.Unpack("BatchAnchored", log.Data)
		if e != nil {
			return e
		}
		if len(values) != 7 || values[0].(uint32) != m.Descriptor.CodecVersion || values[1].(uint64) != m.Descriptor.FirstSeq || values[2].(uint64) != m.Descriptor.LastSeq || values[3].(uint32) != m.Descriptor.LeafCount || values[4].([32]byte) != [32]byte(m.Descriptor.MerkleRoot) || values[5].([32]byte) != [32]byte(m.Descriptor.PrevBatchHash) || values[6].([32]byte) != [32]byte(m.BatchHash) {
			return errors.New("receipt event descriptor mismatch")
		}
		found = true
	}
	if !found {
		return errors.New("receipt event is missing")
	}
	return nil
}

func (s *Store) CreateAudit(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO witness_audit_runs(run_id,state,result,started_at) VALUES(?,'running','incomplete',?)`, id, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) SetAuditTarget(ctx context.Context, id string, batch, block uint64, hash []byte) error {
	_, err := s.db.ExecContext(ctx, `UPDATE witness_audit_runs SET target_batch_id=?,target_block_number=?,target_block_hash=? WHERE run_id=?`, batch, block, hash, id)
	return err
}

func (s *Store) UpdateAuditPrefix(ctx context.Context, id string, p AuditPrefix) error {
	_, err := s.db.ExecContext(ctx, `UPDATE witness_audit_runs SET verified_batch_id=?,verified_entry_seq=?,verified_block_number=? WHERE run_id=?`, p.BatchID, p.EntrySeq, p.BlockNumber, id)
	return err
}

func (s *Store) FinishAudit(ctx context.Context, id string, result string, target AuditTarget, prefix AuditPrefix, failure, detail string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var batch, block any
	var hash any
	if target.BatchID != nil {
		batch = *target.BatchID
	}
	if target.BlockNumber != nil {
		block = *target.BlockNumber
	}
	if target.BlockHash != nil {
		b, _ := hex.DecodeString(strings.TrimPrefix(*target.BlockHash, "0x"))
		hash = b
	}
	var failureValue any
	if failure != "" {
		failureValue = failure
	}
	_, err = tx.ExecContext(ctx, `UPDATE witness_audit_runs SET state='completed',result=?,completed_at=?,target_batch_id=COALESCE(?,target_batch_id),target_block_number=COALESCE(?,target_block_number),target_block_hash=COALESCE(?,target_block_hash),verified_batch_id=?,verified_entry_seq=?,verified_block_number=?,failure_class=?,finding_count=? WHERE run_id=?`, result, time.Now().UTC().Format(time.RFC3339Nano), batch, block, hash, prefix.BatchID, prefix.EntrySeq, prefix.BlockNumber, failureValue, boolInt(detail != ""), id)
	if err != nil {
		return err
	}
	if detail != "" {
		_, err = tx.ExecContext(ctx, `INSERT INTO witness_audit_findings(run_id,batch_id,block_number,classification,details,detected_at) VALUES(?,?,?,?,?,?)`, id, prefix.BatchID, prefix.BlockNumber, failure, detail, time.Now().UTC().Format(time.RFC3339Nano))
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (s *Store) GetAudit(ctx context.Context, id string) (AuditRun, error) {
	var r AuditRun
	var done sql.NullString
	var batch, block sql.NullInt64
	var hash []byte
	var fail sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT run_id,'ledger',state,result,started_at,completed_at,target_batch_id,target_block_number,target_block_hash,verified_batch_id,verified_entry_seq,verified_block_number,failure_class,finding_count FROM witness_audit_runs WHERE run_id=?`, id).Scan(&r.RunID, &r.Type, &r.State, &r.Result, &r.StartedAt, &done, &batch, &block, &hash, &r.VerifiedPrefix.BatchID, &r.VerifiedPrefix.EntrySeq, &r.VerifiedPrefix.BlockNumber, &fail, &r.FindingCount)
	if errors.Is(err, sql.ErrNoRows) {
		return r, sql.ErrNoRows
	}
	if err != nil {
		return r, err
	}
	if done.Valid {
		r.CompletedAt = &done.String
	}
	if batch.Valid {
		v := uint64(batch.Int64)
		r.Target.BatchID = &v
	}
	if block.Valid {
		v := uint64(block.Int64)
		r.Target.BlockNumber = &v
	}
	if len(hash) == 32 {
		v := formatHashFromBytes(hash)
		r.Target.BlockHash = &v
	}
	if fail.Valid {
		r.FailureClass = &fail.String
	}
	return r, nil
}

func (s *Store) LatestAudit(ctx context.Context) (*AuditRun, error) {
	var id string
	err := s.db.QueryRowContext(ctx, `SELECT run_id FROM witness_audit_runs ORDER BY started_at DESC LIMIT 1`).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	run, err := s.GetAudit(ctx, id)
	if err != nil {
		return nil, err
	}
	return &run, nil
}
