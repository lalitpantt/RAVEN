package witness

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"raven/internal/integrity"

	_ "modernc.org/sqlite"
)

const witnessSchemaVersion = 3

var (
	ErrEquivocation = errors.New("conflicting content for retained batch identity")
	ErrContinuity   = errors.New("batch does not continue the retained witness head")
)

type Store struct {
	db       *sql.DB
	streamID integrity.Hash
	genesis  integrity.Hash
}

type ChainIdentity struct {
	ChainID             uint64 `json:"chain_id"`
	GenesisBlockHash    string `json:"genesis_block_hash"`
	ContractAddress     string `json:"contract_address"`
	DeploymentBlock     uint64 `json:"deployment_block"`
	DeploymentBlockHash string `json:"deployment_block_hash"`
	RuntimeCodeHash     string `json:"runtime_code_hash"`
}

type Acknowledgement struct {
	StreamID        string          `json:"stream_id"`
	BatchID         uint64          `json:"batch_id"`
	BatchHash       string          `json:"batch_hash"`
	KeyID           string          `json:"key_id"`
	PreviousAckHash string          `json:"previous_ack_hash"`
	ReceivedAt      string          `json:"received_at"`
	Signature       string          `json:"signature"`
	AnchorState     string          `json:"anchor_state"`
	AnchorReceipt   json.RawMessage `json:"anchor_receipt"`
}

type RetainedBatch struct {
	Manifest        json.RawMessage `json:"manifest"`
	Acknowledgement Acknowledgement `json:"acknowledgement"`
}

type StoredHead struct {
	BatchID  uint64
	EntrySeq uint64
	Hash     *string
}

type StoreStatus struct {
	RetainedHead StoredHead
	BacklogCount int
}

type ReceiptSigner struct {
	KeyID string
	Key   ed25519.PrivateKey
}

type RetainResult struct {
	Acknowledgement Acknowledgement
	Duplicate       bool
}

func OpenStore(path string, streamID, genesis integrity.Hash) (*Store, error) {
	if streamID == (integrity.Hash{}) || genesis == (integrity.Hash{}) {
		return nil, errors.New("witness stream ID and genesis hash must be nonzero")
	}
	if path != ":memory:" && path != "file::memory:?cache=shared" {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, fmt.Errorf("create witness database directory: %w", err)
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if _, err := db.Exec(`PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL;`); err != nil {
		db.Close()
		return nil, fmt.Errorf("configure witness database: %w", err)
	}
	if err := migrateWitnessSchema(db); err != nil {
		db.Close()
		return nil, err
	}
	s := &Store{db: db, streamID: streamID, genesis: genesis}
	if err := s.registerStream(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(`UPDATE witness_audit_runs SET state='completed',result='incomplete',completed_at=?,failure_class='process_interrupted' WHERE state IN ('queued','running')`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		db.Close()
		return nil, fmt.Errorf("recover interrupted witness audits: %w", err)
	}
	return s, nil
}

func migrateWitnessSchema(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err := tx.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if version > witnessSchemaVersion {
		return fmt.Errorf("witness schema version %d is newer than supported version %d", version, witnessSchemaVersion)
	}
	if version == 0 {
		if _, err := tx.Exec(`
			CREATE TABLE witness_streams (
				stream_id BLOB PRIMARY KEY CHECK(length(stream_id)=32),
				genesis_hash BLOB NOT NULL CHECK(length(genesis_hash)=32),
				last_batch_id INTEGER NOT NULL DEFAULT 0 CHECK(last_batch_id BETWEEN 0 AND 9223372036854775807),
				last_seq INTEGER NOT NULL DEFAULT 0 CHECK(last_seq BETWEEN 0 AND 9223372036854775807),
				last_batch_hash BLOB NOT NULL CHECK(length(last_batch_hash)=32),
				last_ack_hash BLOB NOT NULL CHECK(length(last_ack_hash)=32),
				created_at TEXT NOT NULL
			);
			CREATE TABLE witness_batches (
				stream_id BLOB NOT NULL,
				batch_id INTEGER NOT NULL CHECK(batch_id BETWEEN 1 AND 9223372036854775807),
				first_seq INTEGER NOT NULL CHECK(first_seq BETWEEN 1 AND 9223372036854775807),
				last_seq INTEGER NOT NULL CHECK(last_seq BETWEEN first_seq AND 9223372036854775807),
				leaf_count INTEGER NOT NULL CHECK(leaf_count BETWEEN 1 AND 5000 AND leaf_count=last_seq-first_seq+1),
				batch_hash BLOB NOT NULL CHECK(length(batch_hash)=32),
				manifest_hash BLOB NOT NULL CHECK(length(manifest_hash)=32),
				manifest_json BLOB NOT NULL,
				ack_hash BLOB NOT NULL CHECK(length(ack_hash)=32),
				ack_json BLOB NOT NULL,
				received_at TEXT NOT NULL,
				PRIMARY KEY(stream_id,batch_id),
				UNIQUE(stream_id,batch_hash),
				FOREIGN KEY(stream_id) REFERENCES witness_streams(stream_id)
			);
			CREATE TABLE witness_anchor_queue (
				stream_id BLOB NOT NULL,
				batch_id INTEGER NOT NULL,
				state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','running','confirmed','failed')),
				attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count>=0),
				created_at TEXT NOT NULL,
				PRIMARY KEY(stream_id,batch_id),
				FOREIGN KEY(stream_id,batch_id) REFERENCES witness_batches(stream_id,batch_id)
			);
			CREATE INDEX witness_anchor_pending ON witness_anchor_queue(state,created_at);
			CREATE TABLE witness_findings (
				finding_id INTEGER PRIMARY KEY,
				stream_id BLOB NOT NULL,
				batch_id INTEGER NOT NULL,
				classification TEXT NOT NULL,
				details TEXT NOT NULL,
				detected_at TEXT NOT NULL
			);
			CREATE TRIGGER witness_batches_no_update BEFORE UPDATE ON witness_batches BEGIN SELECT RAISE(ABORT,'retained witness batches are immutable'); END;
			CREATE TRIGGER witness_batches_no_delete BEFORE DELETE ON witness_batches BEGIN SELECT RAISE(ABORT,'retained witness batches are immutable'); END;
			CREATE TRIGGER witness_stream_identity_no_update BEFORE UPDATE OF stream_id,genesis_hash ON witness_streams BEGIN SELECT RAISE(ABORT,'witness stream identity is immutable'); END;
			CREATE TRIGGER witness_stream_no_delete BEFORE DELETE ON witness_streams BEGIN SELECT RAISE(ABORT,'witness stream identity cannot be deleted'); END;
			PRAGMA user_version=1;`); err != nil {
			return fmt.Errorf("create witness schema v1: %w", err)
		}
		version = 1
	}
	if version == 1 {
		if _, err := tx.Exec(`
			ALTER TABLE witness_anchor_queue ADD COLUMN nonce INTEGER;
			ALTER TABLE witness_anchor_queue ADD COLUMN tx_bytes BLOB;
			ALTER TABLE witness_anchor_queue ADD COLUMN tx_hash BLOB;
			ALTER TABLE witness_anchor_queue ADD COLUMN receipt_json BLOB;
			ALTER TABLE witness_anchor_queue ADD COLUMN last_error TEXT;
			CREATE TABLE witness_chain_identity (
				id INTEGER PRIMARY KEY CHECK(id=1), identity_json BLOB NOT NULL, pinned_at TEXT NOT NULL
			);
			CREATE TABLE witness_chain_checkpoints (
				block_number INTEGER PRIMARY KEY CHECK(block_number>=0), block_hash BLOB NOT NULL CHECK(length(block_hash)=32), checked_at TEXT NOT NULL
			);
			PRAGMA user_version=2;`); err != nil {
			return fmt.Errorf("upgrade witness schema v1 to v2: %w", err)
		}
		version = 2
	}
	if version == 2 {
		if _, err := tx.Exec(`
			CREATE TABLE witness_audit_runs (
				run_id TEXT PRIMARY KEY,
				state TEXT NOT NULL CHECK(state IN ('queued','running','completed','failed')),
				result TEXT NOT NULL CHECK(result IN ('passed','failed','incomplete','unavailable','disabled')),
				started_at TEXT NOT NULL,
				completed_at TEXT,
				target_batch_id INTEGER CHECK(target_batch_id IS NULL OR target_batch_id>=0),
				target_block_number INTEGER CHECK(target_block_number IS NULL OR target_block_number>=0),
				target_block_hash BLOB CHECK(target_block_hash IS NULL OR length(target_block_hash)=32),
				verified_batch_id INTEGER NOT NULL DEFAULT 0,
				verified_entry_seq INTEGER NOT NULL DEFAULT 0,
				verified_block_number INTEGER NOT NULL DEFAULT 0,
				failure_class TEXT,
				finding_count INTEGER NOT NULL DEFAULT 0 CHECK(finding_count>=0)
			);
			CREATE INDEX witness_audit_latest ON witness_audit_runs(started_at DESC);
			CREATE TABLE witness_audit_findings (
				finding_id INTEGER PRIMARY KEY,
				run_id TEXT NOT NULL REFERENCES witness_audit_runs(run_id),
				batch_id INTEGER,
				block_number INTEGER,
				classification TEXT NOT NULL,
				details TEXT NOT NULL,
				detected_at TEXT NOT NULL
			);
			PRAGMA user_version=3;`); err != nil {
			return fmt.Errorf("upgrade witness schema v2 to v3: %w", err)
		}
	}
	return tx.Commit()
}

func (s *Store) registerStream(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO witness_streams(stream_id,genesis_hash,last_batch_hash,last_ack_hash,created_at) VALUES(?,?,?,?,?)`, s.streamID[:], s.genesis[:], s.genesis[:], make([]byte, 32), time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	var genesis []byte
	if err := s.db.QueryRowContext(ctx, `SELECT genesis_hash FROM witness_streams WHERE stream_id=?`, s.streamID[:]).Scan(&genesis); err != nil {
		return err
	}
	if !bytesEqual(genesis, s.genesis[:]) {
		return errors.New("configured witness stream genesis conflicts with retained identity")
	}
	return nil
}

func (s *Store) Retain(ctx context.Context, v validatedManifest, signer ReceiptSigner) (RetainResult, error) {
	var result RetainResult
	if v.Descriptor.StreamID != s.streamID {
		return result, errors.New("manifest stream is not registered in this witness")
	}
	if len(signer.Key) != ed25519.PrivateKeySize || signer.KeyID == "" {
		return result, errors.New("invalid witness receipt signer")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	var lastBatch, lastSeq uint64
	var lastHash, lastAck []byte
	if err := tx.QueryRowContext(ctx, `SELECT last_batch_id,last_seq,last_batch_hash,last_ack_hash FROM witness_streams WHERE stream_id=?`, s.streamID[:]).Scan(&lastBatch, &lastSeq, &lastHash, &lastAck); err != nil {
		return result, err
	}
	var oldHash, oldManifest, oldAck []byte
	err = tx.QueryRowContext(ctx, `SELECT batch_hash,manifest_hash,ack_json FROM witness_batches WHERE stream_id=? AND batch_id=?`, s.streamID[:], v.Descriptor.BatchID).Scan(&oldHash, &oldManifest, &oldAck)
	if err == nil {
		if bytesEqual(oldHash, v.BatchHash[:]) && bytesEqual(oldManifest, v.ManifestHash[:]) {
			if err := json.Unmarshal(oldAck, &result.Acknowledgement); err != nil {
				return result, fmt.Errorf("decode retained acknowledgement: %w", err)
			}
			result.Duplicate = true
			var receipt []byte
			if err := tx.QueryRowContext(ctx, `SELECT state,receipt_json FROM witness_anchor_queue WHERE stream_id=? AND batch_id=?`, s.streamID[:], v.Descriptor.BatchID).Scan(&result.Acknowledgement.AnchorState, &receipt); err != nil {
				return result, err
			}
			if len(receipt) == 0 {
				result.Acknowledgement.AnchorReceipt = json.RawMessage("null")
			} else {
				result.Acknowledgement.AnchorReceipt = receipt
			}
			return result, tx.Commit()
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO witness_findings(stream_id,batch_id,classification,details,detected_at) VALUES(?,?,'equivocation','conflicting manifest submitted for retained batch identity',?)`, s.streamID[:], v.Descriptor.BatchID, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return result, fmt.Errorf("record witness equivocation: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return result, err
		}
		return result, ErrEquivocation
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return result, err
	}
	if v.Descriptor.BatchID != lastBatch+1 || v.Descriptor.FirstSeq != lastSeq+1 || !bytesEqual(v.Descriptor.PrevBatchHash[:], lastHash) || len(lastAck) != 32 {
		return result, ErrContinuity
	}
	now := time.Now().UTC()
	var previousAck integrity.Hash
	copy(previousAck[:], lastAck)
	receipt := integrity.WitnessAcknowledgement{StreamID: s.streamID, BatchID: v.Descriptor.BatchID, BatchHash: v.BatchHash, PreviousAckHash: previousAck, WitnessKeyID: signer.KeyID, ReceivedAtNS: now.UnixNano()}
	signed, err := integrity.SignAcknowledgement(receipt, signer.Key)
	if err != nil {
		return result, err
	}
	ackHash, err := integrity.AcknowledgementHash(signed)
	if err != nil {
		return result, err
	}
	ack := Acknowledgement{
		StreamID: formatHash(s.streamID), BatchID: v.Descriptor.BatchID, BatchHash: formatHash(v.BatchHash),
		KeyID: signer.KeyID, PreviousAckHash: formatHash(previousAck), ReceivedAt: now.Format(time.RFC3339Nano),
		Signature: base64.StdEncoding.EncodeToString(signed.Signature), AnchorState: "pending", AnchorReceipt: json.RawMessage("null"),
	}
	ackJSON, err := json.Marshal(ack)
	if err != nil {
		return result, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO witness_batches(stream_id,batch_id,first_seq,last_seq,leaf_count,batch_hash,manifest_hash,manifest_json,ack_hash,ack_json,received_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, s.streamID[:], v.Descriptor.BatchID, v.Descriptor.FirstSeq, v.Descriptor.LastSeq, v.Descriptor.LeafCount, v.BatchHash[:], v.ManifestHash[:], v.Canonical, ackHash[:], ackJSON, now.Format(time.RFC3339Nano))
	if err != nil {
		return result, fmt.Errorf("retain witness manifest: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO witness_anchor_queue(stream_id,batch_id,created_at) VALUES(?,?,?)`, s.streamID[:], v.Descriptor.BatchID, now.Format(time.RFC3339Nano)); err != nil {
		return result, fmt.Errorf("queue retained batch for anchoring: %w", err)
	}
	updated, err := tx.ExecContext(ctx, `UPDATE witness_streams SET last_batch_id=?,last_seq=?,last_batch_hash=?,last_ack_hash=? WHERE stream_id=? AND last_batch_id=?`, v.Descriptor.BatchID, v.Descriptor.LastSeq, v.BatchHash[:], ackHash[:], s.streamID[:], lastBatch)
	if err != nil {
		return result, fmt.Errorf("advance witness head: %w", err)
	}
	if affected, _ := updated.RowsAffected(); affected != 1 {
		return result, ErrContinuity
	}
	if err := tx.Commit(); err != nil {
		return result, fmt.Errorf("commit retained witness manifest: %w", err)
	}
	result.Acknowledgement = ack
	return result, nil
}

func (s *Store) GetBatch(ctx context.Context, streamID integrity.Hash, batchID uint64) (RetainedBatch, error) {
	var result RetainedBatch
	if streamID != s.streamID {
		return result, sql.ErrNoRows
	}
	var manifest, ack []byte
	var state string
	var receipt []byte
	if err := s.db.QueryRowContext(ctx, `SELECT b.manifest_json,b.ack_json,q.state,q.receipt_json FROM witness_batches b JOIN witness_anchor_queue q USING(stream_id,batch_id) WHERE b.stream_id=? AND b.batch_id=?`, streamID[:], batchID).Scan(&manifest, &ack, &state, &receipt); err != nil {
		return result, err
	}
	result.Manifest = append(result.Manifest, manifest...)
	if err := json.Unmarshal(ack, &result.Acknowledgement); err != nil {
		return RetainedBatch{}, err
	}
	result.Acknowledgement.AnchorState = state
	if len(receipt) == 0 {
		result.Acknowledgement.AnchorReceipt = json.RawMessage("null")
	} else {
		result.Acknowledgement.AnchorReceipt = receipt
	}
	return result, nil
}

func (s *Store) PinChainIdentity(ctx context.Context, identity ChainIdentity) error {
	encoded, err := json.Marshal(identity)
	if err != nil {
		return err
	}
	var old []byte
	err = s.db.QueryRowContext(ctx, `SELECT identity_json FROM witness_chain_identity WHERE id=1`).Scan(&old)
	if errors.Is(err, sql.ErrNoRows) {
		_, err = s.db.ExecContext(ctx, `INSERT INTO witness_chain_identity(id,identity_json,pinned_at) VALUES(1,?,?)`, encoded, time.Now().UTC().Format(time.RFC3339Nano))
		return err
	}
	if err != nil {
		return err
	}
	if !bytesEqual(old, encoded) {
		_, _ = s.db.ExecContext(ctx, `INSERT INTO witness_findings(stream_id,batch_id,classification,details,detected_at) VALUES(?,0,'chain_identity_divergence','configured Ethereum identity differs from the retained baseline',?)`, s.streamID[:], time.Now().UTC().Format(time.RFC3339Nano))
		return errors.New("configured Ethereum identity conflicts with retained witness baseline")
	}
	return nil
}

func (s *Store) ChainIdentity(ctx context.Context) (*ChainIdentity, error) {
	var raw []byte
	if err := s.db.QueryRowContext(ctx, `SELECT identity_json FROM witness_chain_identity WHERE id=1`).Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	var identity ChainIdentity
	err := json.Unmarshal(raw, &identity)
	return &identity, err
}

type PendingAnchor struct {
	BatchID         uint64
	Manifest        []byte
	Nonce           sql.NullInt64
	TxBytes, TxHash []byte
	State           string
}

func (s *Store) NextAnchor(ctx context.Context) (PendingAnchor, error) {
	var p PendingAnchor
	err := s.db.QueryRowContext(ctx, `SELECT q.batch_id,b.manifest_json,q.nonce,q.tx_bytes,q.tx_hash,q.state FROM witness_anchor_queue q JOIN witness_batches b USING(stream_id,batch_id) WHERE q.stream_id=? AND q.state IN ('pending','running','failed') ORDER BY q.batch_id LIMIT 1`, s.streamID[:]).Scan(&p.BatchID, &p.Manifest, &p.Nonce, &p.TxBytes, &p.TxHash, &p.State)
	return p, err
}

func (s *Store) PersistAnchorTx(ctx context.Context, batch uint64, nonce uint64, raw []byte, hash []byte) error {
	result, err := s.db.ExecContext(ctx, `UPDATE witness_anchor_queue SET state='running',attempt_count=attempt_count+1,nonce=?,tx_bytes=?,tx_hash=?,last_error=NULL WHERE stream_id=? AND batch_id=? AND state IN ('pending','running') AND tx_bytes IS NULL`, nonce, raw, hash, s.streamID[:], batch)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return errors.New("another anchor worker already owns this batch")
	}
	return nil
}

func (s *Store) AnchorError(ctx context.Context, batch uint64, message string) error {
	if len(message) > 512 {
		message = message[:512]
	}
	_, err := s.db.ExecContext(ctx, `UPDATE witness_anchor_queue SET state='pending',last_error=? WHERE stream_id=? AND batch_id=? AND state IN ('pending','running')`, message, s.streamID[:], batch)
	return err
}

func (s *Store) ConfirmAnchor(ctx context.Context, batch uint64, receipt []byte, block uint64, hash []byte) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var existing []byte
	err = tx.QueryRowContext(ctx, `SELECT block_hash FROM witness_chain_checkpoints WHERE block_number=?`, block).Scan(&existing)
	if err == nil && !bytesEqual(existing, hash) {
		return fmt.Errorf("ethereum checkpoint at block %d conflicts with retained hash", block)
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE witness_anchor_queue SET state='confirmed',receipt_json=?,last_error=NULL WHERE stream_id=? AND batch_id=?`, receipt, s.streamID[:], batch); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO witness_chain_checkpoints(block_number,block_hash,checked_at) VALUES(?,?,?)`, block, hash, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) FailAnchor(ctx context.Context, batch uint64, message string) error {
	if len(message) > 512 {
		message = message[:512]
	}
	_, err := s.db.ExecContext(ctx, `UPDATE witness_anchor_queue SET state='failed',last_error=? WHERE stream_id=? AND batch_id=?`, message, s.streamID[:], batch)
	return err
}

func (s *Store) FailAnchorReceipt(ctx context.Context, batch uint64, receipt []byte, block uint64, hash []byte) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var existing []byte
	err = tx.QueryRowContext(ctx, `SELECT block_hash FROM witness_chain_checkpoints WHERE block_number=?`, block).Scan(&existing)
	if err == nil && !bytesEqual(existing, hash) {
		return fmt.Errorf("ethereum checkpoint at block %d conflicts with retained hash", block)
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE witness_anchor_queue SET state='failed',receipt_json=?,last_error='Ethereum anchor transaction reverted' WHERE stream_id=? AND batch_id=?`, receipt, s.streamID[:], batch)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return errors.New("failed anchor receipt has no retained batch")
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO witness_chain_checkpoints(block_number,block_hash,checked_at) VALUES(?,?,?)`, block, hash, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) AddChainFinding(ctx context.Context, class, detail string) error {
	if len(detail) > 512 {
		detail = detail[:512]
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO witness_findings(stream_id,batch_id,classification,details,detected_at) SELECT ?,0,?,?,? WHERE NOT EXISTS (SELECT 1 FROM witness_findings WHERE stream_id=? AND batch_id=0 AND classification=? AND details=?)`, s.streamID[:], class, detail, time.Now().UTC().Format(time.RFC3339Nano), s.streamID[:], class, detail)
	return err
}

func (s *Store) MarkReorg(ctx context.Context, fromBlock uint64, detail string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT batch_id,receipt_json FROM witness_anchor_queue WHERE stream_id=? AND state='confirmed'`, s.streamID[:])
	if err != nil {
		return err
	}
	type item struct {
		batch   uint64
		receipt []byte
	}
	var affected []item
	for rows.Next() {
		var id uint64
		var raw []byte
		if err := rows.Scan(&id, &raw); err != nil {
			rows.Close()
			return err
		}
		var r map[string]json.RawMessage
		if err := json.Unmarshal(raw, &r); err != nil {
			rows.Close()
			return err
		}
		var height uint64
		if err := json.Unmarshal(r["block_number"], &height); err != nil {
			rows.Close()
			return err
		}
		if height >= fromBlock {
			r["status"], _ = json.Marshal("reorged")
			updated, err := json.Marshal(r)
			if err != nil {
				rows.Close()
				return err
			}
			affected = append(affected, item{id, updated})
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, v := range affected {
		if _, err := tx.ExecContext(ctx, `UPDATE witness_anchor_queue SET state='failed',receipt_json=?,last_error='canonical anchor block changed' WHERE stream_id=? AND batch_id=?`, v.receipt, s.streamID[:], v.batch); err != nil {
			return err
		}
	}
	if len(detail) > 512 {
		detail = detail[:512]
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO witness_findings(stream_id,batch_id,classification,details,detected_at) SELECT ?,0,'chain_reorg',?,? WHERE NOT EXISTS (SELECT 1 FROM witness_findings WHERE stream_id=? AND batch_id=0 AND classification='chain_reorg' AND details=?)`, s.streamID[:], detail, time.Now().UTC().Format(time.RFC3339Nano), s.streamID[:], detail); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ConfirmedHead(ctx context.Context) (StoredHead, error) {
	var h StoredHead
	var hash []byte
	err := s.db.QueryRowContext(ctx, `SELECT b.batch_id,b.last_seq,b.batch_hash FROM witness_batches b JOIN witness_anchor_queue q USING(stream_id,batch_id) WHERE b.stream_id=? AND q.state='confirmed' ORDER BY b.batch_id DESC LIMIT 1`, s.streamID[:]).Scan(&h.BatchID, &h.EntrySeq, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return StoredHead{}, nil
	}
	if err != nil {
		return h, err
	}
	text := formatHashFromBytes(hash)
	h.Hash = &text
	return h, nil
}

func (s *Store) Status(ctx context.Context, streamID integrity.Hash) (StoreStatus, error) {
	var result StoreStatus
	if streamID != s.streamID {
		return result, sql.ErrNoRows
	}
	var batchID, seq uint64
	var hash []byte
	if err := s.db.QueryRowContext(ctx, `SELECT last_batch_id,last_seq,last_batch_hash FROM witness_streams WHERE stream_id=?`, streamID[:]).Scan(&batchID, &seq, &hash); err != nil {
		return result, err
	}
	result.RetainedHead = StoredHead{BatchID: batchID, EntrySeq: seq}
	if batchID != 0 {
		text := formatHashFromBytes(hash)
		result.RetainedHead.Hash = &text
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM witness_anchor_queue WHERE stream_id=? AND state IN ('pending','running','failed')`, streamID[:]).Scan(&result.BacklogCount); err != nil {
		return result, err
	}
	return result, nil
}

func (s *Store) Close() error { return s.db.Close() }

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func formatHashFromBytes(data []byte) string {
	var h integrity.Hash
	copy(h[:], data)
	return formatHash(h)
}
