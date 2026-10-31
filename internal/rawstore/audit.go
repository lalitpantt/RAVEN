package rawstore

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"raven/internal/integrity"
)

const (
	dataAuditBudget = 30 * time.Second
	dataAuditBytes  = 64 << 20
)

// shortcut: audits stop at 30 seconds/64 MiB; increase these only after WAL and writer contention measurements.

// AuditIntegrity performs a fixed-head local audit. Deep mode also rehashes raw
// payloads and checks current normalized projections against their evidence.
func (s *RawStore) AuditIntegrity(ctx context.Context, deep bool) (string, string, error) {
	enabled, err := s.IntegrityEnabled(ctx)
	if err != nil {
		return "", "", err
	}
	if !enabled {
		return "", "disabled", nil
	}
	run, active, err := s.StartIntegrityAudit(ctx, deep)
	if err != nil {
		return "", "", err
	}
	if active {
		return run.RunID, run.Result, nil
	}
	result, err := s.RunIntegrityAudit(ctx, run.RunID)
	return run.RunID, result, err
}

// RunIntegrityAudit executes a previously-created fixed-target audit run.
func (s *RawStore) RunIntegrityAudit(ctx context.Context, id string) (string, error) {
	var typ string
	var target uint64
	if err := s.db.QueryRowContext(ctx, `SELECT run_type,target_head FROM integrity_audit_runs WHERE run_id=? AND completed_at IS NULL`, id).Scan(&typ, &target); err != nil {
		return "", err
	}
	if typ != "fast" && typ != "deep" {
		return "", errors.New("unknown integrity audit type")
	}
	deep := typ == "deep"
	auditCtx, cancel := context.WithTimeout(ctx, dataAuditBudget)
	defer cancel()
	result, failure := "passed", ""
	var checked uint64
	var bytesRead int64
	stream, err := s.GetIntegrityStream(auditCtx)
	if err != nil || stream == nil {
		if err == nil {
			err = errors.New("integrity stream disappeared during audit")
		}
		return "unavailable", s.finishDataAudit(context.Background(), id, "unavailable", 0, target, "storage_unavailable", err.Error())
	}
	for checked < target {
		if err := auditCtx.Err(); err != nil {
			result, failure = "incomplete", "budget_or_cancellation"
			break
		}
		entries, err := s.auditEntries(auditCtx, checked, integrity.MaxBatchEntries)
		if err != nil {
			result, failure = "unavailable", "storage_unavailable"
			if auditCtx.Err() != nil {
				result, failure = "incomplete", "budget_or_cancellation"
			}
			break
		}
		if len(entries) == 0 {
			result, failure = "failed", "missing_entry"
			break
		}
		for _, e := range entries {
			if e.Sequence != checked+1 {
				result, failure = "failed", "sequence_gap"
				break
			}
			bytesRead += int64(len(e.EncodedEntry) + len(e.ContentSnapshot) + len(e.MetadataSnapshot))
			decoded, decodeErr := integrity.DecodeEvidenceEntry(e.EncodedEntry)
			leaf := integrity.MerkleLeaf(e.EncodedEntry)
			if decodeErr != nil || decoded.Sequence != e.Sequence || decoded.StreamID != stream.StreamID || decoded.Kind != e.Kind || decoded.ContentDigest != e.ContentDigest || decoded.MetadataDigest != e.MetadataDigest || leaf != e.LeafHash || integrity.HashContent(e.MetadataSnapshot) != e.MetadataDigest {
				result, failure = "failed", "journal_hash_mismatch"
				break
			}
			if e.Kind == integrity.RawCommitted {
				if len(e.ContentSnapshot) != 0 {
					result, failure = "failed", "raw_snapshot_mismatch"
					break
				}
				var storedHash string
				if err := s.db.QueryRowContext(auditCtx, `SELECT raw_sha256 FROM raw_events WHERE raw_id=?`, e.RawID).Scan(&storedHash); err != nil {
					result, failure = "failed", "raw_projection_missing"
					break
				}
				if storedHash != hex.EncodeToString(e.ContentDigest[:]) {
					result, failure = "failed", "raw_digest_mismatch"
					break
				}
			} else if integrity.HashContent(e.ContentSnapshot) != e.ContentDigest {
				result, failure = "failed", "snapshot_digest_mismatch"
				break
			}
			if deep && e.Kind == integrity.RawCommitted {
				var rawBytes int64
				if err := s.db.QueryRowContext(auditCtx, `SELECT byte_count FROM raw_events WHERE raw_id=?`, e.RawID).Scan(&rawBytes); err != nil {
					result, failure = "unavailable", "raw_unavailable"
					break
				}
				if bytesRead+rawBytes > dataAuditBytes {
					result, failure = "incomplete", "snapshot_byte_budget"
					break
				}
				bytesRead += rawBytes
				ok, _, verifyErr := s.Verify(auditCtx, e.RawID)
				if verifyErr != nil {
					result, failure = "unavailable", "raw_unavailable"
					break
				}
				if !ok {
					result, failure = "failed", "raw_content_mismatch"
					break
				}
			}
			if deep && e.Kind == integrity.NormalizedWritten {
				report, verifyErr := s.VerifyNormalized(auditCtx, e.SubjectID)
				if verifyErr != nil {
					result, failure = "failed", "projection_missing"
					break
				}
				if !report.Passed {
					result, failure = "failed", "projection_mismatch"
					break
				}
			}
			checked = e.Sequence
			if bytesRead > dataAuditBytes {
				result, failure = "incomplete", "snapshot_byte_budget"
				break
			}
		}
		if result != "passed" {
			break
		}
		if len(entries) < integrity.MaxBatchEntries && checked < target {
			result, failure = "failed", "missing_entry"
			break
		}
		if _, err := s.db.ExecContext(ctx, `UPDATE integrity_audit_runs SET cursor_seq=?,checked_count=?,heartbeat_at=? WHERE run_id=?`, checked, checked, time.Now().UTC().Format(time.RFC3339Nano), id); err != nil {
			result, failure = "unavailable", "storage_unavailable"
			break
		}
	}
	if result == "passed" {
		if err := s.auditBatches(auditCtx, stream); err != nil {
			result, failure = "failed", "batch_mismatch"
			if auditCtx.Err() != nil {
				result, failure = "incomplete", "budget_or_cancellation"
			}
		}
	}
	if result == "passed" {
		if err := s.auditProjectionMembership(auditCtx, stream.StreamID); err != nil {
			result, failure = "failed", "projection_membership_mismatch"
		}
	}
	if auditCtx.Err() != nil && result == "unavailable" {
		result, failure = "incomplete", "budget_or_cancellation"
	}
	if result == "passed" {
		var current uint64
		if err := s.db.QueryRowContext(ctx, `SELECT next_entry_seq-1 FROM integrity_streams WHERE singleton=1 AND enabled=1`).Scan(&current); err != nil {
			result, failure = "unavailable", "storage_unavailable"
		} else if current != target {
			result, failure = "incomplete", "snapshot_advanced"
		}
	}
	if result == "passed" && checked != target {
		result, failure = "incomplete", "target_not_reached"
	}
	err = s.finishDataAudit(context.Background(), id, result, checked, target, failure, failure)
	return result, err
}

func (s *RawStore) auditBatches(ctx context.Context, stream *IntegrityStream) error {
	readDB := s.auditDB
	if readDB == nil {
		readDB = s.db
	}
	rows, err := readDB.QueryContext(ctx, `SELECT batch_id,first_seq,last_seq,leaf_count,merkle_root,prev_batch_hash,batch_hash,encoded_descriptor FROM integrity_batches WHERE stream_id=? AND batch_id<? ORDER BY batch_id`, stream.StreamID[:], stream.NextBatchID)
	if err != nil {
		return err
	}
	type batch struct {
		id, first, last           uint64
		count                     uint32
		root, prev, hash, encoded []byte
	}
	var batches []batch
	for rows.Next() {
		var b batch
		if err := rows.Scan(&b.id, &b.first, &b.last, &b.count, &b.root, &b.prev, &b.hash, &b.encoded); err != nil {
			rows.Close()
			return err
		}
		batches = append(batches, b)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	previousHash := stream.GenesisHash
	var nextSeq uint64 = 1
	for i, b := range batches {
		if b.id != uint64(i+1) || b.first != nextSeq || b.last < b.first || b.count == 0 || uint64(b.count) != b.last-b.first+1 || len(b.root) != 32 || len(b.prev) != 32 || len(b.hash) != 32 || !equalBytes(b.prev, previousHash[:]) {
			return fmt.Errorf("batch %d descriptor continuity mismatch", b.id)
		}
		members, err := readDB.QueryContext(ctx, `SELECT m.leaf_index,m.entry_seq,m.leaf_hash,e.leaf_hash FROM integrity_batch_entries m LEFT JOIN integrity_entries e ON e.stream_id=m.stream_id AND e.entry_seq=m.entry_seq WHERE m.stream_id=? AND m.batch_id=? ORDER BY m.leaf_index`, stream.StreamID[:], b.id)
		if err != nil {
			return err
		}
		leaves := make([]integrity.Hash, 0, b.count)
		var index int
		for members.Next() {
			var gotIndex int
			var seq uint64
			var leaf, entryLeaf []byte
			if err := members.Scan(&gotIndex, &seq, &leaf, &entryLeaf); err != nil {
				members.Close()
				return err
			}
			if gotIndex != index || seq != b.first+uint64(index) || len(leaf) != 32 || !equalBytes(leaf, entryLeaf) {
				members.Close()
				return fmt.Errorf("batch %d membership mismatch", b.id)
			}
			var h integrity.Hash
			copy(h[:], leaf)
			leaves = append(leaves, h)
			index++
		}
		if err := members.Err(); err != nil {
			members.Close()
			return err
		}
		if err := members.Close(); err != nil {
			return err
		}
		if index != int(b.count) {
			return fmt.Errorf("batch %d membership count mismatch", b.id)
		}
		root, err := integrity.MerkleRoot(leaves)
		if err != nil || !equalBytes(root[:], b.root) {
			return fmt.Errorf("batch %d Merkle root mismatch", b.id)
		}
		d := integrity.BatchDescriptor{CodecVersion: uint32(integrity.CodecVersion), StreamID: stream.StreamID, BatchID: b.id, FirstSeq: b.first, LastSeq: b.last, LeafCount: b.count, MerkleRoot: root, PrevBatchHash: previousHash}
		hash, err := integrity.HashBatchDescriptor(d)
		if err != nil || !equalBytes(hash[:], b.hash) {
			return fmt.Errorf("batch %d hash mismatch", b.id)
		}
		encoded, err := integrity.EncodeBatchDescriptorABI(d)
		if err != nil || !equalBytes(encoded[:], b.encoded) {
			return fmt.Errorf("batch %d ABI descriptor mismatch", b.id)
		}
		previousHash = hash
		nextSeq = b.last + 1
	}
	if len(batches) > 0 && (nextSeq-1 != stream.LastSealedSeq || !equalBytes(previousHash[:], stream.LastBatchHash[:])) {
		return errors.New("sealed stream head mismatch")
	}
	if len(batches) == 0 && (stream.LastSealedSeq != 0 || stream.LastBatchHash != stream.GenesisHash) {
		return errors.New("sealed stream head missing batches")
	}
	return nil
}

func (s *RawStore) auditProjectionMembership(ctx context.Context, stream integrity.Hash) error {
	checks := []string{
		`SELECT COUNT(*) FROM raw_events r WHERE NOT EXISTS(SELECT 1 FROM integrity_entries e WHERE e.stream_id=? AND e.entry_kind=? AND e.raw_id=r.raw_id)`,
		`SELECT COUNT(*) FROM normalized_events n WHERE NOT EXISTS(SELECT 1 FROM integrity_entries e WHERE e.stream_id=? AND e.entry_kind=? AND e.subject_id=n.event_id AND NOT EXISTS(SELECT 1 FROM integrity_entries x WHERE x.stream_id=e.stream_id AND x.subject_id=e.subject_id AND x.entry_seq>e.entry_seq AND x.entry_kind=?))`,
		`SELECT COUNT(*) FROM quarantine q WHERE NOT EXISTS(SELECT 1 FROM integrity_entries e WHERE e.stream_id=? AND e.entry_kind=? AND e.subject_id=q.quarantine_id AND NOT EXISTS(SELECT 1 FROM integrity_entries x WHERE x.stream_id=e.stream_id AND x.subject_id=e.subject_id AND x.entry_seq>e.entry_seq AND x.entry_kind=?))`,
	}
	args := [][]any{{stream[:], integrity.RawCommitted}, {stream[:], integrity.NormalizedWritten, integrity.NormalizedRemoved}, {stream[:], integrity.QuarantineWritten, integrity.QuarantineRemoved}}
	for i, query := range checks {
		var count int
		if err := s.db.QueryRowContext(ctx, query, args[i]...).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return fmt.Errorf("projection membership mismatch (%d rows)", count)
		}
	}
	return nil
}

func (s *RawStore) auditEntries(ctx context.Context, after uint64, limit int) ([]IntegrityEntry, error) {
	db := s.auditDB
	if db == nil {
		db = s.db
	}
	rows, err := db.QueryContext(ctx, `SELECT entry_seq,entry_kind,subject_id,raw_id,child_ordinal,operation_id,occurred_at_unix_ns,content_snapshot,metadata_snapshot,content_digest,metadata_digest,encoded_entry,leaf_hash FROM integrity_entries WHERE stream_id=(SELECT stream_id FROM integrity_streams WHERE singleton=1) AND entry_seq>? ORDER BY entry_seq LIMIT ?`, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IntegrityEntry
	for rows.Next() {
		var e IntegrityEntry
		var subject, raw, operation sql.NullString
		var content, metadata, leaf []byte
		if err := rows.Scan(&e.Sequence, &e.Kind, &subject, &raw, &e.ChildOrdinal, &operation, &e.OccurredAtNS, &e.ContentSnapshot, &e.MetadataSnapshot, &content, &metadata, &e.EncodedEntry, &leaf); err != nil {
			return nil, err
		}
		e.SubjectID = subject.String
		e.RawID = raw.String
		e.OperationID = operation.String
		copy(e.ContentDigest[:], content)
		copy(e.MetadataDigest[:], metadata)
		copy(e.LeafHash[:], leaf)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *RawStore) finishDataAudit(ctx context.Context, id, result string, checked, target uint64, class, detail string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var failure any
	if class != "" {
		failure = class
	}
	if _, err = tx.ExecContext(ctx, `UPDATE integrity_audit_runs SET result=?,completed_at=?,cursor_seq=?,checked_count=?,first_failed_seq=CASE WHEN ?='failed' THEN ? ELSE first_failed_seq END,error_class=? WHERE run_id=?`, result, now, checked, checked, result, checked, failure, id); err != nil {
		return err
	}
	if class != "" {
		if _, err = tx.ExecContext(ctx, `INSERT INTO integrity_findings(run_id,detected_at,entry_seq,classification,details,first_seen_at,last_seen_at) VALUES(?,?,?,?,?,?,?)`, id, now, checked, class, detail, now, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// StartIntegrityAudits runs the opt-in fast and deep checks on their documented cadence.
func (s *RawStore) StartIntegrityAudits(ctx context.Context) {
	s.auditMu.Lock()
	if s.auditCancel != nil {
		s.auditMu.Unlock()
		return
	}
	ctx, s.auditCancel = context.WithCancel(ctx)
	s.auditWG.Add(1)
	s.auditMu.Unlock()
	go func() {
		defer s.auditWG.Done()
		fast := time.NewTicker(time.Hour)
		defer fast.Stop()
		var enabledAt string
		if err := s.db.QueryRowContext(ctx, `SELECT enabled_at FROM integrity_streams WHERE singleton=1 AND enabled=1`).Scan(&enabledAt); err != nil {
			return
		}
		started, err := time.Parse(time.RFC3339Nano, enabledAt)
		if err != nil {
			return
		}
		firstDeep := time.NewTimer(time.Until(started.Add(24 * time.Hour)))
		defer firstDeep.Stop()
		firstDue := firstDeep.C
		var deep *time.Ticker
		var deepDue <-chan time.Time
		defer func() {
			if deep != nil {
				deep.Stop()
			}
		}()
		for {
			select {
			case <-ctx.Done():
				return
			case <-fast.C:
				s.runScheduledDataAudit(ctx, false)
			case <-firstDue:
				firstDue = nil
				s.runScheduledDataAudit(ctx, true)
				deep = time.NewTicker(24 * time.Hour)
				deepDue = deep.C
			case <-deepDue:
				s.runScheduledDataAudit(ctx, true)
			}
		}
	}()
}

func (s *RawStore) stopIntegrityAudits() {
	s.auditMu.Lock()
	if s.auditCancel != nil {
		s.auditCancel()
		s.auditCancel = nil
	}
	s.auditMu.Unlock()
	s.auditWG.Wait()
}

func (s *RawStore) runScheduledDataAudit(ctx context.Context, deep bool) {
	c, cancel := context.WithTimeout(ctx, dataAuditBudget)
	defer cancel()
	_, _, _ = s.AuditIntegrity(c, deep)
}
