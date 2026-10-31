package rawstore

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"
)

type IntegrityAuditRun struct {
	RunID       string  `json:"run_id"`
	Type        string  `json:"type"`
	State       string  `json:"state"`
	Result      string  `json:"result"`
	StartedAt   string  `json:"started_at"`
	CompletedAt *string `json:"completed_at"`
	Target      struct {
		BatchID     *uint64 `json:"batch_id"`
		BlockNumber *uint64 `json:"block_number"`
		BlockHash   *string `json:"block_hash"`
		EntrySeq    uint64  `json:"entry_seq"`
	} `json:"target"`
	VerifiedPrefix struct {
		BatchID     uint64 `json:"batch_id"`
		EntrySeq    uint64 `json:"entry_seq"`
		BlockNumber uint64 `json:"block_number"`
	} `json:"verified_prefix"`
	FailureClass *string `json:"failure_class"`
	FindingCount int     `json:"finding_count"`
}

// StartIntegrityAudit durably queues one fixed-head local audit per type.
func (s *RawStore) StartIntegrityAudit(ctx context.Context, deep bool) (IntegrityAuditRun, bool, error) {
	var run IntegrityAuditRun
	typ := "fast"
	if deep {
		typ = "deep"
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return run, false, err
	}
	defer tx.Rollback()
	if err := tx.QueryRowContext(ctx, `SELECT run_id FROM integrity_audit_runs WHERE run_type=? AND completed_at IS NULL ORDER BY started_at LIMIT 1`, typ).Scan(&run.RunID); err == nil {
		if err := tx.Commit(); err != nil {
			return run, false, err
		}
		existing, err := s.GetIntegrityAudit(ctx, run.RunID)
		return existing, true, err
	} else if !errors.Is(err, sql.ErrNoRows) {
		return run, false, err
	}
	var target uint64
	if err := tx.QueryRowContext(ctx, `SELECT next_entry_seq-1 FROM integrity_streams WHERE singleton=1 AND enabled=1`).Scan(&target); err != nil {
		return run, false, err
	}
	runID, err := newOperationID()
	if err != nil {
		return run, false, err
	}
	started := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `INSERT INTO integrity_audit_runs(run_id,run_type,target_head,started_at,heartbeat_at,cursor_seq,checked_count,result) VALUES(?,?,?,?,?,0,0,'incomplete')`, runID, typ, target, started, started); err != nil {
		return run, false, err
	}
	if err := tx.Commit(); err != nil {
		return run, false, err
	}
	run, err = s.GetIntegrityAudit(ctx, runID)
	return run, false, err
}

func (s *RawStore) GetIntegrityAudit(ctx context.Context, id string) (IntegrityAuditRun, error) {
	var r IntegrityAuditRun
	var target, cursor uint64
	var completed, failure sql.NullString
	var result sql.NullString
	if err := s.db.QueryRowContext(ctx, `SELECT run_id,run_type,target_head,started_at,completed_at,cursor_seq,result,error_class FROM integrity_audit_runs WHERE run_id=?`, id).
		Scan(&r.RunID, &r.Type, &target, &r.StartedAt, &completed, &cursor, &result, &failure); err != nil {
		return r, err
	}
	r.State = "running"
	if completed.Valid {
		r.State = "completed"
		if result.String == "failed" {
			r.State = "failed"
		}
		r.CompletedAt = &completed.String
	}
	r.Result = result.String
	r.Target.EntrySeq = target
	r.VerifiedPrefix.EntrySeq = cursor
	if failure.Valid {
		r.FailureClass = &failure.String
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM integrity_findings WHERE run_id=?`, id).Scan(&r.FindingCount); err != nil {
		return r, err
	}
	var batch uint64
	_ = s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(batch_id),0) FROM integrity_batches WHERE last_seq<=?`, cursor).Scan(&batch)
	r.VerifiedPrefix.BatchID = batch
	return r, nil
}

func (s *RawStore) IntegrityOperatorStatus(ctx context.Context) (enabled bool, localHead map[string]any, backlog int, oldest *string, unsealed uint64, err error) {
	localHead = map[string]any{"batch_id": uint64(0), "entry_seq": uint64(0), "hash": nil}
	stream, err := s.GetIntegrityStream(ctx)
	if err != nil || stream == nil {
		return false, localHead, 0, nil, 0, err
	}
	enabled = true
	localHead["batch_id"], localHead["entry_seq"] = stream.NextBatchID-1, stream.NextEntrySeq-1
	localHead["hash"] = "0x" + hex.EncodeToString(stream.LastBatchHash[:])
	if stream.NextEntrySeq-1 < stream.LastSealedSeq {
		err = errors.New("integrity sealed head exceeds journal head")
		return
	}
	unsealed = stream.NextEntrySeq - 1 - stream.LastSealedSeq
	if err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM integrity_witness_sync WHERE state NOT IN ('anchored','confirmed')`).Scan(&backlog); err != nil {
		return
	}
	var value sql.NullString
	err = s.db.QueryRowContext(ctx, `SELECT MIN(b.sealed_at) FROM integrity_witness_sync w JOIN integrity_batches b USING(stream_id,batch_id) WHERE w.state NOT IN ('anchored','confirmed')`).Scan(&value)
	if value.Valid {
		oldest = &value.String
	}
	return
}
