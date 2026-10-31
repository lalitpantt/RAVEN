package rawstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/url"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"raven/internal/integrity"
	"raven/internal/model"
)

type IntegrityStream struct {
	StreamID          integrity.Hash
	InstallationEpoch integrity.Hash
	GenesisHash       integrity.Hash
	NextEntrySeq      uint64
	NextBatchID       uint64
	LastSealedSeq     uint64
	LastBatchHash     integrity.Hash
}

type IntegrityEntry struct {
	Sequence         uint64
	Kind             integrity.EntryKind
	SubjectID        string
	RawID            string
	ChildOrdinal     sql.NullInt64
	OperationID      string
	OccurredAtNS     int64
	ContentSnapshot  []byte
	MetadataSnapshot []byte
	ContentDigest    integrity.Hash
	MetadataDigest   integrity.Hash
	EncodedEntry     []byte
	LeafHash         integrity.Hash
	CommittedAt      string
}

var (
	ErrReplayOperationConflict = errors.New("replay operation ID conflicts with another request")
	ErrReplayTargetNotFound    = errors.New("quarantine entry not found")
	ErrReplayIneligible        = errors.New("quarantine entry is not eligible for replay")
	ErrReplayAlreadyFailed     = errors.New("replay operation previously failed")
)

type ReplayOperation struct {
	ID         string
	State      string
	Enabled    bool
	Entry      *model.QuarantineEntry
	ResultJSON []byte
}

// BeginReplay claims one target or returns the durable result of a prior attempt.
func (s *RawStore) BeginReplay(ctx context.Context, qID, operationID string) (*ReplayOperation, error) {
	if operationID == "" {
		var err error
		operationID, err = newOperationID()
		if err != nil {
			return nil, err
		}
	}
	if len(operationID) > 128 || !utf8.ValidString(operationID) || strings.IndexByte(operationID, 0) >= 0 {
		return nil, errors.New("replay operation ID must be 1-128 valid UTF-8 bytes without NUL")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	enabled, err := integrityEnabledTx(ctx, tx)
	if err != nil {
		return nil, err
	}
	op := &ReplayOperation{ID: operationID, Enabled: enabled}
	{
		var fingerprint []byte
		var qid, rawID, state string
		var errorClass sql.NullString
		var ordinal int
		var resultSeq sql.NullInt64
		err = tx.QueryRowContext(ctx, `SELECT request_fingerprint,quarantine_id,raw_id,child_ordinal,state,normalized_entry_seq,error_class FROM integrity_operations WHERE operation_id=?`, operationID).Scan(&fingerprint, &qid, &rawID, &ordinal, &state, &resultSeq, &errorClass)
		if err == nil {
			expected := replayFingerprint(qid, rawID, ordinal)
			if qid != qID || !equalBytes(fingerprint, expected[:]) {
				return nil, ErrReplayOperationConflict
			}
			op.State = state
			if state == "completed" {
				if enabled {
					if !resultSeq.Valid {
						return nil, errors.New("completed replay operation has no normalized evidence reference")
					}
					if err := tx.QueryRowContext(ctx, `SELECT content_snapshot FROM integrity_entries WHERE stream_id=(SELECT stream_id FROM integrity_streams WHERE singleton=1) AND entry_seq=? AND entry_kind=?`, resultSeq.Int64, integrity.NormalizedWritten).Scan(&op.ResultJSON); err != nil {
						return nil, fmt.Errorf("load completed replay result: %w", err)
					}
				} else {
					var summary string
					if err := tx.QueryRowContext(ctx, `SELECT result_summary FROM integrity_operations WHERE operation_id=?`, operationID).Scan(&summary); err != nil {
						return nil, fmt.Errorf("load completed replay result: %w", err)
					}
					op.ResultJSON = []byte(summary)
				}
				if err := tx.Commit(); err != nil {
					return nil, err
				}
				return op, nil
			}
			if state == "failed" {
				return nil, fmt.Errorf("%w: %s", ErrReplayAlreadyFailed, errorClass.String)
			}
			if state != "running" {
				return nil, fmt.Errorf("invalid replay operation state %q", state)
			}
			op.Entry, err = loadQuarantineTx(ctx, tx, qID)
			if errors.Is(err, sql.ErrNoRows) {
				return nil, ErrReplayTargetNotFound
			}
			if err != nil {
				return nil, err
			}
			if op.Entry.RawID != rawID || op.Entry.RecordOrdinal != ordinal {
				return nil, ErrReplayOperationConflict
			}
			if !op.Entry.ReplayEligible {
				return nil, ErrReplayIneligible
			}
			if err := tx.Commit(); err != nil {
				return nil, err
			}
			return op, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("read replay operation: %w", err)
		}
	}
	op.Entry, err = loadQuarantineTx(ctx, tx, qID)
	if errors.Is(err, sql.ErrNoRows) {
		var completedOperation string
		if lookupErr := tx.QueryRowContext(ctx, `SELECT operation_id FROM integrity_operations WHERE quarantine_id=? AND state='completed' LIMIT 1`, qID).Scan(&completedOperation); lookupErr == nil {
			return nil, ErrReplayOperationConflict
		} else if !errors.Is(lookupErr, sql.ErrNoRows) {
			return nil, lookupErr
		}
		return nil, fmt.Errorf("%w: %s", ErrReplayTargetNotFound, qID)
	}
	if err != nil {
		return nil, err
	}
	if !op.Entry.ReplayEligible {
		return nil, ErrReplayIneligible
	}
	fingerprint := replayFingerprint(qID, op.Entry.RawID, op.Entry.RecordOrdinal)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `INSERT INTO integrity_operations(operation_id,request_fingerprint,quarantine_id,raw_id,child_ordinal,state,created_at) VALUES(?,?,?,?,?,'running',?)`, operationID, fingerprint[:], qID, op.Entry.RawID, op.Entry.RecordOrdinal, now); err != nil {
		return nil, fmt.Errorf("claim replay operation: %w", err)
	}
	op.State = "running"
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return op, nil
}

type evidenceWrite struct {
	kind               integrity.EntryKind
	subjectID          *string
	rawID              *string
	childOrdinal       *uint32
	operationID        *string
	previousSubjectSeq *uint64
	occurredAt         time.Time
	contentSnapshot    []byte
	contentBytes       []byte
	contentFields      []integrity.TypedField
	metadataFields     []integrity.TypedField
}

func (s *RawStore) IntegrityEnabled(ctx context.Context) (bool, error) {
	var enabled int
	err := s.db.QueryRowContext(ctx, `SELECT enabled FROM integrity_streams WHERE singleton=1`).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return enabled == 1, err
}

// EnableIntegrity starts a new evidence stream only on a truly fresh data store.
func (s *RawStore) EnableIntegrity(ctx context.Context, streamID, installationEpoch integrity.Hash) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if streamID == (integrity.Hash{}) || installationEpoch == (integrity.Hash{}) {
		return errors.New("stream ID and installation epoch must be nonzero random 32-byte values")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var currentID, currentEpoch []byte
	err = tx.QueryRowContext(ctx, `SELECT stream_id,installation_epoch FROM integrity_streams WHERE singleton=1`).Scan(&currentID, &currentEpoch)
	if err == nil {
		if equalBytes(currentID, streamID[:]) && equalBytes(currentEpoch, installationEpoch[:]) {
			return tx.Commit()
		}
		return errors.New("an integrity stream already exists; stream identity cannot be replaced")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read integrity stream: %w", err)
	}
	var existing int64
	if err := tx.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM raw_events)+
		(SELECT COUNT(*) FROM normalized_events)+
		(SELECT COUNT(*) FROM quarantine)`).Scan(&existing); err != nil {
		return err
	}
	if existing != 0 {
		return errors.New("integrity cannot start on a populated database without complete historical evidence; create a fresh development database and stream")
	}
	var auditDB *sql.DB
	if !strings.Contains(s.dbPath, ":memory:") {
		auditDB, err = openReadOnlyDB(s.dbPath)
		if err != nil {
			return fmt.Errorf("open bounded integrity audit reader: %w", err)
		}
		committed := false
		defer func() {
			if !committed {
				_ = auditDB.Close()
			}
		}()
		defer func() {
			if committed {
				s.auditDB = auditDB
			}
		}()
		genesis := integrity.GenesisHash(streamID, installationEpoch)
		_, err = tx.ExecContext(ctx, `INSERT INTO integrity_streams(singleton,stream_id,codec_version,installation_epoch,genesis_hash,enabled,next_entry_seq,next_batch_id,last_sealed_seq,last_batch_hash,enabled_at)
			VALUES(1,?,1,?,?,1,1,1,0,?,?)`, streamID[:], installationEpoch[:], genesis[:], genesis[:], time.Now().UTC().Format(time.RFC3339Nano))
		if err != nil {
			return fmt.Errorf("enable integrity stream: %w", err)
		}
		if err = tx.Commit(); err != nil {
			return err
		}
		committed = true
		s.startIntegritySealer()
		return nil
	}
	genesis := integrity.GenesisHash(streamID, installationEpoch)
	_, err = tx.ExecContext(ctx, `INSERT INTO integrity_streams(singleton,stream_id,codec_version,installation_epoch,genesis_hash,enabled,next_entry_seq,next_batch_id,last_sealed_seq,last_batch_hash,enabled_at)
		VALUES(1,?,1,?,?,1,1,1,0,?,?)`, streamID[:], installationEpoch[:], genesis[:], genesis[:], time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("enable integrity stream: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.startIntegritySealer()
	return nil
}

func (s *RawStore) GetIntegrityStream(ctx context.Context) (*IntegrityStream, error) {
	var row IntegrityStream
	var streamID, epoch, genesis, lastHash []byte
	err := s.db.QueryRowContext(ctx, `SELECT stream_id,installation_epoch,genesis_hash,next_entry_seq,next_batch_id,last_sealed_seq,last_batch_hash
		FROM integrity_streams WHERE singleton=1 AND enabled=1`).Scan(&streamID, &epoch, &genesis, &row.NextEntrySeq, &row.NextBatchID, &row.LastSealedSeq, &lastHash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	copy(row.StreamID[:], streamID)
	copy(row.InstallationEpoch[:], epoch)
	copy(row.GenesisHash[:], genesis)
	copy(row.LastBatchHash[:], lastHash)
	return &row, nil
}

// ListIntegrityEntries reads an ordered, bounded journal page for later sealing and audits.
func (s *RawStore) ListIntegrityEntries(ctx context.Context, after uint64, limit int) ([]IntegrityEntry, error) {
	if limit < 1 {
		limit = 1
	}
	if limit > integrity.MaxBatchEntries {
		limit = integrity.MaxBatchEntries
	}
	readDB := s.db
	if s.auditDB != nil {
		readDB = s.auditDB
	}
	rows, err := readDB.QueryContext(ctx, `SELECT entry_seq,entry_kind,subject_id,raw_id,child_ordinal,operation_id,occurred_at_unix_ns,content_snapshot,metadata_snapshot,content_digest,metadata_digest,encoded_entry,leaf_hash
		FROM integrity_entries WHERE stream_id=(SELECT stream_id FROM integrity_streams WHERE singleton=1) AND entry_seq>? ORDER BY entry_seq LIMIT ?`, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	entries := make([]IntegrityEntry, 0, limit)
	for rows.Next() {
		var e IntegrityEntry
		var subjectID, rawID, operationID sql.NullString
		var contentDigest, metadataDigest, leafHash []byte
		if err := rows.Scan(&e.Sequence, &e.Kind, &subjectID, &rawID, &e.ChildOrdinal, &operationID, &e.OccurredAtNS, &e.ContentSnapshot, &e.MetadataSnapshot, &contentDigest, &metadataDigest, &e.EncodedEntry, &leafHash); err != nil {
			return nil, err
		}
		e.SubjectID = subjectID.String
		e.RawID = rawID.String
		e.OperationID = operationID.String
		copy(e.ContentDigest[:], contentDigest)
		copy(e.MetadataDigest[:], metadataDigest)
		copy(e.LeafHash[:], leafHash)
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

func openReadOnlyDB(path string) (*sql.DB, error) {
	if strings.Contains(path, ":memory:") {
		return nil, errors.New("memory databases do not support a separate audit connection")
	}
	var uri *url.URL
	if strings.HasPrefix(path, "file:") {
		parsed, err := url.Parse(path)
		if err != nil {
			return nil, err
		}
		uri = parsed
	} else {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		uri = &url.URL{Scheme: "file", Path: absolute}
	}
	query := uri.Query()
	query.Set("mode", "ro")
	query.Set("_query_only", "1")
	query.Set("_busy_timeout", "5000")
	uri.RawQuery = query.Encode()
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func appendEvidenceTx(ctx context.Context, tx *sql.Tx, w evidenceWrite) (uint64, error) {
	var streamID []byte
	var seq uint64
	err := tx.QueryRowContext(ctx, `SELECT stream_id,next_entry_seq FROM integrity_streams WHERE singleton=1 AND enabled=1`).Scan(&streamID, &seq)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read active integrity stream: %w", err)
	}
	if seq == 0 || seq > math.MaxInt64 {
		return 0, errors.New("integrity entry sequence exhausted")
	}
	var used int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM integrity_entries WHERE stream_id=? AND entry_seq=?`, streamID, seq).Scan(&used); err != nil {
		return 0, err
	}
	if used != 0 {
		return 0, errors.New("integrity entry sequence exhausted")
	}
	if err := integrity.ValidateKindFields(w.kind, w.contentFields, w.metadataFields); err != nil {
		return 0, err
	}
	metadataFields, err := integrity.EncodeFields(w.metadataFields)
	if err != nil {
		return 0, err
	}
	contentBytes := w.contentBytes
	if contentBytes == nil {
		contentBytes = w.contentSnapshot
	}
	contentDigest := integrity.HashContent(contentBytes)
	metadataDigest := integrity.HashContent(metadataFields)
	if w.occurredAt.IsZero() {
		w.occurredAt = time.Now().UTC()
	}
	var id integrity.Hash
	copy(id[:], streamID)
	entry := integrity.EvidenceEntry{Version: integrity.CodecVersion, StreamID: id, Sequence: seq, Kind: w.kind, SubjectID: w.subjectID, RawID: w.rawID, ChildOrdinal: w.childOrdinal, OperationID: w.operationID, PreviousSubjectSeq: w.previousSubjectSeq, OccurredAtUnixNS: w.occurredAt.UTC().UnixNano(), ContentDigest: contentDigest, MetadataDigest: metadataDigest}
	encoded, err := integrity.EncodeEvidenceEntry(entry)
	if err != nil {
		return 0, err
	}
	leaf := integrity.MerkleLeaf(encoded)
	var ordinal any
	if w.childOrdinal != nil {
		ordinal = *w.childOrdinal
	}
	var previous any
	if w.previousSubjectSeq != nil {
		previous = *w.previousSubjectSeq
	}
	committedAt := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = tx.ExecContext(ctx, `INSERT INTO integrity_entries(stream_id,entry_seq,entry_kind,subject_id,raw_id,child_ordinal,operation_id,previous_subject_seq,occurred_at_unix_ns,content_snapshot,metadata_snapshot,content_digest,metadata_digest,encoded_entry,leaf_hash,committed_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, streamID, seq, w.kind, deref(w.subjectID), deref(w.rawID), ordinal, deref(w.operationID), previous, entry.OccurredAtUnixNS, w.contentSnapshot, metadataFields, contentDigest[:], metadataDigest[:], encoded, leaf[:], committedAt)
	if err != nil {
		return 0, fmt.Errorf("append integrity entry: %w", err)
	}
	next := seq
	if seq < math.MaxInt64 {
		next = seq + 1
	}
	if _, err = tx.ExecContext(ctx, `UPDATE integrity_streams SET next_entry_seq=? WHERE singleton=1 AND stream_id=?`, next, streamID); err != nil {
		return 0, err
	}
	return seq, nil
}

func integrityEnabledTx(ctx context.Context, tx *sql.Tx) (bool, error) {
	var enabled int
	err := tx.QueryRowContext(ctx, `SELECT enabled FROM integrity_streams WHERE singleton=1`).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return enabled == 1, err
}

func rawMetadataFields(event *model.RawEvent) ([]integrity.TypedField, error) {
	if event.SourcePort < 0 || uint64(event.SourcePort) > math.MaxUint32 {
		return nil, fmt.Errorf("source port %d is outside the evidence codec range", event.SourcePort)
	}
	if int64(event.Metadata.KafkaPartition) < math.MinInt32 || int64(event.Metadata.KafkaPartition) > math.MaxInt32 {
		return nil, fmt.Errorf("kafka partition %d is outside the evidence codec range", event.Metadata.KafkaPartition)
	}
	return []integrity.TypedField{
		fieldText(1, event.Transport), fieldText(2, event.SourceIP), fieldU32(3, uint32(event.SourcePort)), fieldU64(4, uint64(event.ByteCount)),
		fieldText(5, event.Metadata.ConnectionID), fieldText(6, event.Metadata.Listener), fieldText(7, event.Metadata.RequestID), fieldText(8, event.Metadata.FilePath),
		fieldText(9, event.Metadata.FileID), fieldI64(10, event.Metadata.FileOffset), fieldText(11, event.Metadata.ObjectKey), fieldText(12, event.Metadata.Watermark),
		fieldText(13, event.Metadata.KafkaTopic), fieldI32(14, int32(event.Metadata.KafkaPartition)), fieldI64(15, event.Metadata.KafkaOffset), fieldText(16, event.Metadata.KafkaKey),
	}, nil
}

func normalizedMetadataFields(event *model.NormalizedEvent) []integrity.TypedField {
	return []integrity.TypedField{
		fieldText(1, event.Raven.ParserPack), fieldText(2, event.Raven.ParserVersion),
		{Tag: 3, Type: integrity.FieldBytes32, Value: event.Raven.ParserFileSHA256[:]},
		fieldText(4, event.Raven.CoreVersion), fieldText(5, event.Raven.SchemaVersion),
	}
}

func quarantineEvidenceFields(entry *model.QuarantineEntry) ([]integrity.TypedField, error) {
	rawHash, err := decodeDigest(entry.RawSHA256)
	if err != nil {
		return nil, err
	}
	candidates, err := fieldStringList(6, entry.CandidatePacks)
	if err != nil {
		return nil, err
	}
	fields := []integrity.TypedField{
		fieldBytes32(1, rawHash), fieldText(2, entry.Stage), fieldText(3, entry.Reason), fieldText(4, entry.ErrorDetails), fieldBytes(5, []byte(entry.RawPreview)),
		candidates, fieldBool(7, entry.ReplayEligible), fieldI64(8, entry.QuarantinedAt.UTC().UnixNano()),
	}
	if entry.ReplayedAt != nil {
		fields = append(fields, fieldI64(9, entry.ReplayedAt.UTC().UnixNano()))
	}
	return fields, nil
}

func loadQuarantineTx(ctx context.Context, tx *sql.Tx, qID string) (*model.QuarantineEntry, error) {
	var e model.QuarantineEntry
	var candidates sql.NullString
	var eligible int
	var quarantined string
	var replayed sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT quarantine_id,raw_id,record_ordinal,raw_sha256,stage,reason,error_details,raw_preview,candidate_packs,replay_eligible,quarantined_at,replayed_at FROM quarantine WHERE quarantine_id=?`, qID).Scan(&e.QuarantineID, &e.RawID, &e.RecordOrdinal, &e.RawSHA256, &e.Stage, &e.Reason, &e.ErrorDetails, &e.RawPreview, &candidates, &eligible, &quarantined, &replayed)
	if err != nil {
		return nil, err
	}
	if candidates.Valid && candidates.String != "" {
		e.CandidatePacks = strings.Split(candidates.String, ",")
	}
	e.ReplayEligible = eligible == 1
	e.QuarantinedAt, _ = time.Parse(time.RFC3339Nano, quarantined)
	if replayed.Valid {
		v, err := time.Parse(time.RFC3339Nano, replayed.String)
		if err != nil {
			return nil, err
		}
		e.ReplayedAt = &v
	}
	return &e, nil
}

func (s *RawStore) RecordReplayFailure(ctx context.Context, entry *model.QuarantineEntry, failure error) error {
	if entry == nil || failure == nil {
		return errors.New("quarantine entry and replay failure are required")
	}
	opID, err := newOperationID()
	if err != nil {
		return err
	}
	if _, err := s.BeginReplay(ctx, entry.QuarantineID, opID); err != nil {
		return err
	}
	return s.RecordReplayFailureWithOperation(ctx, entry, failure, opID)
}

func (s *RawStore) RecordReplayFailureWithOperation(ctx context.Context, entry *model.QuarantineEntry, failure error, opID string) error {
	return s.RecordReplayFailureWithProvenance(ctx, entry, failure, opID, nil)
}

func (s *RawStore) RecordReplayFailureWithProvenance(ctx context.Context, entry *model.QuarantineEntry, failure error, opID string, parserDigest *[32]byte) error {
	if entry == nil || failure == nil {
		return errors.New("quarantine entry and replay failure are required")
	}
	ordinal := uint32(entry.RecordOrdinal)
	if entry.RecordOrdinal < 0 || uint64(entry.RecordOrdinal) > math.MaxInt32 {
		return errors.New("invalid quarantine child ordinal")
	}
	details := sha256.Sum256([]byte(failure.Error()))
	fields := []integrity.TypedField{fieldText(1, "replay_failed"), fieldBytes32(2, details)}
	if parserDigest != nil {
		fields = append(fields, integrity.TypedField{Tag: 3, Type: integrity.FieldBytes32, Value: parserDigest[:]})
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	enabled, err := integrityEnabledTx(ctx, tx)
	if err != nil {
		return err
	}
	if !enabled {
		now := time.Now().UTC().Format(time.RFC3339Nano)
		result, err := tx.ExecContext(ctx, `UPDATE integrity_operations SET state='failed',error_class='replay_failed',result_summary=?,completed_at=? WHERE operation_id=? AND state='running' AND quarantine_id=? AND raw_id=? AND child_ordinal=?`, replayFailureSummary(failure), now, opID, entry.QuarantineID, entry.RawID, entry.RecordOrdinal)
		if err != nil {
			return err
		}
		if n, _ := result.RowsAffected(); n != 1 {
			return errors.New("replay operation is missing or no longer running")
		}
		return tx.Commit()
	}
	subject := entry.QuarantineID
	rawID := entry.RawID
	previous, err := latestEntrySeqTx(ctx, tx, integrity.QuarantineWritten, entry.RawID, entry.RecordOrdinal, entry.QuarantineID)
	if err != nil {
		return err
	}
	var prev *uint64
	if previous > 0 {
		prev = &previous
	}
	if _, err = appendEvidenceTx(ctx, tx, evidenceWrite{kind: integrity.ReplayFailed, subjectID: &subject, rawID: &rawID, childOrdinal: &ordinal, operationID: &opID, previousSubjectSeq: prev, occurredAt: time.Now().UTC(), contentSnapshot: mustFields(fields), contentFields: fields}); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := tx.ExecContext(ctx, `UPDATE integrity_operations SET state='failed',error_class='replay_failed',result_summary=?,completed_at=? WHERE operation_id=? AND state='running' AND quarantine_id=? AND raw_id=? AND child_ordinal=?`, replayFailureSummary(failure), now, opID, entry.QuarantineID, entry.RawID, entry.RecordOrdinal)
	if err != nil {
		return fmt.Errorf("record failed replay operation: %w", err)
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return errors.New("replay operation is missing or no longer running")
	}
	return tx.Commit()
}

func replayFailureSummary(failure error) string {
	text := failure.Error()
	if len(text) > 1024 {
		text = strings.ToValidUTF8(text[:1024], "�")
	}
	return text
}

func newOperationID() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", fmt.Errorf("create replay operation ID: %w", err)
	}
	return hex.EncodeToString(random[:]), nil
}

func replayFingerprint(qID, rawID string, ordinal int) integrity.Hash {
	encoded, _ := integrity.EncodeFields([]integrity.TypedField{fieldText(1, qID), fieldText(2, rawID), fieldU32(3, uint32(ordinal))})
	return integrity.HashContent(encoded)
}

func latestEntrySeqTx(ctx context.Context, tx *sql.Tx, kind integrity.EntryKind, rawID string, ordinal int, subjectID string) (uint64, error) {
	var seq uint64
	err := tx.QueryRowContext(ctx, `SELECT entry_seq FROM integrity_entries WHERE stream_id=(SELECT stream_id FROM integrity_streams WHERE singleton=1) AND entry_kind=? AND raw_id=? AND child_ordinal=? AND (?='' OR subject_id=?) ORDER BY entry_seq DESC LIMIT 1`, kind, rawID, ordinal, subjectID, subjectID).Scan(&seq)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return seq, err
}

func mustFields(fields []integrity.TypedField) []byte {
	b, _ := integrity.EncodeFields(fields)
	return b
}
func deref(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}
func fieldText(tag uint16, v string) integrity.TypedField {
	return integrity.TypedField{Tag: tag, Type: integrity.FieldUTF8, Value: []byte(v)}
}
func fieldBytes(tag uint16, v []byte) integrity.TypedField {
	return integrity.TypedField{Tag: tag, Type: integrity.FieldBytes, Value: v}
}
func fieldBytes32(tag uint16, v [32]byte) integrity.TypedField {
	return integrity.TypedField{Tag: tag, Type: integrity.FieldBytes32, Value: v[:]}
}
func fieldBool(tag uint16, v bool) integrity.TypedField {
	b := byte(0)
	if v {
		b = 1
	}
	return integrity.TypedField{Tag: tag, Type: integrity.FieldBool, Value: []byte{b}}
}
func fieldU32(tag uint16, v uint32) integrity.TypedField {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return integrity.TypedField{Tag: tag, Type: integrity.FieldUint32, Value: b}
}
func fieldU64(tag uint16, v uint64) integrity.TypedField {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return integrity.TypedField{Tag: tag, Type: integrity.FieldUint64, Value: b}
}
func fieldI32(tag uint16, v int32) integrity.TypedField {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(v))
	return integrity.TypedField{Tag: tag, Type: integrity.FieldInt32, Value: b}
}
func fieldI64(tag uint16, v int64) integrity.TypedField {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(v))
	return integrity.TypedField{Tag: tag, Type: integrity.FieldInt64, Value: b}
}
func fieldStringList(tag uint16, v []string) (integrity.TypedField, error) {
	b, err := integrity.StringList(v)
	return integrity.TypedField{Tag: tag, Type: integrity.FieldUTF8List, Value: b}, err
}
func decodeDigest(s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return out, errors.New("expected a 32-byte SHA-256 hex digest")
	}
	copy(out[:], b)
	return out, nil
}
func equalBytes(a, b []byte) bool {
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
