package rawstore

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"strings"
	"time"

	"raven/internal/integrity"
)

const (
	maxManifestBytes = 4 << 20
	sealInterval     = 250 * time.Millisecond
	shutdownBatches  = 16
)

type IntegrityBatch struct {
	Descriptor integrity.BatchDescriptor
	BatchHash  integrity.Hash
	Manifest   []byte
	SealedAt   time.Time
}

type manifestDescriptor struct {
	CodecVersion      uint32 `json:"codec_version"`
	StreamID          string `json:"stream_id"`
	BatchID           uint64 `json:"batch_id"`
	FirstSeq          uint64 `json:"first_seq"`
	LastSeq           uint64 `json:"last_seq"`
	LeafCount         uint32 `json:"leaf_count"`
	MerkleRoot        string `json:"merkle_root"`
	PreviousBatchHash string `json:"previous_batch_hash"`
}

type manifestEntry struct {
	EntrySeq           uint64  `json:"entry_seq"`
	Kind               string  `json:"kind"`
	SubjectID          string  `json:"subject_id"`
	RawID              *string `json:"raw_id"`
	ChildOrdinal       *uint32 `json:"child_ordinal"`
	OperationID        *string `json:"operation_id"`
	PreviousSubjectSeq *uint64 `json:"previous_subject_seq"`
	OccurredAtUnixNS   int64   `json:"occurred_at_unix_ns"`
	ContentDigest      string  `json:"content_digest"`
	MetadataDigest     string  `json:"metadata_digest"`
}

type batchManifest struct {
	Descriptor manifestDescriptor `json:"descriptor"`
	Entries    []manifestEntry    `json:"entries"`
}

type sealCandidate struct {
	entry IntegrityEntry
	wire  manifestEntry
	leaf  integrity.Hash
}

func (s *RawStore) startIntegritySealer() {
	s.sealMu.Lock()
	defer s.sealMu.Unlock()
	if s.sealCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.sealCancel = cancel
	s.sealWG.Add(1)
	go func() {
		defer s.sealWG.Done()
		ticker := time.NewTicker(sealInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := s.SealIntegrityBatch(ctx, false); err != nil && !errors.Is(err, context.Canceled) {
					log.Printf("integrity batch sealing deferred: %v", err)
				}
			}
		}
	}()
}

func (s *RawStore) stopIntegritySealer() {
	s.sealMu.Lock()
	cancel := s.sealCancel
	s.sealCancel = nil
	s.sealMu.Unlock()
	if cancel != nil {
		cancel()
		s.sealWG.Wait()
	}
}

// SealIntegrityBatch persists one contiguous committed prefix, up to the frozen witness limits.
func (s *RawStore) SealIntegrityBatch(ctx context.Context, force bool) (*IntegrityBatch, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var streamBytes, genesisBytes, lastHashBytes []byte
	var nextEntry, nextBatch, lastSealed uint64
	err = tx.QueryRowContext(ctx, `SELECT stream_id,genesis_hash,next_entry_seq,next_batch_id,last_sealed_seq,last_batch_hash FROM integrity_streams WHERE singleton=1 AND enabled=1`).Scan(&streamBytes, &genesisBytes, &nextEntry, &nextBatch, &lastSealed, &lastHashBytes)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(streamBytes) != 32 || len(genesisBytes) != 32 || len(lastHashBytes) != 32 || nextBatch == 0 || nextBatch >= math.MaxInt64 {
		return nil, errors.New("integrity stream head is invalid or exhausted")
	}
	var streamID, previousHash integrity.Hash
	copy(streamID[:], streamBytes)
	copy(previousHash[:], lastHashBytes)
	if lastSealed == 0 {
		if nextBatch != 1 || !equalBytes(genesisBytes, lastHashBytes) {
			return nil, errors.New("initial integrity batch head does not match stream genesis")
		}
	} else {
		var priorLast uint64
		var priorHash []byte
		if err := tx.QueryRowContext(ctx, `SELECT last_seq,batch_hash FROM integrity_batches WHERE stream_id=? AND batch_id=?`, streamBytes, nextBatch-1).Scan(&priorLast, &priorHash); err != nil {
			return nil, fmt.Errorf("load prior sealed batch head: %w", err)
		}
		if priorLast != lastSealed || !equalBytes(priorHash, lastHashBytes) {
			return nil, errors.New("integrity stream head disagrees with the last sealed batch")
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT entry_seq,entry_kind,subject_id,raw_id,child_ordinal,operation_id,previous_subject_seq,occurred_at_unix_ns,content_snapshot,metadata_snapshot,content_digest,metadata_digest,encoded_entry,leaf_hash,committed_at
		FROM integrity_entries WHERE stream_id=? AND entry_seq>? AND entry_seq<? ORDER BY entry_seq LIMIT ?`, streamBytes, lastSealed, nextEntry, integrity.MaxBatchEntries)
	if err != nil {
		return nil, err
	}
	candidates := make([]sealCandidate, 0, integrity.MaxBatchEntries)
	for rows.Next() {
		var e IntegrityEntry
		var subject, rawID, operationID sql.NullString
		var previous sql.NullInt64
		var contentDigest, metadataDigest, leafHash []byte
		if err := rows.Scan(&e.Sequence, &e.Kind, &subject, &rawID, &e.ChildOrdinal, &operationID, &previous, &e.OccurredAtNS, &e.ContentSnapshot, &e.MetadataSnapshot, &contentDigest, &metadataDigest, &e.EncodedEntry, &leafHash, &e.CommittedAt); err != nil {
			rows.Close()
			return nil, err
		}
		e.SubjectID, e.RawID, e.OperationID = subject.String, rawID.String, operationID.String
		copy(e.ContentDigest[:], contentDigest)
		copy(e.MetadataDigest[:], metadataDigest)
		copy(e.LeafHash[:], leafHash)
		var previousSeq *uint64
		if previous.Valid {
			v := uint64(previous.Int64)
			previousSeq = &v
		}
		if len(candidates) > 0 && e.Sequence != candidates[len(candidates)-1].entry.Sequence+1 || len(candidates) == 0 && e.Sequence != lastSealed+1 {
			rows.Close()
			return nil, fmt.Errorf("unsealed evidence has a sequence gap at %d", e.Sequence)
		}
		if e.SubjectID == "" || e.Sequence > math.MaxInt64 || e.ChildOrdinal.Valid && (e.ChildOrdinal.Int64 < 0 || e.ChildOrdinal.Int64 > math.MaxInt32) {
			rows.Close()
			return nil, fmt.Errorf("unsealed evidence entry %d has invalid identity fields", e.Sequence)
		}
		decoded, err := integrity.DecodeEvidenceEntry(e.EncodedEntry)
		var childOrdinal *uint32
		if e.ChildOrdinal.Valid {
			v := uint32(e.ChildOrdinal.Int64)
			childOrdinal = &v
		}
		if err != nil || decoded.Sequence != e.Sequence || decoded.StreamID != streamID || decoded.Kind != e.Kind || decoded.SubjectID == nil || *decoded.SubjectID != e.SubjectID || !equalOptionalString(decoded.RawID, optionalString(rawID)) || !equalOptionalString(decoded.OperationID, optionalString(operationID)) || !equalOptionalUint32(decoded.ChildOrdinal, childOrdinal) || !equalOptionalUint64(decoded.PreviousSubjectSeq, previousSeq) || decoded.OccurredAtUnixNS != e.OccurredAtNS || decoded.ContentDigest != e.ContentDigest || decoded.MetadataDigest != e.MetadataDigest {
			rows.Close()
			return nil, fmt.Errorf("unsealed evidence entry %d does not match its canonical encoding", e.Sequence)
		}
		leaf := integrity.MerkleLeaf(e.EncodedEntry)
		if leaf != e.LeafHash {
			rows.Close()
			return nil, fmt.Errorf("unsealed evidence entry %d has an invalid leaf hash", e.Sequence)
		}
		kind, err := entryKindName(e.Kind)
		if err != nil {
			rows.Close()
			return nil, err
		}
		wire := manifestEntry{
			EntrySeq: e.Sequence, Kind: kind, SubjectID: e.SubjectID,
			RawID: optionalString(rawID), OperationID: optionalString(operationID),
			PreviousSubjectSeq: previousSeq, OccurredAtUnixNS: e.OccurredAtNS,
			ContentDigest:  "0x" + hex.EncodeToString(e.ContentDigest[:]),
			MetadataDigest: "0x" + hex.EncodeToString(e.MetadataDigest[:]),
		}
		if e.ChildOrdinal.Valid {
			v := uint32(e.ChildOrdinal.Int64)
			wire.ChildOrdinal = &v
		}
		candidates = append(candidates, sealCandidate{entry: e, wire: wire, leaf: leaf})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	firstSeq := lastSealed + 1
	if len(candidates) == 0 {
		if nextEntry != firstSeq {
			return nil, fmt.Errorf("unsealed evidence is missing sequence %d", firstSeq)
		}
		return nil, nil
	}
	if len(candidates) < integrity.MaxBatchEntries && candidates[len(candidates)-1].entry.Sequence != nextEntry-1 {
		return nil, fmt.Errorf("unsealed evidence is missing sequence %d", candidates[len(candidates)-1].entry.Sequence+1)
	}
	selected := make([]manifestEntry, 0, len(candidates))
	leaves := make([]integrity.Hash, 0, len(candidates))
	selectedBytes := 0
	var selectedCount int
	bodyLimitHit := false
	for _, candidate := range candidates {
		entryJSON, err := json.Marshal(candidate.wire)
		if err != nil {
			return nil, err
		}
		count := uint32(selectedCount + 1)
		lastSeq := firstSeq + uint64(count) - 1
		wireDescriptor := manifestDescriptor{CodecVersion: uint32(integrity.CodecVersion), StreamID: "0x" + hex.EncodeToString(streamID[:]), BatchID: nextBatch, FirstSeq: firstSeq, LastSeq: lastSeq, LeafCount: count, MerkleRoot: "0x" + strings.Repeat("0", 64), PreviousBatchHash: "0x" + hex.EncodeToString(previousHash[:])}
		descriptorJSON, err := json.Marshal(wireDescriptor)
		if err != nil {
			return nil, err
		}
		entrySeparator := 0
		if selectedCount > 0 {
			entrySeparator = 1
		}
		manifestSize := len(`{"descriptor":`) + len(descriptorJSON) + len(`,"entries":[`) + 2 + selectedBytes + entrySeparator + len(entryJSON)
		if manifestSize > maxManifestBytes {
			bodyLimitHit = true
			if selectedCount == 0 {
				return nil, fmt.Errorf("evidence entry %d alone exceeds the 4 MiB batch manifest limit", candidate.entry.Sequence)
			}
			break
		}
		selected = append(selected, candidate.wire)
		leaves = append(leaves, candidate.leaf)
		selectedBytes += entrySeparator + len(entryJSON)
		selectedCount++
	}
	if selectedCount == 0 {
		return nil, errors.New("no evidence entries fit in a batch manifest")
	}
	firstCommitted, err := time.Parse(time.RFC3339Nano, candidates[0].entry.CommittedAt)
	if err != nil {
		return nil, fmt.Errorf("invalid evidence commit timestamp: %w", err)
	}
	if !force && len(candidates) < integrity.MaxBatchEntries && !bodyLimitHit && time.Since(firstCommitted) < 5*time.Second {
		return nil, nil
	}
	root, err := integrity.MerkleRoot(leaves)
	if err != nil {
		return nil, err
	}
	descriptor := integrity.BatchDescriptor{CodecVersion: uint32(integrity.CodecVersion), StreamID: streamID, BatchID: nextBatch, FirstSeq: firstSeq, LastSeq: firstSeq + uint64(selectedCount) - 1, LeafCount: uint32(selectedCount), MerkleRoot: root, PrevBatchHash: previousHash}
	batchHash, err := integrity.HashBatchDescriptor(descriptor)
	if err != nil {
		return nil, err
	}
	wireDescriptor := manifestDescriptor{CodecVersion: descriptor.CodecVersion, StreamID: "0x" + hex.EncodeToString(descriptor.StreamID[:]), BatchID: descriptor.BatchID, FirstSeq: descriptor.FirstSeq, LastSeq: descriptor.LastSeq, LeafCount: descriptor.LeafCount, MerkleRoot: "0x" + hex.EncodeToString(descriptor.MerkleRoot[:]), PreviousBatchHash: "0x" + hex.EncodeToString(descriptor.PrevBatchHash[:])}
	manifest, err := json.Marshal(batchManifest{Descriptor: wireDescriptor, Entries: selected})
	if err != nil {
		return nil, err
	}
	if len(manifest) > maxManifestBytes {
		return nil, fmt.Errorf("serialized batch manifest is %d bytes, above 4 MiB", len(manifest))
	}
	abi, err := integrity.EncodeBatchDescriptorABI(descriptor)
	if err != nil {
		return nil, err
	}
	sealedAt := time.Now().UTC()
	_, err = tx.ExecContext(ctx, `INSERT INTO integrity_batches(stream_id,batch_id,first_seq,last_seq,leaf_count,merkle_root,prev_batch_hash,batch_hash,encoded_descriptor,sealed_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, streamID[:], descriptor.BatchID, descriptor.FirstSeq, descriptor.LastSeq, descriptor.LeafCount, descriptor.MerkleRoot[:], descriptor.PrevBatchHash[:], batchHash[:], abi[:], sealedAt.Format(time.RFC3339Nano))
	if err != nil {
		return nil, fmt.Errorf("persist sealed integrity batch: %w", err)
	}
	membership, err := tx.PrepareContext(ctx, `INSERT INTO integrity_batch_entries(stream_id,batch_id,leaf_index,entry_seq,leaf_hash) VALUES(?,?,?,?,?)`)
	if err != nil {
		return nil, err
	}
	for i, candidate := range candidates[:selectedCount] {
		if _, err := membership.ExecContext(ctx, streamID[:], descriptor.BatchID, i, candidate.entry.Sequence, candidate.leaf[:]); err != nil {
			membership.Close()
			return nil, fmt.Errorf("persist batch leaf membership %d: %w", i, err)
		}
	}
	if err := membership.Close(); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO integrity_witness_sync(stream_id,batch_id,state) VALUES(?,?,'pending')`, streamID[:], descriptor.BatchID); err != nil {
		return nil, fmt.Errorf("queue retained batch for witness: %w", err)
	}
	updated, err := tx.ExecContext(ctx, `UPDATE integrity_streams SET last_sealed_seq=?,next_batch_id=?,last_batch_hash=? WHERE singleton=1 AND stream_id=? AND last_sealed_seq=? AND next_batch_id=?`, descriptor.LastSeq, descriptor.BatchID+1, batchHash[:], streamID[:], lastSealed, descriptor.BatchID)
	if err != nil {
		return nil, fmt.Errorf("advance integrity batch head: %w", err)
	}
	if affected, _ := updated.RowsAffected(); affected != 1 {
		return nil, errors.New("integrity batch head changed during sealing")
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit sealed integrity batch: %w", err)
	}
	return &IntegrityBatch{Descriptor: descriptor, BatchHash: batchHash, Manifest: manifest, SealedAt: sealedAt}, nil
}

// SealIntegrityPending seals a bounded number of partial batches for shutdown or explicit drains.
func (s *RawStore) SealIntegrityPending(ctx context.Context, maxBatches int) (int, error) {
	if maxBatches <= 0 {
		maxBatches = shutdownBatches
	}
	sealed := 0
	for sealed < maxBatches {
		batch, err := s.SealIntegrityBatch(ctx, true)
		if err != nil {
			return sealed, err
		}
		if batch == nil {
			return sealed, nil
		}
		sealed++
	}
	return sealed, nil
}

func entryKindName(kind integrity.EntryKind) (string, error) {
	switch kind {
	case integrity.RawCommitted:
		return "raw_committed", nil
	case integrity.NormalizedWritten:
		return "normalized_written", nil
	case integrity.QuarantineWritten:
		return "quarantine_written", nil
	case integrity.ReplayFailed:
		return "replay_failed", nil
	case integrity.ReplayResolved:
		return "replay_resolved", nil
	case integrity.NormalizedRemoved:
		return "normalized_removed", nil
	case integrity.QuarantineRemoved:
		return "quarantine_removed", nil
	default:
		return "", fmt.Errorf("unknown evidence kind %d", kind)
	}
}

func optionalString(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	v := value.String
	return &v
}

func equalOptionalString(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func equalOptionalUint32(a, b *uint32) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func equalOptionalUint64(a, b *uint64) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
