package witness

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"raven/internal/integrity"
)

const maxManifestBytes = 4 << 20

type BatchDescriptor struct {
	CodecVersion      uint32 `json:"codec_version"`
	StreamID          string `json:"stream_id"`
	BatchID           uint64 `json:"batch_id"`
	FirstSeq          uint64 `json:"first_seq"`
	LastSeq           uint64 `json:"last_seq"`
	LeafCount         uint32 `json:"leaf_count"`
	MerkleRoot        string `json:"merkle_root"`
	PreviousBatchHash string `json:"previous_batch_hash"`
}

type BatchEntry struct {
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

func (e *BatchEntry) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, name := range []string{"entry_seq", "kind", "subject_id", "raw_id", "child_ordinal", "operation_id", "previous_subject_seq", "occurred_at_unix_ns", "content_digest", "metadata_digest"} {
		if _, ok := fields[name]; !ok {
			return fmt.Errorf("entry is missing required field %q", name)
		}
	}
	for name := range fields {
		switch name {
		case "entry_seq", "kind", "subject_id", "raw_id", "child_ordinal", "operation_id", "previous_subject_seq", "occurred_at_unix_ns", "content_digest", "metadata_digest":
		default:
			return fmt.Errorf("entry has unknown field %q", name)
		}
	}
	type entryAlias BatchEntry
	return json.Unmarshal(data, (*entryAlias)(e))
}

type BatchManifest struct {
	Descriptor BatchDescriptor `json:"descriptor"`
	Entries    []BatchEntry    `json:"entries"`
}

type validatedManifest struct {
	Manifest     BatchManifest
	Canonical    []byte
	Descriptor   integrity.BatchDescriptor
	BatchHash    integrity.Hash
	ManifestHash integrity.Hash
}

func decodeManifest(data []byte) (validatedManifest, error) {
	var result validatedManifest
	if len(data) == 0 || len(data) > maxManifestBytes {
		return result, errors.New("manifest must be between 1 byte and 4 MiB")
	}
	if !utf8.Valid(data) {
		return result, errors.New("manifest must be valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&result.Manifest); err != nil {
		return result, fmt.Errorf("decode manifest: %w", err)
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		if err == nil {
			return result, errors.New("manifest contains trailing JSON")
		}
		return result, fmt.Errorf("manifest trailing data: %w", err)
	}
	d := result.Manifest.Descriptor
	streamID, err := parseHash(d.StreamID)
	if err != nil {
		return result, fmt.Errorf("descriptor stream_id: %w", err)
	}
	root, err := parseHash(d.MerkleRoot)
	if err != nil {
		return result, fmt.Errorf("descriptor merkle_root: %w", err)
	}
	previous, err := parseHash(d.PreviousBatchHash)
	if err != nil {
		return result, fmt.Errorf("descriptor previous_batch_hash: %w", err)
	}
	descriptor := integrity.BatchDescriptor{CodecVersion: d.CodecVersion, StreamID: streamID, BatchID: d.BatchID, FirstSeq: d.FirstSeq, LastSeq: d.LastSeq, LeafCount: d.LeafCount, MerkleRoot: root, PrevBatchHash: previous}
	if _, err := integrity.EncodeBatchDescriptorABI(descriptor); err != nil {
		return result, fmt.Errorf("invalid batch descriptor: %w", err)
	}
	if len(result.Manifest.Entries) != int(d.LeafCount) {
		return result, errors.New("manifest entry count differs from descriptor leaf_count")
	}
	leaves := make([]integrity.Hash, 0, len(result.Manifest.Entries))
	for i, item := range result.Manifest.Entries {
		if item.EntrySeq != d.FirstSeq+uint64(i) {
			return result, fmt.Errorf("manifest entry sequence is not contiguous at index %d", i)
		}
		kind, err := parseEntryKind(item.Kind)
		if err != nil {
			return result, fmt.Errorf("entry %d: %w", item.EntrySeq, err)
		}
		contentDigest, err := parseHash(item.ContentDigest)
		if err != nil {
			return result, fmt.Errorf("entry %d content_digest: %w", item.EntrySeq, err)
		}
		metadataDigest, err := parseHash(item.MetadataDigest)
		if err != nil {
			return result, fmt.Errorf("entry %d metadata_digest: %w", item.EntrySeq, err)
		}
		subject := item.SubjectID
		entry, err := integrity.EncodeEvidenceEntry(integrity.EvidenceEntry{
			Version: integrity.CodecVersion, StreamID: streamID, Sequence: item.EntrySeq, Kind: kind,
			SubjectID: &subject, RawID: item.RawID, ChildOrdinal: item.ChildOrdinal,
			OperationID: item.OperationID, PreviousSubjectSeq: item.PreviousSubjectSeq,
			OccurredAtUnixNS: item.OccurredAtUnixNS, ContentDigest: contentDigest, MetadataDigest: metadataDigest,
		})
		if err != nil {
			return result, fmt.Errorf("entry %d: %w", item.EntrySeq, err)
		}
		leaves = append(leaves, integrity.MerkleLeaf(entry))
	}
	computedRoot, err := integrity.MerkleRoot(leaves)
	if err != nil || computedRoot != root {
		return result, errors.New("manifest Merkle root does not match ordered entries")
	}
	batchHash, err := integrity.HashBatchDescriptor(descriptor)
	if err != nil {
		return result, err
	}
	canonical, err := json.Marshal(result.Manifest)
	if err != nil || len(canonical) > maxManifestBytes {
		return result, errors.New("canonical manifest exceeds 4 MiB")
	}
	result.Canonical = canonical
	result.Descriptor = descriptor
	result.BatchHash = batchHash
	result.ManifestHash = integrity.HashContent(canonical)
	return result, nil
}

func parseHash(s string) (integrity.Hash, error) {
	var result integrity.Hash
	if len(s) != 66 || !strings.HasPrefix(s, "0x") || strings.ToLower(s) != s {
		return result, errors.New("expected lowercase 0x-prefixed 32-byte hex")
	}
	b, err := hex.DecodeString(s[2:])
	if err != nil || len(b) != len(result) {
		return result, errors.New("expected lowercase 0x-prefixed 32-byte hex")
	}
	copy(result[:], b)
	return result, nil
}

func formatHash(h integrity.Hash) string { return "0x" + hex.EncodeToString(h[:]) }

func parseEntryKind(s string) (integrity.EntryKind, error) {
	switch s {
	case "raw_committed":
		return integrity.RawCommitted, nil
	case "normalized_written":
		return integrity.NormalizedWritten, nil
	case "quarantine_written":
		return integrity.QuarantineWritten, nil
	case "replay_failed":
		return integrity.ReplayFailed, nil
	case "replay_resolved":
		return integrity.ReplayResolved, nil
	case "normalized_removed":
		return integrity.NormalizedRemoved, nil
	case "quarantine_removed":
		return integrity.QuarantineRemoved, nil
	default:
		return 0, fmt.Errorf("unknown entry kind %q", s)
	}
}
