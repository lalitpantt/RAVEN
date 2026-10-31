// Package integrity implements the versioned, storage-independent RAVEN evidence protocol.
package integrity

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"unicode/utf8"
)

const CodecVersion uint16 = 1

const (
	MaxBatchEntries = 5000
	maxFieldsBytes  = 65536
)

var evidenceMagic = []byte("RAVEN-EVIDENCE")

type Hash [32]byte

type EntryKind uint8

const (
	RawCommitted EntryKind = iota + 1
	NormalizedWritten
	QuarantineWritten
	ReplayFailed
	ReplayResolved
	NormalizedRemoved
	QuarantineRemoved
)

type EvidenceEntry struct {
	Version            uint16
	StreamID           Hash
	Sequence           uint64
	Kind               EntryKind
	SubjectID          *string
	RawID              *string
	ChildOrdinal       *uint32
	OperationID        *string
	PreviousSubjectSeq *uint64
	OccurredAtUnixNS   int64
	ContentDigest      Hash
	MetadataDigest     Hash
}

func EncodeEvidenceEntry(e EvidenceEntry) ([]byte, error) {
	if err := validateEntry(e); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.Write(evidenceMagic)
	_ = binary.Write(&b, binary.BigEndian, e.Version)
	b.Write(e.StreamID[:])
	_ = binary.Write(&b, binary.BigEndian, e.Sequence)
	b.WriteByte(byte(e.Kind))
	writeOptionalText(&b, e.SubjectID)
	writeOptionalText(&b, e.RawID)
	if e.ChildOrdinal == nil {
		b.WriteByte(0)
	} else {
		b.WriteByte(1)
		_ = binary.Write(&b, binary.BigEndian, *e.ChildOrdinal)
	}
	writeOptionalText(&b, e.OperationID)
	if e.PreviousSubjectSeq == nil {
		b.WriteByte(0)
	} else {
		b.WriteByte(1)
		_ = binary.Write(&b, binary.BigEndian, *e.PreviousSubjectSeq)
	}
	_ = binary.Write(&b, binary.BigEndian, e.OccurredAtUnixNS)
	b.Write(e.ContentDigest[:])
	b.Write(e.MetadataDigest[:])
	return b.Bytes(), nil
}

func DecodeEvidenceEntry(data []byte) (EvidenceEntry, error) {
	var e EvidenceEntry
	r := bytes.NewReader(data)
	magic := make([]byte, len(evidenceMagic))
	if _, err := io.ReadFull(r, magic); err != nil || !bytes.Equal(magic, evidenceMagic) {
		return e, errors.New("invalid evidence magic")
	}
	if err := binary.Read(r, binary.BigEndian, &e.Version); err != nil {
		return e, errors.New("truncated codec version")
	}
	if _, err := io.ReadFull(r, e.StreamID[:]); err != nil {
		return e, errors.New("truncated stream ID")
	}
	if err := binary.Read(r, binary.BigEndian, &e.Sequence); err != nil {
		return e, errors.New("truncated entry sequence")
	}
	kind, err := r.ReadByte()
	if err != nil {
		return e, errors.New("truncated entry kind")
	}
	e.Kind = EntryKind(kind)
	if e.SubjectID, err = readOptionalText(r, 1024); err != nil {
		return e, fmt.Errorf("subject ID: %w", err)
	}
	if e.RawID, err = readOptionalText(r, 1024); err != nil {
		return e, fmt.Errorf("raw ID: %w", err)
	}
	presence, err := readPresence(r)
	if err != nil {
		return e, fmt.Errorf("child ordinal: %w", err)
	}
	if presence == 1 {
		var n uint32
		if err := binary.Read(r, binary.BigEndian, &n); err != nil {
			return e, errors.New("truncated child ordinal")
		}
		e.ChildOrdinal = &n
	}
	if e.OperationID, err = readOptionalText(r, 128); err != nil {
		return e, fmt.Errorf("operation ID: %w", err)
	}
	presence, err = readPresence(r)
	if err != nil {
		return e, fmt.Errorf("previous subject sequence: %w", err)
	}
	if presence == 1 {
		var n uint64
		if err := binary.Read(r, binary.BigEndian, &n); err != nil {
			return e, errors.New("truncated previous subject sequence")
		}
		e.PreviousSubjectSeq = &n
	}
	if err := binary.Read(r, binary.BigEndian, &e.OccurredAtUnixNS); err != nil {
		return e, errors.New("truncated occurrence time")
	}
	if _, err := io.ReadFull(r, e.ContentDigest[:]); err != nil {
		return e, errors.New("truncated content digest")
	}
	if _, err := io.ReadFull(r, e.MetadataDigest[:]); err != nil {
		return e, errors.New("truncated metadata digest")
	}
	if r.Len() != 0 {
		return e, errors.New("trailing evidence bytes")
	}
	if err := validateEntry(e); err != nil {
		return e, err
	}
	return e, nil
}

func HashContent(content []byte) Hash { return sha256.Sum256(content) }

func validateEntry(e EvidenceEntry) error {
	if e.Version != CodecVersion {
		return fmt.Errorf("unsupported codec version %d", e.Version)
	}
	if e.Sequence == 0 || e.Sequence > math.MaxInt64 {
		return errors.New("entry sequence must be in 1..2^63-1")
	}
	if e.Kind < RawCommitted || e.Kind > QuarantineRemoved {
		return fmt.Errorf("unknown entry kind %d", e.Kind)
	}
	if err := validateOptionalText(e.SubjectID, 1024); err != nil {
		return fmt.Errorf("subject ID: %w", err)
	}
	if err := validateOptionalText(e.RawID, 1024); err != nil {
		return fmt.Errorf("raw ID: %w", err)
	}
	if err := validateOptionalText(e.OperationID, 128); err != nil {
		return fmt.Errorf("operation ID: %w", err)
	}
	if e.ChildOrdinal != nil && *e.ChildOrdinal > math.MaxInt32 {
		return errors.New("child ordinal must be in 0..2^31-1")
	}
	if e.PreviousSubjectSeq != nil && (*e.PreviousSubjectSeq == 0 || *e.PreviousSubjectSeq > math.MaxInt64) {
		return errors.New("previous subject sequence must be in 1..2^63-1")
	}
	return nil
}

func validateOptionalText(s *string, max int) error {
	if s == nil {
		return nil
	}
	if len(*s) == 0 || len(*s) > max || !utf8.ValidString(*s) || bytes.IndexByte([]byte(*s), 0) >= 0 {
		return fmt.Errorf("must contain 1..%d valid UTF-8 bytes without NUL", max)
	}
	return nil
}

func writeOptionalText(b *bytes.Buffer, s *string) {
	if s == nil {
		b.WriteByte(0)
		return
	}
	b.WriteByte(1)
	_ = binary.Write(b, binary.BigEndian, uint32(len(*s)))
	b.WriteString(*s)
}

func readOptionalText(r *bytes.Reader, max int) (*string, error) {
	p, err := readPresence(r)
	if err != nil || p == 0 {
		return nil, err
	}
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, errors.New("truncated length")
	}
	if n == 0 || n > uint32(max) || uint64(n) > uint64(r.Len()) {
		return nil, errors.New("invalid text length")
	}
	b := make([]byte, n)
	_, _ = io.ReadFull(r, b)
	if !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0 {
		return nil, errors.New("invalid UTF-8 text")
	}
	s := string(b)
	return &s, nil
}

func readPresence(r *bytes.Reader) (byte, error) {
	p, err := r.ReadByte()
	if err != nil {
		return 0, errors.New("truncated presence byte")
	}
	if p > 1 {
		return 0, fmt.Errorf("invalid presence byte %d", p)
	}
	return p, nil
}
