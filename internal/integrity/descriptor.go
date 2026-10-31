package integrity

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
)

type BatchDescriptor struct {
	CodecVersion  uint32
	StreamID      Hash
	BatchID       uint64
	FirstSeq      uint64
	LastSeq       uint64
	LeafCount     uint32
	MerkleRoot    Hash
	PrevBatchHash Hash
}

func EncodeBatchDescriptorABI(d BatchDescriptor) ([256]byte, error) {
	var out [256]byte
	if err := validateDescriptor(d); err != nil {
		return out, err
	}
	putWordUint(out[0:32], uint64(d.CodecVersion))
	copy(out[32:64], d.StreamID[:])
	putWordUint(out[64:96], d.BatchID)
	putWordUint(out[96:128], d.FirstSeq)
	putWordUint(out[128:160], d.LastSeq)
	putWordUint(out[160:192], uint64(d.LeafCount))
	copy(out[192:224], d.MerkleRoot[:])
	copy(out[224:256], d.PrevBatchHash[:])
	return out, nil
}

func HashBatchDescriptor(d BatchDescriptor) (Hash, error) {
	b, err := EncodeBatchDescriptorABI(d)
	if err != nil {
		return Hash{}, err
	}
	return sha256.Sum256(b[:]), nil
}

func GenesisHash(streamID, installationEpoch Hash) Hash {
	var b [13 + 2 + 32 + 32]byte
	copy(b[:13], "RAVEN-GENESIS")
	binary.BigEndian.PutUint16(b[13:15], CodecVersion)
	copy(b[15:47], streamID[:])
	copy(b[47:], installationEpoch[:])
	return sha256.Sum256(b[:])
}

func validateDescriptor(d BatchDescriptor) error {
	if d.CodecVersion != uint32(CodecVersion) {
		return errors.New("unsupported descriptor codec version")
	}
	if d.BatchID == 0 || d.BatchID > math.MaxInt64 || d.FirstSeq == 0 || d.FirstSeq > math.MaxInt64 || d.LastSeq < d.FirstSeq || d.LastSeq > math.MaxInt64 {
		return errors.New("descriptor IDs and sequence range must be within 1..2^63-1")
	}
	if d.LeafCount == 0 || d.LeafCount > MaxBatchEntries || d.LastSeq-d.FirstSeq+1 != uint64(d.LeafCount) {
		return errors.New("descriptor leaf count must match its sequence range and be in 1..5000")
	}
	return nil
}

func putWordUint(dst []byte, n uint64) {
	binary.BigEndian.PutUint64(dst[24:], n)
}
