package integrity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestCodecAndB00GoldenVectors(t *testing.T) {
	var fixture struct {
		SampleInputs struct {
			StreamID string `json:"stream_id_hex"`
			Epoch    string `json:"installation_epoch_hex"`
		} `json:"sample_inputs"`
		Entries []struct {
			Encoded string `json:"encoded_entry_hex"`
			Leaf    string `json:"leaf_hash_hex"`
		} `json:"entries"`
		Root          string `json:"merkle_3_leaf_root_hex"`
		Genesis       string `json:"genesis_hash_hex"`
		ABIDescriptor string `json:"single_leaf_batch_abi_encoding_hex"`
		BatchHash     string `json:"single_leaf_batch_hash_hex"`
	}
	b, err := os.ReadFile("../../testdata/integrity/codec-v1-golden.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	stream, epoch := mustHash(t, fixture.SampleInputs.StreamID), mustHash(t, fixture.SampleInputs.Epoch)
	if got := GenesisHash(stream, epoch); got != mustHash(t, fixture.Genesis) {
		t.Fatalf("genesis hash mismatch: %x", got)
	}
	leaves := make([]Hash, 0, len(fixture.Entries))
	for i, vector := range fixture.Entries {
		encoded, err := hex.DecodeString(vector.Encoded)
		if err != nil {
			t.Fatal(err)
		}
		entry, err := DecodeEvidenceEntry(encoded)
		if err != nil {
			t.Fatalf("entry %d decode: %v", i+1, err)
		}
		reencoded, err := EncodeEvidenceEntry(entry)
		if err != nil || hex.EncodeToString(reencoded) != vector.Encoded {
			t.Fatalf("entry %d did not round trip canonically: %v", i+1, err)
		}
		leaf := MerkleLeaf(encoded)
		if leaf != mustHash(t, vector.Leaf) {
			t.Fatalf("entry %d leaf mismatch", i+1)
		}
		leaves = append(leaves, leaf)
	}
	root, err := MerkleRoot(leaves)
	if err != nil || root != mustHash(t, fixture.Root) {
		t.Fatalf("three-leaf root mismatch: %x, %v", root, err)
	}
	for i, leaf := range leaves {
		proof, err := MerkleProof(leaves, uint32(i))
		if err != nil || !VerifyMerkleProof(leaf, uint32(i), uint32(len(leaves)), proof, root) {
			t.Fatalf("proof for leaf %d failed: %v", i, err)
		}
	}
	descriptor := BatchDescriptor{
		CodecVersion: 1, StreamID: stream, BatchID: 1, FirstSeq: 1, LastSeq: 1,
		LeafCount: 1, MerkleRoot: leaves[0], PrevBatchHash: mustHash(t, fixture.Genesis),
	}
	abi, err := EncodeBatchDescriptorABI(descriptor)
	if err != nil || hex.EncodeToString(abi[:]) != fixture.ABIDescriptor {
		t.Fatalf("descriptor ABI mismatch: %v", err)
	}
	batchHash, err := HashBatchDescriptor(descriptor)
	if err != nil || batchHash != mustHash(t, fixture.BatchHash) {
		t.Fatalf("descriptor hash mismatch: %x, %v", batchHash, err)
	}
}

func TestEvidenceCodecRejectsMalformedInputs(t *testing.T) {
	entry := EvidenceEntry{Version: 1, Sequence: 1, Kind: RawCommitted}
	b, err := EncodeEvidenceEntry(entry)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"truncated":       b[:len(b)-1],
		"trailing":        append(append([]byte(nil), b...), 0),
		"bad presence":    func() []byte { x := append([]byte(nil), b...); x[57] = 2; return x }(),
		"unknown version": func() []byte { x := append([]byte(nil), b...); x[15] = 2; return x }(),
		"unknown kind":    func() []byte { x := append([]byte(nil), b...); x[56] = 8; return x }(),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeEvidenceEntry(data); err == nil {
				t.Fatal("expected malformed entry to be rejected")
			}
		})
	}
	entry.Sequence = 0
	if _, err := EncodeEvidenceEntry(entry); err == nil {
		t.Fatal("zero entry sequence accepted")
	}
	tooLong := ""
	for i := 0; i < 129; i++ {
		tooLong += "x"
	}
	entry.Sequence, entry.OperationID = 1, &tooLong
	if _, err := EncodeEvidenceEntry(entry); err == nil {
		t.Fatal("oversized operation ID accepted")
	}
	ordinal := uint32(1 << 31)
	entry.OperationID, entry.ChildOrdinal = nil, &ordinal
	if _, err := EncodeEvidenceEntry(entry); err == nil {
		t.Fatal("out-of-range child ordinal accepted")
	}
}

func TestTypedFieldsAndKindSchemas(t *testing.T) {
	for _, kind := range []EntryKind{RawCommitted, NormalizedWritten, QuarantineWritten, ReplayFailed, ReplayResolved, NormalizedRemoved, QuarantineRemoved} {
		content, metadata := validFieldsFor(kind)
		if err := ValidateKindFields(kind, content, metadata); err != nil {
			t.Fatalf("kind %d valid fields: %v", kind, err)
		}
		encoded, err := EncodeFields(content)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeFields(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateKindFields(kind, decoded, metadata); err != nil {
			t.Fatalf("kind %d decode fields: %v", kind, err)
		}
	}
	if err := ValidateKindFields(RawCommitted, nil, nil); err == nil {
		t.Fatal("missing required raw fields accepted")
	}
	if _, err := EncodeFields([]TypedField{{Tag: 2, Type: FieldBytes}, {Tag: 1, Type: FieldBytes}}); err == nil {
		t.Fatal("unsorted tags accepted")
	}
	if _, err := EncodeFields([]TypedField{{Tag: 1, Type: FieldBool, Value: []byte{2}}}); err == nil {
		t.Fatal("invalid boolean accepted")
	}
	list, err := StringList([]string{"z", "a"})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateStringList(list); err != nil {
		t.Fatal(err)
	}
	if _, err := StringList([]string{"a", "a"}); err == nil {
		t.Fatal("duplicate set value accepted")
	}
}

func TestKindFieldGoldenVectors(t *testing.T) {
	var vectors map[string]struct {
		Content  string `json:"content_hex"`
		Metadata string `json:"metadata_hex"`
	}
	b, err := os.ReadFile("../../testdata/integrity/fields-v1-golden.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		kind EntryKind
		name string
	}{
		{RawCommitted, "raw_committed"}, {NormalizedWritten, "normalized_written"}, {QuarantineWritten, "quarantine_written"},
		{ReplayFailed, "replay_failed"}, {ReplayResolved, "replay_resolved"}, {NormalizedRemoved, "normalized_removed"}, {QuarantineRemoved, "quarantine_removed"},
	} {
		content, metadata := validFieldsFor(item.kind)
		contentBytes, err := EncodeFields(content)
		if err != nil {
			t.Fatal(err)
		}
		metadataBytes, err := EncodeFields(metadata)
		if err != nil {
			t.Fatal(err)
		}
		v, ok := vectors[item.name]
		if !ok || hex.EncodeToString(contentBytes) != v.Content || hex.EncodeToString(metadataBytes) != v.Metadata {
			t.Errorf("%s typed-field vector mismatch", item.name)
		}
	}
}

func TestMerkleShapesAndProofBounds(t *testing.T) {
	for _, n := range []int{1, 2, 3, 5, 4999, 5000} {
		leaves := make([]Hash, n)
		for i := range leaves {
			leaves[i] = sha256.Sum256([]byte{byte(i), byte(i >> 8), byte(i >> 16)})
		}
		root, err := MerkleRoot(leaves)
		if err != nil {
			t.Fatalf("size %d: %v", n, err)
		}
		indices := []uint32{0, uint32(n / 2), uint32(n - 1)}
		for _, index := range indices {
			proof, err := MerkleProof(leaves, index)
			if err != nil || !VerifyMerkleProof(leaves[index], index, uint32(n), proof, root) {
				t.Fatalf("size %d index %d proof failed: %v", n, index, err)
			}
			if len(proof) > 0 {
				proof[0][0] ^= 1
				if VerifyMerkleProof(leaves[index], index, uint32(n), proof, root) {
					t.Fatalf("size %d accepted altered proof", n)
				}
			}
		}
	}
	if _, err := MerkleRoot(nil); err == nil {
		t.Fatal("empty tree accepted")
	}
	if VerifyMerkleProof(Hash{}, 0, 1, []Hash{{}}, Hash{}) {
		t.Fatal("extra proof element accepted")
	}
}

func TestAcknowledgementSignatureAndChaining(t *testing.T) {
	seed := sha256.Sum256([]byte("RAVEN synthetic receipt test key; not a secret"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	a := WitnessAcknowledgement{BatchID: 1, WitnessKeyID: "test-witness-1", ReceivedAtNS: -1}
	signed, err := SignAcknowledgement(a, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAcknowledgement(signed, publicKey); err != nil {
		t.Fatal(err)
	}
	digest, err := AcknowledgementHash(signed)
	if err != nil {
		t.Fatal(err)
	}
	a.BatchID, a.PreviousAckHash = 2, digest
	second, err := SignAcknowledgement(a, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAcknowledgement(second, publicKey); err != nil {
		t.Fatal(err)
	}
	second.Acknowledgement.BatchID++
	if err := VerifyAcknowledgement(second, publicKey); err == nil {
		t.Fatal("tampered acknowledgement verified")
	}
	if _, err := SignAcknowledgement(a, make(ed25519.PrivateKey, 3)); err == nil {
		t.Fatal("invalid private key accepted")
	}
}

func TestAcknowledgementGoldenVector(t *testing.T) {
	var vector struct {
		Message   string `json:"message_hex"`
		PublicKey string `json:"public_key_hex"`
		Signature string `json:"signature_hex"`
		Hash      string `json:"acknowledgement_hash_hex"`
	}
	b, err := os.ReadFile("../../testdata/integrity/receipt-v1-golden.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &vector); err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte("RAVEN synthetic receipt test key; not a secret"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	var streamID, batchHash, previousHash Hash
	for i := range streamID {
		streamID[i], batchHash[i], previousHash[i] = 0x11, 0x33, 0x44
	}
	a := WitnessAcknowledgement{StreamID: streamID, BatchID: 7, BatchHash: batchHash, PreviousAckHash: previousHash, WitnessKeyID: "test-witness-1", ReceivedAtNS: 1700000000000000000}
	message, err := EncodeAcknowledgement(a)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignAcknowledgement(a, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := AcknowledgementHash(signed)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(message) != vector.Message || hex.EncodeToString(privateKey.Public().(ed25519.PublicKey)) != vector.PublicKey || hex.EncodeToString(signed.Signature) != vector.Signature || hex.EncodeToString(digest[:]) != vector.Hash {
		t.Fatal("acknowledgement vector mismatch")
	}
	if err := VerifyAcknowledgement(signed, privateKey.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
}

func FuzzDecodeEvidenceEntry(f *testing.F) {
	b, err := os.ReadFile("../../testdata/integrity/codec-v1-golden.json")
	if err != nil {
		f.Fatal(err)
	}
	var fixture struct {
		Entries []struct {
			Encoded string `json:"encoded_entry_hex"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(b, &fixture); err != nil {
		f.Fatal(err)
	}
	for _, vector := range fixture.Entries {
		seed, _ := hex.DecodeString(vector.Encoded)
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		entry, err := DecodeEvidenceEntry(data)
		if err != nil {
			return
		}
		reencoded, err := EncodeEvidenceEntry(entry)
		if err != nil {
			t.Fatalf("decoded value failed encode: %v", err)
		}
		if !bytesEqual(data, reencoded) {
			t.Fatal("decoder accepted noncanonical encoding")
		}
	})
}

func mustHash(t *testing.T, s string) Hash {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("invalid hash fixture %q", s)
	}
	var h Hash
	copy(h[:], b)
	return h
}

func validFieldsFor(kind EntryKind) ([]TypedField, []TypedField) {
	str := func(tag uint16) TypedField { return TypedField{Tag: tag, Type: FieldUTF8} }
	bytes32 := func(tag uint16) TypedField { return TypedField{Tag: tag, Type: FieldBytes32, Value: make([]byte, 32)} }
	uint64 := func(tag uint16) TypedField { return TypedField{Tag: tag, Type: FieldUint64, Value: make([]byte, 8)} }
	int64 := func(tag uint16) TypedField { return TypedField{Tag: tag, Type: FieldInt64, Value: make([]byte, 8)} }
	uint32 := func(tag uint16) TypedField { return TypedField{Tag: tag, Type: FieldUint32, Value: make([]byte, 4)} }
	int32 := func(tag uint16) TypedField { return TypedField{Tag: tag, Type: FieldInt32, Value: make([]byte, 4)} }
	content, metadata := []TypedField{}, []TypedField{}
	switch kind {
	case RawCommitted:
		metadata = []TypedField{str(1), str(2), uint32(3), uint64(4), str(5), str(6), str(7), str(8), str(9), int64(10), str(11), str(12), str(13), int32(14), int64(15), str(16)}
	case NormalizedWritten:
		metadata = []TypedField{str(1), str(2), bytes32(3), str(4), str(5)}
	case QuarantineWritten:
		content = []TypedField{bytes32(1), str(2), str(3), str(4), {Tag: 5, Type: FieldBytes}, {Tag: 6, Type: FieldUTF8List, Value: []byte{0, 0, 0, 0}}, {Tag: 7, Type: FieldBool, Value: []byte{1}}, int64(8)}
	case ReplayFailed:
		content = []TypedField{str(1), bytes32(2)}
	case ReplayResolved:
		content, metadata = []TypedField{uint64(1), uint64(2)}, []TypedField{bytes32(1)}
	case NormalizedRemoved, QuarantineRemoved:
		content = []TypedField{uint64(1), str(2)}
	}
	return content, metadata
}

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
