package integrity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"unicode/utf8"
)

const ReceiptVersion uint16 = 1

var receiptDomain = []byte("RAVEN-WITNESS-ACK")

type WitnessAcknowledgement struct {
	StreamID        Hash
	BatchID         uint64
	BatchHash       Hash
	PreviousAckHash Hash
	WitnessKeyID    string
	ReceivedAtNS    int64
}

type SignedAcknowledgement struct {
	Acknowledgement WitnessAcknowledgement
	Signature       []byte
}

func EncodeAcknowledgement(a WitnessAcknowledgement) ([]byte, error) {
	if a.BatchID == 0 || a.BatchID > math.MaxInt64 {
		return nil, errors.New("acknowledgement batch ID must be in 1..2^63-1")
	}
	if len(a.WitnessKeyID) == 0 || len(a.WitnessKeyID) > 128 || !utf8.ValidString(a.WitnessKeyID) || bytes.IndexByte([]byte(a.WitnessKeyID), 0) >= 0 {
		return nil, errors.New("witness key ID must be 1..128 valid UTF-8 bytes without NUL")
	}
	var b bytes.Buffer
	b.Write(receiptDomain)
	_ = binary.Write(&b, binary.BigEndian, ReceiptVersion)
	b.Write(a.StreamID[:])
	_ = binary.Write(&b, binary.BigEndian, a.BatchID)
	b.Write(a.BatchHash[:])
	b.Write(a.PreviousAckHash[:])
	_ = binary.Write(&b, binary.BigEndian, uint32(len(a.WitnessKeyID)))
	b.WriteString(a.WitnessKeyID)
	_ = binary.Write(&b, binary.BigEndian, a.ReceivedAtNS)
	return b.Bytes(), nil
}

func SignAcknowledgement(a WitnessAcknowledgement, key ed25519.PrivateKey) (SignedAcknowledgement, error) {
	if len(key) != ed25519.PrivateKeySize {
		return SignedAcknowledgement{}, errors.New("invalid Ed25519 private key length")
	}
	message, err := EncodeAcknowledgement(a)
	if err != nil {
		return SignedAcknowledgement{}, err
	}
	return SignedAcknowledgement{Acknowledgement: a, Signature: ed25519.Sign(key, message)}, nil
}

func VerifyAcknowledgement(s SignedAcknowledgement, key ed25519.PublicKey) error {
	if len(key) != ed25519.PublicKeySize || len(s.Signature) != ed25519.SignatureSize {
		return errors.New("invalid Ed25519 public key or signature length")
	}
	message, err := EncodeAcknowledgement(s.Acknowledgement)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, message, s.Signature) {
		return errors.New("invalid acknowledgement signature")
	}
	return nil
}

func AcknowledgementHash(s SignedAcknowledgement) (Hash, error) {
	message, err := EncodeAcknowledgement(s.Acknowledgement)
	if err != nil {
		return Hash{}, err
	}
	if len(s.Signature) != ed25519.SignatureSize {
		return Hash{}, fmt.Errorf("invalid Ed25519 signature length %d", len(s.Signature))
	}
	b := make([]byte, 0, len(message)+len(s.Signature))
	b = append(b, message...)
	b = append(b, s.Signature...)
	return sha256.Sum256(b), nil
}
