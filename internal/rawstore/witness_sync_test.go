package rawstore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"raven/internal/integrity"
	"raven/internal/model"
)

type syncRoundTrip func(*http.Request) (*http.Response, error)

func (f syncRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestWitnessSyncUploadsManifestAndVerifiesPinnedReceipt(t *testing.T) {
	store := setupTestStore(t)
	enableTestIntegrity(t, store)
	ctx := context.Background()
	if _, err := store.Store(ctx, model.IngestedRecord{Transport: "test", RawBytes: []byte("synthetic local lab record"), ReceivedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	batch, err := store.SealIntegrityBatch(ctx, true)
	if err != nil || batch == nil {
		t.Fatalf("seal batch: %#v %v", batch, err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	received := time.Now().UTC().Truncate(time.Nanosecond)
	signed, err := integrity.SignAcknowledgement(integrity.WitnessAcknowledgement{StreamID: batch.Descriptor.StreamID, BatchID: batch.Descriptor.BatchID, BatchHash: batch.BatchHash, WitnessKeyID: "test-key", ReceivedAtNS: received.UnixNano()}, private)
	if err != nil {
		t.Fatal(err)
	}
	wire := witnessAckJSON{StreamID: "0x" + hex.EncodeToString(signed.Acknowledgement.StreamID[:]), BatchID: signed.Acknowledgement.BatchID, BatchHash: "0x" + hex.EncodeToString(signed.Acknowledgement.BatchHash[:]), KeyID: signed.Acknowledgement.WitnessKeyID, PreviousAckHash: "0x" + hex.EncodeToString(signed.Acknowledgement.PreviousAckHash[:]), ReceivedAt: received.Format(time.RFC3339Nano), Signature: base64.StdEncoding.EncodeToString(signed.Signature), AnchorState: "pending"}
	response, _ := json.Marshal(wire)
	client := &http.Client{Transport: syncRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodGet {
			if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("a", 32) {
				t.Errorf("admin credential missing from receipt refresh")
			}
			retained, _ := json.Marshal(map[string]any{"manifest": json.RawMessage(`{}`), "acknowledgement": wire})
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(retained)), Request: r}, nil
		}
		if r.Method != http.MethodPost || r.URL.Path != "/v1/streams/0x"+hex.EncodeToString(batch.Descriptor.StreamID[:])+"/batches" {
			t.Errorf("unexpected witness request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("p", 32) {
			t.Errorf("producer credential missing")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || !bytes.Equal(body, batch.Manifest) {
			t.Errorf("uploaded manifest differs from sealed bytes: bytes=%d err=%v", len(body), err)
		}
		return &http.Response{StatusCode: http.StatusAccepted, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(response)), Request: r}, nil
	})}
	if err := store.SyncWitnessOnce(ctx, client, "http://witness.test", strings.Repeat("p", 32), strings.Repeat("a", 32), public); err != nil {
		t.Fatal(err)
	}
	var state string
	var ack []byte
	if err := store.DB().QueryRow(`SELECT state,acknowledgement FROM integrity_witness_sync WHERE stream_id=? AND batch_id=1`, batch.Descriptor.StreamID[:]).Scan(&state, &ack); err != nil || state != "witnessed" || len(ack) == 0 {
		t.Fatalf("verified acknowledgement not persisted: state=%q bytes=%d err=%v", state, len(ack), err)
	}
	if _, err := store.DB().Exec(`UPDATE integrity_witness_sync SET next_retry_at=NULL WHERE stream_id=? AND batch_id=1`, batch.Descriptor.StreamID[:]); err != nil {
		t.Fatal(err)
	}
	wire.AnchorState = "confirmed"
	wire.AnchorReceipt = map[string]any{"status": "confirmed"}
	confirmed, _ := json.Marshal(map[string]any{"manifest": json.RawMessage(`{}`), "acknowledgement": wire})
	client.Transport = syncRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("a", 32) {
			t.Errorf("expected authenticated receipt refresh request")
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(confirmed)), Request: r}, nil
	})
	if err := store.SyncWitnessOnce(ctx, client, "http://witness.test", strings.Repeat("p", 32), strings.Repeat("a", 32), public); err != nil {
		t.Fatal(err)
	}
	var storedAck []byte
	if err := store.DB().QueryRow(`SELECT state,acknowledgement FROM integrity_witness_sync WHERE stream_id=? AND batch_id=1`, batch.Descriptor.StreamID[:]).Scan(&state, &storedAck); err != nil || state != "anchored" {
		t.Fatalf("confirmed anchor was not persisted: state=%q err=%v", state, err)
	}
	storedWire, err := decodeStoredWitnessAck(storedAck)
	if err != nil || storedWire.BatchID != 1 || storedWire.StreamID == "" {
		t.Fatalf("refreshed acknowledgement was not stored in wire form: %+v %v", storedWire, err)
	}
}

func TestWitnessSyncRejectsUnpinnedSignatureAndRetries(t *testing.T) {
	store := setupTestStore(t)
	enableTestIntegrity(t, store)
	ctx := context.Background()
	if _, err := store.Store(ctx, model.IngestedRecord{Transport: "test", RawBytes: []byte("synthetic"), ReceivedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	batch, err := store.SealIntegrityBatch(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	_, wrongPrivate, _ := ed25519.GenerateKey(rand.Reader)
	pinnedPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	received := time.Now().UTC().Truncate(time.Nanosecond)
	signed, err := integrity.SignAcknowledgement(integrity.WitnessAcknowledgement{StreamID: batch.Descriptor.StreamID, BatchID: 1, BatchHash: batch.BatchHash, WitnessKeyID: "wrong", ReceivedAtNS: received.UnixNano()}, wrongPrivate)
	if err != nil {
		t.Fatal(err)
	}
	ack := witnessAckJSON{StreamID: "0x" + hex.EncodeToString(signed.Acknowledgement.StreamID[:]), BatchID: 1, BatchHash: "0x" + hex.EncodeToString(signed.Acknowledgement.BatchHash[:]), KeyID: "wrong", PreviousAckHash: "0x" + strings.Repeat("0", 64), ReceivedAt: received.Format(time.RFC3339Nano), Signature: base64.StdEncoding.EncodeToString(signed.Signature), AnchorState: "pending"}
	body, _ := json.Marshal(ack)
	client := &http.Client{Transport: syncRoundTrip(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusAccepted, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body)), Request: r}, nil
	})}
	if err := store.SyncWitnessOnce(ctx, client, "http://witness.test", strings.Repeat("p", 32), strings.Repeat("a", 32), pinnedPublic); err == nil {
		t.Fatal("accepted receipt signed by an unpinned key")
	}
	var state string
	var stored sql.NullString
	var retry int
	if err := store.DB().QueryRow(`SELECT state,acknowledgement,retry_count FROM integrity_witness_sync WHERE stream_id=? AND batch_id=1`, batch.Descriptor.StreamID[:]).Scan(&state, &stored, &retry); err != nil || state != "unavailable" || stored.Valid || retry != 1 {
		t.Fatalf("bad invalid-receipt retry state %q ack=%v retry=%d err=%v", state, stored.Valid, retry, err)
	}
}
