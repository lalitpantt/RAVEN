package rawstore

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"raven/internal/integrity"
)

type witnessAckJSON struct {
	StreamID        string `json:"stream_id"`
	BatchID         uint64 `json:"batch_id"`
	BatchHash       string `json:"batch_hash"`
	KeyID           string `json:"key_id"`
	PreviousAckHash string `json:"previous_ack_hash"`
	ReceivedAt      string `json:"received_at"`
	Signature       string `json:"signature"`
	AnchorState     string `json:"anchor_state"`
	AnchorReceipt   any    `json:"anchor_receipt"`
}

// StartWitnessSync retries durable sealed manifests until the store closes.
func (s *RawStore) StartWitnessSync(ctx context.Context, endpoint, token, adminToken string, publicKey ed25519.PublicKey) error {
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("witness URL must be an absolute HTTP(S) URL without embedded credentials")
	}
	if len(token) < 32 || len(adminToken) < 32 || len(publicKey) != ed25519.PublicKeySize {
		return errors.New("witness producer/admin tokens and pinned Ed25519 public key are required")
	}
	s.witnessMu.Lock()
	defer s.witnessMu.Unlock()
	if s.witnessStop != nil {
		return errors.New("witness synchronization is already running")
	}
	runCtx, cancel := context.WithCancel(ctx)
	s.witnessStop = cancel
	s.witnessWG.Add(1)
	go func() {
		defer s.witnessWG.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		client := &http.Client{Timeout: 5 * time.Second}
		for {
			if err := s.SyncWitnessOnce(runCtx, client, endpoint, token, adminToken, publicKey); err != nil && !errors.Is(err, context.Canceled) {
				// Retry state is durable; logging contains no credentials or payloads.
				log.Printf("integrity witness synchronization deferred: %v", err)
			}
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return nil
}

// SyncWitnessOnce sends the oldest due manifests and verifies the pinned signed receipt.
func (s *RawStore) SyncWitnessOnce(ctx context.Context, client *http.Client, endpoint, token, adminToken string, publicKey ed25519.PublicKey) error {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	var streamBytes []byte
	if err := s.db.QueryRowContext(ctx, `SELECT stream_id FROM integrity_streams WHERE singleton=1 AND enabled=1`).Scan(&streamBytes); errors.Is(err, sql.ErrNoRows) {
		return nil
	} else if err != nil {
		return err
	}
	var stream integrity.Hash
	copy(stream[:], streamBytes)
	for {
		var batchID uint64
		err := s.db.QueryRowContext(ctx, `SELECT batch_id FROM integrity_witness_sync WHERE stream_id=? AND acknowledgement IS NULL AND state IN ('pending','failed','unavailable') AND (next_retry_at IS NULL OR next_retry_at<=?) ORDER BY batch_id LIMIT 1`, streamBytes, time.Now().UTC().Format(time.RFC3339Nano)).Scan(&batchID)
		if errors.Is(err, sql.ErrNoRows) {
			break
		}
		if err != nil {
			return err
		}
		manifest, batchHash, err := s.integrityManifest(ctx, stream, batchID)
		if err != nil {
			_ = s.recordWitnessSyncError(ctx, streamBytes, batchID, err)
			return err
		}
		path := "/v1/streams/0x" + hex.EncodeToString(stream[:]) + "/batches"
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(endpoint, "/")+path, strings.NewReader(string(manifest)))
		if err != nil {
			_ = s.recordWitnessSyncError(ctx, streamBytes, batchID, err)
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			_ = s.recordWitnessSyncError(ctx, streamBytes, batchID, err)
			return err
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		if readErr != nil {
			_ = s.recordWitnessSyncError(ctx, streamBytes, batchID, readErr)
			return readErr
		}
		if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
			err = fmt.Errorf("witness returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
			_ = s.recordWitnessSyncError(ctx, streamBytes, batchID, err)
			return err
		}
		var wire witnessAckJSON
		if err = json.Unmarshal(body, &wire); err != nil {
			_ = s.recordWitnessSyncError(ctx, streamBytes, batchID, err)
			return err
		}
		signed, err := decodeWitnessAck(wire)
		if err != nil {
			_ = s.recordWitnessSyncError(ctx, streamBytes, batchID, err)
			return err
		}
		if signed.Acknowledgement.StreamID != stream || signed.Acknowledgement.BatchID != batchID || signed.Acknowledgement.BatchHash != batchHash {
			err = errors.New("witness acknowledgement does not match the submitted batch")
			_ = s.recordWitnessSyncError(ctx, streamBytes, batchID, err)
			return err
		}
		if err = integrity.VerifyAcknowledgement(signed, publicKey); err != nil {
			_ = s.recordWitnessSyncError(ctx, streamBytes, batchID, err)
			return err
		}
		expectedPrevious := integrity.Hash{}
		if batchID > 1 {
			var previous []byte
			if err = s.db.QueryRowContext(ctx, `SELECT acknowledgement FROM integrity_witness_sync WHERE stream_id=? AND batch_id=?`, streamBytes, batchID-1).Scan(&previous); err != nil {
				err = fmt.Errorf("prior witness acknowledgement is missing: %w", err)
				_ = s.recordWitnessSyncError(ctx, streamBytes, batchID, err)
				return err
			}
			var previousWire witnessAckJSON
			if err = json.Unmarshal(previous, &previousWire); err != nil {
				return err
			}
			previousSigned, decodeErr := decodeWitnessAck(previousWire)
			if decodeErr != nil {
				return decodeErr
			}
			expectedPrevious, err = integrity.AcknowledgementHash(previousSigned)
			if err != nil {
				return err
			}
		}
		if signed.Acknowledgement.PreviousAckHash != expectedPrevious {
			err = errors.New("witness acknowledgement chain is discontinuous")
			_ = s.recordWitnessSyncError(ctx, streamBytes, batchID, err)
			return err
		}
		state := "witnessed"
		switch wire.AnchorState {
		case "confirmed":
			state = "anchored"
		case "failed":
			state = "failed"
		case "unavailable":
			state = "unavailable"
		}
		if _, err = s.db.ExecContext(ctx, `UPDATE integrity_witness_sync SET state=?,acknowledgement=?,last_error=NULL,next_retry_at=NULL,retry_count=retry_count+1 WHERE stream_id=? AND batch_id=? AND acknowledgement IS NULL`, state, body, streamBytes, batchID); err != nil {
			return err
		}
	}
	var batchID uint64
	err := s.db.QueryRowContext(ctx, `SELECT batch_id FROM integrity_witness_sync WHERE stream_id=? AND acknowledgement IS NOT NULL AND state!='anchored' AND (next_retry_at IS NULL OR next_retry_at<=?) ORDER BY batch_id LIMIT 1`, streamBytes, time.Now().UTC().Format(time.RFC3339Nano)).Scan(&batchID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return s.refreshWitnessBatch(ctx, client, endpoint, adminToken, publicKey, streamBytes, stream, batchID)
}

func (s *RawStore) refreshWitnessBatch(ctx context.Context, client *http.Client, endpoint, adminToken string, publicKey ed25519.PublicKey, streamBytes []byte, stream integrity.Hash, batchID uint64) error {
	path := "/v1/streams/0x" + hex.EncodeToString(stream[:]) + "/batches/" + fmt.Sprint(batchID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(endpoint, "/")+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := client.Do(req)
	if err != nil {
		_ = s.recordWitnessRefreshError(ctx, streamBytes, batchID, err)
		return err
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	if readErr != nil {
		_ = s.recordWitnessRefreshError(ctx, streamBytes, batchID, readErr)
		return readErr
	}
	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("witness returned HTTP %d while refreshing acknowledgement", resp.StatusCode)
		_ = s.recordWitnessRefreshError(ctx, streamBytes, batchID, err)
		return err
	}
	var retained struct {
		Acknowledgement witnessAckJSON `json:"acknowledgement"`
	}
	if err = json.Unmarshal(body, &retained); err != nil {
		_ = s.recordWitnessRefreshError(ctx, streamBytes, batchID, err)
		return err
	}
	wire := retained.Acknowledgement
	signed, err := decodeWitnessAck(wire)
	if err != nil {
		_ = s.recordWitnessRefreshError(ctx, streamBytes, batchID, err)
		return err
	}
	var batchHashBytes []byte
	if err = s.db.QueryRowContext(ctx, `SELECT batch_hash FROM integrity_batches WHERE stream_id=? AND batch_id=?`, streamBytes, batchID).Scan(&batchHashBytes); err != nil {
		return err
	}
	var batchHash integrity.Hash
	copy(batchHash[:], batchHashBytes)
	if signed.Acknowledgement.StreamID != stream || signed.Acknowledgement.BatchID != batchID || signed.Acknowledgement.BatchHash != batchHash {
		err = errors.New("refreshed witness acknowledgement does not match the batch")
		_ = s.recordWitnessRefreshError(ctx, streamBytes, batchID, err)
		return err
	}
	if err = integrity.VerifyAcknowledgement(signed, publicKey); err != nil {
		_ = s.recordWitnessRefreshError(ctx, streamBytes, batchID, err)
		return err
	}
	var previousHash integrity.Hash
	if batchID > 1 {
		var previous []byte
		if err = s.db.QueryRowContext(ctx, `SELECT acknowledgement FROM integrity_witness_sync WHERE stream_id=? AND batch_id=?`, streamBytes, batchID-1).Scan(&previous); err != nil {
			return fmt.Errorf("prior witness acknowledgement is missing: %w", err)
		}
		var previousWire witnessAckJSON
		if err = json.Unmarshal(previous, &previousWire); err != nil {
			return err
		}
		previousSigned, decodeErr := decodeWitnessAck(previousWire)
		if decodeErr != nil {
			return decodeErr
		}
		previousHash, err = integrity.AcknowledgementHash(previousSigned)
		if err != nil {
			return err
		}
	}
	if signed.Acknowledgement.PreviousAckHash != previousHash {
		err = errors.New("refreshed witness acknowledgement chain is discontinuous")
		_ = s.recordWitnessRefreshError(ctx, streamBytes, batchID, err)
		return err
	}
	state := "witnessed"
	switch wire.AnchorState {
	case "confirmed":
		state = "anchored"
	case "failed", "unavailable":
		state = wire.AnchorState
	}
	next := any(nil)
	if state != "anchored" {
		next = time.Now().UTC().Add(5 * time.Second).Format(time.RFC3339Nano)
	}
	_, err = s.db.ExecContext(ctx, `UPDATE integrity_witness_sync SET state=?,acknowledgement=?,last_error=NULL,next_retry_at=? WHERE stream_id=? AND batch_id=?`, state, body, next, streamBytes, batchID)
	return err
}

func (s *RawStore) recordWitnessRefreshError(ctx context.Context, stream []byte, batch uint64, err error) error {
	var retries int
	_ = s.db.QueryRowContext(ctx, `SELECT retry_count FROM integrity_witness_sync WHERE stream_id=? AND batch_id=?`, stream, batch).Scan(&retries)
	next := time.Now().UTC().Add(time.Second << min(retries, 6)).Format(time.RFC3339Nano)
	_, dbErr := s.db.ExecContext(ctx, `UPDATE integrity_witness_sync SET state='unavailable',retry_count=retry_count+1,next_retry_at=?,last_error=? WHERE stream_id=? AND batch_id=?`, next, err.Error(), stream, batch)
	return dbErr
}

func (s *RawStore) integrityManifest(ctx context.Context, stream integrity.Hash, batchID uint64) ([]byte, integrity.Hash, error) {
	var first, last uint64
	var count uint32
	var root, prev, batchHash []byte
	if err := s.db.QueryRowContext(ctx, `SELECT first_seq,last_seq,leaf_count,merkle_root,prev_batch_hash,batch_hash FROM integrity_batches WHERE stream_id=? AND batch_id=?`, stream[:], batchID).Scan(&first, &last, &count, &root, &prev, &batchHash); err != nil {
		return nil, integrity.Hash{}, err
	}
	var d integrity.Hash
	copy(d[:], batchHash)
	desc := manifestDescriptor{CodecVersion: uint32(integrity.CodecVersion), StreamID: "0x" + hex.EncodeToString(stream[:]), BatchID: batchID, FirstSeq: first, LastSeq: last, LeafCount: count, MerkleRoot: "0x" + hex.EncodeToString(root), PreviousBatchHash: "0x" + hex.EncodeToString(prev)}
	rows, err := s.db.QueryContext(ctx, `SELECT e.encoded_entry FROM integrity_batch_entries m JOIN integrity_entries e USING(stream_id,entry_seq) WHERE m.stream_id=? AND m.batch_id=? ORDER BY m.leaf_index`, stream[:], batchID)
	if err != nil {
		return nil, d, err
	}
	entries := make([]manifestEntry, 0, count)
	for rows.Next() {
		var encoded []byte
		if err = rows.Scan(&encoded); err != nil {
			break
		}
		entry, decodeErr := integrity.DecodeEvidenceEntry(encoded)
		if decodeErr != nil {
			err = decodeErr
			break
		}
		if entry.SubjectID == nil {
			err = errors.New("evidence entry has no subject ID")
			break
		}
		kind, kindErr := entryKindName(entry.Kind)
		if kindErr != nil {
			err = kindErr
			break
		}
		wire := manifestEntry{EntrySeq: entry.Sequence, Kind: kind, SubjectID: *entry.SubjectID, RawID: entry.RawID, ChildOrdinal: entry.ChildOrdinal, OperationID: entry.OperationID, PreviousSubjectSeq: entry.PreviousSubjectSeq, OccurredAtUnixNS: entry.OccurredAtUnixNS, ContentDigest: "0x" + hex.EncodeToString(entry.ContentDigest[:]), MetadataDigest: "0x" + hex.EncodeToString(entry.MetadataDigest[:])}
		entries = append(entries, wire)
	}
	err = errors.Join(err, rows.Err(), rows.Close())
	if err != nil {
		return nil, d, err
	}
	if len(entries) != int(count) || uint64(len(entries)) != last-first+1 {
		return nil, d, errors.New("sealed batch membership is incomplete")
	}
	manifest, err := json.Marshal(batchManifest{Descriptor: desc, Entries: entries})
	if err != nil {
		return nil, d, err
	}
	if len(manifest) > maxManifestBytes {
		return nil, d, errors.New("sealed manifest exceeds witness request limit")
	}
	return manifest, d, nil
}

func decodeWitnessAck(w witnessAckJSON) (integrity.SignedAcknowledgement, error) {
	var result integrity.SignedAcknowledgement
	stream, err := decodeHash(w.StreamID)
	if err != nil {
		return result, err
	}
	batch, err := decodeHash(w.BatchHash)
	if err != nil {
		return result, err
	}
	previous, err := decodeHash(w.PreviousAckHash)
	if err != nil {
		return result, err
	}
	received, err := time.Parse(time.RFC3339Nano, w.ReceivedAt)
	if err != nil {
		return result, err
	}
	signature, err := base64.StdEncoding.DecodeString(w.Signature)
	if err != nil {
		return result, err
	}
	result.Acknowledgement = integrity.WitnessAcknowledgement{StreamID: stream, BatchID: w.BatchID, BatchHash: batch, PreviousAckHash: previous, WitnessKeyID: w.KeyID, ReceivedAtNS: received.UnixNano()}
	result.Signature = signature
	return result, nil
}

func decodeHash(value string) (integrity.Hash, error) {
	var h integrity.Hash
	value = strings.TrimPrefix(value, "0x")
	b, err := hex.DecodeString(value)
	if err != nil || len(b) != len(h) {
		return h, errors.New("witness returned a malformed 32-byte hash")
	}
	copy(h[:], b)
	return h, nil
}

func (s *RawStore) recordWitnessSyncError(ctx context.Context, stream []byte, batch uint64, err error) error {
	var retries int
	_ = s.db.QueryRowContext(ctx, `SELECT retry_count FROM integrity_witness_sync WHERE stream_id=? AND batch_id=?`, stream, batch).Scan(&retries)
	delay := time.Second << min(retries, 6)
	next := time.Now().UTC().Add(delay).Format(time.RFC3339Nano)
	_, dbErr := s.db.ExecContext(ctx, `UPDATE integrity_witness_sync SET state='unavailable',retry_count=retry_count+1,next_retry_at=?,last_error=? WHERE stream_id=? AND batch_id=? AND acknowledgement IS NULL`, next, err.Error(), stream, batch)
	return dbErr
}
