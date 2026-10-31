package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"raven/internal/integrity"
	"raven/internal/rawstore"
)

type integrityDescriptor struct {
	CodecVersion      uint32 `json:"codec_version"`
	StreamID          string `json:"stream_id"`
	BatchID           uint64 `json:"batch_id"`
	FirstSeq          uint64 `json:"first_seq"`
	LastSeq           uint64 `json:"last_seq"`
	LeafCount         uint32 `json:"leaf_count"`
	MerkleRoot        string `json:"merkle_root"`
	PreviousBatchHash string `json:"previous_batch_hash"`
}

func (s *Server) witnessRequest(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	if s.witnessURL == "" || s.witnessAdminToken == "" {
		return nil, errors.New("witness admin endpoint is not configured")
	}
	req, err := http.NewRequestWithContext(ctx, method, s.witnessURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.witnessAdminToken)
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	return integrityWitnessHTTPClient.Do(req)
}

var integrityWitnessHTTPClient = &http.Client{Timeout: 5 * time.Second}

func (s *Server) handleIntegrityStatus(w http.ResponseWriter, r *http.Request) {
	enabled, local, backlog, oldest, unsealed, err := s.store.IntegrityOperatorStatus(r.Context())
	if err != nil {
		s.jsonError(w, http.StatusServiceUnavailable, "integrity storage is unavailable")
		return
	}
	status := map[string]any{
		"enabled": enabled, "stream_id": nil, "local_head": local,
		"witness_head":   map[string]any{"batch_id": uint64(0), "entry_seq": uint64(0), "hash": nil},
		"chain_identity": nil, "chain_head": map[string]any{"batch_id": uint64(0), "entry_seq": uint64(0), "hash": nil},
		"latest_attempt": nil, "last_success": nil, "backlog_count": backlog, "backlog_oldest_at": oldest, "unsealed_entry_count": unsealed,
	}
	if enabled {
		stream, e := s.store.GetIntegrityStream(r.Context())
		if e != nil {
			s.jsonError(w, http.StatusServiceUnavailable, "integrity storage is unavailable")
			return
		}
		status["stream_id"] = "0x" + hex.EncodeToString(stream.StreamID[:])
		var latest, success rawstore.IntegrityAuditRun
		if e := s.store.DB().QueryRowContext(r.Context(), `SELECT run_id FROM integrity_audit_runs ORDER BY started_at DESC LIMIT 1`).Scan(&latest.RunID); e == nil {
			latest, _ = s.store.GetIntegrityAudit(r.Context(), latest.RunID)
			status["latest_attempt"] = latest
		}
		if e := s.store.DB().QueryRowContext(r.Context(), `SELECT run_id FROM integrity_audit_runs WHERE result='passed' ORDER BY completed_at DESC LIMIT 1`).Scan(&success.RunID); e == nil {
			success, _ = s.store.GetIntegrityAudit(r.Context(), success.RunID)
			status["last_success"] = success
		}
		if s.witnessURL != "" && s.witnessAdminToken != "" {
			resp, err := s.witnessRequest(r.Context(), http.MethodGet, "/v1/streams/0x"+hex.EncodeToString(stream.StreamID[:])+"/status", nil)
			if err == nil {
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					var remote struct {
						ChainIdentity any `json:"chain_identity"`
						RetainedHead  any `json:"retained_head"`
						ConfirmedHead any `json:"confirmed_head"`
					}
					if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&remote) == nil {
						status["chain_identity"], status["witness_head"], status["chain_head"] = remote.ChainIdentity, remote.RetainedHead, remote.ConfirmedHead
					}
				}
			}
		}
	}
	s.jsonResponse(w, http.StatusOK, status)
}

func (s *Server) handleStartIntegrityAudit(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Type string `json:"type"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&request); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid audit request")
		return
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		s.jsonError(w, http.StatusBadRequest, "audit request contains trailing JSON")
		return
	}
	if request.Type != "fast" && request.Type != "deep" && request.Type != "ledger" {
		s.jsonError(w, http.StatusBadRequest, "type must be fast, deep, or ledger")
		return
	}
	if request.Type == "ledger" {
		stream, err := s.store.GetIntegrityStream(r.Context())
		if err != nil {
			s.jsonError(w, http.StatusServiceUnavailable, "integrity storage is unavailable")
			return
		}
		if stream == nil {
			s.jsonError(w, http.StatusConflict, "integrity mode is disabled")
			return
		}
		body, _ := json.Marshal(map[string]string{"stream_id": "0x" + hex.EncodeToString(stream.StreamID[:]), "type": "ledger"})
		resp, err := s.witnessRequest(r.Context(), http.MethodPost, "/v1/audits", body)
		if err != nil {
			s.jsonError(w, http.StatusServiceUnavailable, "witness is unavailable")
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			s.jsonError(w, http.StatusServiceUnavailable, "witness could not schedule ledger audit")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.Copy(w, io.LimitReader(resp.Body, 64<<10))
		return
	}
	enabled, err := s.store.IntegrityEnabled(r.Context())
	if err != nil {
		s.jsonError(w, http.StatusServiceUnavailable, "integrity storage is unavailable")
		return
	}
	if !enabled {
		s.jsonError(w, http.StatusConflict, "integrity mode is disabled")
		return
	}
	run, active, err := s.store.StartIntegrityAudit(r.Context(), request.Type == "deep")
	if err != nil {
		s.jsonError(w, http.StatusServiceUnavailable, "could not persist integrity audit")
		return
	}
	if !active {
		s.auditMu.Lock()
		if s.auditCtx == nil {
			s.auditCtx, s.auditCancel = context.WithCancel(context.Background())
		}
		ctx := s.auditCtx
		s.auditWG.Add(1)
		s.auditMu.Unlock()
		go func() { defer s.auditWG.Done(); _, _ = s.store.RunIntegrityAudit(ctx, run.RunID) }()
	}
	s.jsonResponse(w, http.StatusAccepted, map[string]string{"run_id": run.RunID, "state": "running", "type": run.Type})
}

func (s *Server) handleGetIntegrityAudit(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("run_id")
	if len(id) == 0 || len(id) > 128 || strings.ContainsRune(id, 0) {
		s.jsonError(w, http.StatusBadRequest, "invalid run_id")
		return
	}
	run, err := s.store.GetIntegrityAudit(r.Context(), id)
	if err == nil {
		s.jsonResponse(w, http.StatusOK, run)
		return
	}
	if !errors.Is(err, sql.ErrNoRows) {
		s.jsonError(w, http.StatusServiceUnavailable, "integrity storage is unavailable")
		return
	}
	resp, err := s.witnessRequest(r.Context(), http.MethodGet, "/v1/audits/"+id, nil)
	if err != nil {
		s.jsonError(w, http.StatusNotFound, "audit run not found")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		s.jsonError(w, http.StatusNotFound, "audit run not found")
		return
	}
	if resp.StatusCode != http.StatusOK {
		s.jsonError(w, http.StatusServiceUnavailable, "witness audit status is unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, 64<<10))
}

func (s *Server) handleIntegrityProof(w http.ResponseWriter, r *http.Request) {
	seq, err := strconv.ParseUint(r.PathValue("entry_seq"), 10, 63)
	if err != nil || seq == 0 {
		s.jsonError(w, http.StatusBadRequest, "entry_seq must be a positive int64")
		return
	}
	enabled, err := s.store.IntegrityEnabled(r.Context())
	if err != nil {
		s.jsonError(w, http.StatusServiceUnavailable, "integrity storage is unavailable")
		return
	}
	result := map[string]any{"entry_seq": seq, "proof_state": "pending", "audit_state": "incomplete", "batch": nil, "leaf_index": nil, "tree_size": nil, "siblings": []string{}, "witness_acknowledgement": nil, "anchor_receipt": nil, "reason": nil}
	if !enabled {
		result["proof_state"], result["audit_state"], result["reason"] = "unavailable", "disabled", "integrity mode is disabled"
		s.jsonResponse(w, http.StatusOK, result)
		return
	}
	stream, err := s.store.GetIntegrityStream(r.Context())
	if err != nil {
		s.jsonError(w, http.StatusServiceUnavailable, "integrity storage is unavailable")
		return
	}
	var leafBytes []byte
	if err = s.store.DB().QueryRowContext(r.Context(), `SELECT leaf_hash FROM integrity_entries WHERE stream_id=? AND entry_seq=?`, stream.StreamID[:], seq).Scan(&leafBytes); errors.Is(err, sql.ErrNoRows) {
		s.jsonError(w, http.StatusNotFound, "entry not found")
		return
	} else if err != nil {
		s.jsonError(w, http.StatusServiceUnavailable, "integrity storage is unavailable")
		return
	}
	var state sql.NullString
	if s.store.DB().QueryRowContext(r.Context(), `SELECT result FROM integrity_audit_runs ORDER BY started_at DESC LIMIT 1`).Scan(&state) == nil && state.Valid {
		result["audit_state"] = state.String
	}
	var batchID uint64
	var first, last uint64
	var root, prev []byte
	var count uint32
	var index uint32
	err = s.store.DB().QueryRowContext(r.Context(), `SELECT b.batch_id,b.first_seq,b.last_seq,b.leaf_count,b.merkle_root,b.prev_batch_hash,m.leaf_index FROM integrity_batch_entries m JOIN integrity_batches b USING(stream_id,batch_id) WHERE m.stream_id=? AND m.entry_seq=?`, stream.StreamID[:], seq).Scan(&batchID, &first, &last, &count, &root, &prev, &index)
	if errors.Is(err, sql.ErrNoRows) {
		result["reason"] = "entry batch is not sealed"
		s.jsonResponse(w, http.StatusOK, result)
		return
	}
	if err != nil {
		s.jsonError(w, http.StatusServiceUnavailable, "integrity storage is unavailable")
		return
	}
	rows, err := s.store.DB().QueryContext(r.Context(), `SELECT leaf_hash FROM integrity_batch_entries WHERE stream_id=? AND batch_id=? ORDER BY leaf_index`, stream.StreamID[:], batchID)
	if err != nil {
		s.jsonError(w, http.StatusServiceUnavailable, "integrity storage is unavailable")
		return
	}
	leaves := make([]integrity.Hash, 0, count)
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			break
		}
		var h integrity.Hash
		copy(h[:], raw)
		leaves = append(leaves, h)
	}
	err = errors.Join(err, rows.Err(), rows.Close())
	if err != nil || len(leaves) != int(count) {
		s.jsonError(w, http.StatusServiceUnavailable, "batch proof is unavailable")
		return
	}
	proof, err := integrity.MerkleProof(leaves, index)
	var leaf integrity.Hash
	copy(leaf[:], leafBytes)
	var merkleRoot integrity.Hash
	copy(merkleRoot[:], root)
	if err != nil || !integrity.VerifyMerkleProof(leaf, index, uint32(count), proof, merkleRoot) {
		s.jsonError(w, http.StatusServiceUnavailable, "batch proof failed verification")
		return
	}
	desc := integrityDescriptor{CodecVersion: uint32(integrity.CodecVersion), StreamID: "0x" + hex.EncodeToString(stream.StreamID[:]), BatchID: batchID, FirstSeq: first, LastSeq: last, LeafCount: count, MerkleRoot: "0x" + hex.EncodeToString(root), PreviousBatchHash: "0x" + hex.EncodeToString(prev)}
	result["batch"] = desc
	result["leaf_index"] = index
	result["tree_size"] = count
	siblings := make([]string, len(proof))
	for i, h := range proof {
		siblings[i] = "0x" + hex.EncodeToString(h[:])
	}
	result["siblings"] = siblings
	var ack []byte
	if s.store.DB().QueryRowContext(r.Context(), `SELECT acknowledgement FROM integrity_witness_sync WHERE stream_id=? AND batch_id=?`, stream.StreamID[:], batchID).Scan(&ack) == nil && len(ack) > 0 {
		var value any
		if json.Unmarshal(ack, &value) == nil {
			if fields, ok := value.(map[string]any); ok {
				result["witness_acknowledgement"] = fields
				result["proof_state"] = "witnessed"
				if receipt := fields["anchor_receipt"]; receipt != nil {
					result["anchor_receipt"] = receipt
				}
				if fields["anchor_state"] == "confirmed" {
					result["proof_state"] = "anchored"
				}
			}
		}
	}
	path := "/v1/streams/0x" + hex.EncodeToString(stream.StreamID[:]) + "/batches/" + strconv.FormatUint(batchID, 10)
	if resp, requestErr := s.witnessRequest(r.Context(), http.MethodGet, path, nil); requestErr == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			var retained struct {
				Acknowledgement map[string]any `json:"acknowledgement"`
			}
			if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&retained) == nil {
				result["witness_acknowledgement"] = retained.Acknowledgement
				result["anchor_receipt"] = retained.Acknowledgement["anchor_receipt"]
				switch retained.Acknowledgement["anchor_state"] {
				case "confirmed":
					result["proof_state"] = "anchored"
				case "failed", "unavailable":
					result["proof_state"] = retained.Acknowledgement["anchor_state"]
				default:
					result["proof_state"] = "witnessed"
				}
			}
		}
	}
	s.jsonResponse(w, http.StatusOK, result)
}
