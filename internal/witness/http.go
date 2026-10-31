package witness

import (
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"raven/internal/integrity"
)

type Server struct {
	store        *Store
	streamID     integrity.Hash
	producerAuth string
	adminAuth    string
	signer       ReceiptSigner
	auditor      *LedgerAuditor
	mu           http.ServeMux
}

type APIHead struct {
	BatchID  uint64  `json:"batch_id"`
	EntrySeq uint64  `json:"entry_seq"`
	Hash     *string `json:"hash"`
}

type APIStatus struct {
	StreamID      string          `json:"stream_id"`
	ChainIdentity any             `json:"chain_identity"`
	RetainedHead  APIHead         `json:"retained_head"`
	ConfirmedHead APIHead         `json:"confirmed_head"`
	BacklogCount  int             `json:"backlog_count"`
	LedgerAudit   json.RawMessage `json:"ledger_audit"`
}

func NewServer(store *Store, streamID integrity.Hash, producerToken, adminToken string, signer ReceiptSigner) (*Server, error) {
	if store == nil || streamID == (integrity.Hash{}) || streamID != store.streamID {
		return nil, errors.New("witness server requires its registered store stream")
	}
	if len(producerToken) < 32 || len(adminToken) < 32 {
		return nil, errors.New("witness producer and admin credentials must each contain at least 32 bytes")
	}
	if len(signer.Key) != 64 || signer.KeyID == "" {
		return nil, errors.New("witness receipt signing key is invalid")
	}
	if _, err := integrity.EncodeAcknowledgement(integrity.WitnessAcknowledgement{BatchID: 1, WitnessKeyID: signer.KeyID}); err != nil {
		return nil, fmt.Errorf("invalid witness receipt key ID: %w", err)
	}
	s := &Server{store: store, streamID: streamID, producerAuth: producerToken, adminAuth: adminToken, signer: signer}
	s.auditor = NewLedgerAuditor(store, nil, signer)
	s.mu.HandleFunc("POST /v1/streams/{stream_id}/batches", s.retainBatch)
	s.mu.HandleFunc("GET /v1/streams/{stream_id}/batches/{batch_id}", s.getBatch)
	s.mu.HandleFunc("GET /v1/streams/{stream_id}/status", s.getStatus)
	s.mu.HandleFunc("POST /v1/audits", s.startAudit)
	s.mu.HandleFunc("GET /v1/audits/{run_id}", s.getAudit)
	return s, nil
}

func (s *Server) Handler() http.Handler { return &s.mu }

func (s *Server) SetLedgerAuditor(auditor *LedgerAuditor) { s.auditor = auditor }

func (s *Server) retainBatch(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, s.producerAuth) {
		return
	}
	streamID, ok := s.pathStream(w, r)
	if !ok {
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxManifestBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body exceeds 4 MiB")
		} else {
			writeError(w, http.StatusBadRequest, "could not read request body")
		}
		return
	}
	manifest, err := decodeManifest(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if manifest.Descriptor.StreamID != streamID {
		writeError(w, http.StatusBadRequest, "path stream_id differs from manifest descriptor")
		return
	}
	result, err := s.store.Retain(r.Context(), manifest, s.signer)
	if errors.Is(err, ErrEquivocation) {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if errors.Is(err, ErrContinuity) {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "witness could not durably retain this manifest")
		return
	}
	status := http.StatusAccepted
	if result.Acknowledgement.AnchorState == "confirmed" {
		status = http.StatusOK
	}
	writeJSON(w, status, result.Acknowledgement)
}

func (s *Server) getBatch(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, s.adminAuth) {
		return
	}
	streamID, ok := s.pathStream(w, r)
	if !ok {
		return
	}
	batchID, err := strconv.ParseUint(r.PathValue("batch_id"), 10, 64)
	if err != nil || batchID == 0 || batchID > uint64(^uint64(0)>>1) {
		writeError(w, http.StatusBadRequest, "batch_id must be within 1..2^63-1")
		return
	}
	result, err := s.store.GetBatch(r.Context(), streamID, batchID)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "witness storage is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) getStatus(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, s.adminAuth) {
		return
	}
	streamID, ok := s.pathStream(w, r)
	if !ok {
		return
	}
	status, err := s.store.Status(r.Context(), streamID)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "witness storage is unavailable")
		return
	}
	confirmedHead, err := s.store.ConfirmedHead(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "witness storage is unavailable")
		return
	}
	var identity any
	identity, err = s.store.ChainIdentity(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "witness storage is unavailable")
		return
	}
	ledgerAudit, err := s.store.LatestAudit(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "witness storage is unavailable")
		return
	}
	ledgerJSON, _ := json.Marshal(ledgerAudit)
	if ledgerAudit == nil {
		ledgerJSON = []byte("null")
	}
	writeJSON(w, http.StatusOK, APIStatus{
		StreamID: formatHash(streamID), ChainIdentity: identity,
		RetainedHead: APIHead(status.RetainedHead), ConfirmedHead: APIHead(confirmedHead),
		BacklogCount: status.BacklogCount, LedgerAudit: ledgerJSON,
	})
}

func (s *Server) startAudit(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, s.adminAuth) {
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body exceeds 64 KiB")
		} else {
			writeError(w, http.StatusBadRequest, "could not read request body")
		}
		return
	}
	var request struct {
		StreamID string `json:"stream_id"`
		Type     string `json:"type"`
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&request); err != nil || request.Type != "ledger" {
		writeError(w, http.StatusBadRequest, "audit request must select type ledger")
		return
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "audit request contains trailing JSON")
		return
	}
	streamID, err := parseHash(request.StreamID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid stream_id")
		return
	}
	if streamID != s.streamID {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	run, err := s.auditor.Schedule(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "witness could not persist ledger audit")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"run_id": run.RunID, "state": "running", "type": "ledger"})
}

func (s *Server) getAudit(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, s.adminAuth) {
		return
	}
	run, err := s.store.GetAudit(r.Context(), r.PathValue("run_id"))
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "witness storage is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) pathStream(w http.ResponseWriter, r *http.Request) (integrity.Hash, bool) {
	streamID, err := parseHash(r.PathValue("stream_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid stream_id")
		return integrity.Hash{}, false
	}
	if streamID != s.streamID {
		writeError(w, http.StatusNotFound, "not found")
		return integrity.Hash{}, false
	}
	return streamID, true
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request, expected string) bool {
	const prefix = "Bearer "
	authorization := r.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, prefix) || len(authorization) == len(prefix) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return false
	}
	got := []byte(strings.TrimPrefix(authorization, prefix))
	want := []byte(expected)
	if len(got) != len(want) || subtle.ConstantTimeCompare(got, want) != 1 {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	if len(message) > 2048 {
		message = message[:2048]
	}
	writeJSON(w, status, map[string]string{"error": message})
}
