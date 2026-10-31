package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"raven/internal/integrity"
	"raven/internal/rawstore"
)

type integrityRoundTrip func(*http.Request) (*http.Response, error)

func (f integrityRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestWitnessAuditForwardingUsesSeparateAdminCredential(t *testing.T) {
	store, err := rawstore.New(filepath.Join(t.TempDir(), "raven.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var stream, epoch integrity.Hash
	stream[0], epoch[0] = 1, 2
	if err := store.EnableIntegrity(context.Background(), stream, epoch); err != nil {
		t.Fatal(err)
	}
	s := NewServer("", store, nil, nil, "", ConfigInfo{AdminToken: "raven-admin"}, nil, "test")
	s.SetIntegrityWitness("http://witness.test", "witness-admin")
	old := integrityWitnessHTTPClient
	t.Cleanup(func() { integrityWitnessHTTPClient = old })
	integrityWitnessHTTPClient = &http.Client{Transport: integrityRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "Bearer witness-admin" {
			t.Errorf("witness did not receive its separate admin credential")
		}
		if r.URL.Path != "/v1/audits" {
			t.Errorf("unexpected witness route: %s", r.URL.Path)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["type"] != "ledger" || body["stream_id"] != "0x"+hex.EncodeToString(stream[:]) {
			t.Errorf("bad ledger request: %+v %v", body, err)
		}
		return &http.Response{StatusCode: http.StatusAccepted, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"run_id":"remote-1","state":"running","type":"ledger"}`)), Request: r}, nil
	})}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/integrity/audits", strings.NewReader(`{"type":"ledger"}`))
	req.Header.Set("Authorization", "Bearer raven-admin")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), `"run_id":"remote-1"`) {
		t.Fatalf("forward response: %d %s", rec.Code, rec.Body.String())
	}
}

func TestIntegrityStatusQueriesPrefixedWitnessStream(t *testing.T) {
	store, err := rawstore.New(filepath.Join(t.TempDir(), "raven.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var stream, epoch integrity.Hash
	stream[0], epoch[0] = 0xab, 2
	if err := store.EnableIntegrity(context.Background(), stream, epoch); err != nil {
		t.Fatal(err)
	}
	s := NewServer("", store, nil, nil, "", ConfigInfo{AdminToken: "raven-admin"}, nil, "test")
	s.SetIntegrityWitness("http://witness.test", "witness-admin")
	old := integrityWitnessHTTPClient
	t.Cleanup(func() { integrityWitnessHTTPClient = old })
	integrityWitnessHTTPClient = &http.Client{Transport: integrityRoundTrip(func(r *http.Request) (*http.Response, error) {
		want := "/v1/streams/0x" + hex.EncodeToString(stream[:]) + "/status"
		if r.URL.Path != want || r.Header.Get("Authorization") != "Bearer witness-admin" {
			t.Errorf("unexpected witness status request: path=%q auth=%q", r.URL.Path, r.Header.Get("Authorization"))
		}
		body := `{"chain_identity":{"chain_id":31337},"retained_head":{"batch_id":1},"confirmed_head":{"batch_id":1}}`
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/integrity/status", nil)
	req.Header.Set("Authorization", "Bearer raven-admin")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"chain_id":31337`) {
		t.Fatalf("witness head was not included: %d %s", rec.Code, rec.Body.String())
	}
}
