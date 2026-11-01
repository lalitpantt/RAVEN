package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"raven/internal/analysis"
	"raven/internal/api"
	"raven/internal/connections"
	"raven/internal/integrity"
	"raven/internal/model"
	"raven/internal/packs"
	"raven/internal/pipeline"
	"raven/internal/rawstore"
)

func setupTestServer(t *testing.T) (*api.Server, *rawstore.RawStore, *pipeline.Pipeline, string) {
	t.Helper()
	tempDir, err := os.MkdirTemp("", "raven_api_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	dbPath := filepath.Join(tempDir, "raven.db")
	store, err := rawstore.New(dbPath)
	if err != nil {
		t.Fatalf("failed to create raw store: %v", err)
	}

	// Create test parser pack
	packsDir := filepath.Join(tempDir, "packs")
	_ = os.MkdirAll(packsDir, 0755)

	samplePackYAML := `
apiVersion: raven.io/v1
kind: LogSource
metadata:
  name: test-firewall
  version: 1.0.0
  description: Test Firewall Pack
  author: SecurityOps
spec:
  sourceCategory: network_device
  format: syslog
  match:
    contains: "%ASA-6-302013"
  fields:
    src_ip:
      from: src_ip
      type: ip
`
	_ = os.WriteFile(filepath.Join(packsDir, "test-firewall.yaml"), []byte(samplePackYAML), 0644)
	snap, err := packs.LoadDir(packsDir)
	if err != nil {
		t.Fatalf("failed to load packs: %v", err)
	}
	packMgr := packs.NewSnapshotManager(snap)

	pipe := pipeline.New(pipeline.Config{
		Workers:     2,
		BufferSize:  100,
		PackManager: packMgr,
	}, store, nil)
	pipe.Start()

	mockFS := fstest.MapFS{
		"index.html": {
			Data: []byte("<!DOCTYPE html><html><body>RAVEN Test UI</body></html>"),
		},
		"assets/test.js": {
			Data: []byte("console.log('test');"),
		},
	}

	cfg := api.ConfigInfo{
		SyslogUDP:  ":1514",
		SyslogTCP:  ":1514",
		HTTPIngest: ":8080",
		InboxDir:   "data/inbox",
		DBPath:     dbPath,
		Workers:    2,
	}

	srv := api.NewServer("127.0.0.1:0", store, pipe, packMgr, packsDir, cfg, mockFS, "test-version")
	return srv, store, pipe, tempDir
}

func TestAPI_AnalysisReadOnlyTelemetryEndpoints(t *testing.T) {
	srv, store, pipe, tempDir := setupTestServer(t)
	defer os.RemoveAll(tempDir)
	defer store.Close()
	defer pipe.Stop()
	analysisDir := filepath.Join(tempDir, "analysis")
	for _, resource := range []string{
		"devices/app-server-01.yaml",
		"devices/edge-router-01.yaml",
		"rules/device-heartbeat.yaml",
		"rules/interface-down.yaml",
	} {
		data, err := os.ReadFile(filepath.Join("..", "..", "analysis", "examples", resource))
		if err != nil {
			t.Fatal(err)
		}
		destination := filepath.Join(analysisDir, resource)
		if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(destination, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := analysis.LoadDirectory(analysisDir)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := analysis.NewWorker(store, snapshot.Resolver())
	if err != nil {
		t.Fatal(err)
	}
	worker.SetSnapshot(snapshot)
	if err := worker.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer worker.Stop()
	srv.SetAnalysis(snapshot, worker, "")

	ctx := context.Background()
	raw, err := store.Store(ctx, model.IngestedRecord{Transport: "syslog_udp", SourceIP: "10.20.0.1", RawBytes: []byte("heartbeat"), ReceivedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	event := &model.NormalizedEvent{Raven: model.RavenEnvelope{EventID: "api-analysis-heartbeat", RawID: raw.RawID, SourceCategory: "network_device", SourceID: "edge-router-01", ReceivedTime: raw.ReceivedAt}, OCSF: map[string]any{"activity_name": "heartbeat"}}
	if err := store.StoreNormalizedWithOutboxAndHints(ctx, event, nil, model.AnalysisIdentityHints{"source_ip": "10.20.0.1"}); err != nil {
		t.Fatal(err)
	}
	downRaw, err := store.Store(ctx, model.IngestedRecord{Transport: "syslog_udp", SourceIP: "10.20.0.1", RawBytes: []byte("interface down"), ReceivedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	downEvent := &model.NormalizedEvent{Raven: model.RavenEnvelope{EventID: "api-analysis-interface-down", RawID: downRaw.RawID, SourceCategory: "network_device", SourceID: "edge-router-01", ReceivedTime: downRaw.ReceivedAt}, OCSF: map[string]any{"activity_name": "interface_down"}}
	if err := store.StoreNormalizedWithOutboxAndHints(ctx, downEvent, nil, model.AnalysisIdentityHints{"source_ip": "10.20.0.1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Store(ctx, model.IngestedRecord{Transport: "http_post", SourceIP: "192.0.2.44", RawBytes: []byte("unassigned"), ReceivedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	ambiguousRaw, err := store.Store(ctx, model.IngestedRecord{Transport: "syslog_udp", SourceIP: "10.20.0.1", RawBytes: []byte("ambiguous identity"), ReceivedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.QuarantineChild(ctx, model.QuarantineEntry{
		QuarantineID: "analysis-ambiguous-quarantine", RawID: ambiguousRaw.RawID,
		RawSHA256: ambiguousRaw.RawSHA256, Stage: "analysis-test", Reason: "ambiguous identity",
		QuarantinedAt: time.Now().UTC(), AnalysisHints: model.AnalysisIdentityHints{"source_ip": "10.20.0.1", "host": "app-server-01"},
	}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		status, err := worker.Status(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if status.QueueStatus.Pending == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("analysis worker did not drain observations: %+v", status.QueueStatus)
		}
		time.Sleep(10 * time.Millisecond)
	}

	handler := srv.Handler()
	var observationsBefore, telemetryBefore int64
	if err := store.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM analysis_observations`).Scan(&observationsBefore); err != nil {
		t.Fatal(err)
	}
	if err := store.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM analysis_device_telemetry`).Scan(&telemetryBefore); err != nil {
		t.Fatal(err)
	}
	request := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	status := request("/api/v1/analysis/status")
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"state":"running"`) || !strings.Contains(status.Body.String(), `"pending_count":0`) || !strings.Contains(status.Body.String(), `"reason":`) || !strings.Contains(status.Body.String(), `"evaluated_at":`) {
		t.Fatalf("analysis service health response: %d %s", status.Code, status.Body.String())
	}
	baselines := request("/api/v1/analysis/baselines?limit=10&offset=0")
	if baselines.Code != http.StatusOK || !strings.Contains(baselines.Body.String(), `"baselines":[]`) || !strings.Contains(baselines.Body.String(), `"total":0`) {
		t.Fatalf("read-only baseline status response: %d %s", baselines.Code, baselines.Body.String())
	}
	if invalid := request("/api/v1/analysis/baselines?limit=501"); invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid baseline page limit status=%d body=%s", invalid.Code, invalid.Body.String())
	}
	devices := request("/api/v1/analysis/devices?limit=1&offset=1")
	if devices.Code != http.StatusOK || !strings.Contains(devices.Body.String(), `"total":2`) || !strings.Contains(devices.Body.String(), `"limit":1`) {
		t.Fatalf("paginated device response: %d %s", devices.Code, devices.Body.String())
	}
	first := request("/api/v1/analysis/devices?limit=1&offset=1")
	if !strings.Contains(first.Body.String(), `"device_id":"edge-router-01"`) || !strings.Contains(first.Body.String(), `"state":"green"`) || !strings.Contains(first.Body.String(), `"heartbeat_count":1`) || !strings.Contains(first.Body.String(), `"normalized_per_minute":0.4`) {
		t.Fatalf("heartbeat device projection: %s", first.Body.String())
	}
	filteredDevices := request("/api/v1/analysis/devices?state=green&category=network_device&site=hq&device=router&window=1h")
	if filteredDevices.Code != http.StatusOK || !strings.Contains(filteredDevices.Body.String(), `"total":1`) || !strings.Contains(filteredDevices.Body.String(), `"active_finding_count":1`) || !strings.Contains(filteredDevices.Body.String(), `"labels":{"criticality":"high","site":"hq"}`) {
		t.Fatalf("server-filtered device response: %d %s", filteredDevices.Code, filteredDevices.Body.String())
	}
	filteredServer := request("/api/v1/analysis/devices?state=unknown&category=server&site=hq&device=app")
	if filteredServer.Code != http.StatusOK || !strings.Contains(filteredServer.Body.String(), `"total":1`) || !strings.Contains(filteredServer.Body.String(), `"device_id":"app-server-01"`) {
		t.Fatalf("configured device filter response: %d %s", filteredServer.Code, filteredServer.Body.String())
	}
	if invalid := request("/api/v1/analysis/devices?state=broken"); invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid analysis state status=%d body=%s", invalid.Code, invalid.Body.String())
	}
	unassigned := request("/api/v1/analysis/sources?resolution=unassigned&limit=10")
	if unassigned.Code != http.StatusOK || !strings.Contains(unassigned.Body.String(), `"total":2`) || !strings.Contains(unassigned.Body.String(), `"resolution":"unknown"`) || !strings.Contains(unassigned.Body.String(), `"resolution":"ambiguous"`) {
		t.Fatalf("unassigned sources response: %d %s", unassigned.Code, unassigned.Body.String())
	}
	if invalid := request("/api/v1/analysis/devices?limit=501"); invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid page limit status=%d body=%s", invalid.Code, invalid.Body.String())
	}
	findings := request("/api/v1/analysis/findings?status=open")
	if findings.Code != http.StatusOK || !strings.Contains(findings.Body.String(), `"rule_id":"interface-down"`) || !strings.Contains(findings.Body.String(), `"total":1`) {
		t.Fatalf("read-only findings list: %d %s", findings.Code, findings.Body.String())
	}
	filteredFindings := request("/api/v1/analysis/findings?status=open&rule_id=interface-down&device=edge-router-01&window=1h")
	if filteredFindings.Code != http.StatusOK || !strings.Contains(filteredFindings.Body.String(), `"total":1`) {
		t.Fatalf("filtered findings response: %d %s", filteredFindings.Code, filteredFindings.Body.String())
	}
	noFindings := request("/api/v1/analysis/findings?status=open&device=missing-device")
	if noFindings.Code != http.StatusOK || !strings.Contains(noFindings.Body.String(), `"total":0`) {
		t.Fatalf("empty finding filter response: %d %s", noFindings.Code, noFindings.Body.String())
	}
	var findingResponse struct {
		Findings []struct {
			ID string `json:"id"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(findings.Body.Bytes(), &findingResponse); err != nil || len(findingResponse.Findings) != 1 {
		t.Fatalf("decode finding list: %+v err=%v", findingResponse, err)
	}
	detail := request("/api/v1/analysis/findings/" + findingResponse.Findings[0].ID)
	if detail.Code != http.StatusOK || !strings.Contains(detail.Body.String(), "/api/v1/events/api-analysis-interface-down/trace") || !strings.Contains(detail.Body.String(), "/api/v1/events/api-analysis-interface-down/verify") {
		t.Fatalf("finding evidence links: %d %s", detail.Code, detail.Body.String())
	}
	if invalid := request("/api/v1/analysis/findings?status=active"); invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid findings status=%d body=%s", invalid.Code, invalid.Body.String())
	}
	if legacy := request("/api/v1/sources"); legacy.Code != http.StatusOK || !strings.Contains(legacy.Body.String(), `"sources"`) {
		t.Fatalf("existing source API changed: %d %s", legacy.Code, legacy.Body.String())
	}
	var observationsAfter, telemetryAfter int64
	if err := store.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM analysis_observations`).Scan(&observationsAfter); err != nil {
		t.Fatal(err)
	}
	if err := store.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM analysis_device_telemetry`).Scan(&telemetryAfter); err != nil {
		t.Fatal(err)
	}
	if observationsAfter != observationsBefore || telemetryAfter != telemetryBefore {
		t.Fatalf("read-only API mutated analysis state: observations %d->%d telemetry %d->%d", observationsBefore, observationsAfter, telemetryBefore, telemetryAfter)
	}
}

func TestAPI_IntegrityJobsAndPendingProofUnauthenticated(t *testing.T) {
	srv, store, pipe, tempDir := setupTestServer(t)
	defer os.RemoveAll(tempDir)
	defer store.Close()
	defer pipe.Stop()
	handler := srv.Handler()
	request := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	if got := request(http.MethodGet, "/api/v1/integrity/status", ""); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"enabled":false`) {
		t.Fatalf("disabled status: %d %s", got.Code, got.Body.String())
	}
	if got := request(http.MethodPost, "/api/v1/integrity/audits", `{"type":"fast"}`); got.Code != http.StatusConflict {
		t.Fatalf("disabled audit status=%d body=%s", got.Code, got.Body.String())
	}
	var stream, epoch integrity.Hash
	stream[0], epoch[0] = 3, 4
	if err := store.EnableIntegrity(context.Background(), stream, epoch); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Store(context.Background(), model.IngestedRecord{Transport: "test", RawBytes: []byte("evidence"), ReceivedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	started := request(http.MethodPost, "/api/v1/integrity/audits", `{"type":"fast"}`)
	if started.Code != http.StatusAccepted {
		t.Fatalf("start audit: %d %s", started.Code, started.Body.String())
	}
	var accepted struct {
		RunID string `json:"run_id"`
		Type  string `json:"type"`
	}
	if err := json.Unmarshal(started.Body.Bytes(), &accepted); err != nil || accepted.RunID == "" || accepted.Type != "fast" {
		t.Fatalf("bad accepted response: %+v %v", accepted, err)
	}
	var completed *httptest.ResponseRecorder
	for i := 0; i < 100; i++ {
		completed = request(http.MethodGet, "/api/v1/integrity/audits/"+accepted.RunID, "")
		if strings.Contains(completed.Body.String(), `"state":"completed"`) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if completed == nil || completed.Code != http.StatusOK || !strings.Contains(completed.Body.String(), `"result":"passed"`) {
		t.Fatalf("audit did not pass: %v", completed)
	}
	proof := request(http.MethodGet, "/api/v1/integrity/proofs/1", "")
	if proof.Code != http.StatusOK || !strings.Contains(proof.Body.String(), `"proof_state":"pending"`) || !strings.Contains(proof.Body.String(), `"reason":"entry batch is not sealed"`) {
		t.Fatalf("pending proof response: %d %s", proof.Code, proof.Body.String())
	}
	if _, err := store.SealIntegrityBatch(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	sealedProof := request(http.MethodGet, "/api/v1/integrity/proofs/1", "")
	if sealedProof.Code != http.StatusOK || !strings.Contains(sealedProof.Body.String(), `"batch_id":1`) || !strings.Contains(sealedProof.Body.String(), `"leaf_index":0`) {
		t.Fatalf("sealed inclusion proof: %d %s", sealedProof.Code, sealedProof.Body.String())
	}
	if bad := request(http.MethodPost, "/api/v1/integrity/audits", `{"type":"unbounded"}`); bad.Code != http.StatusBadRequest {
		t.Fatalf("invalid audit type status=%d", bad.Code)
	}
}

func TestAPI_HealthAndStats(t *testing.T) {
	srv, store, pipe, tempDir := setupTestServer(t)
	defer os.RemoveAll(tempDir)
	defer store.Close()
	defer pipe.Stop()

	handler := srv.Handler()

	// 1. Health
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var health map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&health); err != nil {
		t.Fatalf("failed to decode health: %v", err)
	}
	if health["status"] != "ok" || health["air_gapped"] != false || health["marketplace_online"] != false || health["version"] != "test-version" {
		t.Fatalf("invalid health response: %+v", health)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	var config map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&config); err != nil {
		t.Fatalf("failed to decode config: %v", err)
	}
	if config["version"] != "test-version" {
		t.Fatalf("expected standalone server version, got %+v", config["version"])
	}

	// 2. Stats
	req = httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var stats map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&stats); err != nil {
		t.Fatalf("failed to decode stats: %v", err)
	}
	if _, ok := stats["loss_audit"]; !ok {
		t.Fatalf("missing loss_audit in stats: %+v", stats)
	}
}

func TestAPI_EventsAndTrace(t *testing.T) {
	srv, store, pipe, tempDir := setupTestServer(t)
	defer os.RemoveAll(tempDir)
	defer store.Close()
	defer pipe.Stop()

	// Insert an event
	ctx := context.Background()
	raw, err := store.Store(ctx, model.IngestedRecord{
		Transport:  "udp",
		SourceIP:   "192.168.1.10",
		SourcePort: 514,
		RawBytes:   []byte("<134>Sep 18 10:00:00 asa %ASA-6-302013: Built outbound TCP connection"),
		ReceivedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("failed to store raw: %v", err)
	}

	evt := &model.NormalizedEvent{
		Raven: model.RavenEnvelope{
			EventID:        "evt-test-123",
			RawID:          raw.RawID,
			RawSHA256:      raw.RawSHA256,
			SourceCategory: "network_device",
			SourceID:       "asa-fw-01",
			ReceivedTime:   time.Now().UTC(),
			Status:         "normalized",
			ProcessingHistory: []model.ProcessingStep{
				{Stage: "raw_commit", Result: "ok"},
				{Stage: "format_detect", Result: "syslog"},
			},
		},
		OCSF: map[string]any{
			"activity_name": "Logon",
			"severity_id":   3,
			"unmapped": map[string]any{
				"custom_flag": "val",
			},
		},
	}
	if err := store.StoreNormalized(ctx, evt); err != nil {
		t.Fatalf("failed to store normalized: %v", err)
	}

	handler := srv.Handler()

	// 1. List Events
	req := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var listResp map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&listResp)
	if total, ok := listResp["total"].(float64); !ok || int(total) != 1 {
		t.Fatalf("expected total 1, got %+v", listResp["total"])
	}

	// 2. Get Single Event
	req = httptest.NewRequest(http.MethodGet, "/api/v1/events/evt-test-123", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	// 3. Event Trace
	req = httptest.NewRequest(http.MethodGet, "/api/v1/events/evt-test-123/trace", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var traceResp map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&traceResp)
	if traceResp["raw_id"] != raw.RawID {
		t.Fatalf("trace raw_id mismatch: %+v", traceResp)
	}
	if traceResp["raw_hex"] == "" {
		t.Fatalf("trace raw_hex empty")
	}

	// 4. Raw Verify
	req = httptest.NewRequest(http.MethodPost, "/api/v1/raw/"+raw.RawID+"/verify", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var verifyResp map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&verifyResp)
	if verifyResp["matches"] != true || verifyResp["status"] != "PASSED" {
		t.Fatalf("expected verify PASSED, got %+v", verifyResp)
	}
}

func TestAPI_PacksValidationAndManagement(t *testing.T) {
	srv, store, pipe, tempDir := setupTestServer(t)
	defer os.RemoveAll(tempDir)
	defer store.Close()
	defer pipe.Stop()

	handler := srv.Handler()

	// 1. List packs
	req := httptest.NewRequest(http.MethodGet, "/api/v1/packs", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var packsResp map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&packsResp)
	packsList := packsResp["packs"].([]any)
	if len(packsList) != 1 {
		t.Fatalf("expected 1 pack, got %d", len(packsList))
	}

	// 2. Validate pack
	validYAML := `
apiVersion: raven.io/v1
kind: LogSource
metadata:
  name: test-ssh
  version: 1.0.0
spec:
  sourceCategory: os
  format: syslog
  match:
    contains: "sshd"
  fields:
    user:
      from: user
      type: string
`
	valPayload := map[string]string{
		"yaml_content": validYAML,
		"sample_log":   "<34>Sep 18 10:00:00 host sshd[1234]: Accepted publickey for ubuntu",
	}
	body, _ := json.Marshal(valPayload)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/packs/validate", bytes.NewReader(body))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var valResp map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&valResp)
	if valResp["valid"] != true || valResp["match"] != true {
		t.Fatalf("expected validation success and match, got %+v", valResp)
	}

	// 3. Static SPA fallback
	req = httptest.NewRequest(http.MethodGet, "/events/123", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("RAVEN Test UI")) {
		t.Fatalf("expected index.html fallback for client routing, got: %s", rec.Body.String())
	}
}

func TestAPI_QuarantineReplayAll(t *testing.T) {
	srv, store, pipe, tempDir := setupTestServer(t)
	defer os.RemoveAll(tempDir)
	defer store.Close()
	defer pipe.Stop()

	handler := srv.Handler()

	// 1. Initially empty quarantine replay-all should succeed with total: 0
	req := httptest.NewRequest(http.MethodPost, "/api/v1/quarantine/replay-all", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp["total"].(float64) != 0 || resp["replayed"].(float64) != 0 {
		t.Fatalf("expected total 0 replayed 0, got %+v", resp)
	}
	badKey := httptest.NewRequest(http.MethodPost, "/api/v1/quarantine/replay-all", nil)
	badKey.Header.Set("Idempotency-Key", strings.Repeat("x", 129))
	badKeyResponse := httptest.NewRecorder()
	handler.ServeHTTP(badKeyResponse, badKey)
	if badKeyResponse.Code != http.StatusBadRequest {
		t.Fatalf("expected oversized idempotency key to be rejected, got %d", badKeyResponse.Code)
	}

	// 2. Test GET /api/v1/packs/{name}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/packs/test-firewall", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for pack test-firewall, got %d: %s", rec.Code, rec.Body.String())
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("test-firewall")) {
		t.Fatalf("expected YAML to contain test-firewall, got: %s", rec.Body.String())
	}
}

func TestAPI_ReplayIdempotencyKeyReturnsSavedResult(t *testing.T) {
	srv, store, pipe, tempDir := setupTestServer(t)
	defer os.RemoveAll(tempDir)
	defer store.Close()
	defer pipe.Stop()
	ctx := context.Background()
	var stream, epoch integrity.Hash
	stream[0], epoch[0] = 7, 8
	if err := store.EnableIntegrity(ctx, stream, epoch); err != nil {
		t.Fatal(err)
	}
	payload := []byte("<166>Sep 20 10:10:15 asa-gw-01 %ASA-6-302013: Built inbound TCP connection 2914823")
	raw, err := store.Store(ctx, model.IngestedRecord{Transport: "syslog", RawBytes: payload, ReceivedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	q := model.QuarantineEntry{QuarantineID: "q-api-idempotent", RawID: raw.RawID, RawSHA256: raw.RawSHA256, Stage: "parser_match", Reason: "retry", ReplayEligible: true, QuarantinedAt: time.Now().UTC()}
	if err := store.Quarantine(ctx, q); err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()
	request := func(key string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/quarantine/q-api-idempotent/replay", nil)
		if key != "" {
			req.Header.Set("Idempotency-Key", key)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	first := request("")
	operationID := first.Header().Get("Idempotency-Key")
	if first.Code != http.StatusOK || operationID == "" || !bytes.Contains(first.Body.Bytes(), []byte(`"operation_id":"`+operationID+`"`)) {
		t.Fatalf("first replay failed: status=%d header=%q body=%s", first.Code, first.Header().Get("Idempotency-Key"), first.Body.String())
	}
	second := request(operationID)
	if second.Code != http.StatusOK || !bytes.Equal(first.Body.Bytes(), second.Body.Bytes()) {
		t.Fatalf("retry did not return saved result: first=%s second=%s status=%d", first.Body.String(), second.Body.String(), second.Code)
	}
	var completed, normalized, outboxCount int
	_ = store.DB().QueryRow(`SELECT COUNT(*) FROM integrity_operations WHERE operation_id=? AND state='completed'`, operationID).Scan(&completed)
	_ = store.DB().QueryRow(`SELECT COUNT(*) FROM normalized_events`).Scan(&normalized)
	_ = store.DB().QueryRow(`SELECT COUNT(*) FROM outbox`).Scan(&outboxCount)
	if completed != 1 || normalized != 1 || outboxCount != 0 {
		t.Fatalf("retry duplicated side effects: completed=%d normalized=%d outbox=%d", completed, normalized, outboxCount)
	}
	entries, err := store.ListIntegrityEntries(ctx, 0, 10)
	if err != nil || len(entries) != 4 || entries[3].Kind != integrity.ReplayResolved || entries[3].OperationID != operationID {
		t.Fatalf("replay evidence does not bind operation: entries=%+v err=%v", entries, err)
	}
	metadata, err := integrity.DecodeFields(entries[2].MetadataSnapshot)
	if err != nil || len(metadata) != 5 || metadata[2].Type != integrity.FieldBytes32 || len(metadata[2].Value) != 32 {
		t.Fatalf("normalized evidence omitted captured parser digest: metadata=%+v err=%v", metadata, err)
	}
	if stats := pipe.Stats(); stats.Normalized != 1 || stats.Delivered != 1 {
		t.Fatalf("retry changed pipeline accounting: %+v", stats)
	}
}

func TestAPI_ConcurrentReplayWithSameKeyResolvesOnce(t *testing.T) {
	srv, store, pipe, tempDir := setupTestServer(t)
	defer os.RemoveAll(tempDir)
	defer store.Close()
	defer pipe.Stop()
	ctx := context.Background()
	raw, err := store.Store(ctx, model.IngestedRecord{Transport: "syslog", RawBytes: []byte("<166>Sep 20 10:10:15 asa-gw-01 %ASA-6-302013: Built inbound TCP connection 2914823"), ReceivedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	q := model.QuarantineEntry{QuarantineID: "q-concurrent-replay", RawID: raw.RawID, RawSHA256: raw.RawSHA256, Stage: "parser_match", Reason: "retry", ReplayEligible: true, QuarantinedAt: time.Now().UTC()}
	if err := store.Quarantine(ctx, q); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan *httptest.ResponseRecorder, 2)
	for range 2 {
		go func() {
			<-start
			req := httptest.NewRequest(http.MethodPost, "/api/v1/quarantine/q-concurrent-replay/replay", nil)
			req.Header.Set("Idempotency-Key", "concurrent-operation")
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)
			results <- rec
		}()
	}
	close(start)
	first, second := <-results, <-results
	if first.Code != http.StatusOK || second.Code != http.StatusOK || !bytes.Equal(first.Body.Bytes(), second.Body.Bytes()) {
		t.Fatalf("concurrent retry mismatch: first=%d %s second=%d %s", first.Code, first.Body.String(), second.Code, second.Body.String())
	}
	var operations, normalized int
	_ = store.DB().QueryRow(`SELECT COUNT(*) FROM integrity_operations WHERE operation_id='concurrent-operation' AND state='completed'`).Scan(&operations)
	_ = store.DB().QueryRow(`SELECT COUNT(*) FROM normalized_events`).Scan(&normalized)
	if operations != 1 || normalized != 1 || pipe.Stats().Normalized != 1 || pipe.Stats().Delivered != 1 {
		t.Fatalf("concurrent replay duplicated work: operations=%d normalized=%d stats=%+v", operations, normalized, pipe.Stats())
	}
}

func TestAPI_PathTraversalBlocked(t *testing.T) {
	srv, store, pipe, tempDir := setupTestServer(t)
	defer os.RemoveAll(tempDir)
	defer store.Close()
	defer pipe.Stop()

	handler := srv.Handler()

	// 1. Path traversal in GET /api/v1/packs/{name}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/packs/..%2f..%2fetc%2fpasswd", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for path traversal attempt, got %d", rec.Code)
	}

	// 2. Path traversal in POST /api/v1/packs/activate with malicious filename
	maliciousPayload := map[string]string{
		"yaml_content": `apiVersion: raven.io/v1
kind: LogSource
metadata:
  name: malicious-pack
  version: 1.0.0
spec:
  sourceCategory: network_device
  format: syslog
  match:
    contains: "TEST"
`,
		"filename": "../../evil.yaml",
	}
	body, _ := json.Marshal(maliciousPayload)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/packs/activate", bytes.NewReader(body))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for malicious filename, got %d", rec.Code)
	}
}

func TestAPI_ReplayIneligibleBlocked(t *testing.T) {
	srv, store, pipe, tempDir := setupTestServer(t)
	defer os.RemoveAll(tempDir)
	defer store.Close()
	defer pipe.Stop()

	ctx := context.Background()
	// Create a raw record and quarantine it as ineligible (replay_eligible = false)
	raw, err := store.Store(ctx, model.IngestedRecord{
		Transport:  "syslog",
		SourceIP:   "127.0.0.1",
		RawBytes:   []byte("<14>1 unparseable"),
		ReceivedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("store failed: %v", err)
	}

	err = store.Quarantine(ctx, model.QuarantineEntry{
		QuarantineID:   "quar-ineligible-01",
		RawID:          raw.RawID,
		RawSHA256:      raw.RawSHA256,
		Stage:          "decode",
		Reason:         "corrupt_binary",
		RawPreview:     "preview",
		ReplayEligible: false, // Ineligible!
		QuarantinedAt:  time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("quarantine failed: %v", err)
	}

	handler := srv.Handler()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/quarantine/quar-ineligible-01/replay", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request when attempting to replay ineligible entry, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAPI_StaticAndSPARouting(t *testing.T) {
	srv, store, pipe, tempDir := setupTestServer(t)
	defer os.RemoveAll(tempDir)
	defer store.Close()
	defer pipe.Stop()

	handler := srv.Handler()

	// 1. Root index.html
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for /, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "RAVEN Test UI") {
		t.Fatalf("expected root to serve index.html, got: %s", rec.Body.String())
	}

	// 2. Static asset file
	req = httptest.NewRequest(http.MethodGet, "/assets/test.js", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for /assets/test.js, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "console.log('test')") {
		t.Fatalf("expected static JS content, got: %s", rec.Body.String())
	}

	// 3. SPA client-side route fallback
	req = httptest.NewRequest(http.MethodGet, "/events/raven-evt-001", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for SPA route, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "RAVEN Test UI") {
		t.Fatalf("expected SPA fallback to index.html, got: %s", rec.Body.String())
	}
}

func TestManagementRoutesUnauthenticated(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "raven_management_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	store, err := rawstore.New(filepath.Join(tempDir, "raven.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	srv := api.NewServer("127.0.0.1:0", store, nil, nil, "", api.ConfigInfo{}, nil, "test-version")
	handler := srv.Handler()
	for _, path := range []string{"/api/v1/raw/raven-raw-nonexistent", "/api/v1/events/event/trace", "/api/v1/integrity/status"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
			t.Errorf("%s unexpectedly requires admin auth: %d", path, rec.Code)
		}
	}

	// Management request limits still reject oversized input without auth.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/connections/test", strings.NewReader(`{"yaml_content":"`+strings.Repeat("x", (1<<20)+1)+`"}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected oversized body to be rejected, got %d", rec.Code)
	}
}

func TestMarketplaceCatalogAndRefreshUnauthenticated(t *testing.T) {
	srv, store, pipe, _ := setupTestServer(t)
	defer store.Close()
	pipe.Stop()
	get := httptest.NewRecorder()
	srv.Handler().ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/api/v1/marketplace/packs?q=network", nil))
	if get.Code != http.StatusOK {
		t.Fatalf("marketplace search status = %d: %s", get.Code, get.Body.String())
	}
	var result struct {
		Packs []map[string]any `json:"packs"`
		Total int              `json:"total"`
	}
	if err := json.Unmarshal(get.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Total < len(result.Packs) {
		t.Fatalf("marketplace returned %d packs but reported total %d", len(result.Packs), result.Total)
	}
	refresh := httptest.NewRecorder()
	srv.Handler().ServeHTTP(refresh, httptest.NewRequest(http.MethodPost, "/api/v1/marketplace/refresh", nil))
	if refresh.Code != http.StatusBadGateway {
		t.Fatalf("unauthenticated refresh should reach the offline marketplace handler: %d %s", refresh.Code, refresh.Body.String())
	}
}

func TestCORSAllowsOnlyExactLoopbackHosts(t *testing.T) {
	srv, _, _, _ := setupTestServer(t)
	for _, tc := range []struct {
		origin string
		allow  bool
	}{
		{"https://localhost:5173", true},
		{"http://127.0.0.1:3000", true},
		{"https://localhost.attacker.example", false},
		{"http://127.0.0.1.attacker.example", false},
		{"https://user@localhost", false},
		{"https://localhost.evil:9090", false},
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
		req.Header.Set("Origin", tc.origin)
		res := httptest.NewRecorder()
		srv.Handler().ServeHTTP(res, req)
		got := res.Header().Get("Access-Control-Allow-Origin") == tc.origin
		if got != tc.allow {
			t.Errorf("origin %q allowed=%v, want %v", tc.origin, got, tc.allow)
		}
	}
}

func TestApplyConnectionReusesManagedFilename(t *testing.T) {
	srv, _, _, dir := setupTestServer(t)
	manager := connections.NewManager(dir)
	content, err := os.ReadFile(filepath.Join("..", "..", "sinks", "http-siem.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "http-siem.yaml"), content, 0600); err != nil {
		t.Fatal(err)
	}
	if err := manager.LoadDir(dir); err != nil {
		t.Fatal(err)
	}
	srv.SetConnManager(manager, dir)
	updated := strings.Replace(string(content), "version: 1.0.0", "version: 1.0.1", 1)
	body, _ := json.Marshal(map[string]string{"yaml_content": updated})
	res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, httptest.NewRequest(http.MethodPost, "/api/v1/connections/apply", bytes.NewReader(body)))
	if res.Code != http.StatusOK {
		t.Fatalf("apply status=%d body=%s", res.Code, res.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "siem-events.yaml")); !os.IsNotExist(err) {
		t.Fatalf("unexpected identity-based duplicate file, stat err=%v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "http-siem.yaml"))
	if err != nil || !strings.Contains(string(got), "version: 1.0.1") {
		t.Fatalf("managed file was not updated: err=%v", err)
	}
}

func TestActivatePackRejectsMissingManager(t *testing.T) {
	srv, store, pipe, _ := setupTestServer(t)
	cfg := api.ConfigInfo{}
	missing := api.NewServer("127.0.0.1:0", store, pipe, nil, "", cfg, fstest.MapFS{"index.html": {Data: []byte("ui")}}, "test")
	body := []byte(`{"yaml_content":"apiVersion: raven.io/v1\nkind: LogSource\nmetadata:\n  name: sample\n  version: 1.0.0\n  description: sample\n  author: test\nspec:\n  sourceCategory: application\n  format: json\n  match:\n    contains: sample\n  fields: {}\n"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/packs/activate", bytes.NewReader(body))
	res := httptest.NewRecorder()
	missing.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusServiceUnavailable {
		t.Fatalf("activation without manager returned %d: %s", res.Code, res.Body.String())
	}
	_ = srv
}
