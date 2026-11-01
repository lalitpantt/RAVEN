package analysis

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"raven/internal/model"
	"raven/internal/rawstore"
)

func TestWorkerProjectsIdentitiesAndResumesFromDurableCheckpoint(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "analysis.db")
	store, err := rawstore.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	devices := []Device{
		{ID: "edge-1", Aliases: map[string][]string{"syslog_host": {"edge-1.internal"}, "source_ip": {"10.0.0.1"}}},
		{ID: "server-1", Aliases: map[string][]string{"host": {"server-1"}, "source_ip": {"10.0.0.2"}}},
		{ID: "proxy-2", Aliases: map[string][]string{"source_ip": {"10.0.0.2"}}},
	}
	resolver, err := NewResolver(devices)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := NewWorker(store, resolver)
	if err != nil {
		t.Fatal(err)
	}
	store.SetAnalysisEnabled(true)

	raw, err := store.Store(ctx, model.IngestedRecord{Transport: "syslog_udp", SourceIP: "10.0.0.1", RawBytes: []byte("edge event"), ReceivedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	event := &model.NormalizedEvent{Raven: model.RavenEnvelope{EventID: "event-1", RawID: raw.RawID, RecordOrdinal: 0, SourceCategory: "network_device", SourceID: "edge-1.internal", ReceivedTime: raw.ReceivedAt}, OCSF: map[string]any{"message": "up"}}
	hints := model.AnalysisIdentityHints{"syslog_host": "edge-1.internal", "source_ip": "10.0.0.1", "ignored": "must not persist"}
	if err := store.StoreNormalizedWithOutboxAndHints(ctx, event, nil, hints); err != nil {
		t.Fatal(err)
	}
	if err := store.StoreNormalizedWithOutboxAndHints(ctx, event, nil, hints); err != nil {
		t.Fatal(err)
	}
	quarantine := model.QuarantineEntry{QuarantineID: "q-1", RawID: raw.RawID, RecordOrdinal: 1, RawSHA256: raw.RawSHA256, Stage: "decode", Reason: "test", RawPreview: "sample", ReplayEligible: true, QuarantinedAt: time.Now().UTC(), AnalysisHints: model.AnalysisIdentityHints{"host": "server-1", "source_ip": "10.0.0.2"}}
	if err := store.QuarantineChild(ctx, quarantine); err != nil {
		t.Fatal(err)
	}
	if err := store.QuarantineChild(ctx, quarantine); err != nil {
		t.Fatal(err)
	}
	unknown, err := store.Store(ctx, model.IngestedRecord{Transport: "http_post", SourceIP: "192.0.2.80", RawBytes: []byte("unknown"), ReceivedAt: time.Now().UTC()})
	if err != nil || unknown == nil {
		t.Fatalf("store unregistered source: raw=%+v err=%v", unknown, err)
	}

	before, err := store.AnalysisStatus(ctx)
	if err != nil || before.Pending != 4 || before.OldestPending.IsZero() {
		t.Fatalf("expected four durable observations before worker: %+v err=%v", before, err)
	}
	processed, err := worker.RunOnce(ctx)
	if err != nil || processed != 4 {
		t.Fatalf("process observation batch: processed=%d err=%v", processed, err)
	}
	status, err := worker.Status(ctx)
	if err != nil || status.QueueStatus.Pending != 0 || status.QueueStatus.CheckpointID == 0 {
		t.Fatalf("worker status after processing: %+v err=%v", status, err)
	}
	if _, err := store.DB().ExecContext(ctx, `UPDATE analysis_worker_state SET checkpoint_id=0 WHERE singleton=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := worker.RunOnce(ctx); err != nil {
		t.Fatalf("replay linked observation batch: %v", err)
	}
	status, err = worker.Status(ctx)
	if err != nil || status.QueueStatus.Pending != 0 {
		t.Fatalf("idempotent projection replay did not advance checkpoint: %+v err=%v", status, err)
	}
	telemetry, err := store.ListAnalysisDeviceTelemetry(ctx, []string{"edge-1"})
	if err != nil || telemetry["edge-1"].ReceivedCount != 1 || telemetry["edge-1"].NormalizedCount != 1 {
		t.Fatalf("replayed batch duplicated device counters: %+v err=%v", telemetry, err)
	}

	matched, err := store.ListAnalysisSources(ctx, "matched", 20, 0)
	if err != nil || len(matched) != 2 {
		t.Fatalf("matched source identities=%d err=%v: %+v", len(matched), err, matched)
	}
	if matched[0].Confidence != "strong" && matched[1].Confidence != "strong" {
		t.Fatalf("normalized host match should be strong: %+v", matched)
	}
	ambiguous, err := store.ListAnalysisSources(ctx, "ambiguous", 20, 0)
	if err != nil || len(ambiguous) != 1 || ambiguous[0].DeviceID != "" {
		t.Fatalf("ambiguous identity projection=%+v err=%v", ambiguous, err)
	}
	unknownSources, err := store.ListAnalysisSources(ctx, "unknown", 20, 0)
	if err != nil || len(unknownSources) != 1 || unknownSources[0].IdentityHints["source_ip"] != "192.0.2.80" {
		t.Fatalf("unknown identity projection=%+v err=%v", unknownSources, err)
	}
	if got := hints["ignored"]; got != "must not persist" {
		t.Fatalf("store mutated caller hints: %q", got)
	}
	var leaked int
	if err := store.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM analysis_observations WHERE identity_hints_json LIKE '%ignored%'`).Scan(&leaked); err != nil || leaked != 0 {
		t.Fatalf("non-allowlisted identity hint persisted: count=%d err=%v", leaked, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = rawstore.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := store.AnalysisStatus(ctx)
	if err != nil || restarted.Pending != 0 || restarted.CheckpointID != status.QueueStatus.CheckpointID {
		t.Fatalf("checkpoint did not survive restart: %+v err=%v", restarted, err)
	}
	store.SetAnalysisEnabled(true)
	if _, err := store.Store(ctx, model.IngestedRecord{Transport: "syslog_tcp", SourceIP: "192.0.2.81", RawBytes: []byte("pending at restart")}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = rawstore.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	restarted, err = store.AnalysisStatus(ctx)
	if err != nil || restarted.Pending != 1 || restarted.CheckpointID != status.QueueStatus.CheckpointID {
		t.Fatalf("unprocessed observation was not durable across restart: %+v err=%v", restarted, err)
	}
	worker, _ = NewWorker(store, resolver)
	if processed, err := worker.RunOnce(ctx); err != nil || processed != 1 {
		t.Fatalf("restart did not resume pending observations: processed=%d err=%v", processed, err)
	}
	restarted, err = store.AnalysisStatus(ctx)
	if err != nil || restarted.Pending != 0 || restarted.CheckpointID != status.QueueStatus.CheckpointID+1 {
		t.Fatalf("restart did not checkpoint recovered observation: %+v err=%v", restarted, err)
	}
}

func TestWorkerProjectsOnlyConfiguredHeartbeatMatches(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	device := strings.Replace(heartbeatDevice("router-heartbeat"), "      - edge-1.example.internal", "      - edge-1.example.internal\n    source_ip:\n      - 10.0.0.8", 1)
	writeConfig(t, directory, "devices", "router.yaml", device)
	writeConfig(t, directory, "rules", "heartbeat.yaml", heartbeatRule("router-heartbeat"))
	snapshot, err := LoadDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	store, err := rawstore.New(filepath.Join(t.TempDir(), "heartbeat.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.SetAnalysisEnabled(true)
	worker, err := NewWorker(store, snapshot.Resolver())
	if err != nil {
		t.Fatal(err)
	}
	worker.SetSnapshot(snapshot)

	for i, activity := range []string{"heartbeat", "configuration_change"} {
		raw, err := store.Store(ctx, model.IngestedRecord{Transport: "syslog_udp", SourceIP: "10.0.0.8", RawBytes: []byte(activity), ReceivedAt: time.Now().UTC()})
		if err != nil {
			t.Fatal(err)
		}
		event := &model.NormalizedEvent{Raven: model.RavenEnvelope{EventID: fmt.Sprintf("heartbeat-event-%d", i), RawID: raw.RawID, ReceivedTime: raw.ReceivedAt}, OCSF: map[string]any{"activity_name": activity}}
		if err := store.StoreNormalizedWithOutboxAndHints(ctx, event, nil, model.AnalysisIdentityHints{"syslog_host": "edge-1.example.internal"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := worker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	telemetry, err := store.ListAnalysisDeviceTelemetry(ctx, []string{"edge-1"})
	if err != nil {
		t.Fatal(err)
	}
	got := telemetry["edge-1"]
	if got.ReceivedCount != 2 || got.NormalizedCount != 2 || got.HeartbeatCount != 1 || got.LastHeartbeatAt.IsZero() || got.ReceivedPerMinute != 0.4 || got.NormalizedPerMinute != 0.4 {
		t.Fatalf("device rollup=%+v; only the configured heartbeat event should count", got)
	}
}

func TestWorkerFindingLifecycleIsIdempotentAndAuditable(t *testing.T) {
	ctx := context.Background()
	snapshot, err := LoadDirectory(filepath.Join("..", "..", "analysis", "examples"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := rawstore.New(filepath.Join(t.TempDir(), "findings.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.SetAnalysisEnabled(true)
	worker, err := NewWorker(store, snapshot.Resolver())
	if err != nil {
		t.Fatal(err)
	}
	worker.SetSnapshot(snapshot)
	addEvent := func(id, activity string) {
		t.Helper()
		raw, err := store.Store(ctx, model.IngestedRecord{Transport: "syslog_udp", SourceIP: "10.20.0.1", RawBytes: []byte(id), ReceivedAt: time.Now().UTC()})
		if err != nil {
			t.Fatal(err)
		}
		event := &model.NormalizedEvent{Raven: model.RavenEnvelope{EventID: id, RawID: raw.RawID, SourceCategory: "network_device", SourceID: "edge-router-01", ReceivedTime: raw.ReceivedAt}, OCSF: map[string]any{"activity_name": activity}}
		if err := store.StoreNormalizedWithOutboxAndHints(ctx, event, nil, model.AnalysisIdentityHints{"source_ip": "10.20.0.1"}); err != nil {
			t.Fatal(err)
		}
	}
	addEvent("event-interface-down", "interface_down")
	if _, err := worker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	findings, total, err := store.ListAnalysisFindings(ctx, "all", 10, 0)
	if err != nil || total != 1 || len(findings) != 1 || findings[0].Status != "open" || findings[0].OccurrenceCount != 1 || findings[0].DeviceID != "edge-router-01" {
		t.Fatalf("open finding=%+v total=%d err=%v", findings, total, err)
	}
	id := findings[0].ID
	if _, err := store.DB().ExecContext(ctx, `UPDATE analysis_worker_state SET checkpoint_id=0 WHERE singleton=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := worker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	findings, _, err = store.ListAnalysisFindings(ctx, "all", 10, 0)
	if err != nil || findings[0].OccurrenceCount != 1 {
		t.Fatalf("replay duplicated finding: %+v err=%v", findings, err)
	}
	addEvent("event-interface-up", "interface_up")
	if _, err := worker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	finding, history, historyTotal, err := store.GetAnalysisFinding(ctx, id, 10, 0)
	if err != nil || historyTotal != 2 || finding.Status != "clearing" || history[0].Action != "clear_started" {
		t.Fatalf("clearing finding=%+v history=%+v total=%d err=%v", finding, history, historyTotal, err)
	}
	if resolved, err := store.ResolveMaturedAnalysisFindings(ctx, time.Now().Add(time.Minute), 10); err != nil || resolved != 1 {
		t.Fatalf("mature finding count=%d err=%v", resolved, err)
	}
	finding, history, historyTotal, err = store.GetAnalysisFinding(ctx, id, 10, 0)
	if err != nil || finding.Status != "resolved" || historyTotal != 3 || history[0].Action != "resolved" {
		t.Fatalf("resolved finding=%+v history=%+v total=%d err=%v", finding, history, historyTotal, err)
	}
	if _, err := store.DB().ExecContext(ctx, `UPDATE analysis_finding_history SET title='edited' WHERE finding_id=?`, id); err == nil {
		t.Fatal("finding transition history was mutable")
	}
	if _, err := store.DB().ExecContext(ctx, `DELETE FROM analysis_finding_history WHERE finding_id=?`, id); err == nil {
		t.Fatal("finding transition history was deletable")
	}
	addEvent("event-interface-down-again", "interface_down")
	if _, err := worker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	finding, history, historyTotal, err = store.GetAnalysisFinding(ctx, id, 10, 0)
	if err != nil || finding.Status != "open" || finding.OccurrenceCount != 1 || historyTotal != 4 || history[0].Action != "opened" {
		t.Fatalf("reopened finding=%+v history=%+v total=%d err=%v", finding, history, historyTotal, err)
	}
}

func TestWorkerWindowRuleUsesConsecutiveMatchesAndExpiresBySharedSweep(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	writeConfig(t, directory, "devices", "edge.yaml", validDevice("edge-1"))
	writeConfig(t, directory, "rules", "window.yaml", `apiVersion: raven.io/v1
kind: AnalysisRule
metadata: {name: auth-burst, version: 1.0.0}
spec:
  kind: window
  sourceCategory: network_device
  match:
    fields:
      - {path: activity_name, op: eq, value: authentication_failure}
  window:
    signal: event_count
    duration: 5m
    groupBy: [src_endpoint.ip]
    countAtLeast: 3
    clearBelow: 1
    consecutive: 2
  finding: {severity: high, state: yellow, title: Authentication burst, for: 30s, clearAfter: 10s}
`)
	snapshot, err := LoadDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	store, err := rawstore.New(filepath.Join(t.TempDir(), "window.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.SetAnalysisEnabled(true)
	worker, err := NewWorker(store, snapshot.Resolver())
	if err != nil {
		t.Fatal(err)
	}
	worker.SetSnapshot(snapshot)
	appendEvent := func(id, activity string, at time.Time) {
		t.Helper()
		raw, e := store.Store(ctx, model.IngestedRecord{Transport: "syslog_udp", SourceIP: "10.0.0.1", RawBytes: []byte(id), ReceivedAt: at})
		if e != nil {
			t.Fatal(e)
		}
		event := &model.NormalizedEvent{Raven: model.RavenEnvelope{EventID: id, RawID: raw.RawID, SourceCategory: "network_device", ReceivedTime: at}, OCSF: map[string]any{"activity_name": activity, "src_endpoint": map[string]any{"ip": "192.0.2.1"}}}
		if e := store.StoreNormalizedWithOutboxAndHints(ctx, event, nil, model.AnalysisIdentityHints{"syslog_host": "edge-1.example.internal"}); e != nil {
			t.Fatal(e)
		}
	}
	base := time.Now().UTC().Add(-time.Minute)
	for i := 0; i < 3; i++ {
		appendEvent(fmt.Sprintf("window-fail-%d", i), "authentication_failure", base.Add(time.Duration(i)*15*time.Second))
	}
	if _, err := worker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if findings, total, err := store.ListAnalysisFindings(ctx, "open", 10, 0); err != nil || total != 0 {
		t.Fatalf("window rule ignored its for duration: findings=%+v total=%d err=%v", findings, total, err)
	}
	for range 2 {
		if err := worker.evaluateTimeRules(ctx, snapshot, snapshot.Rules(), time.Now().UTC().Add(31*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	findings, total, err := store.ListAnalysisFindings(ctx, "open", 10, 0)
	if err != nil || total != 1 || len(findings) != 1 || findings[0].RuleID != "auth-burst" {
		t.Fatalf("window finding=%+v total=%d err=%v", findings, total, err)
	}
	if _, err := store.DB().ExecContext(ctx, `UPDATE analysis_worker_state SET checkpoint_id=0 WHERE singleton=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := worker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	findings, _, err = store.ListAnalysisFindings(ctx, "open", 10, 0)
	var sampleCount int
	if queryErr := store.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM analysis_window_samples WHERE rule_id='auth-burst'`).Scan(&sampleCount); queryErr != nil || err != nil || len(findings) != 1 || findings[0].OccurrenceCount != 1 || sampleCount != 3 {
		t.Fatalf("window replay duplicated state: findings=%+v samples=%d listErr=%v queryErr=%v", findings, sampleCount, err, queryErr)
	}
	appendEvent("window-success", "authentication_success", time.Now().UTC())
	if _, err := worker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	findings, _, err = store.ListAnalysisFindings(ctx, "open", 10, 0)
	if err != nil || len(findings) != 1 {
		t.Fatalf("a count between clear and trigger thresholds cleared the finding: %+v err=%v", findings, err)
	}
	future := time.Now().UTC().Add(7 * time.Minute)
	if err := worker.evaluateTimeRules(ctx, snapshot, snapshot.Rules(), future); err != nil {
		t.Fatal(err)
	}
	if err := worker.evaluateTimeRules(ctx, snapshot, snapshot.Rules(), future); err != nil {
		t.Fatal(err)
	}
	findings, _, err = store.ListAnalysisFindings(ctx, "clearing", 10, 0)
	if err != nil || len(findings) != 1 {
		t.Fatalf("expired window did not begin recovery hold: %+v err=%v", findings, err)
	}
	if resolved, err := store.ResolveMaturedAnalysisFindings(ctx, future.Add(11*time.Second), 20); err != nil || resolved != 1 {
		t.Fatalf("window recovery resolved=%d err=%v", resolved, err)
	}
	findings, _, err = store.ListAnalysisFindings(ctx, "resolved", 10, 0)
	if err != nil || len(findings) != 1 {
		t.Fatalf("resolved window finding=%+v err=%v", findings, err)
	}
}

func TestWorkerQualityRuleUsesCompletedOutcomesAndHysteresis(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	writeConfig(t, directory, "rules", "quality.yaml", `apiVersion: raven.io/v1
kind: AnalysisRule
metadata: {name: quarantine-ratio, version: 1.0.0}
spec:
  kind: quality
  match: {fields: []}
  window: {signal: quarantine_ratio, duration: 5m, ratioAtLeast: 0.5, clearRatio: 0.2}
  finding: {severity: high, state: yellow, title: Source quality degraded, clearAfter: 10s}
`)
	snapshot, err := LoadDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	store, err := rawstore.New(filepath.Join(t.TempDir(), "quality.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.SetAnalysisEnabled(true)
	worker, _ := NewWorker(store, snapshot.Resolver())
	worker.SetSnapshot(snapshot)
	const sourceIP = "192.0.2.44"
	quarantine := func(id string) {
		t.Helper()
		raw, e := store.Store(ctx, model.IngestedRecord{Transport: "http_post", SourceIP: sourceIP, RawBytes: []byte(id), ReceivedAt: time.Now().UTC()})
		if e != nil {
			t.Fatal(e)
		}
		e = store.QuarantineChild(ctx, model.QuarantineEntry{QuarantineID: id, RawID: raw.RawID, RawSHA256: raw.RawSHA256, Stage: "normalize", Reason: "fixture", QuarantinedAt: time.Now().UTC(), AnalysisHints: model.AnalysisIdentityHints{"source_ip": sourceIP}})
		if e != nil {
			t.Fatal(e)
		}
	}
	normalized := func(id string) {
		t.Helper()
		raw, e := store.Store(ctx, model.IngestedRecord{Transport: "http_post", SourceIP: sourceIP, RawBytes: []byte(id), ReceivedAt: time.Now().UTC()})
		if e != nil {
			t.Fatal(e)
		}
		event := &model.NormalizedEvent{Raven: model.RavenEnvelope{EventID: id, RawID: raw.RawID, ReceivedTime: raw.ReceivedAt}, OCSF: map[string]any{"activity_name": "ok"}}
		if e := store.StoreNormalizedWithOutboxAndHints(ctx, event, nil, model.AnalysisIdentityHints{"source_ip": sourceIP}); e != nil {
			t.Fatal(e)
		}
	}
	quarantine("quality-bad-1")
	normalized("quality-good-1")
	if _, err := worker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	findings, total, err := store.ListAnalysisFindings(ctx, "open", 10, 0)
	if err != nil || total != 1 || len(findings) != 1 || findings[0].RuleID != "quarantine-ratio" {
		t.Fatalf("quality finding=%+v total=%d err=%v", findings, total, err)
	}
	for i := 0; i < 10; i++ {
		normalized(fmt.Sprintf("quality-good-%d", i+2))
	}
	if _, err := worker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	findings, _, err = store.ListAnalysisFindings(ctx, "clearing", 10, 0)
	if err != nil || len(findings) != 1 {
		t.Fatalf("quality ratio below clear threshold did not recover: %+v err=%v", findings, err)
	}
	if resolved, err := store.ResolveMaturedAnalysisFindings(ctx, time.Now().Add(time.Minute), 20); err != nil || resolved != 1 {
		t.Fatalf("quality finding resolve=%d err=%v", resolved, err)
	}
}

func TestWorkerHeartbeatDeadlineEscalatesRecoversAndHonorsMaintenance(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	device := heartbeatDevice("pulse")
	device = strings.Replace(device, "      - edge-1.example.internal", "      - edge-1.example.internal\n    source_ip:\n      - 10.0.0.8", 1)
	writeConfig(t, directory, "devices", "edge.yaml", device)
	writeConfig(t, directory, "rules", "heartbeat.yaml", heartbeatRule("pulse"))
	snapshot, err := LoadDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	store, err := rawstore.New(filepath.Join(t.TempDir(), "heartbeat-deadline.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.SetAnalysisEnabled(true)
	worker, _ := NewWorker(store, snapshot.Resolver())
	worker.SetSnapshot(snapshot)
	appendHeartbeat := func(id string, at time.Time) {
		t.Helper()
		raw, e := store.Store(ctx, model.IngestedRecord{Transport: "syslog_udp", SourceIP: "10.0.0.8", RawBytes: []byte(id), ReceivedAt: at})
		if e != nil {
			t.Fatal(e)
		}
		event := &model.NormalizedEvent{Raven: model.RavenEnvelope{EventID: id, RawID: raw.RawID, SourceCategory: "network_device", ReceivedTime: at}, OCSF: map[string]any{"activity_name": "heartbeat"}}
		if e := store.StoreNormalizedWithOutboxAndHints(ctx, event, nil, model.AnalysisIdentityHints{"syslog_host": "edge-1.example.internal"}); e != nil {
			t.Fatal(e)
		}
	}
	last := time.Now().UTC()
	appendHeartbeat("deadline-heartbeat-old", last)
	if _, err := worker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	evidence, err := store.ListAnalysisHeartbeatEvidence(ctx, "", 1)
	if err != nil || len(evidence) != 1 {
		t.Fatalf("heartbeat evidence page=%+v err=%v", evidence, err)
	}
	if next, err := store.ListAnalysisHeartbeatEvidence(ctx, evidence[0].DeviceID, 1); err != nil || len(next) != 0 {
		t.Fatalf("heartbeat evidence pagination returned %+v err=%v", next, err)
	}
	last = evidence[0].OccurredAt
	warningAt := last.Add(2 * time.Minute)
	for range 2 {
		if err := worker.evaluateTimeRules(ctx, snapshot, snapshot.Rules(), warningAt); err != nil {
			t.Fatal(err)
		}
	}
	findings, _, err := store.ListAnalysisFindings(ctx, "open", 10, 0)
	if err != nil || len(findings) != 1 || findings[0].State != "yellow" {
		t.Fatalf("warning deadline finding=%+v err=%v", findings, err)
	}
	criticalAt := last.Add(5 * time.Minute)
	for range 2 {
		if err := worker.evaluateTimeRules(ctx, snapshot, snapshot.Rules(), criticalAt); err != nil {
			t.Fatal(err)
		}
	}
	findings, _, err = store.ListAnalysisFindings(ctx, "open", 10, 0)
	if err != nil || len(findings) != 1 || findings[0].Severity != "critical" || findings[0].State != "red" {
		t.Fatalf("critical deadline finding=%+v err=%v", findings, err)
	}
	appendHeartbeat("deadline-heartbeat-fresh", time.Now().UTC())
	if _, err := worker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	findings, _, err = store.ListAnalysisFindings(ctx, "resolved", 10, 0)
	if err != nil || len(findings) != 1 {
		t.Fatalf("fresh heartbeat did not resolve deadline finding=%+v err=%v", findings, err)
	}

	maintenanceAt := time.Now().UTC().Truncate(time.Hour).Add(time.Hour + 2*time.Minute)
	start, end := maintenanceAt.Add(-time.Minute), maintenanceAt.Add(5*time.Minute)
	maintenanceDevice := strings.Replace(device, "  reporting:", fmt.Sprintf("  maintenance:\n    timeZone: UTC\n    windows:\n      - weekdays: [%s]\n        start: %s\n        end: %s\n  reporting:", weekday(maintenanceAt.Weekday()), start.Format("15:04"), end.Format("15:04")), 1)
	maintenanceDir := t.TempDir()
	writeConfig(t, maintenanceDir, "devices", "edge.yaml", maintenanceDevice)
	writeConfig(t, maintenanceDir, "rules", "heartbeat.yaml", heartbeatRule("pulse"))
	maintenanceSnapshot, err := LoadDirectory(maintenanceDir)
	if err != nil {
		t.Fatal(err)
	}
	maintenanceStore, err := rawstore.New(filepath.Join(t.TempDir(), "heartbeat-maintenance.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer maintenanceStore.Close()
	maintenanceStore.SetAnalysisEnabled(true)
	maintenanceWorker, _ := NewWorker(maintenanceStore, maintenanceSnapshot.Resolver())
	maintenanceWorker.SetSnapshot(maintenanceSnapshot)
	old := maintenanceAt.Add(-4 * time.Minute)
	raw, e := maintenanceStore.Store(ctx, model.IngestedRecord{Transport: "syslog_udp", SourceIP: "10.0.0.8", RawBytes: []byte("maintenance-old"), ReceivedAt: old})
	if e != nil {
		t.Fatal(e)
	}
	event := &model.NormalizedEvent{Raven: model.RavenEnvelope{EventID: "maintenance-heartbeat-old", RawID: raw.RawID, SourceCategory: "network_device", ReceivedTime: old}, OCSF: map[string]any{"activity_name": "heartbeat"}}
	if err := maintenanceStore.StoreNormalizedWithOutboxAndHints(ctx, event, nil, model.AnalysisIdentityHints{"syslog_host": "edge-1.example.internal"}); err != nil {
		t.Fatal(err)
	}
	if _, err := maintenanceWorker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if err := maintenanceWorker.evaluateTimeRules(ctx, maintenanceSnapshot, maintenanceSnapshot.Rules(), maintenanceAt); err != nil {
		t.Fatal(err)
	}
	findings, total, err := maintenanceStore.ListAnalysisFindings(ctx, "all", 10, 0)
	if err != nil || total != 0 {
		t.Fatalf("maintenance failed to suppress missing-report finding: %+v total=%d err=%v", findings, total, err)
	}
	if err := maintenanceWorker.evaluateTimeRules(ctx, maintenanceSnapshot, maintenanceSnapshot.Rules(), end.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	findings, _, err = maintenanceStore.ListAnalysisFindings(ctx, "open", 10, 0)
	if err != nil || len(findings) != 1 || findings[0].State != "red" {
		t.Fatalf("stale heartbeat did not alert after maintenance: %+v err=%v", findings, err)
	}
}

func TestWorkerBatchProjectionAndCheckpointRollbackTogether(t *testing.T) {
	ctx := context.Background()
	store, err := rawstore.New(filepath.Join(t.TempDir(), "rollback.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.SetAnalysisEnabled(true)
	if _, err := store.Store(ctx, model.IngestedRecord{Transport: "syslog_udp", SourceIP: "10.0.0.9", RawBytes: []byte("event")}); err != nil {
		t.Fatal(err)
	}
	worker, _ := NewWorker(store, &Resolver{})
	if _, err := store.DB().ExecContext(ctx, `CREATE TRIGGER fail_analysis_projection BEFORE INSERT ON analysis_sources BEGIN SELECT RAISE(ABORT,'test failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := worker.RunOnce(ctx); err == nil {
		t.Fatal("worker succeeded despite projection failure")
	}
	status, err := store.AnalysisStatus(ctx)
	if err != nil || status.CheckpointID != 0 || status.Pending != 1 {
		t.Fatalf("failed batch advanced durable cursor: %+v err=%v", status, err)
	}
	var sourceCount int
	if err := store.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM analysis_sources`).Scan(&sourceCount); err != nil || sourceCount != 0 {
		t.Fatalf("failed projection partially committed: sources=%d err=%v", sourceCount, err)
	}
	if _, err := store.DB().ExecContext(ctx, `DROP TRIGGER fail_analysis_projection`); err != nil {
		t.Fatal(err)
	}
	if processed, err := worker.RunOnce(ctx); err != nil || processed != 1 {
		t.Fatalf("retry failed batch: processed=%d err=%v", processed, err)
	}
	if status, err = store.AnalysisStatus(ctx); err != nil || status.CheckpointID != 1 || status.Pending != 0 {
		t.Fatalf("successful retry did not advance cursor: %+v err=%v", status, err)
	}
}

func TestWorkerLifecycleLeavesHandoffDurableWhenStopped(t *testing.T) {
	ctx := context.Background()
	store, err := rawstore.New(filepath.Join(t.TempDir(), "lifecycle.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	worker, _ := NewWorker(store, &Resolver{})
	if err := worker.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Store(ctx, model.IngestedRecord{Transport: "http_post", SourceIP: "192.0.2.1", RawBytes: []byte("first")}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		status, err := worker.Status(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if status.QueueStatus.CheckpointID == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("worker did not advance checkpoint: %+v", status)
		}
		time.Sleep(10 * time.Millisecond)
	}
	worker.Stop()
	if _, err := store.Store(ctx, model.IngestedRecord{Transport: "http_post", SourceIP: "192.0.2.2", RawBytes: []byte("while stopped")}); err != nil {
		t.Fatalf("stopped analyzer blocked ingress: %v", err)
	}
	status, err := worker.Status(ctx)
	if err != nil || status.QueueStatus.Pending != 1 || status.QueueStatus.CheckpointID != 1 {
		t.Fatalf("stopped worker did not leave durable backlog: %+v err=%v", status, err)
	}
}
