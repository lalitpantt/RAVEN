package analysis

import (
	"context"
	"path/filepath"
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
