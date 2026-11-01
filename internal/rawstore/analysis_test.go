package rawstore

import (
	"context"
	"testing"
	"time"

	"raven/internal/model"
	"raven/internal/outbox"
)

func TestAnalysisOutboxWritesAreAtomicWithLifecycleRows(t *testing.T) {
	ctx := context.Background()
	store := setupTestStore(t)
	store.SetAnalysisEnabled(true)
	if _, err := store.DB().ExecContext(ctx, `CREATE TRIGGER fail_raw_analysis BEFORE INSERT ON analysis_observations WHEN NEW.kind='raw_received' BEGIN SELECT RAISE(ABORT,'test raw outbox failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Store(ctx, model.IngestedRecord{Transport: "syslog_udp", SourceIP: "10.0.0.1", RawBytes: []byte("raw")}); err == nil {
		t.Fatal("raw write succeeded after its required analysis observation failed")
	}
	if count, err := store.CountRaw(ctx); err != nil || count != 0 {
		t.Fatalf("raw receipt partially committed: count=%d err=%v", count, err)
	}
	if _, err := store.DB().ExecContext(ctx, `DROP TRIGGER fail_raw_analysis`); err != nil {
		t.Fatal(err)
	}
	raw, err := store.Store(ctx, model.IngestedRecord{Transport: "syslog_udp", SourceIP: "10.0.0.1", RawBytes: []byte("raw"), ReceivedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `CREATE TRIGGER fail_normalized_analysis BEFORE INSERT ON analysis_observations WHEN NEW.kind='normalized' BEGIN SELECT RAISE(ABORT,'test normalized outbox failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := outbox.NewOutbox(store.DB()); err != nil {
		t.Fatal(err)
	}
	event := &model.NormalizedEvent{Raven: model.RavenEnvelope{EventID: "event-atomic", RawID: raw.RawID, SourceCategory: "test", SourceID: "device", ReceivedTime: raw.ReceivedAt}, OCSF: map[string]any{"message": "ok"}}
	if err := store.StoreNormalizedWithOutboxAndHints(ctx, event, []string{"sink"}, model.AnalysisIdentityHints{"host": "device"}); err == nil {
		t.Fatal("normalized write succeeded after its required analysis observation failed")
	}
	if count, err := store.CountNormalized(ctx); err != nil || count != 0 {
		t.Fatalf("normalized projection partially committed: count=%d err=%v", count, err)
	}
	var pendingDelivery int
	if err := store.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox`).Scan(&pendingDelivery); err != nil || pendingDelivery != 0 {
		t.Fatalf("delivery intent partially committed: count=%d err=%v", pendingDelivery, err)
	}
	if _, err := store.DB().ExecContext(ctx, `DROP TRIGGER fail_normalized_analysis`); err != nil {
		t.Fatal(err)
	}
	if err := store.StoreNormalizedWithOutboxAndHints(ctx, event, []string{"sink"}, model.AnalysisIdentityHints{"host": "device"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `CREATE TRIGGER fail_quarantine_analysis BEFORE INSERT ON analysis_observations WHEN NEW.kind='quarantined' BEGIN SELECT RAISE(ABORT,'test quarantine outbox failure'); END`); err != nil {
		t.Fatal(err)
	}
	entry := model.QuarantineEntry{QuarantineID: "q-atomic", RawID: raw.RawID, RawSHA256: raw.RawSHA256, Stage: "test", Reason: "failed", ReplayEligible: true, QuarantinedAt: time.Now().UTC()}
	if err := store.QuarantineChild(ctx, entry); err == nil {
		t.Fatal("quarantine write succeeded after its required analysis observation failed")
	}
	if count, err := store.CountQuarantine(ctx); err != nil || count != 0 {
		t.Fatalf("quarantine projection partially committed: count=%d err=%v", count, err)
	}
	var observationCount int
	if err := store.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM analysis_observations`).Scan(&observationCount); err != nil || observationCount != 2 {
		t.Fatalf("unexpected committed observations after rollback/retry: count=%d err=%v", observationCount, err)
	}
}

func TestAnalysisMigrationAddsIsolatedTablesWithoutChangingRawRows(t *testing.T) {
	ctx := context.Background()
	store := setupTestStore(t)
	raw, err := store.Store(ctx, model.IngestedRecord{Transport: "syslog_tcp", SourceIP: "192.0.2.3", RawBytes: []byte("preserve me"), ReceivedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	var payload []byte
	if err := store.DB().QueryRowContext(ctx, `SELECT payload FROM raw_events WHERE raw_id=?`, raw.RawID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if string(payload) != "preserve me" {
		t.Fatalf("raw fixture changed before migration assertion: %q", payload)
	}
	var fkViolations int
	rows, err := store.DB().QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		fkViolations++
	}
	rows.Close()
	if fkViolations != 0 {
		t.Fatalf("analysis migration introduced %d foreign-key violations", fkViolations)
	}
	if _, err := store.DB().ExecContext(ctx, `DROP TABLE analysis_observation_sources; DROP TABLE analysis_sources; DROP TABLE analysis_worker_state; DROP TABLE analysis_observations; PRAGMA user_version=7`); err != nil {
		t.Fatal(err)
	}
	if err := initSchema(store.DB()); err != nil {
		t.Fatal(err)
	}
	var after []byte
	if err := store.DB().QueryRowContext(ctx, `SELECT payload FROM raw_events WHERE raw_id=?`, raw.RawID).Scan(&after); err != nil || string(after) != "preserve me" {
		t.Fatalf("schema v8 migration changed existing raw bytes: %q err=%v", after, err)
	}
}

func TestAnalysisIsDisabledByDefaultAndFileSpoolRetryIsIdempotent(t *testing.T) {
	ctx := context.Background()
	store := setupTestStore(t)
	if _, err := store.Store(ctx, model.IngestedRecord{Transport: "syslog_tcp", SourceIP: "192.0.2.3", RawBytes: []byte("baseline")}); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := store.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM analysis_observations`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("disabled analysis wrote observations: count=%d err=%v", count, err)
	}
	store.SetAnalysisEnabled(true)
	record := model.IngestedRecord{Transport: "file", SourceIP: "local", RawBytes: []byte("spooled"), ReceivedAt: time.Now().UTC(), Metadata: model.ReceiveMetadata{FileID: "file-identity", FileOffset: 128}}
	first, err := store.Store(ctx, record)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Store(ctx, record)
	if err != nil || !second.Duplicate || second.RawID != first.RawID {
		t.Fatalf("file spool retry was not deduplicated: first=%+v second=%+v err=%v", first, second, err)
	}
	if err := store.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM analysis_observations`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("file spool retry duplicated analysis observation: count=%d err=%v", count, err)
	}
}

func TestAnalysisTelemetryMigrationBackfillsExistingProjections(t *testing.T) {
	ctx := context.Background()
	store := setupTestStore(t)
	store.SetAnalysisEnabled(true)
	if _, err := store.Store(ctx, model.IngestedRecord{Transport: "syslog_udp", SourceIP: "203.0.113.9", RawBytes: []byte("preserve"), ReceivedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	observations, checkpoint, err := store.AnalysisBatch(ctx, 10)
	if err != nil || len(observations) != 1 {
		t.Fatalf("load raw observation: rows=%d err=%v", len(observations), err)
	}
	hints := observations[0].IdentityHints
	resolution := AnalysisResolution{SourceKey: AnalysisSourceKey(hints), Resolution: "matched", DeviceID: "edge-1", MatchMethod: "source_ip", Confidence: "weak"}
	if err := store.CommitAnalysisBatch(ctx, checkpoint, observations, []AnalysisResolution{resolution}); err != nil {
		t.Fatal(err)
	}
	dbPath := store.dbPath
	if _, err := store.DB().ExecContext(ctx, `DROP TABLE analysis_device_telemetry; PRAGMA user_version=8`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	migrated, err := New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer migrated.Close()
	projection, err := migrated.ListAnalysisDeviceTelemetry(ctx, []string{"edge-1"})
	if err != nil {
		t.Fatal(err)
	}
	got := projection["edge-1"]
	if got.ReceivedCount != 1 || got.LastReceivedAt.IsZero() || got.IdentityConfidence != "weak" {
		t.Fatalf("v9 migration failed to backfill telemetry: %+v", got)
	}
	var fkViolations int
	rows, err := migrated.DB().QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		fkViolations++
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if fkViolations != 0 {
		t.Fatalf("migration left %d foreign-key violations", fkViolations)
	}
}

func TestAnalysisObservationsRemainOutsideIntegrityEvidence(t *testing.T) {
	ctx := context.Background()
	store := setupTestStore(t)
	enableTestIntegrity(t, store)
	store.SetAnalysisEnabled(true)
	raw, err := store.Store(ctx, model.IngestedRecord{Transport: "syslog_udp", SourceIP: "10.1.0.4", RawBytes: []byte("evidence stays unchanged"), ReceivedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	if ok, _, err := store.Verify(ctx, raw.RawID); err != nil || !ok {
		t.Fatalf("analysis observation changed raw evidence verification: valid=%v err=%v", ok, err)
	}
	entries, err := store.ListIntegrityEntries(ctx, 0, 10)
	if err != nil || len(entries) != 1 || entries[0].Kind != 1 {
		t.Fatalf("analysis observation entered the integrity journal: entries=%+v err=%v", entries, err)
	}
	var observations int
	if err := store.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM analysis_observations`).Scan(&observations); err != nil || observations != 1 {
		t.Fatalf("raw observation missing from its own journal: count=%d err=%v", observations, err)
	}
}
