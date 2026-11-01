package rawstore

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"raven/internal/integrity"
	"raven/internal/model"
	"raven/internal/outbox"
)

func setupTestStore(t *testing.T) *RawStore {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test_rawstore.db")
	store, err := New(dbPath)
	if err != nil {
		t.Fatalf("failed to create test rawstore: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})
	return store
}

func enableTestIntegrity(t *testing.T, store *RawStore) {
	t.Helper()
	var stream, epoch integrity.Hash
	stream[0], epoch[0] = 1, 2
	if err := store.EnableIntegrity(context.Background(), stream, epoch); err != nil {
		t.Fatal(err)
	}
}

func TestStartIntegrityAuditCoalescesOnlyActiveRuns(t *testing.T) {
	store := setupTestStore(t)
	enableTestIntegrity(t, store)
	ctx := context.Background()
	first, active, err := store.StartIntegrityAudit(ctx, false)
	if err != nil || active {
		t.Fatalf("first audit: active=%v err=%v", active, err)
	}
	duplicate, active, err := store.StartIntegrityAudit(ctx, false)
	if err != nil || !active || duplicate.RunID != first.RunID {
		t.Fatalf("duplicate audit did not coalesce: %+v active=%v err=%v", duplicate, active, err)
	}
	if result, err := store.RunIntegrityAudit(ctx, first.RunID); err != nil || result != "passed" {
		t.Fatalf("run local audit: result=%q err=%v", result, err)
	}
	next, active, err := store.StartIntegrityAudit(ctx, false)
	if err != nil || active || next.RunID == first.RunID {
		t.Fatalf("completed audit was reused: %+v active=%v err=%v", next, active, err)
	}
}

func insertSealerTestEntries(t *testing.T, store *RawStore, count, subjectPad int, age time.Duration) {
	t.Helper()
	tx, err := store.DB().Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var streamBytes []byte
	var firstSeq uint64
	if err := tx.QueryRow(`SELECT stream_id,next_entry_seq FROM integrity_streams WHERE singleton=1`).Scan(&streamBytes, &firstSeq); err != nil {
		t.Fatal(err)
	}
	var stream integrity.Hash
	copy(stream[:], streamBytes)
	metadata, err := integrity.EncodeFields(nil)
	if err != nil {
		t.Fatal(err)
	}
	contentFields := []integrity.TypedField{fieldText(1, "replay_failed"), fieldBytes32(2, integrity.HashContent([]byte("test failure")))}
	content, err := integrity.EncodeFields(contentFields)
	if err != nil {
		t.Fatal(err)
	}
	contentDigest, metadataDigest := integrity.HashContent(content), integrity.HashContent(metadata)
	insert, err := tx.Prepare(`INSERT INTO integrity_entries(stream_id,entry_seq,entry_kind,subject_id,occurred_at_unix_ns,content_snapshot,metadata_snapshot,content_digest,metadata_digest,encoded_entry,leaf_hash,committed_at) VALUES(?,?,?, ?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		t.Fatal(err)
	}
	defer insert.Close()
	committedAt := time.Now().UTC().Add(-age)
	for i := 0; i < count; i++ {
		seq := firstSeq + uint64(i)
		subject := fmt.Sprintf("test-%04d-%s", i, strings.Repeat("s", subjectPad))
		entry := integrity.EvidenceEntry{Version: integrity.CodecVersion, StreamID: stream, Sequence: seq, Kind: integrity.ReplayFailed, SubjectID: &subject, OccurredAtUnixNS: committedAt.UnixNano(), ContentDigest: contentDigest, MetadataDigest: metadataDigest}
		encoded, err := integrity.EncodeEvidenceEntry(entry)
		if err != nil {
			t.Fatal(err)
		}
		leaf := integrity.MerkleLeaf(encoded)
		if _, err := insert.Exec(streamBytes, seq, integrity.ReplayFailed, subject, entry.OccurredAtUnixNS, content, metadata, contentDigest[:], metadataDigest[:], encoded, leaf[:], committedAt.Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec(`UPDATE integrity_streams SET next_entry_seq=? WHERE singleton=1`, firstSeq+uint64(count)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestIntegritySchemaFutureVersionAndFreshEnable(t *testing.T) {
	store := setupTestStore(t)
	var version int
	if err := store.DB().QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != CurrentSchemaVersion {
		t.Fatalf("schema version=%d err=%v", version, err)
	}
	for _, table := range []string{"integrity_streams", "integrity_entries", "integrity_batches", "integrity_batch_entries", "integrity_witness_sync", "integrity_operations", "integrity_audit_runs", "integrity_findings"} {
		var count int
		if err := store.DB().QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&count); err != nil || count != 1 {
			t.Fatalf("table %s missing: count=%d err=%v", table, count, err)
		}
	}
	var committedAtColumn int
	if err := store.DB().QueryRow(`SELECT COUNT(*) FROM pragma_table_info('integrity_entries') WHERE name='committed_at'`).Scan(&committedAtColumn); err != nil || committedAtColumn != 1 {
		t.Fatalf("integrity entry append timestamp missing: count=%d err=%v", committedAtColumn, err)
	}
	if _, err := store.DB().Exec(`DROP TRIGGER integrity_stream_identity_no_update;
		ALTER TABLE integrity_streams DROP COLUMN enabled_at;
		CREATE TRIGGER integrity_stream_identity_no_update BEFORE UPDATE OF stream_id,codec_version,installation_epoch,genesis_hash,enabled ON integrity_streams BEGIN SELECT RAISE(ABORT,'integrity stream identity is immutable'); END;
		ALTER TABLE integrity_entries DROP COLUMN committed_at;
		PRAGMA user_version=5`); err != nil {
		t.Fatalf("prepare schema v5 database: %v", err)
	}
	if err := initSchema(store.DB()); err != nil {
		t.Fatalf("migrate schema v5 timestamp column: %v", err)
	}
	if err := store.DB().QueryRow(`SELECT COUNT(*) FROM pragma_table_info('integrity_entries') WHERE name='committed_at'`).Scan(&committedAtColumn); err != nil || committedAtColumn != 1 {
		t.Fatalf("schema v5 migration did not add commit timestamp: count=%d err=%v", committedAtColumn, err)
	}
	enableTestIntegrity(t, store)
	var enabledAtColumns int
	if err := store.DB().QueryRow(`SELECT COUNT(*) FROM pragma_table_info('integrity_streams') WHERE name='enabled_at'`).Scan(&enabledAtColumns); err != nil || enabledAtColumns != 1 {
		t.Fatalf("integrity enable time missing after schema v7 migration: columns=%d err=%v", enabledAtColumns, err)
	}
	if _, err := store.DB().Exec(`UPDATE integrity_streams SET enabled_at='2000-01-01T00:00:00Z'`); err == nil {
		t.Fatal("integrity enable time was mutable")
	}
	if err := initSchema(store.DB()); err != nil {
		t.Fatalf("reopen migrated schema: %v", err)
	}
	if _, err := store.DB().ExecContext(context.Background(), `PRAGMA user_version=11`); err != nil {
		t.Fatal(err)
	}
	if err := initSchema(store.DB()); err == nil {
		t.Fatal("future database schema was accepted")
	}
	if err := store.DB().QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 11 {
		t.Fatalf("future schema version changed: version=%d err=%v", version, err)
	}
}

func TestIntegrityBatchSealerPersistsContiguousFullBatch(t *testing.T) {
	ctx := context.Background()
	store := setupTestStore(t)
	enableTestIntegrity(t, store)
	store.stopIntegritySealer()
	insertSealerTestEntries(t, store, integrity.MaxBatchEntries, 0, 0)
	batch, err := store.SealIntegrityBatch(ctx, false)
	if err != nil || batch == nil {
		t.Fatalf("seal full batch: batch=%+v err=%v", batch, err)
	}
	if batch.Descriptor.BatchID != 1 || batch.Descriptor.FirstSeq != 1 || batch.Descriptor.LastSeq != integrity.MaxBatchEntries || batch.Descriptor.LeafCount != integrity.MaxBatchEntries || len(batch.Manifest) > maxManifestBytes {
		t.Fatalf("unexpected sealed descriptor: %+v manifest_bytes=%d", batch.Descriptor, len(batch.Manifest))
	}
	var manifest batchManifest
	if err := json.Unmarshal(batch.Manifest, &manifest); err != nil || len(manifest.Entries) != integrity.MaxBatchEntries {
		t.Fatalf("invalid persisted manifest: entries=%d err=%v", len(manifest.Entries), err)
	}
	rows, err := store.DB().Query(`SELECT entry_seq,leaf_hash FROM integrity_batch_entries WHERE stream_id=(SELECT stream_id FROM integrity_streams WHERE singleton=1) AND batch_id=1 ORDER BY leaf_index`)
	if err != nil {
		t.Fatal(err)
	}
	leaves := make([]integrity.Hash, 0, integrity.MaxBatchEntries)
	for i := 0; rows.Next(); i++ {
		var seq uint64
		var leaf []byte
		if err := rows.Scan(&seq, &leaf); err != nil {
			t.Fatal(err)
		}
		if seq != uint64(i+1) {
			t.Fatalf("membership gap at index %d: seq=%d", i, seq)
		}
		var h integrity.Hash
		copy(h[:], leaf)
		leaves = append(leaves, h)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	root, err := integrity.MerkleRoot(leaves)
	if err != nil || root != batch.Descriptor.MerkleRoot {
		t.Fatalf("batch root does not match ordered membership: root=%x err=%v", root, err)
	}
	wantHash, err := integrity.HashBatchDescriptor(batch.Descriptor)
	if err != nil || wantHash != batch.BatchHash {
		t.Fatalf("batch hash mismatch: got=%x want=%x err=%v", batch.BatchHash, wantHash, err)
	}
	var sealed, queued, lastSeq, nextBatch int
	_ = store.DB().QueryRow(`SELECT COUNT(*) FROM integrity_batches`).Scan(&sealed)
	_ = store.DB().QueryRow(`SELECT COUNT(*) FROM integrity_witness_sync WHERE state='pending'`).Scan(&queued)
	_ = store.DB().QueryRow(`SELECT last_sealed_seq,next_batch_id FROM integrity_streams WHERE singleton=1`).Scan(&lastSeq, &nextBatch)
	if sealed != 1 || queued != 1 || lastSeq != integrity.MaxBatchEntries || nextBatch != 2 {
		t.Fatalf("batch head or witness queue is incomplete: batches=%d queued=%d last=%d next=%d", sealed, queued, lastSeq, nextBatch)
	}
	if duplicate, err := store.SealIntegrityBatch(ctx, true); err != nil || duplicate != nil {
		t.Fatalf("already-sealed prefix was duplicated: batch=%+v err=%v", duplicate, err)
	}
}

func TestIntegrityBatchSealerFlushesAtBodyLimitAndPreservesNextPrefix(t *testing.T) {
	ctx := context.Background()
	store := setupTestStore(t)
	enableTestIntegrity(t, store)
	store.stopIntegritySealer()
	insertSealerTestEntries(t, store, integrity.MaxBatchEntries, 900, 0)
	first, err := store.SealIntegrityBatch(ctx, false)
	if err != nil || first == nil {
		t.Fatalf("seal body-limited prefix: batch=%+v err=%v", first, err)
	}
	if first.Descriptor.LeafCount >= integrity.MaxBatchEntries || len(first.Manifest) > maxManifestBytes {
		t.Fatalf("body limit did not split a bounded request: count=%d bytes=%d", first.Descriptor.LeafCount, len(first.Manifest))
	}
	second, err := store.SealIntegrityBatch(ctx, true)
	if err != nil || second == nil {
		t.Fatalf("seal remaining prefix: batch=%+v err=%v", second, err)
	}
	if second.Descriptor.BatchID != 2 || second.Descriptor.FirstSeq != first.Descriptor.LastSeq+1 || second.Descriptor.PrevBatchHash != first.BatchHash || second.Descriptor.LastSeq != integrity.MaxBatchEntries {
		t.Fatalf("second batch broke continuity: first=%+v second=%+v", first.Descriptor, second.Descriptor)
	}
	var membershipCount int
	if err := store.DB().QueryRow(`SELECT COUNT(*) FROM integrity_batch_entries`).Scan(&membershipCount); err != nil || membershipCount != integrity.MaxBatchEntries {
		t.Fatalf("sealed prefix membership count=%d err=%v", membershipCount, err)
	}
}

func TestIntegrityBatchSealerAgeFlushRollbackRestartAndCloseDrain(t *testing.T) {
	ctx := context.Background()
	store := setupTestStore(t)
	enableTestIntegrity(t, store)
	store.stopIntegritySealer()
	insertSealerTestEntries(t, store, 2, 0, 6*time.Second)
	batch, err := store.SealIntegrityBatch(ctx, false)
	if err != nil || batch == nil || batch.Descriptor.LeafCount != 2 {
		t.Fatalf("aged partial batch was not sealed: batch=%+v err=%v", batch, err)
	}
	insertSealerTestEntries(t, store, 2, 0, 0)
	if pending, err := store.SealIntegrityBatch(ctx, false); err != nil || pending != nil {
		t.Fatalf("young partial batch sealed too early: batch=%+v err=%v", pending, err)
	}
	if _, err := store.DB().Exec(`CREATE TRIGGER fail_batch_membership BEFORE INSERT ON integrity_batch_entries BEGIN SELECT RAISE(ABORT,'injected membership failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SealIntegrityBatch(ctx, true); err == nil {
		t.Fatal("batch seal succeeded despite membership failure")
	}
	var batches, memberships, pendingQueue, lastSeq, nextBatch int
	_ = store.DB().QueryRow(`SELECT COUNT(*) FROM integrity_batches`).Scan(&batches)
	_ = store.DB().QueryRow(`SELECT COUNT(*) FROM integrity_batch_entries`).Scan(&memberships)
	_ = store.DB().QueryRow(`SELECT COUNT(*) FROM integrity_witness_sync`).Scan(&pendingQueue)
	_ = store.DB().QueryRow(`SELECT last_sealed_seq,next_batch_id FROM integrity_streams`).Scan(&lastSeq, &nextBatch)
	if batches != 1 || memberships != 2 || pendingQueue != 1 || lastSeq != 2 || nextBatch != 2 {
		t.Fatalf("failed seal left partial state: batches=%d memberships=%d queue=%d last=%d next=%d", batches, memberships, pendingQueue, lastSeq, nextBatch)
	}
	if _, err := store.DB().Exec(`DROP TRIGGER fail_batch_membership`); err != nil {
		t.Fatal(err)
	}
	if count, err := store.SealIntegrityPending(ctx, 1); err != nil || count != 1 {
		t.Fatalf("explicit bounded drain failed: count=%d err=%v", count, err)
	}
	path := store.dbPath
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var finalBatches, finalMembership int
	_ = db.QueryRow(`SELECT COUNT(*) FROM integrity_batches`).Scan(&finalBatches)
	_ = db.QueryRow(`SELECT COUNT(*) FROM integrity_batch_entries`).Scan(&finalMembership)
	if finalBatches != 2 || finalMembership != 4 {
		t.Fatalf("shutdown drain lost sealed state: batches=%d membership=%d", finalBatches, finalMembership)
	}
}

func TestIntegrityBatchSealerWorkerFlushesAgedTail(t *testing.T) {
	store := setupTestStore(t)
	enableTestIntegrity(t, store)
	insertSealerTestEntries(t, store, 2, 0, 6*time.Second)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var batches int
		if err := store.DB().QueryRow(`SELECT COUNT(*) FROM integrity_batches`).Scan(&batches); err != nil {
			t.Fatal(err)
		}
		if batches == 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("background sealer did not flush the aged partial batch")
}

func TestIntegrityBatchSealerResumesAfterRestartAndCloseDrainsTail(t *testing.T) {
	ctx := context.Background()
	store := setupTestStore(t)
	enableTestIntegrity(t, store)
	store.stopIntegritySealer()
	insertSealerTestEntries(t, store, 2, 0, 0)
	path := store.dbPath
	if err := store.auditDB.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.DB().Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	first, err := reopened.SealIntegrityBatch(ctx, true)
	if err != nil || first == nil || first.Descriptor.LastSeq != 2 {
		t.Fatalf("restart lost unsealed evidence: batch=%+v err=%v", first, err)
	}
	insertSealerTestEntries(t, reopened, 1, 0, 0)
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var batches, entries int
	if err := db.QueryRow(`SELECT COUNT(*) FROM integrity_batches`).Scan(&batches); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM integrity_batch_entries`).Scan(&entries); err != nil {
		t.Fatal(err)
	}
	if batches != 2 || entries != 3 {
		t.Fatalf("close did not drain its bounded tail: batches=%d entries=%d", batches, entries)
	}
}

func TestIntegrityEnableRejectsPopulatedStoreAndRawAppendIsAtomic(t *testing.T) {
	ctx := context.Background()
	store := setupTestStore(t)
	if _, err := store.Store(ctx, model.IngestedRecord{Transport: "test", RawBytes: []byte("before-enable"), ReceivedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	var stream, epoch integrity.Hash
	stream[0], epoch[0] = 1, 2
	if err := store.EnableIntegrity(ctx, stream, epoch); err == nil {
		t.Fatal("enabled evidence over existing rows")
	}
	if enabled, err := store.IntegrityEnabled(ctx); err != nil || enabled {
		t.Fatalf("unexpected stream state enabled=%t err=%v", enabled, err)
	}

	store2 := setupTestStore(t)
	enableTestIntegrity(t, store2)
	rec := model.IngestedRecord{Transport: "file", SourceIP: "127.0.0.1", SourcePort: 514, RawBytes: []byte("exact raw bytes"), ReceivedAt: time.Now().UTC(), Metadata: model.ReceiveMetadata{FileID: "input-1", FileOffset: 9}}
	first, err := store2.Store(ctx, rec)
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := store2.Store(ctx, rec)
	if err != nil {
		t.Fatal(err)
	}
	if !duplicate.Duplicate {
		t.Fatal("expected duplicate file coordinate")
	}
	entries, err := store2.ListIntegrityEntries(ctx, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Kind != integrity.RawCommitted {
		t.Fatalf("unexpected journal: %+v", entries)
	}
	decoded, err := integrity.DecodeEvidenceEntry(entries[0].EncodedEntry)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Sequence != 1 || decoded.RawID == nil || *decoded.RawID != first.RawID || entries[0].LeafHash != integrity.MerkleLeaf(entries[0].EncodedEntry) {
		t.Fatalf("raw evidence does not bind committed row: %+v", entries[0])
	}
	wantContentDigest := integrity.HashContent(rec.RawBytes)
	if entries[0].ContentDigest != wantContentDigest {
		t.Fatal("raw content digest does not match exact bytes")
	}

	if _, err := store2.DB().Exec(`CREATE TRIGGER fail_evidence BEFORE INSERT ON integrity_entries BEGIN SELECT RAISE(ABORT,'injected evidence failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := store2.Store(ctx, model.IngestedRecord{Transport: "test", RawBytes: []byte("must rollback"), ReceivedAt: time.Now().UTC()}); err == nil {
		t.Fatal("raw commit succeeded without required evidence")
	}
	count, err := store2.CountRaw(ctx)
	if err != nil || count != 1 {
		t.Fatalf("raw write was not rolled back: count=%d err=%v", count, err)
	}
}

func TestIntegrityAuditReaderIsBoundedReadOnlyAndReopens(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "audit.db")
	store, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	enableTestIntegrity(t, store)
	if _, err := store.Store(ctx, model.IngestedRecord{Transport: "test", RawBytes: []byte("audit"), ReceivedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if store.auditDB == nil {
		t.Fatal("integrity mode did not open a separate audit reader")
	}
	if _, err := store.auditDB.ExecContext(ctx, `UPDATE integrity_streams SET next_entry_seq=99`); err == nil {
		t.Fatal("audit connection allowed a write")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	entries, err := reopened.ListIntegrityEntries(ctx, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Sequence != 1 {
		t.Fatalf("audit reader did not read durable journal after reopen: %+v", entries)
	}
}

func TestIntegrityFastAndDeepAuditPersistResultsAndDetectRawTamper(t *testing.T) {
	ctx := context.Background()
	store := setupTestStore(t)
	enableTestIntegrity(t, store)
	rec, err := store.Store(ctx, model.IngestedRecord{Transport: "test", RawBytes: []byte("audit payload"), ReceivedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SealIntegrityBatch(ctx, true); err != nil {
		t.Fatal(err)
	}
	if _, result, err := store.AuditIntegrity(ctx, false); err != nil || result != "passed" {
		t.Fatalf("fast audit result=%q err=%v", result, err)
	}
	if _, result, err := store.AuditIntegrity(ctx, true); err != nil || result != "passed" {
		t.Fatalf("deep audit result=%q err=%v", result, err)
	}
	if _, err := store.DB().ExecContext(ctx, `UPDATE raw_events SET payload=? WHERE raw_id=?`, []byte("tampered"), rec.RawID); err != nil {
		t.Fatal(err)
	}
	if _, result, err := store.AuditIntegrity(ctx, false); err != nil || result != "passed" {
		t.Fatalf("fast audit should only establish saved digest consistency, got result=%q err=%v", result, err)
	}
	if _, result, err := store.AuditIntegrity(ctx, true); err != nil || result != "failed" {
		t.Fatalf("deep audit did not catch raw tampering: result=%q err=%v", result, err)
	}
	var count int
	if err := store.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM integrity_audit_runs`).Scan(&count); err != nil || count != 4 {
		t.Fatalf("audit runs were not persisted: count=%d err=%v", count, err)
	}
}

func TestIntegrityFastAuditDetectsSealedBatchMembershipTampering(t *testing.T) {
	ctx := context.Background()
	store := setupTestStore(t)
	enableTestIntegrity(t, store)
	if _, err := store.Store(ctx, model.IngestedRecord{Transport: "test", RawBytes: []byte("sealed audit"), ReceivedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SealIntegrityBatch(ctx, true); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().Exec(`DROP TRIGGER integrity_membership_no_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().Exec(`UPDATE integrity_batch_entries SET leaf_hash=zeroblob(32) WHERE batch_id=1`); err != nil {
		t.Fatal(err)
	}
	if _, result, err := store.AuditIntegrity(ctx, false); err != nil || result != "failed" {
		t.Fatalf("fast audit accepted changed sealed membership: result=%q err=%v", result, err)
	}
}

func TestIntegrityNormalizedVersionsAndRemoval(t *testing.T) {
	ctx := context.Background()
	store := setupTestStore(t)
	enableTestIntegrity(t, store)
	raw, err := store.Store(ctx, model.IngestedRecord{Transport: "test", RawBytes: []byte("payload"), ReceivedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	event := integrityTestEvent(raw.RawID, raw.RawSHA256, 0, "first")
	if err := store.StoreNormalized(ctx, event); err != nil {
		t.Fatal(err)
	}
	if err := store.StoreNormalized(ctx, event); err != nil {
		t.Fatal(err)
	}
	event.Raven.ParserFileSHA256[1] = 8
	if err := store.StoreNormalized(ctx, event); err != nil {
		t.Fatal(err)
	}
	event.OCSF["message"] = "second"
	if err := store.StoreNormalized(ctx, event); err != nil {
		t.Fatal(err)
	}
	entries, err := store.ListIntegrityEntries(ctx, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 || entries[1].Kind != integrity.NormalizedWritten || entries[2].Kind != integrity.NormalizedWritten || entries[3].Kind != integrity.NormalizedWritten {
		t.Fatalf("identical retry or changed version journal incorrect: %+v", entries)
	}
	version, err := integrity.DecodeEvidenceEntry(entries[3].EncodedEntry)
	if err != nil {
		t.Fatal(err)
	}
	if version.PreviousSubjectSeq == nil || *version.PreviousSubjectSeq != 3 {
		t.Fatalf("normalized version missing previous evidence reference: %+v", version)
	}
	var persisted string
	if err := store.DB().QueryRow(`SELECT event_json FROM normalized_events WHERE raw_id=?`, raw.RawID).Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	if string(entries[3].ContentSnapshot) != persisted || entries[3].ContentDigest != integrity.HashContent([]byte(persisted)) {
		t.Fatal("evidence did not retain exact normalized JSON bytes")
	}
	if _, err := store.DB().Exec(`CREATE TRIGGER fail_norm_remove BEFORE INSERT ON integrity_entries WHEN NEW.entry_kind=6 BEGIN SELECT RAISE(ABORT,'injected removal failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteNormalizedChild(ctx, raw.RawID, 0); err == nil {
		t.Fatal("normalized projection was removed without evidence")
	}
	var normalizedCount int
	if err := store.DB().QueryRow(`SELECT COUNT(*) FROM normalized_events WHERE raw_id=?`, raw.RawID).Scan(&normalizedCount); err != nil || normalizedCount != 1 {
		t.Fatalf("normalized removal failure was not atomic: count=%d err=%v", normalizedCount, err)
	}
	if _, err := store.DB().Exec(`DROP TRIGGER fail_norm_remove`); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteNormalizedChild(ctx, raw.RawID, 0); err != nil {
		t.Fatal(err)
	}
	entries, err = store.ListIntegrityEntries(ctx, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 5 || entries[4].Kind != integrity.NormalizedRemoved {
		t.Fatalf("normalized removal transition missing: %+v", entries)
	}
}

func TestIntegrityQuarantineSnapshotUpdateRemovalAndReplayResolution(t *testing.T) {
	ctx := context.Background()
	store := setupTestStore(t)
	enableTestIntegrity(t, store)
	raw, err := store.Store(ctx, model.IngestedRecord{Transport: "test", RawBytes: []byte("bad input"), ReceivedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	q := model.QuarantineEntry{QuarantineID: "q1", RawID: raw.RawID, RawSHA256: raw.RawSHA256, Stage: "decode", Reason: "invalid", RawPreview: "626164", CandidatePacks: []string{"z-pack", "a-pack"}, ReplayEligible: true, QuarantinedAt: time.Now().UTC()}
	if err := store.QuarantineChild(ctx, q); err != nil {
		t.Fatal(err)
	}
	if err := store.QuarantineChild(ctx, q); err != nil {
		t.Fatal(err)
	}
	q.ErrorDetails = "bounded detail"
	if err := store.QuarantineChild(ctx, q); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().Exec(`CREATE TRIGGER fail_quarantine_remove BEFORE INSERT ON integrity_entries WHEN NEW.entry_kind=7 BEGIN SELECT RAISE(ABORT,'injected removal failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteQuarantine(ctx, "q1"); err == nil {
		t.Fatal("quarantine projection was removed without evidence")
	}
	if _, err := store.GetQuarantineByID(ctx, "q1"); err != nil {
		t.Fatalf("failed quarantine removal was not rolled back: %v", err)
	}
	if _, err := store.DB().Exec(`DROP TRIGGER fail_quarantine_remove`); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteQuarantine(ctx, "q1"); err != nil {
		t.Fatal(err)
	}
	entries, err := store.ListIntegrityEntries(ctx, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 || entries[1].Kind != integrity.QuarantineWritten || entries[2].Kind != integrity.QuarantineWritten || entries[3].Kind != integrity.QuarantineRemoved {
		t.Fatalf("quarantine journal transitions unexpected: %+v", entries)
	}
	var removed integrity.EvidenceEntry
	if removed, err = integrity.DecodeEvidenceEntry(entries[3].EncodedEntry); err != nil || removed.PreviousSubjectSeq == nil || *removed.PreviousSubjectSeq != 3 {
		t.Fatalf("quarantine removal lacks prior evidence ref: %+v err=%v", removed, err)
	}

	store2 := setupTestStore(t)
	enableTestIntegrity(t, store2)
	if _, err := store2.Store(ctx, model.IngestedRecord{Transport: "test", RawBytes: []byte("replay"), ReceivedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if _, err := outbox.NewOutbox(store2.DB()); err != nil {
		t.Fatal(err)
	}
	raw2, err := store2.ListRawByStatus(ctx, model.StatusAccepted)
	if err != nil || len(raw2) != 1 {
		t.Fatalf("load raw: %v", err)
	}
	entry := model.QuarantineEntry{QuarantineID: "q-resolve", RawID: raw2[0].RawID, RawSHA256: raw2[0].RawSHA256, Stage: "decode", Reason: "retry", ReplayEligible: true, QuarantinedAt: time.Now().UTC()}
	if err := store2.Quarantine(ctx, entry); err != nil {
		t.Fatal(err)
	}
	norm := integrityTestEvent(entry.RawID, entry.RawSHA256, 0, "resolved")
	if err := store2.ResolveQuarantineWithOutbox(ctx, entry.QuarantineID, norm, []string{"sink"}); err != nil {
		t.Fatal(err)
	}
	resolved, err := store2.ListIntegrityEntries(ctx, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 4 || resolved[3].Kind != integrity.ReplayResolved || resolved[3].OperationID == "" {
		t.Fatalf("replay resolution not committed with evidence: %+v", resolved)
	}
	var qCount, normCount, outboxCount, operationCount int
	_ = store2.DB().QueryRow(`SELECT COUNT(*) FROM quarantine`).Scan(&qCount)
	_ = store2.DB().QueryRow(`SELECT COUNT(*) FROM normalized_events`).Scan(&normCount)
	_ = store2.DB().QueryRow(`SELECT COUNT(*) FROM outbox`).Scan(&outboxCount)
	_ = store2.DB().QueryRow(`SELECT COUNT(*) FROM integrity_operations WHERE state='completed'`).Scan(&operationCount)
	if qCount != 0 || normCount != 1 || outboxCount != 1 || operationCount != 1 {
		t.Fatalf("replay transaction incomplete q=%d normalized=%d outbox=%d operations=%d", qCount, normCount, outboxCount, operationCount)
	}
}

func TestReplayOperationReturnsCommittedResultAndRejectsDifferentTarget(t *testing.T) {
	ctx := context.Background()
	store := setupTestStore(t)
	enableTestIntegrity(t, store)
	if _, err := outbox.NewOutbox(store.DB()); err != nil {
		t.Fatal(err)
	}
	raw, err := store.Store(ctx, model.IngestedRecord{Transport: "test", RawBytes: []byte("retry-safe replay"), ReceivedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	q := model.QuarantineEntry{QuarantineID: "q-idempotent", RawID: raw.RawID, RawSHA256: raw.RawSHA256, Stage: "decode", Reason: "retry", ReplayEligible: true, QuarantinedAt: time.Now().UTC()}
	if err := store.Quarantine(ctx, q); err != nil {
		t.Fatal(err)
	}
	first, err := store.BeginReplay(ctx, q.QuarantineID, "stable-operation")
	if err != nil || first.State != "running" {
		t.Fatalf("claim replay: operation=%+v err=%v", first, err)
	}
	event := integrityTestEvent(raw.RawID, raw.RawSHA256, 0, "resolved once")
	if err := store.ResolveQuarantineWithOutboxOperation(ctx, q.QuarantineID, event, []string{"sink"}, first.ID); err != nil {
		t.Fatal(err)
	}
	wantResult, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := store.BeginReplay(ctx, q.QuarantineID, first.ID)
	if err != nil || retry.State != "completed" || !bytes.Equal(retry.ResultJSON, wantResult) {
		t.Fatalf("retry did not return committed result: operation=%+v err=%v", retry, err)
	}
	if _, err := store.BeginReplay(ctx, "another-target", first.ID); !errors.Is(err, ErrReplayOperationConflict) {
		t.Fatalf("same operation ID accepted another target: %v", err)
	}
	if _, err := store.BeginReplay(ctx, q.QuarantineID, "competing-operation"); !errors.Is(err, ErrReplayOperationConflict) {
		t.Fatalf("second operation claimed an already-resolved target: %v", err)
	}
	var normalized, outboxCount, resolved, operations int
	_ = store.DB().QueryRow(`SELECT COUNT(*) FROM normalized_events`).Scan(&normalized)
	_ = store.DB().QueryRow(`SELECT COUNT(*) FROM outbox`).Scan(&outboxCount)
	_ = store.DB().QueryRow(`SELECT COUNT(*) FROM integrity_entries WHERE entry_kind=?`, integrity.ReplayResolved).Scan(&resolved)
	_ = store.DB().QueryRow(`SELECT COUNT(*) FROM integrity_operations WHERE state='completed'`).Scan(&operations)
	if normalized != 1 || outboxCount != 1 || resolved != 1 || operations != 1 {
		t.Fatalf("replay retry duplicated side effects: normalized=%d outbox=%d resolved=%d operations=%d", normalized, outboxCount, resolved, operations)
	}
}

func TestReplayFailureOperationIsNotRetried(t *testing.T) {
	ctx := context.Background()
	store := setupTestStore(t)
	enableTestIntegrity(t, store)
	raw, err := store.Store(ctx, model.IngestedRecord{Transport: "test", RawBytes: []byte("failure replay"), ReceivedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	q := model.QuarantineEntry{QuarantineID: "q-failed-retry", RawID: raw.RawID, RawSHA256: raw.RawSHA256, Stage: "decode", Reason: "retry", ReplayEligible: true, QuarantinedAt: time.Now().UTC()}
	if err := store.Quarantine(ctx, q); err != nil {
		t.Fatal(err)
	}
	op, err := store.BeginReplay(ctx, q.QuarantineID, "failed-operation")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RecordReplayFailureWithOperation(ctx, op.Entry, errors.New("decode failed"), op.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.BeginReplay(ctx, q.QuarantineID, op.ID); !errors.Is(err, ErrReplayAlreadyFailed) {
		t.Fatalf("failed operation was attempted again: %v", err)
	}
	var failures, failedOps int
	_ = store.DB().QueryRow(`SELECT COUNT(*) FROM integrity_entries WHERE entry_kind=?`, integrity.ReplayFailed).Scan(&failures)
	_ = store.DB().QueryRow(`SELECT COUNT(*) FROM integrity_operations WHERE state='failed'`).Scan(&failedOps)
	if failures != 1 || failedOps != 1 {
		t.Fatalf("failed retry duplicated evidence: replay_failed=%d failed_operations=%d", failures, failedOps)
	}
}

func TestVerifyChecksCommittedRawMetadata(t *testing.T) {
	ctx := context.Background()
	store := setupTestStore(t)
	enableTestIntegrity(t, store)
	raw, err := store.Store(ctx, model.IngestedRecord{Transport: "file", SourceIP: "127.0.0.1", SourcePort: 514, RawBytes: []byte("metadata-bound"), ReceivedAt: time.Now().UTC(), Metadata: model.ReceiveMetadata{FileID: "file-a", FileOffset: 12}})
	if err != nil {
		t.Fatal(err)
	}
	if ok, _, err := store.Verify(ctx, raw.RawID); err != nil || !ok {
		t.Fatalf("untampered evidence failed verification: ok=%t err=%v", ok, err)
	}
	if _, err := store.DB().ExecContext(ctx, `UPDATE raw_events SET source_ip='127.0.0.2' WHERE raw_id=?`, raw.RawID); err != nil {
		t.Fatal(err)
	}
	if ok, _, err := store.Verify(ctx, raw.RawID); err != nil || ok {
		t.Fatalf("metadata tampering was not detected: ok=%t err=%v", ok, err)
	}
}

func TestIntegrityEvidenceFailureRollsBackNormalizedQuarantineAndOutbox(t *testing.T) {
	ctx := context.Background()
	store := setupTestStore(t)
	enableTestIntegrity(t, store)
	raw, err := store.Store(ctx, model.IngestedRecord{Transport: "test", RawBytes: []byte("payload"), ReceivedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := outbox.NewOutbox(store.DB()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().Exec(`CREATE TRIGGER fail_evidence BEFORE INSERT ON integrity_entries BEGIN SELECT RAISE(ABORT,'injected evidence failure'); END`); err != nil {
		t.Fatal(err)
	}
	event := integrityTestEvent(raw.RawID, raw.RawSHA256, 0, "message")
	if err := store.StoreNormalizedWithOutbox(ctx, event, []string{"sink"}); err == nil {
		t.Fatal("normalized write succeeded without evidence")
	}
	var normalized, outboxCount int
	_ = store.DB().QueryRow(`SELECT COUNT(*) FROM normalized_events`).Scan(&normalized)
	_ = store.DB().QueryRow(`SELECT COUNT(*) FROM outbox`).Scan(&outboxCount)
	if normalized != 0 || outboxCount != 0 {
		t.Fatalf("projection/outbox not rolled back: normalized=%d outbox=%d", normalized, outboxCount)
	}
	q := model.QuarantineEntry{QuarantineID: "q-rollback", RawID: raw.RawID, RawSHA256: raw.RawSHA256, Stage: "decode", Reason: "failure", QuarantinedAt: time.Now().UTC()}
	if err := store.Quarantine(ctx, q); err == nil {
		t.Fatal("quarantine write succeeded without evidence")
	}
	var quarantines int
	_ = store.DB().QueryRow(`SELECT COUNT(*) FROM quarantine`).Scan(&quarantines)
	if quarantines != 0 {
		t.Fatalf("quarantine projection not rolled back: %d", quarantines)
	}
}

func TestIntegrityReplayFailureIsJournaledAndResolutionRollsBackAtomically(t *testing.T) {
	ctx := context.Background()
	store := setupTestStore(t)
	enableTestIntegrity(t, store)
	raw, err := store.Store(ctx, model.IngestedRecord{Transport: "test", RawBytes: []byte("replay payload"), ReceivedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	q := model.QuarantineEntry{QuarantineID: "q-fail", RawID: raw.RawID, RawSHA256: raw.RawSHA256, Stage: "decode", Reason: "bad", ReplayEligible: true, QuarantinedAt: time.Now().UTC()}
	if err := store.Quarantine(ctx, q); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordReplayFailure(ctx, &q, errors.New("synthetic parser failure")); err != nil {
		t.Fatal(err)
	}
	entries, err := store.ListIntegrityEntries(ctx, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 || entries[2].Kind != integrity.ReplayFailed || entries[2].OperationID == "" {
		t.Fatalf("replay failure was not recorded: %+v", entries)
	}
	var failedOperations int
	if err := store.DB().QueryRow(`SELECT COUNT(*) FROM integrity_operations WHERE state='failed'`).Scan(&failedOperations); err != nil || failedOperations != 1 {
		t.Fatalf("failed replay operation not recorded: count=%d err=%v", failedOperations, err)
	}
	if _, err := outbox.NewOutbox(store.DB()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().Exec(`CREATE TRIGGER fail_resolution BEFORE INSERT ON integrity_entries WHEN NEW.entry_kind=5 BEGIN SELECT RAISE(ABORT,'injected resolution failure'); END`); err != nil {
		t.Fatal(err)
	}
	event := integrityTestEvent(raw.RawID, raw.RawSHA256, 0, "replayed")
	if err := store.ResolveQuarantineWithOutbox(ctx, q.QuarantineID, event, []string{"sink"}); err == nil {
		t.Fatal("replay resolution succeeded without resolution evidence")
	}
	var qCount, normCount, outboxCount int
	_ = store.DB().QueryRow(`SELECT COUNT(*) FROM quarantine`).Scan(&qCount)
	_ = store.DB().QueryRow(`SELECT COUNT(*) FROM normalized_events`).Scan(&normCount)
	_ = store.DB().QueryRow(`SELECT COUNT(*) FROM outbox`).Scan(&outboxCount)
	if qCount != 1 || normCount != 0 || outboxCount != 0 {
		t.Fatalf("failed replay resolution left partial data q=%d normalized=%d outbox=%d", qCount, normCount, outboxCount)
	}
}

func TestSchemaV4MigrationRejectsDuplicateChildrenAndRollsBackDDL(t *testing.T) {
	ctx := context.Background()
	t.Run("additive migration preserves data", func(t *testing.T) {
		store := setupTestStore(t)
		raw, err := store.Store(ctx, model.IngestedRecord{Transport: "test", RawBytes: []byte("preserve"), ReceivedAt: time.Now().UTC()})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.DB().Exec(`DROP TABLE integrity_findings; DROP TABLE integrity_audit_runs; DROP TABLE integrity_operations; DROP TABLE integrity_witness_sync; DROP TABLE integrity_batch_entries; DROP TABLE integrity_batches; DROP TABLE integrity_entries; DROP TABLE integrity_streams; PRAGMA user_version=4`); err != nil {
			t.Fatal(err)
		}
		if err := initSchema(store.DB()); err != nil {
			t.Fatalf("v4 to v6 migration: %v", err)
		}
		var version int
		if err := store.DB().QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != CurrentSchemaVersion {
			t.Fatalf("migrated user_version=%d err=%v", version, err)
		}
		if _, err := store.Retrieve(ctx, raw.RawID); err != nil {
			t.Fatalf("migration lost preexisting raw data: %v", err)
		}
	})
	t.Run("duplicate normalized child", func(t *testing.T) {
		store := setupTestStore(t)
		raw, err := store.Store(ctx, model.IngestedRecord{Transport: "test", RawBytes: []byte("x"), ReceivedAt: time.Now().UTC()})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.DB().Exec(`DROP INDEX idx_normalized_child; PRAGMA user_version=4`); err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{"first", "second"} {
			_, err := store.DB().Exec(`INSERT INTO normalized_events(event_id,raw_id,record_ordinal,source_category,source_id,event_time,received_time,event_json,event_sha256) VALUES(?,?,0,'test','test',0,'now','{}','')`, id, raw.RawID)
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := initSchema(store.DB()); err == nil {
			t.Fatal("migration accepted duplicate child identities")
		}
		var version int
		_ = store.DB().QueryRow(`PRAGMA user_version`).Scan(&version)
		if version != 4 {
			t.Fatalf("failed migration changed version to %d", version)
		}
	})
	t.Run("partial DDL rollback", func(t *testing.T) {
		store := setupTestStore(t)
		if _, err := store.DB().Exec(`DROP INDEX idx_normalized_child; DROP TABLE integrity_findings; DROP TABLE integrity_audit_runs; DROP TABLE integrity_operations; DROP TABLE integrity_witness_sync; DROP TABLE integrity_batch_entries; DROP TABLE integrity_batches; DROP TABLE integrity_entries; DROP TABLE integrity_streams; PRAGMA user_version=4; CREATE VIEW integrity_streams AS SELECT 1 AS singleton`); err != nil {
			t.Fatal(err)
		}
		if err := initSchema(store.DB()); err == nil {
			t.Fatal("migration unexpectedly accepted conflicting schema object")
		}
		var version, indexCount int
		_ = store.DB().QueryRow(`PRAGMA user_version`).Scan(&version)
		_ = store.DB().QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_normalized_child'`).Scan(&indexCount)
		if version != 4 || indexCount != 0 {
			t.Fatalf("migration did not roll back version/index: version=%d index=%d", version, indexCount)
		}
	})
}

func integrityTestEvent(rawID, rawHash string, ordinal int, message string) *model.NormalizedEvent {
	var parserHash [32]byte
	parserHash[0] = 9
	return &model.NormalizedEvent{Raven: model.RavenEnvelope{EventID: "event-" + rawID, RawID: rawID, RawSHA256: rawHash, RecordOrdinal: ordinal, ParserPack: "test-pack", ParserVersion: "1.0.0", ParserFileSHA256: parserHash, CoreVersion: "test", SchemaVersion: "1.3.0", ReceivedTime: time.Now().UTC(), Status: "normalized"}, OCSF: map[string]any{"message": message, "time": int64(1)}}
}

func TestStoreAndRetrieveLossless(t *testing.T) {
	store := setupTestStore(t)
	ctx := context.Background()
	var synchronous int
	if err := store.DB().QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous); err != nil || synchronous != 2 {
		t.Fatalf("expected SQLite synchronous=FULL (2), got %d (err=%v)", synchronous, err)
	}

	originalBytes := []byte("<14>1 2026-09-20T10:05:23+05:30 pa-fw-01 paloalto - TRAFFIC - vendor_product=PAN-OS action=allow")
	rec := model.IngestedRecord{
		Transport:  "syslog_udp",
		SourceIP:   "10.0.1.50",
		SourcePort: 514,
		RawBytes:   originalBytes,
		ReceivedAt: time.Now().UTC(),
	}

	saved, err := store.Store(ctx, rec)
	if err != nil {
		t.Fatalf("store.Store failed: %v", err)
	}

	if saved.RawID == "" {
		t.Errorf("expected non-empty RawID")
	}
	if saved.ByteCount != len(originalBytes) {
		t.Errorf("expected ByteCount %d, got %d", len(originalBytes), saved.ByteCount)
	}

	retrieved, err := store.Retrieve(ctx, saved.RawID)
	if err != nil {
		t.Fatalf("store.Retrieve failed: %v", err)
	}

	if !bytes.Equal(retrieved.Payload, originalBytes) {
		t.Fatalf("byte mismatch! retrieved: %q, expected: %q", retrieved.Payload, originalBytes)
	}
	if retrieved.RawSHA256 != saved.RawSHA256 {
		t.Errorf("SHA-256 mismatch: got %s, expected %s", retrieved.RawSHA256, saved.RawSHA256)
	}
	if retrieved.Status != model.StatusAccepted {
		t.Errorf("expected status %s, got %s", model.StatusAccepted, retrieved.Status)
	}
}

func TestListRawByStatusDoesNotDeadlockSingleConnection(t *testing.T) {
	store := setupTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	saved, err := store.Store(ctx, model.IngestedRecord{Transport: "test", RawBytes: []byte(`{"event":"restart"}`), ReceivedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	events, err := store.ListRawByStatus(ctx, model.StatusAccepted)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].RawID != saved.RawID {
		t.Fatalf("unexpected accepted recovery set: %+v", events)
	}
}

func TestVerifyIntegrityAndTamperDetection(t *testing.T) {
	store := setupTestStore(t)
	ctx := context.Background()

	payload := []byte(`{"event": "payment_processed", "amount": 100.50, "currency": "INR"}`)
	rec := model.IngestedRecord{
		Transport:  "http_post",
		SourceIP:   "192.168.1.100",
		RawBytes:   payload,
		ReceivedAt: time.Now().UTC(),
	}

	saved, err := store.Store(ctx, rec)
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	// 1. Verify clean record
	valid, computedHash, err := store.Verify(ctx, saved.RawID)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !valid {
		t.Errorf("expected valid=true for untampered record")
	}
	if computedHash != saved.RawSHA256 {
		t.Errorf("hash mismatch: %s != %s", computedHash, saved.RawSHA256)
	}

	// 2. Tamper record directly in database
	tamperedPayload := []byte(`{"event": "payment_processed", "amount": 999999.00, "currency": "INR"}`)
	_, err = store.db.Exec("UPDATE raw_events SET payload = ? WHERE raw_id = ?", tamperedPayload, saved.RawID)
	if err != nil {
		t.Fatalf("direct DB tamper failed: %v", err)
	}

	// 3. Verify tampered record should fail!
	valid, tamperedHash, err := store.Verify(ctx, saved.RawID)
	if err != nil {
		t.Fatalf("Verify after tamper failed: %v", err)
	}
	if valid {
		t.Errorf("expected valid=false after tampering, but got true!")
	}
	if tamperedHash == saved.RawSHA256 {
		t.Errorf("expected tampered hash %s to differ from original %s", tamperedHash, saved.RawSHA256)
	}
}

func TestQuarantineAndReplayStatus(t *testing.T) {
	store := setupTestStore(t)
	ctx := context.Background()

	garbage := []byte("INVALID_GARBAGE_LINE_THAT_IS_NOT_A_LOG")
	rec := model.IngestedRecord{
		Transport:  "file_spool",
		SourceIP:   "local",
		RawBytes:   garbage,
		ReceivedAt: time.Now().UTC(),
	}

	saved, err := store.Store(ctx, rec)
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	qEntry := model.QuarantineEntry{
		RawID:          saved.RawID,
		RawSHA256:      saved.RawSHA256,
		Stage:          "format_detect",
		Reason:         "parse_error",
		ErrorDetails:   "unrecognized wire format",
		RawPreview:     string(garbage),
		CandidatePacks: []string{"server-webaccess", "network-device-firewall"},
		ReplayEligible: true,
	}

	if err := store.Quarantine(ctx, qEntry); err != nil {
		t.Fatalf("Quarantine failed: %v", err)
	}
	// Recovery may reprocess the same accepted parent after a crash. The child
	// lifecycle row must be updated, not duplicated.
	qEntry.ErrorDetails = "same child retried after restart"
	if err := store.Quarantine(ctx, qEntry); err != nil {
		t.Fatalf("idempotent Quarantine failed: %v", err)
	}

	// Check raw event status updated
	raw, err := store.Retrieve(ctx, saved.RawID)
	if err != nil {
		t.Fatalf("Retrieve failed: %v", err)
	}
	if raw.Status != model.StatusQuarantined {
		t.Errorf("expected raw status %s, got %s", model.StatusQuarantined, raw.Status)
	}

	// Check quarantine query
	entries, err := store.GetQuarantined(ctx, 10, 0)
	if err != nil {
		t.Fatalf("GetQuarantined failed: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 quarantine entry, got %d", len(entries))
	}
	if entries[0].RawID != saved.RawID {
		t.Errorf("expected quarantine RawID %s, got %s", saved.RawID, entries[0].RawID)
	}
	if len(entries[0].CandidatePacks) != 2 {
		t.Errorf("expected 2 candidate packs, got %d", len(entries[0].CandidatePacks))
	}
}

func TestVerifyNormalized_TamperDetection(t *testing.T) {
	store := setupTestStore(t)
	ctx := context.Background()

	// 1. Commit raw event
	raw, err := store.Store(ctx, model.IngestedRecord{
		Transport:  "syslog_udp",
		SourceIP:   "10.0.1.50",
		RawBytes:   []byte("<14>Sep 19 10:00:00 fw01: connection allowed"),
		ReceivedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("Store raw failed: %v", err)
	}

	// 2. Commit normalized event
	evt := &model.NormalizedEvent{
		Raven: model.RavenEnvelope{
			EventID:        "raven-evt-test-999",
			RawID:          raw.RawID,
			RawSHA256:      raw.RawSHA256,
			SourceCategory: "network_device",
			SourceID:       "fw01",
			ReceivedTime:   time.Now().UTC(),
			Status:         "normalized",
		},
		OCSF: map[string]any{
			"activity_name": "Traffic",
			"severity_id":   1,
			"message":       "connection allowed",
		},
	}

	if err := store.StoreNormalized(ctx, evt); err != nil {
		t.Fatalf("StoreNormalized failed: %v", err)
	}

	// 3. Verify clean event -> MUST PASS
	rep, err := store.VerifyNormalized(ctx, "raven-evt-test-999")
	if err != nil {
		t.Fatalf("VerifyNormalized error: %v", err)
	}
	if !rep.Passed || rep.Status != "PASSED" {
		t.Fatalf("expected clean event to PASS, got %+v", rep)
	}

	// 4. Tamper 1: Modify message column (e.g. user adding 'hello' in SQLite Web GUI)
	_, err = store.db.Exec("UPDATE normalized_events SET message = 'connection allowed hello' WHERE event_id = 'raven-evt-test-999';")
	if err != nil {
		t.Fatalf("failed to tamper message column: %v", err)
	}

	repTamperedMsg, err := store.VerifyNormalized(ctx, "raven-evt-test-999")
	if err != nil {
		t.Fatalf("VerifyNormalized after tamper error: %v", err)
	}
	if repTamperedMsg.Passed || repTamperedMsg.Status != "TAMPER DETECTED" {
		t.Fatalf("expected message tamper to be DETECTED, but got Passed=true!")
	}
	t.Logf("Message tamper detected as expected: %s", repTamperedMsg.FailureReason)

	// Revert message column
	_, _ = store.db.Exec("UPDATE normalized_events SET message = 'connection allowed' WHERE event_id = 'raven-evt-test-999';")

	// 5. Tamper 2: Modify event_json column
	_, err = store.db.Exec("UPDATE normalized_events SET event_json = replace(event_json, 'connection allowed', 'connection denied') WHERE event_id = 'raven-evt-test-999';")
	if err != nil {
		t.Fatalf("failed to tamper event_json column: %v", err)
	}

	repTamperedJSON, err := store.VerifyNormalized(ctx, "raven-evt-test-999")
	if err != nil {
		t.Fatalf("VerifyNormalized after JSON tamper error: %v", err)
	}
	if repTamperedJSON.Passed || repTamperedJSON.Status != "TAMPER DETECTED" {
		t.Fatalf("expected JSON tamper to be DETECTED, but got Passed=true!")
	}
	t.Logf("JSON tamper detected as expected: %s", repTamperedJSON.FailureReason)
}

func TestSchemaUserVersion(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "version_test.db")

	// First initialization: should execute schema v1 and set user_version = 1
	store1, err := New(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	var version1 int
	if err := store1.db.QueryRow("PRAGMA user_version;").Scan(&version1); err != nil {
		t.Fatalf("failed to query user_version: %v", err)
	}
	if version1 != CurrentSchemaVersion {
		t.Fatalf("expected user_version=%d, got %d", CurrentSchemaVersion, version1)
	}
	_ = store1.Close()

	// Second initialization: should read user_version = 1 and skip DDL execution
	store2, err := New(dbPath)
	if err != nil {
		t.Fatalf("failed to reopen store: %v", err)
	}
	defer store2.Close()

	var version2 int
	if err := store2.db.QueryRow("PRAGMA user_version;").Scan(&version2); err != nil {
		t.Fatalf("failed to query user_version on reopened store: %v", err)
	}
	if version2 != CurrentSchemaVersion {
		t.Fatalf("expected user_version=%d on reopen, got %d", CurrentSchemaVersion, version2)
	}
}

func TestDeleteQuarantineAndCounts(t *testing.T) {
	store := setupTestStore(t)
	ctx := context.Background()

	// Initial counts should be 0
	rawCount, _ := store.CountRaw(ctx)
	normCount, _ := store.CountNormalized(ctx)
	quarCount, _ := store.CountQuarantine(ctx)
	if rawCount != 0 || normCount != 0 || quarCount != 0 {
		t.Fatalf("expected all counts to be 0, got raw=%d norm=%d quar=%d", rawCount, normCount, quarCount)
	}

	// 1. Store a raw event
	rec := model.IngestedRecord{
		Transport: "syslog_udp",
		SourceIP:  "127.0.0.1",
		RawBytes:  []byte("<14>test"),
	}
	savedRaw, err := store.Store(ctx, rec)
	if err != nil {
		t.Fatalf("store failed: %v", err)
	}

	rawCount, _ = store.CountRaw(ctx)
	if rawCount != 1 {
		t.Fatalf("expected rawCount 1, got %d", rawCount)
	}

	// 2. Quarantine it
	qEntry := model.QuarantineEntry{
		QuarantineID:   "quar-del-test",
		RawID:          savedRaw.RawID,
		RawSHA256:      savedRaw.RawSHA256,
		Stage:          "parser_match",
		Reason:         "unknown_source",
		RawPreview:     "<14>test",
		ReplayEligible: true,
		QuarantinedAt:  time.Now().UTC(),
	}
	if err := store.Quarantine(ctx, qEntry); err != nil {
		t.Fatalf("quarantine failed: %v", err)
	}

	quarCount, _ = store.CountQuarantine(ctx)
	if quarCount != 1 {
		t.Fatalf("expected quarCount 1, got %d", quarCount)
	}

	// 3. Delete from quarantine
	if err := store.DeleteQuarantine(ctx, "quar-del-test"); err != nil {
		t.Fatalf("delete quarantine failed: %v", err)
	}

	quarCount, _ = store.CountQuarantine(ctx)
	if quarCount != 0 {
		t.Fatalf("expected quarCount 0 after deletion, got %d", quarCount)
	}
}

func TestBatchChildrenAndSourcePort(t *testing.T) {
	store := setupTestStore(t)
	ctx := context.Background()

	rec := model.IngestedRecord{
		Transport:  "syslog_tcp",
		SourceIP:   "10.0.0.1",
		SourcePort: 5140,
		RawBytes:   []byte("batch payload line 1\nbatch payload line 2"),
		ReceivedAt: time.Now().UTC(),
	}
	rawEvt, err := store.Store(ctx, rec)
	if err != nil {
		t.Fatalf("store failed: %v", err)
	}

	retrieved, err := store.Retrieve(ctx, rawEvt.RawID)
	if err != nil {
		t.Fatalf("retrieve failed: %v", err)
	}
	if retrieved.SourcePort != 5140 {
		t.Errorf("expected SourcePort 5140, got %d", retrieved.SourcePort)
	}

	// Store child 0
	evt0 := &model.NormalizedEvent{
		Raven: model.RavenEnvelope{
			EventID:        "evt-child-0",
			RawID:          rawEvt.RawID,
			RecordOrdinal:  0,
			SourceCategory: "server",
			SourceID:       "srv1",
			ReceivedTime:   time.Now().UTC(),
		},
		OCSF: map[string]any{
			"time":    time.Now().UnixMilli(),
			"message": "child zero",
		},
	}
	if err := store.StoreNormalized(ctx, evt0); err != nil {
		t.Fatalf("StoreNormalized child 0 failed: %v", err)
	}

	// Store child 1
	evt1 := &model.NormalizedEvent{
		Raven: model.RavenEnvelope{
			EventID:        "evt-child-1",
			RawID:          rawEvt.RawID,
			RecordOrdinal:  1,
			SourceCategory: "server",
			SourceID:       "srv1",
			ReceivedTime:   time.Now().UTC(),
		},
		OCSF: map[string]any{
			"time":    time.Now().UnixMilli(),
			"message": "child one",
		},
	}
	if err := store.StoreNormalized(ctx, evt1); err != nil {
		t.Fatalf("StoreNormalized child 1 failed: %v", err)
	}

	// Both child records must exist
	count, err := store.CountNormalized(ctx)
	if err != nil {
		t.Fatalf("CountNormalized failed: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 normalized child records, got %d", count)
	}

	// Quarantine child 2
	qEntry := model.QuarantineEntry{
		QuarantineID:  "quar-child-2",
		RawID:         rawEvt.RawID,
		RecordOrdinal: 2,
		RawSHA256:     rawEvt.RawSHA256,
		Stage:         "parser_match",
		Reason:        "unknown_source",
		RawPreview:    "child two preview",
	}
	if err := store.Quarantine(ctx, qEntry); err != nil {
		t.Fatalf("Quarantine failed: %v", err)
	}

	gotQ, err := store.GetQuarantineByID(ctx, "quar-child-2")
	if err != nil {
		t.Fatalf("GetQuarantineByID failed: %v", err)
	}
	if gotQ.RecordOrdinal != 2 {
		t.Errorf("expected RecordOrdinal 2, got %d", gotQ.RecordOrdinal)
	}
}

func TestStoreDeduplicatesRecoveredFileSpoolCoordinates(t *testing.T) {
	store := setupTestStore(t)
	ctx := context.Background()
	rec := model.IngestedRecord{Transport: "file", RawBytes: []byte("line one"), Metadata: model.ReceiveMetadata{FileID: "file-fingerprint", FileOffset: 0}}
	first, err := store.Store(ctx, rec)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Store(ctx, rec)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Duplicate || second.RawID != first.RawID {
		t.Fatalf("expected duplicate existing row, first=%+v second=%+v", first, second)
	}
	count, err := store.CountRaw(ctx)
	if err != nil || count != 1 {
		t.Fatalf("expected one raw row, got %d (err=%v)", count, err)
	}
	rec.RawBytes = []byte("changed bytes")
	if _, err := store.Store(ctx, rec); err == nil {
		t.Fatal("expected changed bytes at an existing file coordinate to be rejected")
	}
}

func TestMigrateLegacySchemaTransactionallyAndIdempotently(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "legacy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	legacy := `
CREATE TABLE raw_events(raw_id TEXT PRIMARY KEY, raw_sha256 TEXT NOT NULL, byte_count INTEGER NOT NULL, transport TEXT NOT NULL, source_ip TEXT NOT NULL, received_at TEXT NOT NULL, payload BLOB NOT NULL, status TEXT NOT NULL);
CREATE TABLE quarantine(quarantine_id TEXT PRIMARY KEY, raw_id TEXT NOT NULL, raw_sha256 TEXT NOT NULL, stage TEXT NOT NULL, reason TEXT NOT NULL, error_details TEXT, raw_preview TEXT NOT NULL, candidate_packs TEXT, replay_eligible INTEGER NOT NULL, quarantined_at TEXT NOT NULL, replayed_at TEXT);
CREATE TABLE normalized_events(event_id TEXT PRIMARY KEY, raw_id TEXT NOT NULL, source_category TEXT NOT NULL, source_id TEXT NOT NULL, severity_id TEXT, activity_name TEXT, message TEXT, event_time INTEGER NOT NULL, received_time TEXT NOT NULL, event_json TEXT NOT NULL, event_sha256 TEXT NOT NULL DEFAULT '');
PRAGMA user_version=1;`
	if _, err := db.Exec(legacy); err != nil {
		t.Fatal(err)
	}
	if err := initSchema(db); err != nil {
		t.Fatalf("migrate legacy schema: %v", err)
	}
	if err := initSchema(db); err != nil {
		t.Fatalf("repeat migration: %v", err)
	}
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != CurrentSchemaVersion {
		t.Fatalf("user_version=%d err=%v", version, err)
	}
	for _, col := range []string{"source_port", "metadata_json"} {
		var count int
		if err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('raw_events') WHERE name=?", col).Scan(&count); err != nil || count != 1 {
			t.Fatalf("expected raw_events.%s after migration, count=%d err=%v", col, count, err)
		}
	}
}

func TestMigrationFailureDoesNotAdvanceOrPartiallyApply(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "broken-legacy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	legacy := `
CREATE TABLE raw_events(raw_id TEXT PRIMARY KEY, raw_sha256 TEXT NOT NULL, byte_count INTEGER NOT NULL, transport TEXT NOT NULL, source_ip TEXT NOT NULL, source_port INTEGER NOT NULL DEFAULT 0, received_at TEXT NOT NULL, payload BLOB NOT NULL, status TEXT NOT NULL);
CREATE TABLE quarantine(quarantine_id TEXT PRIMARY KEY, raw_id TEXT NOT NULL, record_ordinal INTEGER NOT NULL DEFAULT 0, raw_sha256 TEXT NOT NULL, stage TEXT NOT NULL, reason TEXT NOT NULL, error_details TEXT, raw_preview TEXT NOT NULL, candidate_packs TEXT, replay_eligible INTEGER NOT NULL, quarantined_at TEXT NOT NULL, replayed_at TEXT);
CREATE TABLE normalized_events(event_id TEXT PRIMARY KEY, raw_id TEXT NOT NULL, source_category TEXT NOT NULL, source_id TEXT NOT NULL, severity_id TEXT, activity_name TEXT, message TEXT, event_time INTEGER NOT NULL, received_time TEXT NOT NULL, event_json TEXT NOT NULL, event_sha256 TEXT NOT NULL DEFAULT '');
PRAGMA user_version=1;`
	if _, err := db.Exec(legacy); err != nil {
		t.Fatal(err)
	}
	if err := initSchema(db); err == nil {
		t.Fatal("expected migration to fail on inconsistent v1 schema")
	}
	var version, sourcePortCount int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('raw_events') WHERE name='source_port'").Scan(&sourcePortCount); err != nil {
		t.Fatal(err)
	}
	if version != 1 || sourcePortCount != 1 {
		t.Fatalf("failed migration changed schema/version unexpectedly: version=%d source_port_count=%d", version, sourcePortCount)
	}
}

func TestReplayUpdatesNormalizedProjectionColumns(t *testing.T) {
	store := setupTestStore(t)
	ctx := context.Background()
	raw, err := store.Store(ctx, model.IngestedRecord{Transport: "test", RawBytes: []byte("raw")})
	if err != nil {
		t.Fatal(err)
	}
	event := &model.NormalizedEvent{Raven: model.RavenEnvelope{EventID: "event-old", RawID: raw.RawID, RecordOrdinal: 0, SourceCategory: "old-category", SourceID: "old-source", ReceivedTime: time.Unix(1, 0).UTC()}, OCSF: map[string]any{"time": int64(1000), "severity_id": 1, "activity_name": "old-activity", "message": "old-message"}}
	if err := store.StoreNormalized(ctx, event); err != nil {
		t.Fatal(err)
	}
	event.Raven.SourceCategory = "new-category"
	event.Raven.SourceID = "new-source"
	event.Raven.ReceivedTime = time.Unix(2, 0).UTC()
	event.OCSF = map[string]any{"time": int64(2000), "severity_id": 5, "activity_name": "new-activity", "message": "new-message"}
	if err := store.StoreNormalized(ctx, event); err != nil {
		t.Fatal(err)
	}
	var category, sourceID, severity, activity, message, received string
	var eventTime int64
	err = store.db.QueryRow(`SELECT source_category,source_id,severity_id,activity_name,message,event_time,received_time
		FROM normalized_events WHERE raw_id=? AND record_ordinal=0`, raw.RawID).Scan(&category, &sourceID, &severity, &activity, &message, &eventTime, &received)
	if err != nil {
		t.Fatal(err)
	}
	if category != "new-category" || sourceID != "new-source" || severity != "5" || activity != "new-activity" || message != "new-message" || eventTime != 2000 || received != event.Raven.ReceivedTime.Format(time.RFC3339Nano) {
		t.Fatalf("replay projection columns are stale: category=%q source=%q severity=%q activity=%q message=%q time=%d received=%q", category, sourceID, severity, activity, message, eventTime, received)
	}
}

func TestVerifyNormalizedAcceptsDecodedEscapedMessage(t *testing.T) {
	store := setupTestStore(t)
	ctx := context.Background()
	raw, err := store.Store(ctx, model.IngestedRecord{Transport: "test", RawBytes: []byte(`{"message":"hello\nworld"}`)})
	if err != nil {
		t.Fatal(err)
	}
	event := &model.NormalizedEvent{
		Raven: model.RavenEnvelope{EventID: "escaped-message", RawID: raw.RawID, RawSHA256: raw.RawSHA256, ReceivedTime: time.Now().UTC()},
		OCSF:  map[string]any{"message": "hello\nworld"},
	}
	if err := store.StoreNormalized(ctx, event); err != nil {
		t.Fatal(err)
	}
	report, err := store.VerifyNormalized(ctx, event.Raven.EventID)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatalf("untampered escaped message failed verification: %+v", report)
	}
}

func TestResolveQuarantineWithOutboxIsAtomicAndPreservesSiblingStatus(t *testing.T) {
	store := setupTestStore(t)
	if _, err := outbox.NewOutbox(store.DB()); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	raw, err := store.Store(ctx, model.IngestedRecord{Transport: "test", RawBytes: []byte(`[1,2]`)})
	if err != nil {
		t.Fatal(err)
	}
	for ordinal := 0; ordinal < 2; ordinal++ {
		if err := store.Quarantine(ctx, model.QuarantineEntry{QuarantineID: fmt.Sprintf("q-%d", ordinal), RawID: raw.RawID, RecordOrdinal: ordinal, RawSHA256: raw.RawSHA256, Stage: "test", Reason: "unknown_source", ReplayEligible: true}); err != nil {
			t.Fatal(err)
		}
	}
	event := &model.NormalizedEvent{Raven: model.RavenEnvelope{EventID: "resolved-child", RawID: raw.RawID, RecordOrdinal: 0, ReceivedTime: time.Now().UTC()}, OCSF: map[string]any{"message": "first"}}
	if _, err := store.DB().Exec(`CREATE TRIGGER fail_quarantine_delete BEFORE DELETE ON quarantine BEGIN SELECT RAISE(FAIL, 'injected delete failure'); END;`); err != nil {
		t.Fatal(err)
	}
	if err := store.ResolveQuarantineWithOutbox(ctx, "q-0", event, []string{"sink"}); err == nil {
		t.Fatal("expected injected quarantine deletion error")
	}
	if count, _ := store.CountNormalized(ctx); count != 0 {
		t.Fatalf("normalized rows after rolled-back replay = %d", count)
	}
	if count, _ := store.CountQuarantine(ctx); count != 2 {
		t.Fatalf("quarantine rows after rolled-back replay = %d", count)
	}
	_, _ = store.DB().Exec(`DROP TRIGGER fail_quarantine_delete`)
	if err := store.ResolveQuarantineWithOutbox(ctx, "q-0", event, []string{"sink"}); err != nil {
		t.Fatal(err)
	}
	if count, _ := store.CountNormalized(ctx); count != 1 {
		t.Fatalf("normalized rows after successful replay = %d", count)
	}
	if count, _ := store.CountQuarantine(ctx); count != 1 {
		t.Fatalf("remaining sibling quarantine rows = %d", count)
	}
	parent, err := store.Retrieve(ctx, raw.RawID)
	if err != nil || parent.Status != model.StatusPartial {
		t.Fatalf("parent status = %q, err=%v; want partial", parent.Status, err)
	}
}
