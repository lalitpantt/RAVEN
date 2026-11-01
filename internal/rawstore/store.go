package rawstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"raven/internal/integrity"
	"raven/internal/model"

	_ "modernc.org/sqlite"
)

// RawStore provides durable, cryptographically verified storage for raw byte streams.
type RawStore struct {
	db              *sql.DB
	auditDB         *sql.DB
	dbPath          string
	writeMu         sync.Mutex
	sealMu          sync.Mutex
	sealCancel      context.CancelFunc
	sealWG          sync.WaitGroup
	witnessMu       sync.Mutex
	witnessStop     context.CancelFunc
	witnessWG       sync.WaitGroup
	auditMu         sync.Mutex
	auditCancel     context.CancelFunc
	auditWG         sync.WaitGroup
	counter         atomic.Uint64
	analysisEnabled atomic.Bool
}

// New opens an SQLite database, creates required tables and enables WAL mode.
func New(dbPath string) (*RawStore, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open raw store sqlite db: %w", err)
	}

	// Single connection serialization for SQLite concurrency safety
	db.SetMaxOpenConns(1)

	// Set pragmas for crash resilience and concurrency
	pragmas := []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA synchronous=FULL;",
		"PRAGMA busy_timeout=5000;",
		"PRAGMA foreign_keys=ON;",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to set pragma %q: %w", p, err)
		}
	}

	if err := initSchema(db); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(`UPDATE integrity_audit_runs SET result='incomplete',completed_at=?,error_class='process_interrupted' WHERE completed_at IS NULL`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		db.Close()
		return nil, fmt.Errorf("recover interrupted integrity audits: %w", err)
	}

	store := &RawStore{db: db, dbPath: dbPath}
	enabled, err := store.IntegrityEnabled(context.Background())
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("read integrity stream state: %w", err)
	}
	if enabled && !strings.Contains(dbPath, ":memory:") {
		store.auditDB, err = openReadOnlyDB(dbPath)
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("open bounded integrity audit reader: %w", err)
		}
	}
	if enabled {
		store.startIntegritySealer()
	}
	return store, nil
}

// CurrentSchemaVersion tracks the active database schema migration version.
const CurrentSchemaVersion = 14

func initSchema(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin schema migration: %w", err)
	}
	defer tx.Rollback()
	if err := migrateSchema(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func migrateSchema(db sqlExecutor) error {
	var version int
	if err := db.QueryRow("PRAGMA user_version;").Scan(&version); err != nil {
		return fmt.Errorf("failed to read user_version: %w", err)
	}
	if version > CurrentSchemaVersion {
		return fmt.Errorf("database schema version %d is newer than supported version %d", version, CurrentSchemaVersion)
	}

	if version < 1 {
		schema := `
		CREATE TABLE IF NOT EXISTS raw_events (
			raw_id TEXT PRIMARY KEY,
			raw_sha256 TEXT NOT NULL,
			byte_count INTEGER NOT NULL,
			transport TEXT NOT NULL,
			source_ip TEXT NOT NULL,
			source_port INTEGER NOT NULL DEFAULT 0,
			received_at TEXT NOT NULL,
			payload BLOB NOT NULL,
			status TEXT NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_raw_events_sha ON raw_events(raw_sha256);
		CREATE INDEX IF NOT EXISTS idx_raw_events_status ON raw_events(status);

		CREATE TABLE IF NOT EXISTS quarantine (
			quarantine_id TEXT PRIMARY KEY,
			raw_id TEXT NOT NULL,
			record_ordinal INTEGER NOT NULL DEFAULT 0,
			raw_sha256 TEXT NOT NULL,
			stage TEXT NOT NULL,
			reason TEXT NOT NULL,
			error_details TEXT,
			raw_preview TEXT NOT NULL,
			candidate_packs TEXT,
			replay_eligible INTEGER NOT NULL,
			quarantined_at TEXT NOT NULL,
			replayed_at TEXT,
			FOREIGN KEY (raw_id) REFERENCES raw_events(raw_id)
		);
		CREATE INDEX IF NOT EXISTS idx_quarantine_raw ON quarantine(raw_id);
		CREATE INDEX IF NOT EXISTS idx_quarantine_reason ON quarantine(reason);

		CREATE TABLE IF NOT EXISTS normalized_events (
			event_id TEXT PRIMARY KEY,
			raw_id TEXT NOT NULL,
			record_ordinal INTEGER NOT NULL DEFAULT 0,
			source_category TEXT NOT NULL,
			source_id TEXT NOT NULL,
			severity_id TEXT,
			activity_name TEXT,
			message TEXT,
			event_time INTEGER NOT NULL,
			received_time TEXT NOT NULL,
			event_json TEXT NOT NULL,
			event_sha256 TEXT NOT NULL DEFAULT '',
			FOREIGN KEY (raw_id) REFERENCES raw_events(raw_id)
		);
		CREATE INDEX IF NOT EXISTS idx_norm_cat ON normalized_events(source_category);
		CREATE INDEX IF NOT EXISTS idx_norm_time ON normalized_events(event_time);
		`
		if _, err := db.Exec(schema); err != nil {
			return fmt.Errorf("failed to initialize raw store schema v2: %w", err)
		}
		version = 2
	}

	if version < 2 {
		migrations := []string{
			"ALTER TABLE raw_events ADD COLUMN source_port INTEGER NOT NULL DEFAULT 0;",
			"ALTER TABLE quarantine ADD COLUMN record_ordinal INTEGER NOT NULL DEFAULT 0;",
			"ALTER TABLE normalized_events ADD COLUMN record_ordinal INTEGER NOT NULL DEFAULT 0;",
		}
		for _, m := range migrations {
			if _, err := db.Exec(m); err != nil {
				return fmt.Errorf("failed to apply schema migration %q: %w", m, err)
			}
		}
		version = 2
	}

	if version < 3 {
		if _, err := db.Exec("ALTER TABLE raw_events ADD COLUMN metadata_json TEXT NOT NULL DEFAULT '{}';"); err != nil {
			return fmt.Errorf("failed to add raw event metadata column: %w", err)
		}
		version = 3
	}

	if version < 4 {
		// A process can restart after a child was quarantined but before its parent
		// raw status was finalized. Keep that recovery replay idempotent.
		if _, err := db.Exec(`DELETE FROM quarantine WHERE rowid NOT IN (
			SELECT MIN(rowid) FROM quarantine GROUP BY raw_id, record_ordinal, stage, reason
		);`); err != nil {
			return fmt.Errorf("failed to deduplicate quarantine rows: %w", err)
		}
		if _, err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_quarantine_child
			ON quarantine(raw_id, record_ordinal, stage, reason);`); err != nil {
			return fmt.Errorf("failed to create quarantine child index: %w", err)
		}
		version = 4
	}

	if version < 5 {
		var duplicateChildren int
		if err := db.QueryRow(`SELECT COUNT(*) FROM (
			SELECT raw_id, record_ordinal FROM normalized_events
			GROUP BY raw_id, record_ordinal HAVING COUNT(*) > 1
		)`).Scan(&duplicateChildren); err != nil {
			return fmt.Errorf("check duplicate normalized children before schema v5: %w", err)
		}
		if duplicateChildren != 0 {
			return fmt.Errorf("cannot apply schema v5: found %d duplicate normalized child identities; resolve them explicitly before migration", duplicateChildren)
		}
		if _, err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_normalized_child
			ON normalized_events(raw_id, record_ordinal);

			CREATE TABLE integrity_streams (
				singleton INTEGER PRIMARY KEY CHECK(singleton=1),
				stream_id BLOB NOT NULL UNIQUE CHECK(length(stream_id)=32),
				codec_version INTEGER NOT NULL CHECK(codec_version=1),
				installation_epoch BLOB NOT NULL CHECK(length(installation_epoch)=32),
				genesis_hash BLOB NOT NULL CHECK(length(genesis_hash)=32),
				enabled INTEGER NOT NULL CHECK(enabled=1),
				next_entry_seq INTEGER NOT NULL CHECK(next_entry_seq BETWEEN 1 AND 9223372036854775807),
				next_batch_id INTEGER NOT NULL CHECK(next_batch_id BETWEEN 1 AND 9223372036854775807),
				last_sealed_seq INTEGER NOT NULL DEFAULT 0 CHECK(last_sealed_seq BETWEEN 0 AND 9223372036854775807),
				last_batch_hash BLOB NOT NULL CHECK(length(last_batch_hash)=32)
			);
			CREATE TABLE integrity_entries (
				stream_id BLOB NOT NULL CHECK(length(stream_id)=32),
				entry_seq INTEGER NOT NULL CHECK(entry_seq BETWEEN 1 AND 9223372036854775807),
				entry_kind INTEGER NOT NULL CHECK(entry_kind BETWEEN 1 AND 7),
				subject_id TEXT,
				raw_id TEXT,
				child_ordinal INTEGER CHECK(child_ordinal BETWEEN 0 AND 2147483647),
				operation_id TEXT,
				previous_subject_seq INTEGER CHECK(previous_subject_seq BETWEEN 1 AND 9223372036854775807),
				occurred_at_unix_ns INTEGER NOT NULL,
				content_snapshot BLOB NOT NULL,
				metadata_snapshot BLOB NOT NULL,
				content_digest BLOB NOT NULL CHECK(length(content_digest)=32),
				metadata_digest BLOB NOT NULL CHECK(length(metadata_digest)=32),
				encoded_entry BLOB NOT NULL,
				leaf_hash BLOB NOT NULL CHECK(length(leaf_hash)=32),
				PRIMARY KEY(stream_id,entry_seq),
				FOREIGN KEY(stream_id) REFERENCES integrity_streams(stream_id),
				FOREIGN KEY(raw_id) REFERENCES raw_events(raw_id)
			);
			CREATE UNIQUE INDEX idx_integrity_new_raw ON integrity_entries(stream_id,raw_id) WHERE entry_kind=1 AND raw_id IS NOT NULL;
			CREATE UNIQUE INDEX idx_integrity_operation_kind ON integrity_entries(stream_id,operation_id,entry_kind) WHERE operation_id IS NOT NULL;
			CREATE INDEX idx_integrity_subject ON integrity_entries(stream_id,subject_id,entry_seq);
			CREATE INDEX idx_integrity_raw ON integrity_entries(stream_id,raw_id,entry_seq);
			CREATE TABLE integrity_batches (
				stream_id BLOB NOT NULL CHECK(length(stream_id)=32),
				batch_id INTEGER NOT NULL CHECK(batch_id BETWEEN 1 AND 9223372036854775807),
				first_seq INTEGER NOT NULL CHECK(first_seq BETWEEN 1 AND 9223372036854775807),
				last_seq INTEGER NOT NULL CHECK(last_seq BETWEEN first_seq AND 9223372036854775807),
				leaf_count INTEGER NOT NULL CHECK(leaf_count BETWEEN 1 AND 5000 AND leaf_count=last_seq-first_seq+1),
				merkle_root BLOB NOT NULL CHECK(length(merkle_root)=32),
				prev_batch_hash BLOB NOT NULL CHECK(length(prev_batch_hash)=32),
				batch_hash BLOB NOT NULL UNIQUE CHECK(length(batch_hash)=32),
				encoded_descriptor BLOB NOT NULL CHECK(length(encoded_descriptor)=256),
				sealed_at TEXT NOT NULL,
				PRIMARY KEY(stream_id,batch_id),
				FOREIGN KEY(stream_id) REFERENCES integrity_streams(stream_id)
			);
			CREATE TABLE integrity_batch_entries (
				stream_id BLOB NOT NULL,
				batch_id INTEGER NOT NULL,
				leaf_index INTEGER NOT NULL CHECK(leaf_index BETWEEN 0 AND 4999),
				entry_seq INTEGER NOT NULL,
				leaf_hash BLOB NOT NULL CHECK(length(leaf_hash)=32),
				PRIMARY KEY(stream_id,batch_id,leaf_index),
				UNIQUE(stream_id,entry_seq),
				FOREIGN KEY(stream_id,batch_id) REFERENCES integrity_batches(stream_id,batch_id),
				FOREIGN KEY(stream_id,entry_seq) REFERENCES integrity_entries(stream_id,entry_seq)
			);
			CREATE TABLE integrity_witness_sync (
				stream_id BLOB NOT NULL,
				batch_id INTEGER NOT NULL,
				retry_count INTEGER NOT NULL DEFAULT 0 CHECK(retry_count>=0),
				next_retry_at TEXT,
				state TEXT NOT NULL DEFAULT 'pending',
				acknowledgement BLOB,
				anchor_tx_hash BLOB CHECK(anchor_tx_hash IS NULL OR length(anchor_tx_hash)=32),
				anchor_block_number INTEGER,
				anchor_block_hash BLOB CHECK(anchor_block_hash IS NULL OR length(anchor_block_hash)=32),
				last_error TEXT,
				PRIMARY KEY(stream_id,batch_id),
				FOREIGN KEY(stream_id,batch_id) REFERENCES integrity_batches(stream_id,batch_id)
			);
			CREATE TABLE integrity_operations (
				operation_id TEXT PRIMARY KEY,
				request_fingerprint BLOB NOT NULL CHECK(length(request_fingerprint)=32),
				quarantine_id TEXT NOT NULL,
				raw_id TEXT NOT NULL,
				child_ordinal INTEGER NOT NULL CHECK(child_ordinal BETWEEN 0 AND 2147483647),
				state TEXT NOT NULL CHECK(state IN ('running','completed','failed')),
				normalized_entry_seq INTEGER,
				result_summary TEXT,
				error_class TEXT,
				created_at TEXT NOT NULL,
				completed_at TEXT
			);
			CREATE TABLE integrity_audit_runs (
				run_id TEXT PRIMARY KEY,
				run_type TEXT NOT NULL,
				target_head INTEGER NOT NULL CHECK(target_head BETWEEN 0 AND 9223372036854775807),
				target_hash BLOB CHECK(target_hash IS NULL OR length(target_hash)=32),
				started_at TEXT NOT NULL,
				completed_at TEXT,
				heartbeat_at TEXT,
				cursor_seq INTEGER NOT NULL DEFAULT 0 CHECK(cursor_seq BETWEEN 0 AND 9223372036854775807),
				checked_count INTEGER NOT NULL DEFAULT 0 CHECK(checked_count>=0),
				result TEXT,
				first_failed_seq INTEGER,
				first_failed_batch INTEGER,
				error_class TEXT
			);
			CREATE TABLE integrity_findings (
				finding_id INTEGER PRIMARY KEY,
				run_id TEXT NOT NULL,
				detected_at TEXT NOT NULL,
				subject_id TEXT,
				batch_id INTEGER,
				entry_seq INTEGER,
				expected_hash BLOB CHECK(expected_hash IS NULL OR length(expected_hash)=32),
				actual_hash BLOB CHECK(actual_hash IS NULL OR length(actual_hash)=32),
				classification TEXT NOT NULL,
				details TEXT NOT NULL DEFAULT '',
				first_seen_at TEXT NOT NULL,
				last_seen_at TEXT NOT NULL,
				occurrence_count INTEGER NOT NULL DEFAULT 1 CHECK(occurrence_count>0),
				FOREIGN KEY(run_id) REFERENCES integrity_audit_runs(run_id)
			);
			CREATE TRIGGER integrity_entries_no_update BEFORE UPDATE ON integrity_entries BEGIN SELECT RAISE(ABORT,'integrity entries are immutable'); END;
			CREATE TRIGGER integrity_entries_no_delete BEFORE DELETE ON integrity_entries BEGIN SELECT RAISE(ABORT,'integrity entries are immutable'); END;
			CREATE TRIGGER integrity_batches_no_update BEFORE UPDATE ON integrity_batches BEGIN SELECT RAISE(ABORT,'integrity batches are immutable'); END;
			CREATE TRIGGER integrity_batches_no_delete BEFORE DELETE ON integrity_batches BEGIN SELECT RAISE(ABORT,'integrity batches are immutable'); END;
			CREATE TRIGGER integrity_stream_identity_no_update BEFORE UPDATE OF stream_id,codec_version,installation_epoch,genesis_hash,enabled ON integrity_streams BEGIN SELECT RAISE(ABORT,'integrity stream identity is immutable'); END;
			CREATE TRIGGER integrity_stream_no_delete BEFORE DELETE ON integrity_streams BEGIN SELECT RAISE(ABORT,'integrity stream cannot be deleted'); END;
			CREATE TRIGGER integrity_membership_no_update BEFORE UPDATE ON integrity_batch_entries BEGIN SELECT RAISE(ABORT,'sealed batch membership is immutable'); END;
			CREATE TRIGGER integrity_membership_no_delete BEFORE DELETE ON integrity_batch_entries BEGIN SELECT RAISE(ABORT,'sealed batch membership is immutable'); END;
			`); err != nil {
			return fmt.Errorf("failed to create integrity schema v5: %w", err)
		}
		version = 5
	}

	if version < 6 {
		if _, err := db.Exec(`ALTER TABLE integrity_entries ADD COLUMN committed_at TEXT NOT NULL DEFAULT '1970-01-01T00:00:00Z'`); err != nil {
			return fmt.Errorf("failed to add evidence commit timestamps for schema v6: %w", err)
		}
		version = 6
	}

	if version < 7 {
		if _, err := db.Exec(`ALTER TABLE integrity_streams ADD COLUMN enabled_at TEXT NOT NULL DEFAULT '1970-01-01T00:00:00Z'`); err != nil {
			return fmt.Errorf("failed to add integrity enable time for schema v7: %w", err)
		}
		if _, err := db.Exec(`UPDATE integrity_streams SET enabled_at=?`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return fmt.Errorf("backfill integrity enable time for schema v7: %w", err)
		}
		if _, err := db.Exec(`DROP TRIGGER integrity_stream_identity_no_update; CREATE TRIGGER integrity_stream_identity_no_update BEFORE UPDATE OF stream_id,codec_version,installation_epoch,genesis_hash,enabled,enabled_at ON integrity_streams BEGIN SELECT RAISE(ABORT,'integrity stream identity is immutable'); END;`); err != nil {
			return fmt.Errorf("protect integrity enable time in schema v7: %w", err)
		}
		version = 7
	}

	if version < 8 {
		if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS analysis_observations (
			observation_id INTEGER PRIMARY KEY,
			observation_key TEXT NOT NULL UNIQUE,
			kind TEXT NOT NULL CHECK(kind IN ('raw_received','normalized','quarantined')),
			occurred_at TEXT NOT NULL,
			raw_id TEXT NOT NULL,
			event_id TEXT,
			quarantine_id TEXT,
			record_ordinal INTEGER NOT NULL DEFAULT 0 CHECK(record_ordinal BETWEEN 0 AND 2147483647),
			transport TEXT NOT NULL,
			identity_hints_json TEXT NOT NULL CHECK(length(identity_hints_json)<=2048),
			FOREIGN KEY(raw_id) REFERENCES raw_events(raw_id)
		);
		CREATE INDEX IF NOT EXISTS idx_analysis_observations_raw ON analysis_observations(raw_id,observation_id);
		CREATE TABLE IF NOT EXISTS analysis_worker_state (
			singleton INTEGER PRIMARY KEY CHECK(singleton=1),
			checkpoint_id INTEGER NOT NULL DEFAULT 0 CHECK(checkpoint_id>=0),
			updated_at TEXT NOT NULL
		);
		INSERT OR IGNORE INTO analysis_worker_state(singleton,checkpoint_id,updated_at) VALUES(1,0,'1970-01-01T00:00:00Z');
		CREATE TABLE IF NOT EXISTS analysis_sources (
			source_key TEXT PRIMARY KEY CHECK(length(source_key)=64),
			identity_hints_json TEXT NOT NULL CHECK(length(identity_hints_json)<=2048),
			resolution TEXT NOT NULL CHECK(resolution IN ('matched','unknown','ambiguous')),
			device_id TEXT,
			match_method TEXT NOT NULL,
			confidence TEXT NOT NULL CHECK(confidence IN ('strong','weak','none')),
			first_seen_at TEXT NOT NULL,
			last_seen_at TEXT NOT NULL,
			observation_count INTEGER NOT NULL CHECK(observation_count>0),
			last_observation_id INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_analysis_sources_resolution ON analysis_sources(resolution,last_seen_at);
		CREATE TABLE IF NOT EXISTS analysis_observation_sources (
			observation_id INTEGER PRIMARY KEY,
			source_key TEXT NOT NULL,
			resolution TEXT NOT NULL CHECK(resolution IN ('matched','unknown','ambiguous')),
			device_id TEXT,
			match_method TEXT NOT NULL,
			confidence TEXT NOT NULL CHECK(confidence IN ('strong','weak','none')),
			FOREIGN KEY(observation_id) REFERENCES analysis_observations(observation_id),
			FOREIGN KEY(source_key) REFERENCES analysis_sources(source_key)
		);`); err != nil {
			return fmt.Errorf("failed to create analysis observation schema v8: %w", err)
		}
		version = 8
	}

	if version < 9 {
		if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS analysis_device_telemetry (
			device_id TEXT PRIMARY KEY,
			last_received_at TEXT,
			last_normalized_at TEXT,
			last_quarantined_at TEXT,
			last_heartbeat_at TEXT,
			received_count INTEGER NOT NULL DEFAULT 0 CHECK(received_count>=0),
			normalized_count INTEGER NOT NULL DEFAULT 0 CHECK(normalized_count>=0),
			quarantined_count INTEGER NOT NULL DEFAULT 0 CHECK(quarantined_count>=0),
			heartbeat_count INTEGER NOT NULL DEFAULT 0 CHECK(heartbeat_count>=0),
			identity_confidence TEXT NOT NULL DEFAULT 'none' CHECK(identity_confidence IN ('strong','weak','none')),
			match_method TEXT NOT NULL DEFAULT '',
			last_observation_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);
		INSERT OR IGNORE INTO analysis_device_telemetry(
			device_id,last_received_at,last_normalized_at,last_quarantined_at,
			received_count,normalized_count,quarantined_count,identity_confidence,
			match_method,last_observation_at,updated_at
		)
		SELECT aos.device_id,
			MAX(CASE WHEN o.kind='raw_received' THEN o.occurred_at END),
			MAX(CASE WHEN o.kind='normalized' THEN o.occurred_at END),
			MAX(CASE WHEN o.kind='quarantined' THEN o.occurred_at END),
			SUM(CASE WHEN o.kind='raw_received' THEN 1 ELSE 0 END),
			SUM(CASE WHEN o.kind='normalized' THEN 1 ELSE 0 END),
			SUM(CASE WHEN o.kind='quarantined' THEN 1 ELSE 0 END),
			CASE WHEN MAX(CASE WHEN aos.confidence='strong' THEN 1 ELSE 0 END)=1 THEN 'strong' ELSE 'weak' END,
			'historical',MAX(o.occurred_at),MAX(o.occurred_at)
		FROM analysis_observation_sources aos
		JOIN analysis_observations o ON o.observation_id=aos.observation_id
		WHERE aos.resolution='matched' AND aos.device_id IS NOT NULL
		GROUP BY aos.device_id;`); err != nil {
			return fmt.Errorf("failed to create analysis telemetry schema v9: %w", err)
		}
		version = 9
	}

	if version < 10 {
		if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS analysis_device_minute_buckets (
			device_id TEXT NOT NULL,
			bucket_start TEXT NOT NULL,
			received_count INTEGER NOT NULL DEFAULT 0 CHECK(received_count>=0),
			normalized_count INTEGER NOT NULL DEFAULT 0 CHECK(normalized_count>=0),
			quarantined_count INTEGER NOT NULL DEFAULT 0 CHECK(quarantined_count>=0),
			PRIMARY KEY(device_id,bucket_start)
		);
		CREATE INDEX IF NOT EXISTS idx_analysis_device_buckets_start ON analysis_device_minute_buckets(bucket_start);`); err != nil {
			return fmt.Errorf("failed to create analysis rate schema v10: %w", err)
		}
		version = 10
	}

	if version < 11 {
		if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS analysis_findings (
			finding_id TEXT PRIMARY KEY CHECK(length(finding_id)=64),
			owner_type TEXT NOT NULL CHECK(owner_type IN ('device','source')),
			owner_id TEXT NOT NULL,
			device_id TEXT,
			source_key TEXT NOT NULL CHECK(length(source_key)=64),
			rule_id TEXT NOT NULL,
			rule_version TEXT NOT NULL,
			status TEXT NOT NULL CHECK(status IN ('open','clearing','resolved')),
			severity TEXT NOT NULL CHECK(severity IN ('low','medium','high','critical')),
			state TEXT NOT NULL CHECK(state IN ('yellow','red')),
			title TEXT NOT NULL,
			first_seen_at TEXT NOT NULL,
			last_seen_at TEXT NOT NULL,
			last_event_id TEXT NOT NULL,
			last_raw_id TEXT NOT NULL,
			record_ordinal INTEGER NOT NULL CHECK(record_ordinal BETWEEN 0 AND 2147483647),
			occurrence_count INTEGER NOT NULL CHECK(occurrence_count>0),
			clear_since TEXT,
			clear_deadline TEXT,
			clear_observation_id INTEGER,
			clear_event_id TEXT,
			clear_raw_id TEXT,
			clear_ordinal INTEGER,
			resolved_at TEXT,
			updated_at TEXT NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_analysis_findings_status_updated ON analysis_findings(status,updated_at DESC);
		CREATE TABLE IF NOT EXISTS analysis_finding_history (
			history_id INTEGER PRIMARY KEY,
			finding_id TEXT NOT NULL,
			observation_id INTEGER NOT NULL,
			action TEXT NOT NULL CHECK(action IN ('opened','updated','clear_started','clear_cancelled','resolved')),
			occurred_at TEXT NOT NULL,
			event_id TEXT NOT NULL,
			raw_id TEXT NOT NULL,
			record_ordinal INTEGER NOT NULL,
			rule_version TEXT NOT NULL,
			severity TEXT NOT NULL,
			state TEXT NOT NULL,
			title TEXT NOT NULL,
			UNIQUE(finding_id,observation_id,action),
			FOREIGN KEY(finding_id) REFERENCES analysis_findings(finding_id),
			FOREIGN KEY(observation_id) REFERENCES analysis_observations(observation_id)
		);
		CREATE INDEX IF NOT EXISTS idx_analysis_finding_history ON analysis_finding_history(finding_id,history_id DESC);
		CREATE TRIGGER IF NOT EXISTS analysis_finding_history_no_update BEFORE UPDATE ON analysis_finding_history BEGIN SELECT RAISE(ABORT,'analysis finding history is immutable'); END;
		CREATE TRIGGER IF NOT EXISTS analysis_finding_history_no_delete BEFORE DELETE ON analysis_finding_history BEGIN SELECT RAISE(ABORT,'analysis finding history is immutable'); END;`); err != nil {
			return fmt.Errorf("failed to create analysis finding schema v11: %w", err)
		}
		version = 11
	}

	if version < 12 {
		var historySchema sql.NullString
		if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name='analysis_finding_history'`).Scan(&historySchema); err != nil {
			return fmt.Errorf("inspect finding history for schema v12: %w", err)
		}
		if strings.Contains(historySchema.String, "UNIQUE(finding_id,observation_id,action)") {
			if _, err := db.Exec(`DROP TRIGGER IF EXISTS analysis_finding_history_no_update;
				DROP TRIGGER IF EXISTS analysis_finding_history_no_delete;
				ALTER TABLE analysis_finding_history RENAME TO analysis_finding_history_v11;
				CREATE TABLE analysis_finding_history (
					history_id INTEGER PRIMARY KEY,
					finding_id TEXT NOT NULL,
					observation_id INTEGER NOT NULL,
					action TEXT NOT NULL CHECK(action IN ('opened','updated','clear_started','clear_cancelled','resolved','escalated')),
					occurred_at TEXT NOT NULL,
					event_id TEXT NOT NULL,
					raw_id TEXT NOT NULL,
					record_ordinal INTEGER NOT NULL,
					rule_version TEXT NOT NULL,
					severity TEXT NOT NULL,
					state TEXT NOT NULL,
					title TEXT NOT NULL,
					FOREIGN KEY(finding_id) REFERENCES analysis_findings(finding_id),
					FOREIGN KEY(observation_id) REFERENCES analysis_observations(observation_id)
				);
				INSERT INTO analysis_finding_history SELECT * FROM analysis_finding_history_v11;
				DROP TABLE analysis_finding_history_v11;
				CREATE INDEX IF NOT EXISTS idx_analysis_finding_history ON analysis_finding_history(finding_id,history_id DESC);
				CREATE TRIGGER analysis_finding_history_no_update BEFORE UPDATE ON analysis_finding_history BEGIN SELECT RAISE(ABORT,'analysis finding history is immutable'); END;
				CREATE TRIGGER analysis_finding_history_no_delete BEFORE DELETE ON analysis_finding_history BEGIN SELECT RAISE(ABORT,'analysis finding history is immutable'); END;`); err != nil {
				return fmt.Errorf("upgrade finding history for schema v12: %w", err)
			}
		}
		for _, column := range []struct{ table, name, ddl string }{
			{"analysis_findings", "instance_key", `ALTER TABLE analysis_findings ADD COLUMN instance_key TEXT NOT NULL DEFAULT ''`},
			{"analysis_device_telemetry", "last_heartbeat_observation_id", `ALTER TABLE analysis_device_telemetry ADD COLUMN last_heartbeat_observation_id INTEGER NOT NULL DEFAULT 0`},
		} {
			var exists int
			if err := db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM pragma_table_info('%s') WHERE name=?", column.table), column.name).Scan(&exists); err != nil {
				return fmt.Errorf("inspect schema v12 column %s.%s: %w", column.table, column.name, err)
			}
			if exists == 0 {
				if _, err := db.Exec(column.ddl); err != nil {
					return fmt.Errorf("add schema v12 column %s.%s: %w", column.table, column.name, err)
				}
			}
		}
		if _, err := db.Exec(`UPDATE analysis_device_telemetry SET last_heartbeat_observation_id=COALESCE((SELECT MAX(o.observation_id) FROM analysis_observations o JOIN analysis_observation_sources aos ON aos.observation_id=o.observation_id WHERE aos.device_id=analysis_device_telemetry.device_id AND o.kind='normalized' AND o.occurred_at=analysis_device_telemetry.last_heartbeat_at),0) WHERE heartbeat_count>0;
			CREATE TABLE IF NOT EXISTS analysis_window_samples (
				rule_id TEXT NOT NULL,
				owner_type TEXT NOT NULL CHECK(owner_type IN ('device','source')),
				owner_id TEXT NOT NULL,
				instance_key TEXT NOT NULL,
				observation_id INTEGER NOT NULL,
				occurred_at TEXT NOT NULL,
				matched INTEGER NOT NULL CHECK(matched IN (0,1)),
				outcome TEXT NOT NULL CHECK(outcome IN ('normalized','quarantined')),
				event_id TEXT NOT NULL,
				raw_id TEXT NOT NULL,
				record_ordinal INTEGER NOT NULL,
				PRIMARY KEY(rule_id,observation_id),
				FOREIGN KEY(observation_id) REFERENCES analysis_observations(observation_id)
			);
			CREATE INDEX IF NOT EXISTS idx_analysis_window_samples ON analysis_window_samples(rule_id,owner_type,owner_id,instance_key,occurred_at);
			CREATE INDEX IF NOT EXISTS idx_analysis_window_retention ON analysis_window_samples(occurred_at);
			CREATE INDEX IF NOT EXISTS idx_analysis_findings_instance ON analysis_findings(rule_id,owner_type,owner_id,instance_key,status);`); err != nil {
			return fmt.Errorf("create analysis window schema v12: %w", err)
		}
		version = 12
	}

	if version < 13 {
		if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_analysis_findings_device_status ON analysis_findings(device_id,status);`); err != nil {
			return fmt.Errorf("create analysis finding device index: %w", err)
		}
		version = 13
	}

	if version < 14 {
		if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS analysis_baseline_states (
			rule_id TEXT NOT NULL,
			owner_type TEXT NOT NULL CHECK(owner_type IN ('device','source')),
			owner_id TEXT NOT NULL,
			instance_key TEXT NOT NULL,
			algorithm TEXT NOT NULL,
			algorithm_version TEXT NOT NULL,
			status TEXT NOT NULL CHECK(status IN ('warming_up','ready','anomaly','maintenance')),
			direction TEXT NOT NULL DEFAULT '',
			minimum_history INTEGER NOT NULL,
			history_count INTEGER NOT NULL,
			first_seen_at TEXT NOT NULL,
			interval_start TEXT NOT NULL,
			interval_end TEXT NOT NULL,
			observed_count INTEGER NOT NULL,
			baseline_median REAL NOT NULL,
			baseline_mad REAL NOT NULL,
			lower_threshold REAL NOT NULL,
			upper_threshold REAL NOT NULL,
			finding_id TEXT NOT NULL DEFAULT '',
			updated_at TEXT NOT NULL,
			PRIMARY KEY(rule_id,owner_type,owner_id,instance_key)
		);
		CREATE INDEX IF NOT EXISTS idx_analysis_baseline_state ON analysis_baseline_states(status,updated_at DESC);
		CREATE INDEX IF NOT EXISTS idx_analysis_baseline_owner ON analysis_baseline_states(owner_type,owner_id,updated_at DESC);`); err != nil {
			return fmt.Errorf("create analysis baseline state schema: %w", err)
		}
		version = 14
	}

	if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version = %d;", CurrentSchemaVersion)); err != nil {
		return fmt.Errorf("failed to set user_version: %w", err)
	}

	return nil
}

type sqlExecutor interface {
	Exec(query string, args ...any) (sql.Result, error)
	QueryRow(query string, args ...any) *sql.Row
}

// Store commits verbatim raw bytes, calculates SHA-256 digest, and assigns an immutable raw ID.
func (s *RawStore) Store(ctx context.Context, rec model.IngestedRecord) (*model.RawEvent, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if rec.ReceivedAt.IsZero() {
		rec.ReceivedAt = time.Now().UTC()
	}

	hash := sha256.Sum256(rec.RawBytes)
	shaHex := hex.EncodeToString(hash[:])
	if rec.Transport == "file" && rec.Metadata.FileID != "" {
		var existingID, existingHash string
		err := s.db.QueryRowContext(ctx, `SELECT raw_id, raw_sha256 FROM raw_events
			WHERE json_extract(metadata_json, '$.file_id')=? AND COALESCE(json_extract(metadata_json, '$.file_offset'),0)=?
			LIMIT 1`, rec.Metadata.FileID, rec.Metadata.FileOffset).Scan(&existingID, &existingHash)
		if err == nil {
			if existingHash != shaHex {
				return nil, fmt.Errorf("file spool identity %s at offset %d was already committed with different bytes", rec.Metadata.FileID, rec.Metadata.FileOffset)
			}
			event, err := s.Retrieve(ctx, existingID)
			if err != nil {
				return nil, err
			}
			event.Duplicate = true
			return event, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("check file spool replay identity: %w", err)
		}
	}

	// Format monotonic, predictable raw ID: raven-raw-YYYYMMDD-<seq>-<rand>
	seq := s.counter.Add(1)
	var randBytes [4]byte
	_, _ = rand.Read(randBytes[:])
	rawID := fmt.Sprintf("raven-raw-%s-%06d-%x", rec.ReceivedAt.Format("20060102"), seq, randBytes)

	event := &model.RawEvent{
		RawID:      rawID,
		RawSHA256:  shaHex,
		ByteCount:  len(rec.RawBytes),
		Transport:  rec.Transport,
		SourceIP:   rec.SourceIP,
		SourcePort: rec.SourcePort,
		Metadata:   rec.Metadata,
		ReceivedAt: rec.ReceivedAt,
		Payload:    rec.RawBytes,
		Status:     model.StatusAccepted,
	}

	metadataJSON, err := json.Marshal(event.Metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to encode receive metadata: %w", err)
	}
	query := `
	INSERT INTO raw_events (raw_id, raw_sha256, byte_count, transport, source_ip, source_port, metadata_json, received_at, payload, status)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
	`
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin raw commit transaction: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, query,
		event.RawID,
		event.RawSHA256,
		event.ByteCount,
		event.Transport,
		event.SourceIP,
		event.SourcePort,
		string(metadataJSON),
		event.ReceivedAt.Format(time.RFC3339Nano),
		event.Payload,
		string(event.Status),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to persist raw record %s: %w", rawID, err)
	}
	enabled, err := integrityEnabledTx(ctx, tx)
	if err != nil {
		return nil, err
	}
	if enabled {
		metadataFields, err := rawMetadataFields(event)
		if err != nil {
			return nil, err
		}
		id := event.RawID
		if _, err := appendEvidenceTx(ctx, tx, evidenceWrite{
			kind: integrity.RawCommitted, subjectID: &id, rawID: &id, occurredAt: event.ReceivedAt,
			contentSnapshot: []byte{}, contentBytes: event.Payload, metadataFields: metadataFields,
		}); err != nil {
			return nil, fmt.Errorf("failed to append raw commit evidence: %w", err)
		}
	}
	if s.analysisEnabled.Load() {
		if err := appendAnalysisObservationTx(ctx, tx, "raw_received", "raw:"+event.RawID, event.ReceivedAt, event.RawID, "", "", 0, event.Transport, model.AnalysisIdentityHints{"source_ip": event.SourceIP}); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit raw record %s: %w", rawID, err)
	}

	return event, nil
}

// Retrieve returns the raw record and exact bytes by raw ID.
func (s *RawStore) Retrieve(ctx context.Context, rawID string) (*model.RawEvent, error) {
	query := `
	SELECT raw_id, raw_sha256, byte_count, transport, source_ip, source_port, metadata_json, received_at, payload, status
	FROM raw_events WHERE raw_id = ?;
	`
	var (
		evt          model.RawEvent
		receivedAt   string
		statusStr    string
		metadataJSON string
	)

	err := s.db.QueryRowContext(ctx, query, rawID).Scan(
		&evt.RawID,
		&evt.RawSHA256,
		&evt.ByteCount,
		&evt.Transport,
		&evt.SourceIP,
		&evt.SourcePort,
		&metadataJSON,
		&receivedAt,
		&evt.Payload,
		&statusStr,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("raw event not found: %s", rawID)
		}
		return nil, fmt.Errorf("failed to retrieve raw event %s: %w", rawID, err)
	}

	t, err := time.Parse(time.RFC3339Nano, receivedAt)
	if err != nil {
		t, _ = time.Parse(time.RFC3339, receivedAt)
	}
	evt.ReceivedAt = t
	evt.Status = model.RawStatus(statusStr)
	if err := json.Unmarshal([]byte(metadataJSON), &evt.Metadata); err != nil {
		return nil, fmt.Errorf("invalid receive metadata for %s: %w", rawID, err)
	}

	return &evt, nil
}

// Verify recalculates the SHA-256 digest of stored bytes and verifies cryptographic integrity.
func (s *RawStore) Verify(ctx context.Context, rawID string) (bool, string, error) {
	evt, err := s.Retrieve(ctx, rawID)
	if err != nil {
		return false, "", err
	}

	computed := sha256.Sum256(evt.Payload)
	computedHex := hex.EncodeToString(computed[:])

	matches := computedHex == evt.RawSHA256 && evt.ByteCount == len(evt.Payload)
	enabled, err := s.IntegrityEnabled(ctx)
	if err != nil {
		return false, computedHex, err
	}
	if enabled {
		fields, err := rawMetadataFields(evt)
		if err != nil {
			return false, computedHex, err
		}
		metadata, err := integrity.EncodeFields(fields)
		if err != nil {
			return false, computedHex, err
		}
		var subject string
		var occurredAt int64
		var streamID, contentSnapshot, metadataSnapshot, contentDigest, metadataDigest, encoded, leaf []byte
		var sequence uint64
		err = s.db.QueryRowContext(ctx, `SELECT stream_id,entry_seq,subject_id,occurred_at_unix_ns,content_snapshot,metadata_snapshot,content_digest,metadata_digest,encoded_entry,leaf_hash FROM integrity_entries WHERE stream_id=(SELECT stream_id FROM integrity_streams WHERE singleton=1) AND entry_kind=? AND raw_id=? ORDER BY entry_seq LIMIT 1`, integrity.RawCommitted, rawID).Scan(&streamID, &sequence, &subject, &occurredAt, &contentSnapshot, &metadataSnapshot, &contentDigest, &metadataDigest, &encoded, &leaf)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return false, computedHex, nil
			}
			return false, computedHex, err
		}
		contentHash := integrity.HashContent(evt.Payload)
		metadataHash := integrity.HashContent(metadata)
		decoded, decodeErr := integrity.DecodeEvidenceEntry(encoded)
		leafHash := integrity.MerkleLeaf(encoded)
		matches = matches && decodeErr == nil && decoded.Kind == integrity.RawCommitted && decoded.Sequence == sequence && equalBytes(decoded.StreamID[:], streamID) && decoded.SubjectID != nil && *decoded.SubjectID == rawID && decoded.RawID != nil && *decoded.RawID == rawID && decoded.ChildOrdinal == nil && decoded.OperationID == nil && subject == rawID && occurredAt == evt.ReceivedAt.UTC().UnixNano() && len(contentSnapshot) == 0 && equalBytes(metadataSnapshot, metadata) && equalBytes(contentDigest, contentHash[:]) && equalBytes(metadataDigest, metadataHash[:]) && decoded.ContentDigest == contentHash && decoded.MetadataDigest == metadataHash && equalBytes(leaf, leafHash[:])
	}
	return matches, computedHex, nil
}

// Quarantine persists an unparseable or schema-violating event in the quarantine table
// and updates the raw event status to "quarantined".
func (s *RawStore) Quarantine(ctx context.Context, entry model.QuarantineEntry) error {
	return s.quarantine(ctx, entry, true)
}

// QuarantineChild records a batch child while keeping its parent recoverable until the batch finalizes.
func (s *RawStore) QuarantineChild(ctx context.Context, entry model.QuarantineEntry) error {
	return s.quarantine(ctx, entry, false)
}

func (s *RawStore) quarantine(ctx context.Context, entry model.QuarantineEntry, finalize bool) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if entry.QuarantineID == "" {
		var randBytes [4]byte
		_, _ = rand.Read(randBytes[:])
		entry.QuarantineID = fmt.Sprintf("raven-quar-%s-%x", time.Now().Format("20060102"), randBytes)
	}
	if entry.QuarantinedAt.IsZero() {
		entry.QuarantinedAt = time.Now().UTC()
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin quarantine tx: %w", err)
	}
	defer tx.Rollback()
	enabled, err := integrityEnabledTx(ctx, tx)
	if err != nil {
		return err
	}

	replayVal := 0
	if entry.ReplayEligible {
		replayVal = 1
	}

	candidateStr := strings.Join(entry.CandidatePacks, ",")
	qQuery := `
	INSERT INTO quarantine (quarantine_id, raw_id, record_ordinal, raw_sha256, stage, reason, error_details, raw_preview, candidate_packs, replay_eligible, quarantined_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(raw_id, record_ordinal, stage, reason) DO UPDATE SET
		error_details=excluded.error_details,
		raw_preview=excluded.raw_preview,
		candidate_packs=excluded.candidate_packs,
		replay_eligible=excluded.replay_eligible;
	`
	_, err = tx.ExecContext(ctx, qQuery,
		entry.QuarantineID,
		entry.RawID,
		entry.RecordOrdinal,
		entry.RawSHA256,
		entry.Stage,
		entry.Reason,
		entry.ErrorDetails,
		entry.RawPreview,
		candidateStr,
		replayVal,
		entry.QuarantinedAt.Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("failed to insert quarantine entry: %w", err)
	}
	if enabled {
		var persistedID string
		if err := tx.QueryRowContext(ctx, `SELECT quarantine_id FROM quarantine WHERE raw_id=? AND record_ordinal=? AND stage=? AND reason=?`, entry.RawID, entry.RecordOrdinal, entry.Stage, entry.Reason).Scan(&persistedID); err != nil {
			return err
		}
		persisted, err := loadQuarantineTx(ctx, tx, persistedID)
		if err != nil {
			return err
		}
		fields, err := quarantineEvidenceFields(persisted)
		if err != nil {
			return err
		}
		snapshot, err := integrity.EncodeFields(fields)
		if err != nil {
			return err
		}
		previous, err := latestEntrySeqTx(ctx, tx, integrity.QuarantineWritten, persisted.RawID, persisted.RecordOrdinal, persisted.QuarantineID)
		if err != nil {
			return err
		}
		changed := true
		if previous != 0 {
			var last []byte
			if err := tx.QueryRowContext(ctx, `SELECT content_snapshot FROM integrity_entries WHERE stream_id=(SELECT stream_id FROM integrity_streams WHERE singleton=1) AND entry_seq=?`, previous).Scan(&last); err != nil {
				return err
			}
			changed = !equalBytes(last, snapshot)
		}
		if changed {
			id, rawID := persisted.QuarantineID, persisted.RawID
			ordinal := uint32(persisted.RecordOrdinal)
			var prev *uint64
			if previous > 0 {
				prev = &previous
			}
			if _, err := appendEvidenceTx(ctx, tx, evidenceWrite{kind: integrity.QuarantineWritten, subjectID: &id, rawID: &rawID, childOrdinal: &ordinal, previousSubjectSeq: prev, occurredAt: persisted.QuarantinedAt, contentSnapshot: snapshot, contentFields: fields}); err != nil {
				return fmt.Errorf("append quarantine evidence: %w", err)
			}
		}
	}
	if finalize {
		if _, err := tx.ExecContext(ctx, `UPDATE raw_events SET status = ? WHERE raw_id = ?`, string(model.StatusQuarantined), entry.RawID); err != nil {
			return fmt.Errorf("failed to update raw event status to quarantined: %w", err)
		}
	}
	if s.analysisEnabled.Load() {
		var persistedID, transport, sourceIP string
		if err := tx.QueryRowContext(ctx, `SELECT q.quarantine_id,r.transport,r.source_ip FROM quarantine q JOIN raw_events r ON r.raw_id=q.raw_id WHERE q.raw_id=? AND q.record_ordinal=? AND q.stage=? AND q.reason=?`, entry.RawID, entry.RecordOrdinal, entry.Stage, entry.Reason).Scan(&persistedID, &transport, &sourceIP); err != nil {
			return fmt.Errorf("load committed quarantine for analysis observation: %w", err)
		}
		hints := model.AnalysisIdentityHints{"source_ip": sourceIP}
		for key, value := range entry.AnalysisHints {
			hints[key] = value
		}
		if err := appendAnalysisObservationTx(ctx, tx, "quarantined", "quarantined:"+persistedID, entry.QuarantinedAt, entry.RawID, "", persistedID, entry.RecordOrdinal, transport, hints); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// UpdateStatus updates the lifecycle state of a committed raw record.
func (s *RawStore) UpdateStatus(ctx context.Context, rawID string, status model.RawStatus) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	query := `UPDATE raw_events SET status = ? WHERE raw_id = ?;`
	res, err := s.db.ExecContext(ctx, query, string(status), rawID)
	if err != nil {
		return fmt.Errorf("failed to update status of %s: %w", rawID, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("raw event not found for status update: %s", rawID)
	}
	return nil
}

// GetQuarantined retrieves paginated quarantined records.
func (s *RawStore) GetQuarantined(ctx context.Context, limit, offset int) ([]model.QuarantineEntry, error) {
	query := `
	SELECT quarantine_id, raw_id, record_ordinal, raw_sha256, stage, reason, error_details, raw_preview, candidate_packs, replay_eligible, quarantined_at, replayed_at
	FROM quarantine
	ORDER BY quarantined_at DESC
	LIMIT ? OFFSET ?;
	`
	rows, err := s.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query quarantine entries: %w", err)
	}
	defer rows.Close()

	var entries []model.QuarantineEntry
	for rows.Next() {
		var (
			e            model.QuarantineEntry
			candidateStr sql.NullString
			replayInt    int
			qAtStr       string
			rAtStr       sql.NullString
		)
		err := rows.Scan(
			&e.QuarantineID,
			&e.RawID,
			&e.RecordOrdinal,
			&e.RawSHA256,
			&e.Stage,
			&e.Reason,
			&e.ErrorDetails,
			&e.RawPreview,
			&candidateStr,
			&replayInt,
			&qAtStr,
			&rAtStr,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan quarantine entry: %w", err)
		}

		if candidateStr.Valid && candidateStr.String != "" {
			e.CandidatePacks = strings.Split(candidateStr.String, ",")
		}
		e.ReplayEligible = (replayInt == 1)
		t, _ := time.Parse(time.RFC3339Nano, qAtStr)
		e.QuarantinedAt = t
		if rAtStr.Valid {
			rt, _ := time.Parse(time.RFC3339Nano, rAtStr.String)
			e.ReplayedAt = &rt
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate quarantine entries: %w", err)
	}
	return entries, nil
}

// GetQuarantineByID retrieves a single quarantined entry by its quarantine ID.
func (s *RawStore) GetQuarantineByID(ctx context.Context, qID string) (*model.QuarantineEntry, error) {
	query := `
	SELECT quarantine_id, raw_id, record_ordinal, raw_sha256, stage, reason, error_details, raw_preview, candidate_packs, replay_eligible, quarantined_at, replayed_at
	FROM quarantine
	WHERE quarantine_id = ?;
	`
	var (
		e            model.QuarantineEntry
		candidateStr sql.NullString
		replayInt    int
		qAtStr       string
		rAtStr       sql.NullString
	)
	err := s.db.QueryRowContext(ctx, query, qID).Scan(
		&e.QuarantineID,
		&e.RawID,
		&e.RecordOrdinal,
		&e.RawSHA256,
		&e.Stage,
		&e.Reason,
		&e.ErrorDetails,
		&e.RawPreview,
		&candidateStr,
		&replayInt,
		&qAtStr,
		&rAtStr,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("quarantine entry not found: %s", qID)
		}
		return nil, fmt.Errorf("failed to query quarantine entry %s: %w", qID, err)
	}

	if candidateStr.Valid && candidateStr.String != "" {
		e.CandidatePacks = strings.Split(candidateStr.String, ",")
	}
	e.ReplayEligible = (replayInt == 1)
	t, _ := time.Parse(time.RFC3339Nano, qAtStr)
	e.QuarantinedAt = t
	if rAtStr.Valid {
		rt, _ := time.Parse(time.RFC3339Nano, rAtStr.String)
		e.ReplayedAt = &rt
	}
	return &e, nil
}

// MarkReplayed updates the replayed_at timestamp of a quarantined record.
func (s *RawStore) MarkReplayed(ctx context.Context, qID string) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	enabled, err := integrityEnabledTx(ctx, tx)
	if err != nil {
		return err
	}
	var entry *model.QuarantineEntry
	var previous uint64
	if enabled {
		entry, err = loadQuarantineTx(ctx, tx, qID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("quarantine entry not found for replay update: %s", qID)
			}
			return err
		}
		previous, err = latestEntrySeqTx(ctx, tx, integrity.QuarantineWritten, entry.RawID, entry.RecordOrdinal, entry.QuarantineID)
		if err != nil {
			return err
		}
		if previous == 0 {
			return errors.New("quarantine entry has no integrity evidence")
		}
	}
	nowStr := time.Now().UTC().Format(time.RFC3339Nano)
	query := `UPDATE quarantine SET replayed_at = ? WHERE quarantine_id = ?;`
	res, err := tx.ExecContext(ctx, query, nowStr, qID)
	if err != nil {
		return fmt.Errorf("failed to mark quarantine %s as replayed: %w", qID, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("quarantine entry not found for replay update: %s", qID)
	}
	if enabled {
		updated, err := loadQuarantineTx(ctx, tx, qID)
		if err != nil {
			return err
		}
		fields, err := quarantineEvidenceFields(updated)
		if err != nil {
			return err
		}
		snapshot, err := integrity.EncodeFields(fields)
		if err != nil {
			return err
		}
		id, rawID := updated.QuarantineID, updated.RawID
		ordinal := uint32(updated.RecordOrdinal)
		prev := previous
		if _, err := appendEvidenceTx(ctx, tx, evidenceWrite{kind: integrity.QuarantineWritten, subjectID: &id, rawID: &rawID, childOrdinal: &ordinal, previousSubjectSeq: &prev, occurredAt: time.Now().UTC(), contentSnapshot: snapshot, contentFields: fields}); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// GetReplayPendingIDs returns quarantine IDs eligible for reprocessing.
// If includeAlreadyReplayed is false, returns only records where replayed_at IS NULL.
func (s *RawStore) GetReplayPendingIDs(ctx context.Context, includeAlreadyReplayed bool) ([]string, error) {
	query := `SELECT quarantine_id FROM quarantine WHERE replay_eligible = 1 AND replayed_at IS NULL ORDER BY quarantined_at ASC;`
	if includeAlreadyReplayed {
		query = `SELECT quarantine_id FROM quarantine WHERE replay_eligible = 1 ORDER BY quarantined_at ASC;`
	}

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query replayable quarantine IDs: %w", err)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate replayable quarantine IDs: %w", err)
	}
	return ids, nil
}

// DeleteQuarantine removes a record from the quarantine table once it has been successfully replayed.
func (s *RawStore) DeleteQuarantine(ctx context.Context, qID string) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	enabled, err := integrityEnabledTx(ctx, tx)
	if err != nil {
		return err
	}
	var entry *model.QuarantineEntry
	var previous uint64
	if enabled {
		entry, err = loadQuarantineTx(ctx, tx, qID)
		if errors.Is(err, sql.ErrNoRows) {
			return tx.Commit()
		}
		if err != nil {
			return err
		}
		previous, err = latestEntrySeqTx(ctx, tx, integrity.QuarantineWritten, entry.RawID, entry.RecordOrdinal, entry.QuarantineID)
		if err != nil {
			return err
		}
		if previous == 0 {
			return errors.New("quarantine entry has no integrity evidence")
		}
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM quarantine WHERE quarantine_id=?`, qID)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return tx.Commit()
	}
	if enabled {
		if entry.RecordOrdinal < 0 || int64(entry.RecordOrdinal) > math.MaxInt32 {
			return errors.New("quarantine child ordinal is outside the evidence codec range")
		}
		fields := []integrity.TypedField{fieldU64(1, previous), fieldText(2, "projection_removed")}
		snapshot, err := integrity.EncodeFields(fields)
		if err != nil {
			return err
		}
		id, rawID := entry.QuarantineID, entry.RawID
		ordinal := uint32(entry.RecordOrdinal)
		prev := previous
		if _, err := appendEvidenceTx(ctx, tx, evidenceWrite{kind: integrity.QuarantineRemoved, subjectID: &id, rawID: &rawID, childOrdinal: &ordinal, previousSubjectSeq: &prev, occurredAt: time.Now().UTC(), contentSnapshot: snapshot, contentFields: fields}); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// CountRaw returns the total number of raw events in storage.
func (s *RawStore) CountRaw(ctx context.Context) (int64, error) {
	var count int64
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM raw_events;").Scan(&count)
	return count, err
}

// CountNormalized returns the total number of normalized events in storage.
func (s *RawStore) CountNormalized(ctx context.Context) (int64, error) {
	var count int64
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM normalized_events;").Scan(&count)
	return count, err
}

// CountQuarantine returns the total number of unresolved quarantine records in storage.
func (s *RawStore) CountQuarantine(ctx context.Context) (int64, error) {
	var count int64
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM quarantine;").Scan(&count)
	return count, err
}

func (s *RawStore) CountUnmapped(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM normalized_events WHERE EXISTS (SELECT 1 FROM json_each(json_extract(event_json,'$.ocsf.unmapped')))`).Scan(&n)
	return n, err
}

// StoreNormalized inserts or updates a normalized event in the SQLite database.
func (s *RawStore) StoreNormalized(ctx context.Context, event *model.NormalizedEvent) error {
	return s.StoreNormalizedWithOutbox(ctx, event, nil)
}

func (s *RawStore) DeleteNormalizedChild(ctx context.Context, rawID string, ordinal int) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	enabled, err := integrityEnabledTx(ctx, tx)
	if err != nil {
		return err
	}
	var eventID string
	err = tx.QueryRowContext(ctx, `SELECT event_id FROM normalized_events WHERE raw_id=? AND record_ordinal=?`, rawID, ordinal).Scan(&eventID)
	if errors.Is(err, sql.ErrNoRows) {
		return tx.Commit()
	}
	if err != nil {
		return err
	}
	if enabled {
		previous, err := latestEntrySeqTx(ctx, tx, integrity.NormalizedWritten, rawID, ordinal, eventID)
		if err != nil {
			return err
		}
		if previous == 0 {
			return errors.New("normalized child has no integrity evidence")
		}
		if ordinal < 0 || int64(ordinal) > math.MaxInt32 {
			return errors.New("normalized child ordinal is outside the evidence codec range")
		}
		fields := []integrity.TypedField{fieldU64(1, previous), fieldText(2, "projection_removed")}
		snapshot, err := integrity.EncodeFields(fields)
		if err != nil {
			return err
		}
		seq := previous
		child := uint32(ordinal)
		if _, err := tx.ExecContext(ctx, `DELETE FROM normalized_events WHERE raw_id=? AND record_ordinal=?`, rawID, ordinal); err != nil {
			return err
		}
		if _, err := appendEvidenceTx(ctx, tx, evidenceWrite{kind: integrity.NormalizedRemoved, subjectID: &eventID, rawID: &rawID, childOrdinal: &child, previousSubjectSeq: &seq, occurredAt: time.Now().UTC(), contentSnapshot: snapshot, contentFields: fields}); err != nil {
			return err
		}
		return tx.Commit()
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM normalized_events WHERE raw_id=? AND record_ordinal=?", rawID, ordinal); err != nil {
		return err
	}
	return tx.Commit()
}

// StoreNormalizedWithOutbox atomically stores the projection and one idempotent delivery row per destination.
func (s *RawStore) StoreNormalizedWithOutbox(ctx context.Context, event *model.NormalizedEvent, destinations []string) error {
	hints := model.AnalysisIdentityHints{"host": event.Raven.SourceID}
	return s.StoreNormalizedWithOutboxAndHints(ctx, event, destinations, hints)
}

// StoreNormalizedWithOutboxAndHints atomically persists normalized output,
// delivery intent, and the bounded Analysis observation when Analysis is enabled.
func (s *RawStore) StoreNormalizedWithOutboxAndHints(ctx context.Context, event *model.NormalizedEvent, destinations []string, hints model.AnalysisIdentityHints) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := storeNormalizedTx(ctx, tx, event, destinations); err != nil {
		return err
	}
	if s.analysisEnabled.Load() {
		var transport, sourceIP string
		if err := tx.QueryRowContext(ctx, `SELECT transport,source_ip FROM raw_events WHERE raw_id=?`, event.Raven.RawID).Scan(&transport, &sourceIP); err != nil {
			return fmt.Errorf("load raw source for analysis observation: %w", err)
		}
		hints = addSourceIP(hints, sourceIP)
		if err := appendAnalysisObservationTx(ctx, tx, "normalized", "normalized:"+event.Raven.EventID, time.Now().UTC(), event.Raven.RawID, event.Raven.EventID, "", event.Raven.RecordOrdinal, transport, hints); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ResolveQuarantineWithOutbox atomically replaces one quarantined child and updates its parent outcome.
func (s *RawStore) ResolveQuarantineWithOutbox(ctx context.Context, qID string, event *model.NormalizedEvent, destinations []string) error {
	opID, err := newOperationID()
	if err != nil {
		return err
	}
	op, err := s.BeginReplay(ctx, qID, opID)
	if err != nil {
		return err
	}
	if op.State == "completed" {
		return nil
	}
	return s.ResolveQuarantineWithOutboxOperation(ctx, qID, event, destinations, opID)
}

func (s *RawStore) ResolveQuarantineWithOutboxOperation(ctx context.Context, qID string, event *model.NormalizedEvent, destinations []string, opID string) error {
	hints := model.AnalysisIdentityHints{"host": event.Raven.SourceID}
	return s.ResolveQuarantineWithOutboxOperationAndHints(ctx, qID, event, destinations, opID, hints)
}

func (s *RawStore) ResolveQuarantineWithOutboxOperationAndHints(ctx context.Context, qID string, event *model.NormalizedEvent, destinations []string, opID string, hints model.AnalysisIdentityHints) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	enabled, err := integrityEnabledTx(ctx, tx)
	if err != nil {
		return err
	}
	q, err := loadQuarantineTx(ctx, tx, qID)
	if err != nil {
		return fmt.Errorf("load quarantine for resolution: %w", err)
	}
	if !q.ReplayEligible {
		return ErrReplayIneligible
	}
	if q.RawID != event.Raven.RawID || q.RecordOrdinal != event.Raven.RecordOrdinal {
		return errors.New("quarantine identity does not match normalized child")
	}
	var quarantineSeq uint64
	if enabled {
		quarantineSeq, err = latestEntrySeqTx(ctx, tx, integrity.QuarantineWritten, q.RawID, q.RecordOrdinal, q.QuarantineID)
		if err != nil {
			return err
		}
		if quarantineSeq == 0 {
			return errors.New("quarantine entry has no integrity evidence")
		}
	}
	if err := storeNormalizedTx(ctx, tx, event, destinations); err != nil {
		return err
	}
	if s.analysisEnabled.Load() {
		var transport, sourceIP string
		if err := tx.QueryRowContext(ctx, `SELECT transport,source_ip FROM raw_events WHERE raw_id=?`, event.Raven.RawID).Scan(&transport, &sourceIP); err != nil {
			return fmt.Errorf("load replay source for analysis observation: %w", err)
		}
		hints = addSourceIP(hints, sourceIP)
		if err := appendAnalysisObservationTx(ctx, tx, "normalized", "normalized:"+event.Raven.EventID, time.Now().UTC(), event.Raven.RawID, event.Raven.EventID, "", event.Raven.RecordOrdinal, transport, hints); err != nil {
			return err
		}
	}
	var normalizedSeq any
	if enabled {
		seq, err := latestEntrySeqTx(ctx, tx, integrity.NormalizedWritten, event.Raven.RawID, event.Raven.RecordOrdinal, event.Raven.EventID)
		if err != nil {
			return err
		}
		if seq == 0 {
			return errors.New("normalized child has no integrity evidence")
		}
		normalizedSeq = seq
		content := []integrity.TypedField{fieldU64(1, quarantineSeq), fieldU64(2, seq)}
		snapshot, err := integrity.EncodeFields(content)
		if err != nil {
			return err
		}
		ordinal := uint32(q.RecordOrdinal)
		subject, rawID := q.QuarantineID, q.RawID
		previous := quarantineSeq
		metadata := []integrity.TypedField{fieldBytes32(1, event.Raven.ParserFileSHA256)}
		if _, err := appendEvidenceTx(ctx, tx, evidenceWrite{kind: integrity.ReplayResolved, subjectID: &subject, rawID: &rawID, childOrdinal: &ordinal, operationID: &opID, previousSubjectSeq: &previous, occurredAt: time.Now().UTC(), contentSnapshot: snapshot, contentFields: content, metadataFields: metadata}); err != nil {
			return fmt.Errorf("append replay resolution evidence: %w", err)
		}
	}
	resultJSON, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal replay result: %w", err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	completed, err := tx.ExecContext(ctx, `UPDATE integrity_operations SET state='completed',normalized_entry_seq=?,result_summary=?,completed_at=? WHERE operation_id=? AND state='running' AND quarantine_id=? AND raw_id=? AND child_ordinal=?`, normalizedSeq, string(resultJSON), now, opID, q.QuarantineID, q.RawID, q.RecordOrdinal)
	if err != nil {
		return fmt.Errorf("complete replay operation: %w", err)
	}
	if n, _ := completed.RowsAffected(); n != 1 {
		return errors.New("replay operation is missing or no longer running")
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM quarantine WHERE quarantine_id=? AND raw_id=? AND record_ordinal=?`, qID, event.Raven.RawID, event.Raven.RecordOrdinal)
	if err != nil {
		return fmt.Errorf("delete resolved quarantine entry: %w", err)
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return fmt.Errorf("quarantine entry %s was not resolved", qID)
	}
	var normalized, quarantined int64
	if err := tx.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM normalized_events WHERE raw_id=?),
		(SELECT COUNT(*) FROM quarantine WHERE raw_id=?)`, event.Raven.RawID, event.Raven.RawID).Scan(&normalized, &quarantined); err != nil {
		return err
	}
	status := model.StatusNormalized
	if normalized == 0 && quarantined > 0 {
		status = model.StatusQuarantined
	} else if quarantined > 0 {
		status = model.StatusPartial
	}
	if _, err := tx.ExecContext(ctx, `UPDATE raw_events SET status=? WHERE raw_id=?`, string(status), event.Raven.RawID); err != nil {
		return err
	}
	return tx.Commit()
}

func storeNormalizedTx(ctx context.Context, tx *sql.Tx, event *model.NormalizedEvent, destinations []string) error {
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal normalized event: %w", err)
	}
	eventTime := event.Raven.ReceivedTime.UnixMilli()
	switch v := event.OCSF["time"].(type) {
	case int64:
		eventTime = v
	case float64:
		eventTime = int64(v)
	case int:
		eventTime = int64(v)
	}
	severity, activity, msg := "", "", ""
	if v, ok := event.OCSF["severity_id"]; ok && v != nil {
		severity = fmt.Sprint(v)
	}
	if v, ok := event.OCSF["activity_name"].(string); ok {
		activity = v
	}
	if v, ok := event.OCSF["message"].(string); ok {
		msg = v
	}
	var existingID, existingJSON string
	existingErr := tx.QueryRowContext(ctx, "SELECT event_id,event_json FROM normalized_events WHERE raw_id=? AND record_ordinal=? LIMIT 1", event.Raven.RawID, event.Raven.RecordOrdinal).Scan(&existingID, &existingJSON)
	if existingErr != nil && !errors.Is(existingErr, sql.ErrNoRows) {
		return fmt.Errorf("read normalized child projection: %w", existingErr)
	}
	if existingErr == nil && existingID != "" {
		event.Raven.EventID = existingID
		data, err = json.Marshal(event)
		if err != nil {
			return fmt.Errorf("marshal normalized event with committed ID: %w", err)
		}
	}
	changed := existingErr != nil || existingJSON != string(data)
	sum := sha256.Sum256(data)
	_, err = tx.ExecContext(ctx, `INSERT INTO normalized_events(event_id,raw_id,record_ordinal,source_category,source_id,severity_id,activity_name,message,event_time,received_time,event_json,event_sha256) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(event_id) DO UPDATE SET source_category=excluded.source_category,source_id=excluded.source_id,severity_id=excluded.severity_id,activity_name=excluded.activity_name,message=excluded.message,event_time=excluded.event_time,received_time=excluded.received_time,event_json=excluded.event_json,event_sha256=excluded.event_sha256`, event.Raven.EventID, event.Raven.RawID, event.Raven.RecordOrdinal, event.Raven.SourceCategory, event.Raven.SourceID, severity, activity, msg, eventTime, event.Raven.ReceivedTime.Format(time.RFC3339Nano), string(data), hex.EncodeToString(sum[:]))
	if err != nil {
		return err
	}
	enabled, err := integrityEnabledTx(ctx, tx)
	if err != nil {
		return err
	}
	if enabled {
		if event.Raven.RecordOrdinal < 0 || int64(event.Raven.RecordOrdinal) > math.MaxInt32 {
			return errors.New("normalized child ordinal is outside the evidence codec range")
		}
		fields := normalizedMetadataFields(event)
		metadataSnapshot, err := integrity.EncodeFields(fields)
		if err != nil {
			return err
		}
		id, rawID := event.Raven.EventID, event.Raven.RawID
		ordinal := uint32(event.Raven.RecordOrdinal)
		previous, err := latestEntrySeqTx(ctx, tx, integrity.NormalizedWritten, rawID, event.Raven.RecordOrdinal, id)
		if err != nil {
			return err
		}
		evidenceChanged := changed
		if previous > 0 {
			var lastContent, lastMetadata []byte
			if err := tx.QueryRowContext(ctx, `SELECT content_snapshot,metadata_snapshot FROM integrity_entries WHERE stream_id=(SELECT stream_id FROM integrity_streams WHERE singleton=1) AND entry_seq=?`, previous).Scan(&lastContent, &lastMetadata); err != nil {
				return err
			}
			evidenceChanged = !equalBytes(lastContent, data) || !equalBytes(lastMetadata, metadataSnapshot)
		}
		var prev *uint64
		if previous > 0 {
			prev = &previous
		}
		if evidenceChanged {
			if _, err := appendEvidenceTx(ctx, tx, evidenceWrite{kind: integrity.NormalizedWritten, subjectID: &id, rawID: &rawID, childOrdinal: &ordinal, previousSubjectSeq: prev, occurredAt: time.Now().UTC(), contentSnapshot: data, metadataFields: fields}); err != nil {
				return fmt.Errorf("append normalized evidence: %w", err)
			}
		}
	}
	now := time.Now().UTC()
	for _, dest := range destinations {
		if _, err = tx.ExecContext(ctx, `INSERT INTO outbox(event_id,destination,payload,attempts,next_retry_at,status,created_at) VALUES(?,?,?,0,?,'pending',?) ON CONFLICT(event_id,destination) DO UPDATE SET payload=excluded.payload WHERE outbox.status!='delivered'`, event.Raven.EventID, dest, data, now, now); err != nil {
			return err
		}
	}
	return nil
}

func (s *RawStore) DB() *sql.DB { return s.db }

// CountCompletedChildren returns child outcomes already committed for a raw input.
func (s *RawStore) CountCompletedChildren(ctx context.Context, rawID string) (int64, error) {
	var count int64
	err := s.db.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM normalized_events WHERE raw_id=?) +
		(SELECT COUNT(*) FROM quarantine WHERE raw_id=?)`, rawID, rawID).Scan(&count)
	return count, err
}

func (s *RawStore) ChildOutcomeCounts(ctx context.Context, rawID string) (normalized, quarantined int64, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM normalized_events WHERE raw_id=?),
		(SELECT COUNT(*) FROM quarantine WHERE raw_id=?)`, rawID, rawID).Scan(&normalized, &quarantined)
	return
}

// HasCompletedChild reports whether normalization or quarantine has committed a child outcome.
func (s *RawStore) HasCompletedChild(ctx context.Context, rawID string, ordinal int) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM normalized_events WHERE raw_id=? AND record_ordinal=?) +
		(SELECT COUNT(*) FROM quarantine WHERE raw_id=? AND record_ordinal=?)`, rawID, ordinal, rawID, ordinal).Scan(&count)
	return count > 0, err
}

func (s *RawStore) CountRawStatus(ctx context.Context, status model.RawStatus) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM raw_events WHERE status=?", string(status)).Scan(&n)
	return n, err
}
func (s *RawStore) ListRawByStatus(ctx context.Context, status model.RawStatus) ([]*model.RawEvent, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT raw_id FROM raw_events WHERE status=? ORDER BY received_at", string(status))
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	// RawStore intentionally uses one SQLite connection. Close the ID cursor
	// before Retrieve opens another query or restart recovery will deadlock.
	if err := rows.Close(); err != nil {
		return nil, err
	}
	out := make([]*model.RawEvent, 0, len(ids))
	for _, id := range ids {
		e, err := s.Retrieve(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// ListNormalized retrieves paginated normalized events with optional category and severity filtering.
func (s *RawStore) ListNormalized(ctx context.Context, category, severity, search string, limit, offset int) ([]*model.NormalizedEvent, int, error) {
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	var conditions []string
	var args []any

	if category != "" && category != "all" {
		conditions = append(conditions, "source_category = ?")
		args = append(args, category)
	}
	if severity != "" && severity != "all" {
		conditions = append(conditions, "severity_id = ?")
		args = append(args, severity)
	}
	if search != "" {
		conditions = append(conditions, "(message LIKE ? OR source_id LIKE ? OR event_id LIKE ?)")
		pattern := "%" + search + "%"
		args = append(args, pattern, pattern, pattern)
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM normalized_events %s;", whereClause)
	var total int
	if err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count normalized events: %w", err)
	}

	dataQuery := fmt.Sprintf(`
		SELECT event_json
		FROM normalized_events
		%s
		ORDER BY event_time DESC
		LIMIT ? OFFSET ?;
	`, whereClause)

	dataArgs := append(args, limit, offset)
	rows, err := s.db.QueryContext(ctx, dataQuery, dataArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list normalized events: %w", err)
	}
	defer rows.Close()

	var events []*model.NormalizedEvent
	for rows.Next() {
		var jsonStr string
		if err := rows.Scan(&jsonStr); err != nil {
			return nil, 0, err
		}
		var evt model.NormalizedEvent
		if err := json.Unmarshal([]byte(jsonStr), &evt); err != nil {
			continue
		}
		events = append(events, &evt)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("failed to iterate normalized events: %w", err)
	}

	return events, total, nil
}

// GetNormalizedByID retrieves a single normalized event by its unique event ID.
func (s *RawStore) GetNormalizedByID(ctx context.Context, eventID string) (*model.NormalizedEvent, error) {
	query := `SELECT event_json FROM normalized_events WHERE event_id = ?;`
	var jsonStr string
	err := s.db.QueryRowContext(ctx, query, eventID).Scan(&jsonStr)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("event not found: %s", eventID)
		}
		return nil, fmt.Errorf("failed to query event %s: %w", eventID, err)
	}

	var evt model.NormalizedEvent
	if err := json.Unmarshal([]byte(jsonStr), &evt); err != nil {
		return nil, fmt.Errorf("failed to unmarshal event json: %w", err)
	}
	return &evt, nil
}

// NormalizedVerificationReport holds the cryptographic verification report for a normalized event.
type NormalizedVerificationReport struct {
	EventID         string `json:"event_id"`
	RawID           string `json:"raw_id"`
	StoredHash      string `json:"stored_hash"`
	ComputedHash    string `json:"computed_hash"`
	HashMatches     bool   `json:"hash_matches"`
	StoredMessage   string `json:"stored_message"`
	ExpectedMessage string `json:"expected_message"`
	MessageMatches  bool   `json:"message_matches"`
	RawValid        bool   `json:"raw_valid"`
	Passed          bool   `json:"passed"`
	Status          string `json:"status"`
	FailureReason   string `json:"failure_reason,omitempty"`
}

// VerifyNormalized verifies the cryptographic integrity of a normalized event:
// 1. Checks that sha256(event_json) matches event_sha256.
// 2. Checks that the column message matches the message declared in event_json.
// 3. Checks that the underlying raw wire datagram in raw_events is untampered.
func (s *RawStore) VerifyNormalized(ctx context.Context, eventID string) (*NormalizedVerificationReport, error) {
	query := `SELECT event_id, raw_id, message, event_json, event_sha256 FROM normalized_events WHERE event_id = ?;`
	var (
		evtID      string
		rawID      string
		colMsg     string
		eventJSON  string
		storedHash string
	)
	err := s.db.QueryRowContext(ctx, query, eventID).Scan(&evtID, &rawID, &colMsg, &eventJSON, &storedHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("normalized event not found: %s", eventID)
		}
		return nil, fmt.Errorf("query error for event %s: %w", eventID, err)
	}

	computed := sha256.Sum256([]byte(eventJSON))
	computedHex := hex.EncodeToString(computed[:])

	hashMatches := (storedHash != "" && computedHex == storedHash)

	// Extract message from event_json to check column integrity
	var parsed model.NormalizedEvent
	expectedMsg := ""
	if err := json.Unmarshal([]byte(eventJSON), &parsed); err == nil {
		if m, ok := parsed.OCSF["message"].(string); ok {
			expectedMsg = m
		}
	}
	messageMatches := (colMsg == expectedMsg)

	// Verify parent raw bytes independently; decoded messages need not be literal wire substrings.
	rawMatches, _, rawErr := s.Verify(ctx, rawID)
	rawValid := (rawErr == nil && rawMatches)
	passed := hashMatches && messageMatches && rawValid

	report := &NormalizedVerificationReport{
		EventID:         evtID,
		RawID:           rawID,
		StoredHash:      storedHash,
		ComputedHash:    computedHex,
		HashMatches:     hashMatches,
		StoredMessage:   colMsg,
		ExpectedMessage: expectedMsg,
		MessageMatches:  messageMatches,
		RawValid:        rawValid,
		Passed:          passed,
		Status:          "PASSED",
	}

	if !passed {
		report.Status = "TAMPER DETECTED"
		var reasons []string
		if !hashMatches {
			reasons = append(reasons, "event_json payload was modified (hash mismatch)")
		}
		if !messageMatches {
			reasons = append(reasons, fmt.Sprintf("message column (%q) does not match event_json payload (%q)", colMsg, expectedMsg))
		}
		if !rawValid {
			reasons = append(reasons, "parent raw event wire bytes were modified or corrupted")
		}
		report.FailureReason = strings.Join(reasons, "; ")
	}

	return report, nil
}

// ListQuarantinePaged retrieves a paginated list of dead-letter quarantine entries.
func (s *RawStore) ListQuarantinePaged(ctx context.Context, limit, offset int) ([]model.QuarantineEntry, int, error) {
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM quarantine;").Scan(&total); err != nil {
		return nil, 0, err
	}

	query := `
	SELECT quarantine_id, raw_id, record_ordinal, raw_sha256, stage, reason, error_details, raw_preview, candidate_packs, replay_eligible, quarantined_at, replayed_at
	FROM quarantine
	ORDER BY quarantined_at DESC
	LIMIT ? OFFSET ?;
	`
	rows, err := s.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var entries []model.QuarantineEntry
	for rows.Next() {
		var (
			e            model.QuarantineEntry
			candidateStr sql.NullString
			replayInt    int
			qAtStr       string
			rAtStr       sql.NullString
		)
		err := rows.Scan(
			&e.QuarantineID,
			&e.RawID,
			&e.RecordOrdinal,
			&e.RawSHA256,
			&e.Stage,
			&e.Reason,
			&e.ErrorDetails,
			&e.RawPreview,
			&candidateStr,
			&replayInt,
			&qAtStr,
			&rAtStr,
		)
		if err != nil {
			return nil, 0, err
		}

		if candidateStr.Valid && candidateStr.String != "" {
			e.CandidatePacks = strings.Split(candidateStr.String, ",")
		}
		e.ReplayEligible = (replayInt == 1)
		t, _ := time.Parse(time.RFC3339Nano, qAtStr)
		e.QuarantinedAt = t
		if rAtStr.Valid {
			rt, _ := time.Parse(time.RFC3339Nano, rAtStr.String)
			e.ReplayedAt = &rt
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("failed to iterate quarantine entries: %w", err)
	}

	return entries, total, nil
}

// ListSources returns an aggregated inventory of active data sources.
func (s *RawStore) ListSources(ctx context.Context) ([]map[string]any, error) {
	query := `
	SELECT 
		source_category,
		source_id,
		COUNT(*) as event_count,
		MAX(received_time) as last_seen
	FROM normalized_events
	GROUP BY source_category, source_id
	ORDER BY event_count DESC;
	`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sources []map[string]any
	for rows.Next() {
		var (
			category string
			sourceID string
			count    int64
			lastSeen string
		)
		if err := rows.Scan(&category, &sourceID, &count, &lastSeen); err != nil {
			return nil, err
		}
		sources = append(sources, map[string]any{
			"category":  category,
			"source_id": sourceID,
			"events":    count,
			"last_seen": lastSeen,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate sources: %w", err)
	}
	return sources, nil
}

// Ping verifies that the underlying SQLite database handle is healthy.
func (s *RawStore) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// Close closes the underlying SQLite database handle.
func (s *RawStore) Close() error {
	s.stopIntegrityAudits()
	s.witnessMu.Lock()
	if s.witnessStop != nil {
		s.witnessStop()
	}
	s.witnessMu.Unlock()
	s.witnessWG.Wait()
	s.stopIntegritySealer()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	_, sealErr := s.SealIntegrityPending(ctx, shutdownBatches)
	cancel()
	var auditErr error
	if s.auditDB != nil {
		auditErr = s.auditDB.Close()
	}
	return errors.Join(sealErr, auditErr, s.db.Close())
}
