package rawstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"raven/internal/model"
)

const maxAnalysisIdentityHintBytes = 256

// AnalysisObservation is a small pointer to an existing RAVEN record. It never
// contains raw bytes or normalized event JSON.
type AnalysisObservation struct {
	ID            int64
	Kind          string
	OccurredAt    time.Time
	RawID         string
	EventID       string
	QuarantineID  string
	RecordOrdinal int
	Transport     string
	IdentityHints model.AnalysisIdentityHints
}

type AnalysisResolution struct {
	SourceKey   string
	Resolution  string
	DeviceID    string
	MatchMethod string
	Confidence  string
}

type AnalysisSource struct {
	SourceKey        string
	IdentityHints    model.AnalysisIdentityHints
	Resolution       string
	DeviceID         string
	MatchMethod      string
	Confidence       string
	FirstSeenAt      time.Time
	LastSeenAt       time.Time
	ObservationCount int64
	LastObservation  int64
}

type AnalysisQueueStatus struct {
	Pending       int64
	OldestPending time.Time
	CheckpointID  int64
}

var ErrAnalysisCheckpointConflict = errors.New("analysis checkpoint changed while processing batch")

// SetAnalysisEnabled controls whether new lifecycle outcomes are appended to
// the durable analysis outbox. Existing backlog remains available when disabled.
func (s *RawStore) SetAnalysisEnabled(enabled bool) {
	s.analysisEnabled.Store(enabled)
}

func sanitizeAnalysisHints(hints model.AnalysisIdentityHints) model.AnalysisIdentityHints {
	clean := make(model.AnalysisIdentityHints, 4)
	for _, key := range []string{"syslog_host", "host", "server", "source_ip"} {
		value := strings.TrimSpace(hints[key])
		if value == "" {
			continue
		}
		if len(value) > maxAnalysisIdentityHintBytes {
			value = value[:maxAnalysisIdentityHintBytes]
		}
		clean[key] = value
	}
	return clean
}

func addSourceIP(hints model.AnalysisIdentityHints, sourceIP string) model.AnalysisIdentityHints {
	merged := make(model.AnalysisIdentityHints, len(hints)+1)
	for key, value := range hints {
		merged[key] = value
	}
	if sourceIP != "" {
		merged["source_ip"] = sourceIP
	}
	return merged
}

func appendAnalysisObservationTx(ctx context.Context, tx *sql.Tx, kind, key string, at time.Time, rawID, eventID, quarantineID string, ordinal int, transport string, hints model.AnalysisIdentityHints) error {
	if kind != "raw_received" && kind != "normalized" && kind != "quarantined" {
		return fmt.Errorf("invalid analysis observation kind %q", kind)
	}
	if ordinal < 0 || ordinal > int(^uint32(0)>>1) {
		return fmt.Errorf("analysis record ordinal is out of range: %d", ordinal)
	}
	encoded, err := json.Marshal(sanitizeAnalysisHints(hints))
	if err != nil {
		return fmt.Errorf("encode analysis identity hints: %w", err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO analysis_observations(observation_key,kind,occurred_at,raw_id,event_id,quarantine_id,record_ordinal,transport,identity_hints_json)
		VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(observation_key) DO NOTHING`, key, kind, at.UTC().Format(time.RFC3339Nano), rawID, nullableString(eventID), nullableString(quarantineID), ordinal, transport, string(encoded))
	if err != nil {
		return fmt.Errorf("append analysis observation %s: %w", key, err)
	}
	return nil
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

// AnalysisBatch returns the next bounded, uncheckpointed batch in insertion order.
func (s *RawStore) AnalysisBatch(ctx context.Context, limit int) ([]AnalysisObservation, int64, error) {
	if limit <= 0 || limit > 512 {
		return nil, 0, errors.New("analysis batch limit must be between 1 and 512")
	}
	var checkpoint int64
	if err := s.db.QueryRowContext(ctx, `SELECT checkpoint_id FROM analysis_worker_state WHERE singleton=1`).Scan(&checkpoint); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT observation_id,kind,occurred_at,raw_id,COALESCE(event_id,''),COALESCE(quarantine_id,''),record_ordinal,transport,identity_hints_json
		FROM analysis_observations WHERE observation_id>? ORDER BY observation_id LIMIT ?`, checkpoint, limit)
	if err != nil {
		return nil, checkpoint, err
	}
	defer rows.Close()
	observations := make([]AnalysisObservation, 0, limit)
	for rows.Next() {
		var observation AnalysisObservation
		var occurredAt, hintsJSON string
		if err := rows.Scan(&observation.ID, &observation.Kind, &occurredAt, &observation.RawID, &observation.EventID, &observation.QuarantineID, &observation.RecordOrdinal, &observation.Transport, &hintsJSON); err != nil {
			return nil, checkpoint, err
		}
		observation.OccurredAt, err = time.Parse(time.RFC3339Nano, occurredAt)
		if err != nil {
			return nil, checkpoint, fmt.Errorf("parse analysis observation %d timestamp: %w", observation.ID, err)
		}
		if err := json.Unmarshal([]byte(hintsJSON), &observation.IdentityHints); err != nil {
			return nil, checkpoint, fmt.Errorf("decode analysis observation %d identity hints: %w", observation.ID, err)
		}
		observations = append(observations, observation)
	}
	if err := rows.Err(); err != nil {
		return nil, checkpoint, err
	}
	return observations, checkpoint, nil
}

// CommitAnalysisBatch stores idempotent source identity projections and advances
// the durable cursor atomically, so a restart replays either the whole batch or none.
func (s *RawStore) CommitAnalysisBatch(ctx context.Context, expectedCheckpoint int64, observations []AnalysisObservation, resolutions []AnalysisResolution) error {
	if len(observations) == 0 || len(observations) != len(resolutions) {
		return errors.New("analysis observations and resolutions must have the same non-zero length")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var checkpoint int64
	if err := tx.QueryRowContext(ctx, `SELECT checkpoint_id FROM analysis_worker_state WHERE singleton=1`).Scan(&checkpoint); err != nil {
		return err
	}
	if checkpoint != expectedCheckpoint {
		return ErrAnalysisCheckpointConflict
	}
	var available int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM analysis_observations WHERE observation_id>? AND observation_id<=?`, expectedCheckpoint, observations[len(observations)-1].ID).Scan(&available); err != nil {
		return err
	}
	if available != len(observations) {
		return errors.New("analysis batch does not contain every observation before its checkpoint")
	}
	previousID := checkpoint
	for i, observation := range observations {
		resolution := resolutions[i]
		if observation.ID <= previousID || resolution.SourceKey != AnalysisSourceKey(observation.IdentityHints) || (resolution.Resolution != "matched" && resolution.Resolution != "unknown" && resolution.Resolution != "ambiguous") {
			return fmt.Errorf("invalid analysis batch item %d", i)
		}
		if len(resolution.MatchMethod) == 0 || len(resolution.MatchMethod) > 64 || len(resolution.DeviceID) > 128 {
			return fmt.Errorf("invalid analysis match metadata at batch item %d", i)
		}
		if resolution.Confidence != "strong" && resolution.Confidence != "weak" && resolution.Confidence != "none" {
			return fmt.Errorf("invalid analysis confidence %q", resolution.Confidence)
		}
		if resolution.Resolution == "matched" && resolution.DeviceID == "" {
			return errors.New("matched analysis identity has no device ID")
		}
		if resolution.Resolution != "matched" && resolution.DeviceID != "" {
			return errors.New("unmatched analysis identity must not have a device ID")
		}
		if (resolution.Resolution == "matched") == (resolution.Confidence == "none") {
			return errors.New("analysis confidence does not agree with identity resolution")
		}
		hints, err := json.Marshal(sanitizeAnalysisHints(observation.IdentityHints))
		if err != nil {
			return err
		}
		var existingLink int
		linkErr := tx.QueryRowContext(ctx, `SELECT 1 FROM analysis_observation_sources WHERE observation_id=?`, observation.ID).Scan(&existingLink)
		if errors.Is(linkErr, sql.ErrNoRows) {
			if _, err := tx.ExecContext(ctx, `INSERT INTO analysis_sources(source_key,identity_hints_json,resolution,device_id,match_method,confidence,first_seen_at,last_seen_at,observation_count,last_observation_id)
				VALUES(?,?,?,?,?,?,?,?,1,?) ON CONFLICT(source_key) DO UPDATE SET identity_hints_json=excluded.identity_hints_json,resolution=excluded.resolution,device_id=excluded.device_id,match_method=excluded.match_method,confidence=excluded.confidence,last_seen_at=excluded.last_seen_at,observation_count=analysis_sources.observation_count+1,last_observation_id=excluded.last_observation_id`, resolution.SourceKey, string(hints), resolution.Resolution, nullableString(resolution.DeviceID), resolution.MatchMethod, resolution.Confidence, observation.OccurredAt.UTC().Format(time.RFC3339Nano), observation.OccurredAt.UTC().Format(time.RFC3339Nano), observation.ID); err != nil {
				return err
			}
		} else if linkErr != nil {
			return linkErr
		} else {
			continue
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO analysis_observation_sources(observation_id,source_key,resolution,device_id,match_method,confidence)
			VALUES(?,?,?,?,?,?)`, observation.ID, resolution.SourceKey, resolution.Resolution, nullableString(resolution.DeviceID), resolution.MatchMethod, resolution.Confidence); err != nil {
			return err
		}
		previousID = observation.ID
	}
	result, err := tx.ExecContext(ctx, `UPDATE analysis_worker_state SET checkpoint_id=?,updated_at=? WHERE singleton=1 AND checkpoint_id=?`, previousID, time.Now().UTC().Format(time.RFC3339Nano), expectedCheckpoint)
	if err != nil {
		return err
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return ErrAnalysisCheckpointConflict
	}
	return tx.Commit()
}

// AnalysisStatus reports the persisted worker cursor and the oldest pending age.
func (s *RawStore) AnalysisStatus(ctx context.Context) (AnalysisQueueStatus, error) {
	var status AnalysisQueueStatus
	var oldest sql.NullString
	if err := s.db.QueryRowContext(ctx, `SELECT checkpoint_id FROM analysis_worker_state WHERE singleton=1`).Scan(&status.CheckpointID); err != nil {
		return status, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*),MIN(occurred_at) FROM analysis_observations WHERE observation_id>?`, status.CheckpointID).Scan(&status.Pending, &oldest); err != nil {
		return status, err
	}
	if oldest.Valid {
		parsed, err := time.Parse(time.RFC3339Nano, oldest.String)
		if err != nil {
			return status, fmt.Errorf("parse oldest pending analysis timestamp: %w", err)
		}
		status.OldestPending = parsed
	}
	return status, nil
}

// ListAnalysisSources pages matched, unknown, or ambiguous source identities.
func (s *RawStore) ListAnalysisSources(ctx context.Context, resolution string, limit, offset int) ([]AnalysisSource, error) {
	if limit <= 0 || limit > 500 || offset < 0 {
		return nil, errors.New("analysis source limit must be between 1 and 500 and offset must be non-negative")
	}
	query := `SELECT source_key,identity_hints_json,resolution,COALESCE(device_id,''),match_method,confidence,first_seen_at,last_seen_at,observation_count,last_observation_id FROM analysis_sources`
	args := []any{}
	if resolution != "" {
		if resolution != "matched" && resolution != "unknown" && resolution != "ambiguous" {
			return nil, fmt.Errorf("invalid analysis source resolution %q", resolution)
		}
		query += ` WHERE resolution=?`
		args = append(args, resolution)
	}
	query += ` ORDER BY last_seen_at DESC,source_key LIMIT ? OFFSET ?`
	args = append(args, limit, offset)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sources := make([]AnalysisSource, 0)
	for rows.Next() {
		var source AnalysisSource
		var hints, first, last string
		if err := rows.Scan(&source.SourceKey, &hints, &source.Resolution, &source.DeviceID, &source.MatchMethod, &source.Confidence, &first, &last, &source.ObservationCount, &source.LastObservation); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(hints), &source.IdentityHints); err != nil {
			return nil, err
		}
		source.FirstSeenAt, _ = time.Parse(time.RFC3339Nano, first)
		source.LastSeenAt, _ = time.Parse(time.RFC3339Nano, last)
		sources = append(sources, source)
	}
	return sources, rows.Err()
}

func AnalysisSourceKey(hints model.AnalysisIdentityHints) string {
	hints = sanitizeAnalysisHints(hints)
	keys := make([]string, 0, len(hints))
	for key := range hints {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	canonical := make([][2]string, 0, len(keys))
	for _, key := range keys {
		canonical = append(canonical, [2]string{key, hints[key]})
	}
	encoded, _ := json.Marshal(canonical)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
