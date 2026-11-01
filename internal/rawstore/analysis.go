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
	SourceKey     string
	Resolution    string
	DeviceID      string
	MatchMethod   string
	Confidence    string
	HeartbeatRule string
	Findings      []AnalysisFindingEvaluation
	WindowSamples []AnalysisWindowSample
}

type AnalysisWindowSample struct {
	RuleID, OwnerType, OwnerID, InstanceKey, EventID, RawID, Outcome string
	SourceKey, DeviceID, RuleVersion, Severity, State, Title         string
	RecordOrdinal, CountAtLeast, ClearBelow, Consecutive             int
	RatioAtLeast, ClearRatio                                         float64
	Duration, For, ClearAfter                                        time.Duration
	OccurredAt, EvaluatedAt                                          time.Time
	Matched                                                          bool
}

type AnalysisHeartbeatEvidence struct {
	DeviceID, SourceKey, EventID, RawID string
	ObservationID                       int64
	RecordOrdinal                       int
	OccurredAt                          time.Time
}

type AnalysisSource struct {
	SourceKey        string                      `json:"source_key"`
	IdentityHints    model.AnalysisIdentityHints `json:"identity_hints"`
	Resolution       string                      `json:"resolution"`
	DeviceID         string                      `json:"device_id,omitempty"`
	MatchMethod      string                      `json:"match_method"`
	Confidence       string                      `json:"confidence"`
	FirstSeenAt      time.Time                   `json:"first_seen_at"`
	LastSeenAt       time.Time                   `json:"last_seen_at"`
	ObservationCount int64                       `json:"observation_count"`
	LastObservation  int64                       `json:"last_observation_id"`
}

type AnalysisDeviceTelemetry struct {
	DeviceID             string
	LastReceivedAt       time.Time
	LastNormalizedAt     time.Time
	LastQuarantinedAt    time.Time
	LastHeartbeatAt      time.Time
	ReceivedCount        int64
	NormalizedCount      int64
	QuarantinedCount     int64
	HeartbeatCount       int64
	ReceivedPerMinute    float64
	NormalizedPerMinute  float64
	QuarantinedPerMinute float64
	IdentityConfidence   string
	MatchMethod          string
	LastObservationAt    time.Time
	UpdatedAt            time.Time
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
		if len(resolution.MatchMethod) == 0 || len(resolution.MatchMethod) > 64 || len(resolution.DeviceID) > 128 || len(resolution.HeartbeatRule) > 128 {
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
			previousID = observation.ID
			continue
		}
		if resolution.Resolution == "matched" {
			if err := upsertAnalysisDeviceTelemetry(ctx, tx, observation, resolution); err != nil {
				return err
			}
		}
		for _, finding := range resolution.Findings {
			if finding.SourceKey != resolution.SourceKey || finding.DeviceID != resolution.DeviceID || finding.EventID != observation.EventID || finding.RawID != observation.RawID || finding.RecordOrdinal != observation.RecordOrdinal {
				return fmt.Errorf("analysis finding evidence does not match observation %d", observation.ID)
			}
			if finding.ClearIfLatestHeartbeat {
				var latest int64
				if err := tx.QueryRowContext(ctx, `SELECT last_heartbeat_observation_id FROM analysis_device_telemetry WHERE device_id=?`, resolution.DeviceID).Scan(&latest); err != nil {
					return err
				}
				if latest != observation.ID {
					continue
				}
			}
			if err := applyAnalysisFindingTx(ctx, tx, observation.ID, finding); err != nil {
				return fmt.Errorf("apply analysis finding for observation %d: %w", observation.ID, err)
			}
		}
		for _, sample := range resolution.WindowSamples {
			if sample.SourceKey != resolution.SourceKey || sample.DeviceID != resolution.DeviceID || sample.EventID != observation.EventID || sample.RawID != observation.RawID || sample.RecordOrdinal != observation.RecordOrdinal {
				return fmt.Errorf("analysis window evidence does not match observation %d", observation.ID)
			}
			if err := applyAnalysisWindowSampleTx(ctx, tx, observation.ID, sample); err != nil {
				return fmt.Errorf("apply analysis window sample for observation %d: %w", observation.ID, err)
			}
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
	if _, err := tx.ExecContext(ctx, `DELETE FROM analysis_device_minute_buckets WHERE bucket_start<?`, time.Now().UTC().Add(-time.Hour).Truncate(time.Minute).Format(time.RFC3339)); err != nil {
		return fmt.Errorf("prune expired device rate buckets: %w", err)
	}
	return tx.Commit()
}

func upsertAnalysisDeviceTelemetry(ctx context.Context, tx *sql.Tx, observation AnalysisObservation, resolution AnalysisResolution) error {
	if resolution.HeartbeatRule != "" && (observation.Kind != "normalized" || resolution.Resolution != "matched") {
		return errors.New("heartbeat signal must refer to a matched normalized observation")
	}
	at := observation.OccurredAt.UTC().Format(time.RFC3339Nano)
	bucket := observation.OccurredAt.UTC().Truncate(time.Minute).Format(time.RFC3339)
	var receivedAt, normalizedAt, quarantinedAt, heartbeatAt any
	switch observation.Kind {
	case "raw_received":
		receivedAt = at
	case "normalized":
		normalizedAt = at
		if resolution.HeartbeatRule != "" {
			heartbeatAt = at
		}
	case "quarantined":
		quarantinedAt = at
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO analysis_device_telemetry(
		device_id,last_received_at,last_normalized_at,last_quarantined_at,last_heartbeat_at,
		received_count,normalized_count,quarantined_count,heartbeat_count,identity_confidence,
		match_method,last_observation_at,updated_at
	) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
	ON CONFLICT(device_id) DO UPDATE SET
		last_received_at=CASE WHEN excluded.last_received_at IS NULL THEN analysis_device_telemetry.last_received_at WHEN analysis_device_telemetry.last_received_at IS NULL OR excluded.last_received_at>analysis_device_telemetry.last_received_at THEN excluded.last_received_at ELSE analysis_device_telemetry.last_received_at END,
		last_normalized_at=CASE WHEN excluded.last_normalized_at IS NULL THEN analysis_device_telemetry.last_normalized_at WHEN analysis_device_telemetry.last_normalized_at IS NULL OR excluded.last_normalized_at>analysis_device_telemetry.last_normalized_at THEN excluded.last_normalized_at ELSE analysis_device_telemetry.last_normalized_at END,
		last_quarantined_at=CASE WHEN excluded.last_quarantined_at IS NULL THEN analysis_device_telemetry.last_quarantined_at WHEN analysis_device_telemetry.last_quarantined_at IS NULL OR excluded.last_quarantined_at>analysis_device_telemetry.last_quarantined_at THEN excluded.last_quarantined_at ELSE analysis_device_telemetry.last_quarantined_at END,
		last_heartbeat_at=CASE WHEN excluded.last_heartbeat_at IS NULL THEN analysis_device_telemetry.last_heartbeat_at WHEN analysis_device_telemetry.last_heartbeat_at IS NULL OR excluded.last_heartbeat_at>analysis_device_telemetry.last_heartbeat_at THEN excluded.last_heartbeat_at ELSE analysis_device_telemetry.last_heartbeat_at END,
		received_count=analysis_device_telemetry.received_count+excluded.received_count,
		normalized_count=analysis_device_telemetry.normalized_count+excluded.normalized_count,
		quarantined_count=analysis_device_telemetry.quarantined_count+excluded.quarantined_count,
		heartbeat_count=analysis_device_telemetry.heartbeat_count+excluded.heartbeat_count,
		identity_confidence=CASE WHEN excluded.last_observation_at>=analysis_device_telemetry.last_observation_at THEN excluded.identity_confidence ELSE analysis_device_telemetry.identity_confidence END,
		match_method=CASE WHEN excluded.last_observation_at>=analysis_device_telemetry.last_observation_at THEN excluded.match_method ELSE analysis_device_telemetry.match_method END,
		last_observation_at=MAX(analysis_device_telemetry.last_observation_at,excluded.last_observation_at),
		updated_at=MAX(analysis_device_telemetry.updated_at,excluded.updated_at)`, resolution.DeviceID, receivedAt, normalizedAt, quarantinedAt, heartbeatAt, boolCount(observation.Kind == "raw_received"), boolCount(observation.Kind == "normalized"), boolCount(observation.Kind == "quarantined"), boolCount(resolution.HeartbeatRule != ""), resolution.Confidence, resolution.MatchMethod, at, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("update device telemetry %s: %w", resolution.DeviceID, err)
	}
	if resolution.HeartbeatRule != "" {
		if _, err := tx.ExecContext(ctx, `UPDATE analysis_device_telemetry SET last_heartbeat_observation_id=? WHERE device_id=? AND last_heartbeat_at=? AND (? > last_heartbeat_observation_id OR last_heartbeat_observation_id=0)`, observation.ID, resolution.DeviceID, at, observation.ID); err != nil {
			return fmt.Errorf("store heartbeat evidence pointer %s: %w", resolution.DeviceID, err)
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO analysis_device_minute_buckets(device_id,bucket_start,received_count,normalized_count,quarantined_count)
		VALUES(?,?,?,?,?) ON CONFLICT(device_id,bucket_start) DO UPDATE SET
		received_count=analysis_device_minute_buckets.received_count+excluded.received_count,
		normalized_count=analysis_device_minute_buckets.normalized_count+excluded.normalized_count,
		quarantined_count=analysis_device_minute_buckets.quarantined_count+excluded.quarantined_count`, resolution.DeviceID, bucket, boolCount(observation.Kind == "raw_received"), boolCount(observation.Kind == "normalized"), boolCount(observation.Kind == "quarantined"))
	if err != nil {
		return fmt.Errorf("update device event-rate bucket %s: %w", resolution.DeviceID, err)
	}
	return nil
}

func boolCount(value bool) int {
	if value {
		return 1
	}
	return 0
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

func (s *RawStore) ListAnalysisHeartbeatEvidence(ctx context.Context, afterDeviceID string, limit int) ([]AnalysisHeartbeatEvidence, error) {
	if limit < 1 || limit > 512 {
		return nil, errors.New("analysis heartbeat query limit must be between 1 and 512")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT t.device_id,aos.source_key,o.observation_id,COALESCE(o.event_id,''),o.raw_id,o.record_ordinal,o.occurred_at FROM analysis_device_telemetry t JOIN analysis_observations o ON o.observation_id=t.last_heartbeat_observation_id JOIN analysis_observation_sources aos ON aos.observation_id=o.observation_id WHERE t.heartbeat_count>0 AND t.last_heartbeat_observation_id>0 AND t.device_id>? ORDER BY t.device_id LIMIT ?`, afterDeviceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]AnalysisHeartbeatEvidence, 0)
	for rows.Next() {
		var item AnalysisHeartbeatEvidence
		var at string
		if err := rows.Scan(&item.DeviceID, &item.SourceKey, &item.ObservationID, &item.EventID, &item.RawID, &item.RecordOrdinal, &at); err != nil {
			return nil, err
		}
		item.OccurredAt, err = time.Parse(time.RFC3339Nano, at)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// ListAnalysisSources pages matched, unknown, or ambiguous source identities.
func (s *RawStore) ListAnalysisSources(ctx context.Context, resolution string, limit, offset int) ([]AnalysisSource, error) {
	if limit <= 0 || limit > 500 || offset < 0 {
		return nil, errors.New("analysis source limit must be between 1 and 500 and offset must be non-negative")
	}
	query := `SELECT source_key,identity_hints_json,resolution,COALESCE(device_id,''),match_method,confidence,first_seen_at,last_seen_at,observation_count,last_observation_id FROM analysis_sources`
	args := []any{}
	if resolution != "" {
		if resolution != "matched" && resolution != "unknown" && resolution != "ambiguous" && resolution != "unassigned" {
			return nil, fmt.Errorf("invalid analysis source resolution %q", resolution)
		}
		if resolution == "unassigned" {
			query += ` WHERE resolution IN ('unknown','ambiguous')`
		} else {
			query += ` WHERE resolution=?`
			args = append(args, resolution)
		}
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

func (s *RawStore) CountAnalysisSources(ctx context.Context, resolution string) (int64, error) {
	query := `SELECT COUNT(*) FROM analysis_sources`
	var args []any
	switch resolution {
	case "":
	case "unassigned":
		query += ` WHERE resolution IN ('unknown','ambiguous')`
	case "matched", "unknown", "ambiguous":
		query += ` WHERE resolution=?`
		args = append(args, resolution)
	default:
		return 0, fmt.Errorf("invalid analysis source resolution %q", resolution)
	}
	var count int64
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&count)
	return count, err
}

func (s *RawStore) ListAnalysisDeviceTelemetry(ctx context.Context, deviceIDs []string) (map[string]AnalysisDeviceTelemetry, error) {
	result := make(map[string]AnalysisDeviceTelemetry, len(deviceIDs))
	if len(deviceIDs) == 0 {
		return result, nil
	}
	if len(deviceIDs) > 500 {
		return nil, errors.New("analysis device telemetry query is limited to 500 IDs")
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(deviceIDs)), ",")
	args := make([]any, len(deviceIDs))
	for i, id := range deviceIDs {
		args[i] = id
	}
	since := time.Now().UTC().Truncate(time.Minute).Add(-4 * time.Minute).Format(time.RFC3339)
	rows, err := s.db.QueryContext(ctx, `SELECT t.device_id,COALESCE(t.last_received_at,''),COALESCE(t.last_normalized_at,''),COALESCE(t.last_quarantined_at,''),COALESCE(t.last_heartbeat_at,''),t.received_count,t.normalized_count,t.quarantined_count,t.heartbeat_count,t.identity_confidence,t.match_method,t.last_observation_at,t.updated_at,
		COALESCE(SUM(b.received_count),0)/5.0,COALESCE(SUM(b.normalized_count),0)/5.0,COALESCE(SUM(b.quarantined_count),0)/5.0
		FROM analysis_device_telemetry t LEFT JOIN analysis_device_minute_buckets b ON b.device_id=t.device_id AND b.bucket_start>=?
		WHERE t.device_id IN (`+placeholders+") GROUP BY t.device_id", append([]any{since}, args...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var item AnalysisDeviceTelemetry
		var received, normalized, quarantined, heartbeat string
		var last, updated string
		if err := rows.Scan(&item.DeviceID, &received, &normalized, &quarantined, &heartbeat, &item.ReceivedCount, &item.NormalizedCount, &item.QuarantinedCount, &item.HeartbeatCount, &item.IdentityConfidence, &item.MatchMethod, &last, &updated, &item.ReceivedPerMinute, &item.NormalizedPerMinute, &item.QuarantinedPerMinute); err != nil {
			return nil, err
		}
		for _, timestamp := range []struct {
			value  string
			target *time.Time
		}{{received, &item.LastReceivedAt}, {normalized, &item.LastNormalizedAt}, {quarantined, &item.LastQuarantinedAt}, {heartbeat, &item.LastHeartbeatAt}, {last, &item.LastObservationAt}, {updated, &item.UpdatedAt}} {
			if timestamp.value == "" {
				continue
			}
			parsed, err := time.Parse(time.RFC3339Nano, timestamp.value)
			if err != nil {
				return nil, fmt.Errorf("parse analysis device telemetry timestamp: %w", err)
			}
			*timestamp.target = parsed
		}
		result[item.DeviceID] = item
	}
	return result, rows.Err()
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
