package rawstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

type AnalysisFindingEvaluation struct {
	RuleID, RuleVersion, OwnerType, OwnerID, InstanceKey, DeviceID, SourceKey string
	EventID, RawID, Severity, State, Title, Action                            string
	RecordOrdinal                                                             int
	OccurredAt                                                                time.Time
	ClearAfter                                                                time.Duration
	Matched, ClearMatched, CancelClear                                        bool
	ClearIfLatestHeartbeat                                                    bool
}

type AnalysisFinding struct {
	ID              string     `json:"id"`
	OwnerType       string     `json:"owner_type"`
	OwnerID         string     `json:"owner_id"`
	DeviceID        string     `json:"device_id,omitempty"`
	SourceKey       string     `json:"source_key"`
	RuleID          string     `json:"rule_id"`
	InstanceKey     string     `json:"instance_key,omitempty"`
	RuleVersion     string     `json:"rule_version"`
	Status          string     `json:"status"`
	Severity        string     `json:"severity"`
	State           string     `json:"state"`
	Title           string     `json:"title"`
	FirstSeenAt     time.Time  `json:"first_seen_at"`
	LastSeenAt      time.Time  `json:"last_seen_at"`
	LastEventID     string     `json:"last_event_id"`
	LastRawID       string     `json:"last_raw_id"`
	RecordOrdinal   int        `json:"record_ordinal"`
	OccurrenceCount int64      `json:"occurrence_count"`
	ClearSince      *time.Time `json:"clear_since,omitempty"`
	ClearDeadline   *time.Time `json:"clear_deadline,omitempty"`
	ResolvedAt      *time.Time `json:"resolved_at,omitempty"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

type AnalysisFindingFilter struct {
	Status, RuleID, DeviceID string
	Since                    *time.Time
}

type AnalysisFindingHistory struct {
	ID            int64     `json:"id"`
	FindingID     string    `json:"finding_id"`
	ObservationID int64     `json:"observation_id"`
	Action        string    `json:"action"`
	OccurredAt    time.Time `json:"occurred_at"`
	EventID       string    `json:"event_id"`
	RawID         string    `json:"raw_id"`
	RecordOrdinal int       `json:"record_ordinal"`
	RuleVersion   string    `json:"rule_version"`
	Severity      string    `json:"severity"`
	State         string    `json:"state"`
	Title         string    `json:"title"`
}

type AnalysisWindowCandidate struct {
	RuleID, OwnerType, OwnerID, InstanceKey      string
	DeviceID, SourceKey, EventID, RawID, Outcome string
	ObservationID                                int64
	CursorID                                     int64
	RecordOrdinal                                int
	OccurredAt                                   time.Time
	Matched                                      bool
}

type AnalysisDeadlineFinding struct {
	ObservationID int64
	Finding       AnalysisFindingEvaluation
	WindowSample  *AnalysisWindowSample
}

func (s *RawStore) ListAnalysisWindowCandidates(ctx context.Context, ruleIDs []string, after int64, limit int) ([]AnalysisWindowCandidate, error) {
	if len(ruleIDs) == 0 || len(ruleIDs) > 500 || limit < 1 || limit > 512 {
		return nil, errors.New("invalid analysis window candidate query")
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ruleIDs)), ",")
	args := make([]any, 0, len(ruleIDs)+2)
	for _, id := range ruleIDs {
		args = append(args, id)
	}
	args = append(args, after, limit)
	rows, err := s.db.QueryContext(ctx, `SELECT s.rule_id,s.owner_type,s.owner_id,s.instance_key,COALESCE(aos.device_id,''),COALESCE(aos.source_key,''),s.observation_id,s.occurred_at,s.outcome,s.event_id,s.raw_id,s.record_ordinal,s.matched,s.observation_id FROM analysis_window_samples s LEFT JOIN analysis_observation_sources aos ON aos.observation_id=s.observation_id WHERE s.rule_id IN (`+placeholders+`) AND s.observation_id=(SELECT MAX(s2.observation_id) FROM analysis_window_samples s2 WHERE s2.rule_id=s.rule_id AND s2.owner_type=s.owner_type AND s2.owner_id=s.owner_id AND s2.instance_key=s.instance_key) AND s.observation_id>? ORDER BY s.observation_id LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]AnalysisWindowCandidate, 0, limit)
	for rows.Next() {
		var c AnalysisWindowCandidate
		var at string
		if err := rows.Scan(&c.RuleID, &c.OwnerType, &c.OwnerID, &c.InstanceKey, &c.DeviceID, &c.SourceKey, &c.ObservationID, &at, &c.Outcome, &c.EventID, &c.RawID, &c.RecordOrdinal, &c.Matched, &c.CursorID); err != nil {
			return nil, err
		}
		c.OccurredAt, err = time.Parse(time.RFC3339Nano, at)
		if err != nil {
			return nil, err
		}
		items = append(items, c)
	}
	return items, rows.Err()
}

func (s *RawStore) ApplyAnalysisDeadlineFindings(ctx context.Context, items []AnalysisDeadlineFinding) error {
	if len(items) > 512 {
		return errors.New("analysis deadline batch exceeds 512 findings")
	}
	if len(items) == 0 {
		return nil
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, item := range items {
		if item.ObservationID <= 0 {
			return errors.New("analysis deadline has no evidence observation")
		}
		if item.WindowSample != nil {
			if err := applyAnalysisWindowSampleTx(ctx, tx, item.ObservationID, *item.WindowSample); err != nil {
				return err
			}
			continue
		}
		if err := applyAnalysisFindingTx(ctx, tx, item.ObservationID, item.Finding); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func analysisFindingID(ownerType, ownerID, ruleID, instanceKey string) string {
	key := ownerType + "\x00" + ownerID + "\x00" + ruleID
	if instanceKey != "" {
		key += "\x00" + instanceKey
	}
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func applyAnalysisFindingTx(ctx context.Context, tx *sql.Tx, observationID int64, e AnalysisFindingEvaluation) error {
	if e.RuleID == "" || e.RuleVersion == "" || (e.OwnerType != "device" && e.OwnerType != "source") || e.OwnerID == "" || len(e.SourceKey) != 64 || e.RawID == "" || e.RecordOrdinal < 0 || e.ClearAfter < 0 || (e.Matched && e.ClearMatched) || (e.Matched && e.CancelClear) || (e.ClearMatched && e.CancelClear) {
		return errors.New("invalid analysis finding evaluation")
	}
	if !e.Matched && !e.ClearMatched && !e.CancelClear {
		return nil
	}
	if (e.Severity != "low" && e.Severity != "medium" && e.Severity != "high" && e.Severity != "critical") || (e.State != "yellow" && e.State != "red") || e.Title == "" {
		return errors.New("invalid analysis finding metadata")
	}
	id := analysisFindingID(e.OwnerType, e.OwnerID, e.RuleID, e.InstanceKey)
	at := e.OccurredAt.UTC().Format(time.RFC3339Nano)
	var status, lastEvent, currentVersion, currentSeverity, currentState, currentTitle string
	err := tx.QueryRowContext(ctx, `SELECT status,last_event_id,rule_version,severity,state,title FROM analysis_findings WHERE finding_id=?`, id).Scan(&status, &lastEvent, &currentVersion, &currentSeverity, &currentState, &currentTitle)
	if errors.Is(err, sql.ErrNoRows) {
		if !e.Matched {
			return nil
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO analysis_findings(finding_id,owner_type,owner_id,device_id,source_key,rule_id,instance_key,rule_version,status,severity,state,title,first_seen_at,last_seen_at,last_event_id,last_raw_id,record_ordinal,occurrence_count,updated_at) VALUES(?,?,?,?,?,?,?,?,'open',?,?,?,?,?,?,?, ?,1,?)`, id, e.OwnerType, e.OwnerID, nullableString(e.DeviceID), e.SourceKey, e.RuleID, e.InstanceKey, e.RuleVersion, e.Severity, e.State, e.Title, at, at, e.EventID, e.RawID, e.RecordOrdinal, at)
		if err != nil {
			return err
		}
		return insertFindingHistory(ctx, tx, id, observationID, "opened", e, at)
	}
	if err != nil {
		return err
	}
	if e.CancelClear {
		if status != "clearing" {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `UPDATE analysis_findings SET status='open',rule_version=?,severity=?,state=?,title=?,last_seen_at=?,last_event_id=?,last_raw_id=?,record_ordinal=?,clear_since=NULL,clear_deadline=NULL,clear_observation_id=NULL,clear_event_id=NULL,clear_raw_id=NULL,clear_ordinal=NULL,updated_at=? WHERE finding_id=?`, e.RuleVersion, e.Severity, e.State, e.Title, at, e.EventID, e.RawID, e.RecordOrdinal, at, id); err != nil {
			return err
		}
		return insertFindingHistory(ctx, tx, id, observationID, "clear_cancelled", e, at)
	}
	if e.Matched {
		if status == "open" && lastEvent == e.EventID && currentVersion == e.RuleVersion && currentSeverity == e.Severity && currentState == e.State && currentTitle == e.Title {
			return nil
		}
		action := e.Action
		if action == "" {
			action = "updated"
		}
		if status == "resolved" {
			action = "opened"
		}
		if status == "clearing" {
			action = "clear_cancelled"
		}
		if status == "resolved" {
			_, err = tx.ExecContext(ctx, `UPDATE analysis_findings SET rule_version=?,status='open',severity=?,state=?,title=?,first_seen_at=?,last_seen_at=?,last_event_id=?,last_raw_id=?,record_ordinal=?,occurrence_count=1,clear_since=NULL,clear_deadline=NULL,clear_observation_id=NULL,clear_event_id=NULL,clear_raw_id=NULL,clear_ordinal=NULL,resolved_at=NULL,updated_at=? WHERE finding_id=?`, e.RuleVersion, e.Severity, e.State, e.Title, at, at, e.EventID, e.RawID, e.RecordOrdinal, at, id)
		} else {
			_, err = tx.ExecContext(ctx, `UPDATE analysis_findings SET rule_version=?,status='open',severity=?,state=?,title=?,last_seen_at=?,last_event_id=?,last_raw_id=?,record_ordinal=?,occurrence_count=occurrence_count+1,clear_since=NULL,clear_deadline=NULL,clear_observation_id=NULL,clear_event_id=NULL,clear_raw_id=NULL,clear_ordinal=NULL,updated_at=? WHERE finding_id=?`, e.RuleVersion, e.Severity, e.State, e.Title, at, e.EventID, e.RawID, e.RecordOrdinal, at, id)
		}
		if err != nil {
			return err
		}
		return insertFindingHistory(ctx, tx, id, observationID, action, e, at)
	}
	if status == "resolved" || status == "clearing" {
		return nil
	}
	deadline := e.OccurredAt.Add(e.ClearAfter).UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `UPDATE analysis_findings SET rule_version=?,status='clearing',severity=?,state=?,title=?,clear_since=?,clear_deadline=?,clear_observation_id=?,clear_event_id=?,clear_raw_id=?,clear_ordinal=?,updated_at=? WHERE finding_id=?`, e.RuleVersion, e.Severity, e.State, e.Title, at, deadline, observationID, e.EventID, e.RawID, e.RecordOrdinal, at, id); err != nil {
		return err
	}
	return insertFindingHistory(ctx, tx, id, observationID, "clear_started", e, at)
}

func insertFindingHistory(ctx context.Context, tx *sql.Tx, id string, observationID int64, action string, e AnalysisFindingEvaluation, at string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO analysis_finding_history(finding_id,observation_id,action,occurred_at,event_id,raw_id,record_ordinal,rule_version,severity,state,title) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, id, observationID, action, at, e.EventID, e.RawID, e.RecordOrdinal, e.RuleVersion, e.Severity, e.State, e.Title)
	return err
}

func applyAnalysisWindowSampleTx(ctx context.Context, tx *sql.Tx, observationID int64, sample AnalysisWindowSample) error {
	if sample.RuleID == "" || (sample.OwnerType != "device" && sample.OwnerType != "source") || sample.OwnerID == "" || sample.InstanceKey == "" || len(sample.SourceKey) != 64 || sample.RawID == "" || (sample.Outcome != "normalized" && sample.Outcome != "quarantined") || sample.Duration <= 0 || sample.ClearAfter < 0 || sample.Consecutive < 1 || sample.Consecutive > 1000 {
		return errors.New("invalid analysis window sample")
	}
	at := sample.OccurredAt.UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `INSERT INTO analysis_window_samples(rule_id,owner_type,owner_id,instance_key,observation_id,occurred_at,matched,outcome,event_id,raw_id,record_ordinal) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(rule_id,observation_id) DO NOTHING`, sample.RuleID, sample.OwnerType, sample.OwnerID, sample.InstanceKey, observationID, at, boolCount(sample.Matched), sample.Outcome, sample.EventID, sample.RawID, sample.RecordOrdinal); err != nil {
		return err
	}
	evaluatedAt := sample.EvaluatedAt.UTC()
	cutoff := evaluatedAt.Add(-sample.Duration).Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `DELETE FROM analysis_window_samples WHERE occurred_at<? AND rowid IN (SELECT rowid FROM analysis_window_samples WHERE occurred_at<? LIMIT 1000)`, evaluatedAt.Add(-30*24*time.Hour).Format(time.RFC3339Nano), evaluatedAt.Add(-30*24*time.Hour).Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("prune expired analysis window samples: %w", err)
	}
	if sample.BaselineMinimumHistory > 0 {
		return nil
	}
	var matchedCount, normalizedCount, quarantinedCount int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(matched),0),COALESCE(SUM(outcome='normalized'),0),COALESCE(SUM(outcome='quarantined'),0) FROM analysis_window_samples WHERE rule_id=? AND owner_type=? AND owner_id=? AND instance_key=? AND occurred_at>=?`, sample.RuleID, sample.OwnerType, sample.OwnerID, sample.InstanceKey, cutoff).Scan(&matchedCount, &normalizedCount, &quarantinedCount); err != nil {
		return err
	}
	matched, cleared, cancelClear := false, false, false
	if sample.RatioAtLeast > 0 {
		denominator := normalizedCount + quarantinedCount
		if denominator == 0 {
			return nil
		}
		ratio := float64(quarantinedCount) / float64(denominator)
		matched, cleared = ratio >= sample.RatioAtLeast, ratio <= sample.ClearRatio
		cancelClear = !matched && !cleared
	} else if sample.CountAtLeast > 0 {
		consecutive := 0
		var consecutiveSince time.Time
		rows, err := tx.QueryContext(ctx, `SELECT occurred_at,matched FROM analysis_window_samples WHERE rule_id=? AND owner_type=? AND owner_id=? AND instance_key=? AND occurred_at>=? ORDER BY occurred_at DESC,observation_id DESC LIMIT ?`, sample.RuleID, sample.OwnerType, sample.OwnerID, sample.InstanceKey, cutoff, sample.Consecutive)
		if err != nil {
			return err
		}
		for rows.Next() {
			var at string
			var value int
			if err := rows.Scan(&at, &value); err != nil {
				rows.Close()
				return err
			}
			if value != 1 {
				break
			}
			consecutive++
			parsed, err := time.Parse(time.RFC3339Nano, at)
			if err != nil {
				rows.Close()
				return err
			}
			consecutiveSince = parsed
		}
		if err := rows.Close(); err != nil {
			return err
		}
		matched = matchedCount >= int64(sample.CountAtLeast) && consecutive == sample.Consecutive && (sample.For == 0 || sample.EvaluatedAt.Sub(consecutiveSince) >= sample.For)
		cleared = matchedCount <= int64(sample.ClearBelow)
		cancelClear = !matched && !cleared
	}
	if !matched && !cleared && !cancelClear {
		return nil
	}
	occurredAt := sample.EvaluatedAt
	if occurredAt.IsZero() {
		occurredAt = sample.OccurredAt
	}
	e := AnalysisFindingEvaluation{RuleID: sample.RuleID, RuleVersion: sample.RuleVersion, OwnerType: sample.OwnerType, OwnerID: sample.OwnerID, InstanceKey: sample.InstanceKey, DeviceID: sample.DeviceID, SourceKey: sample.SourceKey, EventID: sample.EventID, RawID: sample.RawID, Severity: sample.Severity, State: sample.State, Title: sample.Title, RecordOrdinal: sample.RecordOrdinal, OccurredAt: occurredAt, ClearAfter: sample.ClearAfter, Matched: matched, ClearMatched: cleared, CancelClear: cancelClear}
	return applyAnalysisFindingTx(ctx, tx, observationID, e)
}

func (s *RawStore) ResolveMaturedAnalysisFindings(ctx context.Context, now time.Time, limit int) (int, error) {
	if limit < 1 || limit > 512 {
		return 0, errors.New("finding resolution limit must be between 1 and 512")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT finding_id,clear_observation_id,clear_event_id,clear_raw_id,clear_ordinal,rule_version,severity,state,title,clear_deadline FROM analysis_findings WHERE status='clearing' AND clear_deadline<=? ORDER BY clear_deadline LIMIT ?`, now.UTC().Format(time.RFC3339Nano), limit)
	if err != nil {
		return 0, err
	}
	type row struct {
		id                                  string
		obs                                 int64
		event, raw                          string
		ordinal                             int
		version, severity, state, title, at string
	}
	var matured []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.obs, &r.event, &r.raw, &r.ordinal, &r.version, &r.severity, &r.state, &r.title, &r.at); err != nil {
			rows.Close()
			return 0, err
		}
		matured = append(matured, r)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	for _, r := range matured {
		if _, err := tx.ExecContext(ctx, `UPDATE analysis_findings SET status='resolved',resolved_at=?,updated_at=? WHERE finding_id=? AND status='clearing'`, r.at, r.at, r.id); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO analysis_finding_history(finding_id,observation_id,action,occurred_at,event_id,raw_id,record_ordinal,rule_version,severity,state,title) VALUES(?,?,'resolved',?,?,?,?,?,?,?,?)`, r.id, r.obs, r.at, r.event, r.raw, r.ordinal, r.version, r.severity, r.state, r.title); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(matured), nil
}

func (s *RawStore) ListAnalysisFindings(ctx context.Context, status string, limit, offset int) ([]AnalysisFinding, int64, error) {
	return s.ListAnalysisFindingsFiltered(ctx, AnalysisFindingFilter{Status: status}, limit, offset)
}

func (s *RawStore) ListAnalysisFindingsFiltered(ctx context.Context, filter AnalysisFindingFilter, limit, offset int) ([]AnalysisFinding, int64, error) {
	if limit < 1 || limit > 500 || offset < 0 || offset > 1_000_000_000 {
		return nil, 0, errors.New("invalid analysis finding pagination")
	}
	where, args, err := findingWhere(filter.Status)
	if err != nil {
		return nil, 0, err
	}
	for _, condition := range []struct {
		column string
		value  string
	}{{"rule_id", filter.RuleID}, {"device_id", filter.DeviceID}} {
		if condition.value == "" {
			continue
		}
		if where == "" {
			where = " WHERE "
		} else {
			where += " AND "
		}
		where += condition.column + "=?"
		args = append(args, condition.value)
	}
	if filter.Since != nil {
		if where == "" {
			where = " WHERE "
		} else {
			where += " AND "
		}
		where += "last_seen_at>=?"
		args = append(args, filter.Since.UTC().Format(time.RFC3339Nano))
	}
	var total int64
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM analysis_findings"+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT finding_id,owner_type,owner_id,COALESCE(device_id,''),source_key,rule_id,instance_key,rule_version,status,severity,state,title,first_seen_at,last_seen_at,last_event_id,last_raw_id,record_ordinal,occurrence_count,clear_since,clear_deadline,resolved_at,updated_at FROM analysis_findings`+where+` ORDER BY CASE status WHEN 'open' THEN 0 WHEN 'clearing' THEN 1 ELSE 2 END,updated_at DESC,finding_id LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := make([]AnalysisFinding, 0)
	for rows.Next() {
		f, err := scanAnalysisFinding(rows)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, f)
	}
	return items, total, rows.Err()
}

func (s *RawStore) CountActiveAnalysisFindingsByDevice(ctx context.Context, deviceIDs []string) (map[string]int64, error) {
	counts := make(map[string]int64, len(deviceIDs))
	if len(deviceIDs) == 0 {
		return counts, nil
	}
	if len(deviceIDs) > 500 {
		return nil, errors.New("analysis finding count query is limited to 500 devices")
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(deviceIDs)), ",")
	args := make([]any, len(deviceIDs))
	for i, id := range deviceIDs {
		args[i] = id
	}
	rows, err := s.db.QueryContext(ctx, `SELECT device_id,COUNT(*) FROM analysis_findings WHERE status IN ('open','clearing') AND device_id IN (`+placeholders+") GROUP BY device_id", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var count int64
		if err := rows.Scan(&id, &count); err != nil {
			return nil, err
		}
		counts[id] = count
	}
	return counts, rows.Err()
}

type rowScanner interface{ Scan(...any) error }

func scanAnalysisFinding(row rowScanner) (AnalysisFinding, error) {
	var f AnalysisFinding
	var first, last, clearSince, clearDeadline, resolved, updated sql.NullString
	err := row.Scan(&f.ID, &f.OwnerType, &f.OwnerID, &f.DeviceID, &f.SourceKey, &f.RuleID, &f.InstanceKey, &f.RuleVersion, &f.Status, &f.Severity, &f.State, &f.Title, &first, &last, &f.LastEventID, &f.LastRawID, &f.RecordOrdinal, &f.OccurrenceCount, &clearSince, &clearDeadline, &resolved, &updated)
	if err != nil {
		return f, err
	}
	for _, v := range []struct {
		s sql.NullString
		p *time.Time
	}{{first, &f.FirstSeenAt}, {last, &f.LastSeenAt}, {updated, &f.UpdatedAt}} {
		if v.s.Valid {
			parsed, e := time.Parse(time.RFC3339Nano, v.s.String)
			if e != nil {
				return f, e
			}
			*v.p = parsed
		}
	}
	for _, v := range []struct {
		s sql.NullString
		p **time.Time
	}{{clearSince, &f.ClearSince}, {clearDeadline, &f.ClearDeadline}, {resolved, &f.ResolvedAt}} {
		if v.s.Valid {
			parsed, e := time.Parse(time.RFC3339Nano, v.s.String)
			if e != nil {
				return f, e
			}
			*v.p = &parsed
		}
	}
	return f, nil
}

func findingWhere(status string) (string, []any, error) {
	switch status {
	case "", "open":
		return ` WHERE status='open'`, nil, nil
	case "clearing", "resolved":
		return ` WHERE status=?`, []any{status}, nil
	case "all":
		return "", nil, nil
	default:
		return "", nil, fmt.Errorf("invalid analysis finding status %q", status)
	}
}

func (s *RawStore) GetAnalysisFinding(ctx context.Context, id string, limit, offset int) (AnalysisFinding, []AnalysisFindingHistory, int64, error) {
	var f AnalysisFinding
	if limit < 1 || limit > 500 || offset < 0 || offset > 1_000_000_000 {
		return f, nil, 0, errors.New("invalid analysis finding history pagination")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT finding_id,owner_type,owner_id,COALESCE(device_id,''),source_key,rule_id,instance_key,rule_version,status,severity,state,title,first_seen_at,last_seen_at,last_event_id,last_raw_id,record_ordinal,occurrence_count,clear_since,clear_deadline,resolved_at,updated_at FROM analysis_findings WHERE finding_id=?`, id)
	if err != nil {
		return f, nil, 0, err
	}
	if rows.Next() {
		f, err = scanAnalysisFinding(rows)
	} else {
		err = sql.ErrNoRows
	}
	rows.Close()
	if err != nil {
		return f, nil, 0, err
	}
	var total int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM analysis_finding_history WHERE finding_id=?`, id).Scan(&total); err != nil {
		return f, nil, 0, err
	}
	historyRows, err := s.db.QueryContext(ctx, `SELECT history_id,finding_id,observation_id,action,occurred_at,event_id,raw_id,record_ordinal,rule_version,severity,state,title FROM analysis_finding_history WHERE finding_id=? ORDER BY history_id DESC LIMIT ? OFFSET ?`, id, limit, offset)
	if err != nil {
		return f, nil, 0, err
	}
	defer historyRows.Close()
	history := make([]AnalysisFindingHistory, 0)
	for historyRows.Next() {
		var h AnalysisFindingHistory
		var at string
		if err := historyRows.Scan(&h.ID, &h.FindingID, &h.ObservationID, &h.Action, &at, &h.EventID, &h.RawID, &h.RecordOrdinal, &h.RuleVersion, &h.Severity, &h.State, &h.Title); err != nil {
			return f, nil, 0, err
		}
		h.OccurredAt, err = time.Parse(time.RFC3339Nano, at)
		if err != nil {
			return f, nil, 0, err
		}
		history = append(history, h)
	}
	return f, history, total, historyRows.Err()
}
