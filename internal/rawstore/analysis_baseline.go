package rawstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

type AnalysisBaselineState struct {
	RuleID           string    `json:"rule_id"`
	OwnerType        string    `json:"owner_type"`
	OwnerID          string    `json:"owner_id"`
	InstanceKey      string    `json:"instance_key"`
	Algorithm        string    `json:"algorithm"`
	AlgorithmVersion string    `json:"algorithm_version"`
	Status           string    `json:"status"`
	Direction        string    `json:"direction,omitempty"`
	MinimumHistory   int       `json:"minimum_history"`
	HistoryCount     int       `json:"history_count"`
	FirstSeenAt      time.Time `json:"first_seen_at"`
	IntervalStart    time.Time `json:"interval_start"`
	IntervalEnd      time.Time `json:"interval_end"`
	ObservedCount    int64     `json:"observed_count"`
	Median           float64   `json:"baseline_median"`
	MAD              float64   `json:"baseline_mad"`
	LowerThreshold   float64   `json:"lower_threshold"`
	UpperThreshold   float64   `json:"upper_threshold"`
	FindingID        string    `json:"finding_id,omitempty"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type AnalysisBaselineSeries struct {
	FirstSeenAt   time.Time
	History       []int64
	Observed      int64
	EventID       string
	RawID         string
	RecordOrdinal int
	ObservationID int64
}

type AnalysisBaselineFinding struct {
	ObservationID int64
	Evaluation    AnalysisFindingEvaluation
}

func (s *RawStore) ReadAnalysisBaselineSeries(ctx context.Context, ruleID, ownerType, ownerID, instanceKey string, intervalStart, intervalEnd time.Time, interval time.Duration, history int) (AnalysisBaselineSeries, error) {
	var result AnalysisBaselineSeries
	if ruleID == "" || (ownerType != "device" && ownerType != "source") || ownerID == "" || instanceKey == "" || interval <= 0 || interval%time.Second != 0 || history < 1 || history > 28 || !intervalEnd.After(intervalStart) {
		return result, errors.New("invalid analysis baseline series query")
	}
	keyArgs := []any{ruleID, ownerType, ownerID, instanceKey}
	var firstSeen string
	err := s.db.QueryRowContext(ctx, `SELECT first_seen_at FROM analysis_baseline_states WHERE rule_id=? AND owner_type=? AND owner_id=? AND instance_key=?`, keyArgs...).Scan(&firstSeen)
	if errors.Is(err, sql.ErrNoRows) {
		err = s.db.QueryRowContext(ctx, `SELECT MIN(occurred_at) FROM analysis_window_samples WHERE rule_id=? AND owner_type=? AND owner_id=? AND instance_key=?`, keyArgs...).Scan(&firstSeen)
	}
	if err != nil {
		return result, err
	}
	result.FirstSeenAt, err = time.Parse(time.RFC3339Nano, firstSeen)
	if err != nil {
		return result, fmt.Errorf("parse baseline first observation: %w", err)
	}
	result.History = make([]int64, history)
	intervalSeconds := int64(interval / time.Second)
	historyStart := intervalStart.Add(-time.Duration(history) * interval)
	rows, err := s.db.QueryContext(ctx, `SELECT ((CAST(strftime('%s',occurred_at) AS INTEGER)-?)/?) AS bucket,COUNT(*)
		FROM analysis_window_samples
		WHERE rule_id=? AND owner_type=? AND owner_id=? AND instance_key=? AND matched=1 AND occurred_at>=? AND occurred_at<?
		GROUP BY bucket`, historyStart.Unix(), intervalSeconds, ruleID, ownerType, ownerID, instanceKey, historyStart.UTC().Format(time.RFC3339Nano), intervalStart.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var bucket int
		var count int64
		if err := rows.Scan(&bucket, &count); err != nil {
			rows.Close()
			return result, err
		}
		if bucket >= 0 && bucket < len(result.History) {
			result.History[bucket] = count
		}
	}
	if err := rows.Close(); err != nil {
		return result, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM analysis_window_samples WHERE rule_id=? AND owner_type=? AND owner_id=? AND instance_key=? AND matched=1 AND occurred_at>=? AND occurred_at<?`, ruleID, ownerType, ownerID, instanceKey, intervalStart.UTC().Format(time.RFC3339Nano), intervalEnd.UTC().Format(time.RFC3339Nano)).Scan(&result.Observed); err != nil {
		return result, err
	}
	err = s.db.QueryRowContext(ctx, `SELECT observation_id,event_id,raw_id,record_ordinal FROM analysis_window_samples
		WHERE rule_id=? AND owner_type=? AND owner_id=? AND instance_key=? AND matched=1 AND occurred_at<? ORDER BY occurred_at DESC,observation_id DESC LIMIT 1`, keyArgs[0], keyArgs[1], keyArgs[2], keyArgs[3], intervalEnd.UTC().Format(time.RFC3339Nano)).Scan(&result.ObservationID, &result.EventID, &result.RawID, &result.RecordOrdinal)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return result, err
	}
	return result, nil
}

func (s *RawStore) ApplyAnalysisBaselineState(ctx context.Context, state AnalysisBaselineState, finding *AnalysisBaselineFinding) error {
	if state.RuleID == "" || (state.OwnerType != "device" && state.OwnerType != "source") || state.OwnerID == "" || state.InstanceKey == "" || state.Algorithm == "" || state.AlgorithmVersion == "" || (state.Status != "warming_up" && state.Status != "ready" && state.Status != "anomaly" && state.Status != "maintenance") || state.MinimumHistory < 4 || state.MinimumHistory > 28 || state.HistoryCount < 0 || state.HistoryCount > state.MinimumHistory || state.ObservedCount < 0 || state.FirstSeenAt.IsZero() || !state.IntervalEnd.After(state.IntervalStart) || state.UpdatedAt.IsZero() {
		return errors.New("invalid analysis baseline state")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if finding != nil {
		if err := applyAnalysisFindingTx(ctx, tx, finding.ObservationID, finding.Evaluation); err != nil {
			return err
		}
		if finding.Evaluation.Matched {
			state.FindingID = analysisFindingID(finding.Evaluation.OwnerType, finding.Evaluation.OwnerID, finding.Evaluation.RuleID, finding.Evaluation.InstanceKey)
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO analysis_baseline_states(rule_id,owner_type,owner_id,instance_key,algorithm,algorithm_version,status,direction,minimum_history,history_count,first_seen_at,interval_start,interval_end,observed_count,baseline_median,baseline_mad,lower_threshold,upper_threshold,finding_id,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(rule_id,owner_type,owner_id,instance_key) DO UPDATE SET
		algorithm=excluded.algorithm,algorithm_version=excluded.algorithm_version,status=excluded.status,direction=excluded.direction,minimum_history=excluded.minimum_history,history_count=excluded.history_count,interval_start=excluded.interval_start,interval_end=excluded.interval_end,observed_count=excluded.observed_count,baseline_median=excluded.baseline_median,baseline_mad=excluded.baseline_mad,lower_threshold=excluded.lower_threshold,upper_threshold=excluded.upper_threshold,finding_id=CASE WHEN excluded.finding_id='' THEN analysis_baseline_states.finding_id ELSE excluded.finding_id END,updated_at=excluded.updated_at
		WHERE analysis_baseline_states.status<>excluded.status OR analysis_baseline_states.direction<>excluded.direction OR analysis_baseline_states.minimum_history<>excluded.minimum_history OR analysis_baseline_states.history_count<>excluded.history_count OR analysis_baseline_states.interval_start<>excluded.interval_start OR analysis_baseline_states.interval_end<>excluded.interval_end OR analysis_baseline_states.observed_count<>excluded.observed_count OR analysis_baseline_states.baseline_median<>excluded.baseline_median OR analysis_baseline_states.baseline_mad<>excluded.baseline_mad OR analysis_baseline_states.lower_threshold<>excluded.lower_threshold OR analysis_baseline_states.upper_threshold<>excluded.upper_threshold OR (analysis_baseline_states.finding_id='' AND excluded.finding_id<>'')`,
		state.RuleID, state.OwnerType, state.OwnerID, state.InstanceKey, state.Algorithm, state.AlgorithmVersion, state.Status, state.Direction, state.MinimumHistory, state.HistoryCount, state.FirstSeenAt.UTC().Format(time.RFC3339Nano), state.IntervalStart.UTC().Format(time.RFC3339Nano), state.IntervalEnd.UTC().Format(time.RFC3339Nano), state.ObservedCount, state.Median, state.MAD, state.LowerThreshold, state.UpperThreshold, state.FindingID, state.UpdatedAt.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *RawStore) ListAnalysisBaselineStates(ctx context.Context, limit, offset int) ([]AnalysisBaselineState, int64, error) {
	if limit < 1 || limit > 500 || offset < 0 || offset > 1_000_000_000 {
		return nil, 0, errors.New("invalid analysis baseline pagination")
	}
	var total int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM analysis_baseline_states`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT rule_id,owner_type,owner_id,instance_key,algorithm,algorithm_version,status,direction,minimum_history,history_count,first_seen_at,interval_start,interval_end,observed_count,baseline_median,baseline_mad,lower_threshold,upper_threshold,finding_id,updated_at FROM analysis_baseline_states ORDER BY updated_at DESC,rule_id,owner_id,instance_key LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := make([]AnalysisBaselineState, 0)
	for rows.Next() {
		var item AnalysisBaselineState
		var first, start, end, updated string
		if err := rows.Scan(&item.RuleID, &item.OwnerType, &item.OwnerID, &item.InstanceKey, &item.Algorithm, &item.AlgorithmVersion, &item.Status, &item.Direction, &item.MinimumHistory, &item.HistoryCount, &first, &start, &end, &item.ObservedCount, &item.Median, &item.MAD, &item.LowerThreshold, &item.UpperThreshold, &item.FindingID, &updated); err != nil {
			return nil, 0, err
		}
		for _, value := range []struct {
			raw string
			dst *time.Time
		}{{first, &item.FirstSeenAt}, {start, &item.IntervalStart}, {end, &item.IntervalEnd}, {updated, &item.UpdatedAt}} {
			parsed, err := time.Parse(time.RFC3339Nano, value.raw)
			if err != nil {
				return nil, 0, err
			}
			*value.dst = parsed
		}
		items = append(items, item)
	}
	return items, total, rows.Err()
}
