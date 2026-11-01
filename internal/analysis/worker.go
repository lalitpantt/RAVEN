package analysis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"raven/internal/model"
	"raven/internal/rawstore"
)

const (
	analysisBatchSize = 64
	analysisPollDelay = 100 * time.Millisecond
	analysisSweepPage = 256
)

type WorkerStatus struct {
	QueueStatus rawstore.AnalysisQueueStatus
	LastError   string
	Running     bool
}

// Worker consumes durable observations after the ingestion transactions commit.
type Worker struct {
	store  *rawstore.RawStore
	config atomic.Pointer[workerConfig]

	mu              sync.Mutex
	cancel          context.CancelFunc
	done            chan struct{}
	started         bool
	lastErr         string
	windowCursor    int64
	heartbeatCursor string
}

type workerConfig struct {
	resolver *Resolver
	snapshot *Snapshot
}

func NewWorker(store *rawstore.RawStore, resolver *Resolver) (*Worker, error) {
	if store == nil {
		return nil, errors.New("analysis worker requires a raw store")
	}
	if resolver == nil {
		resolver = &Resolver{}
	}
	worker := &Worker{store: store}
	worker.config.Store(&workerConfig{resolver: resolver})
	return worker, nil
}

// SetResolver atomically replaces the identity resolver for future batches.
func (w *Worker) SetResolver(resolver *Resolver) {
	if resolver == nil {
		resolver = &Resolver{}
	}
	w.config.Store(&workerConfig{resolver: resolver})
}

// SetSnapshot atomically activates validated inventory and heartbeat rules.
func (w *Worker) SetSnapshot(snapshot *Snapshot) {
	if snapshot == nil {
		w.config.Store(&workerConfig{resolver: &Resolver{}})
		return
	}
	w.config.Store(&workerConfig{resolver: snapshot.Resolver(), snapshot: snapshot})
}

// Start enables durable handoff before beginning the worker. Stopping the worker
// intentionally leaves handoff enabled, so slow or stopped analysis accumulates
// a measurable durable backlog without blocking ingestion.
func (w *Worker) Start(parent context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.started {
		return errors.New("analysis worker is already started")
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	w.cancel = cancel
	w.done = make(chan struct{})
	w.started = true
	w.store.SetAnalysisEnabled(true)
	go w.run(ctx)
	return nil
}

func (w *Worker) run(ctx context.Context) {
	defer close(w.done)
	ticker := time.NewTicker(analysisPollDelay)
	defer ticker.Stop()
	for {
		_, err := w.RunOnce(ctx)
		w.mu.Lock()
		shouldLog := false
		if err != nil {
			shouldLog = w.lastErr != err.Error()
			w.lastErr = err.Error()
		} else {
			w.lastErr = ""
		}
		w.mu.Unlock()
		if err != nil && shouldLog {
			log.Printf("analysis worker batch failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// RunOnce processes at most one bounded batch; it is also useful for deterministic
// recovery checks and keeps each SQLite write transaction short.
func (w *Worker) RunOnce(ctx context.Context) (int, error) {
	observations, checkpoint, err := w.store.AnalysisBatch(ctx, analysisBatchSize)
	if err != nil {
		return 0, err
	}
	resolutions := make([]rawstore.AnalysisResolution, len(observations))
	config := w.config.Load()
	rules := []AnalysisRuleResource(nil)
	if config.snapshot != nil {
		rules = config.snapshot.Rules()
	}
	for i, observation := range observations {
		resolutions[i] = config.resolver.Resolve(observation.IdentityHints)
		if config.snapshot == nil {
			continue
		}
		ownerType, ownerID := "source", resolutions[i].SourceKey
		if resolutions[i].Resolution == "matched" {
			ownerType, ownerID = "device", resolutions[i].DeviceID
		}
		var event *model.NormalizedEvent
		needsEvent := observation.Kind == "normalized"
		if needsEvent {
			event, err = w.store.GetNormalizedByID(ctx, observation.EventID)
			if err != nil {
				return 0, err
			}
		}
		var heartbeat AnalysisRuleResource
		hasHeartbeat := false
		if event != nil && resolutions[i].Resolution == "matched" {
			heartbeat, hasHeartbeat = heartbeatRuleFor(config.snapshot, resolutions[i].DeviceID)
		}
		if hasHeartbeat && matchesRuleFields(heartbeat, event.OCSF) {
			resolutions[i].HeartbeatRule = heartbeat.Metadata.Name
			resolutions[i].Findings = append(resolutions[i].Findings, rawstore.AnalysisFindingEvaluation{
				RuleID: heartbeat.Metadata.Name, RuleVersion: heartbeat.Metadata.Version, OwnerType: "device", OwnerID: resolutions[i].DeviceID,
				DeviceID: resolutions[i].DeviceID, SourceKey: resolutions[i].SourceKey, EventID: observation.EventID, RawID: observation.RawID,
				RecordOrdinal: observation.RecordOrdinal, OccurredAt: observation.OccurredAt, ClearAfter: 0, Severity: heartbeat.Spec.Finding.Severity,
				State: heartbeat.Spec.Finding.State, Title: heartbeat.Spec.Finding.Title, ClearMatched: true, ClearIfLatestHeartbeat: true,
			})
		}
		for _, rule := range rules {
			if rule.Spec.Enabled != nil && !*rule.Spec.Enabled {
				continue
			}
			if rule.Spec.Kind == "quality" && (observation.Kind == "normalized" || observation.Kind == "quarantined") {
				resolutions[i].WindowSamples = append(resolutions[i].WindowSamples, makeWindowSample(rule, ownerType, ownerID, resolutions[i], observation, event, false, time.Now().UTC()))
				continue
			}
			if rule.Spec.Kind != "event" && rule.Spec.Kind != "window" || observation.Kind != "normalized" {
				continue
			}
			if rule.Spec.Kind == "window" {
				categoryMatch := rule.Spec.SourceCategory == "" || rule.Spec.SourceCategory == event.Raven.SourceCategory
				matched := categoryMatch && matchesRuleFields(rule, event.OCSF)
				resolutions[i].WindowSamples = append(resolutions[i].WindowSamples, makeWindowSample(rule, ownerType, ownerID, resolutions[i], observation, event, matched, time.Now().UTC()))
				continue
			}
			evaluation := EvaluateEventRule(rule, event)
			if !evaluation.Matched && !evaluation.ClearMatched {
				continue
			}
			clearMatched := evaluation.ClearMatched && !evaluation.Matched
			resolutions[i].Findings = append(resolutions[i].Findings, rawstore.AnalysisFindingEvaluation{
				RuleID: rule.Metadata.Name, RuleVersion: rule.Metadata.Version, OwnerType: ownerType, OwnerID: ownerID,
				DeviceID: resolutions[i].DeviceID, SourceKey: resolutions[i].SourceKey, EventID: observation.EventID,
				RawID: observation.RawID, RecordOrdinal: observation.RecordOrdinal, OccurredAt: observation.OccurredAt,
				Severity: rule.Spec.Finding.Severity, State: rule.Spec.Finding.State, Title: rule.Spec.Finding.Title,
				ClearAfter: rule.Spec.Finding.ClearAfter.Value(), Matched: evaluation.Matched, ClearMatched: clearMatched,
			})
		}
	}
	if len(observations) > 0 {
		if err := w.store.CommitAnalysisBatch(ctx, checkpoint, observations, resolutions); err != nil {
			return 0, err
		}
	}
	if err := w.evaluateTimeRules(ctx, config.snapshot, rules, time.Now().UTC()); err != nil {
		return 0, err
	}
	if _, err := w.store.ResolveMaturedAnalysisFindings(ctx, time.Now().UTC(), analysisBatchSize); err != nil {
		return 0, err
	}
	return len(observations), nil
}

func makeWindowSample(rule AnalysisRuleResource, ownerType, ownerID string, resolution rawstore.AnalysisResolution, observation rawstore.AnalysisObservation, event *model.NormalizedEvent, matched bool, now time.Time) rawstore.AnalysisWindowSample {
	values := make([]any, 0, len(rule.Spec.Window.GroupBy))
	for _, path := range rule.Spec.Window.GroupBy {
		value, ok := lookupField(event.OCSF, path)
		if !ok {
			value = nil
		}
		values = append(values, value)
	}
	groupKey := "default"
	if len(values) > 0 {
		encoded, _ := json.Marshal(values)
		sum := sha256.Sum256(encoded)
		groupKey = hex.EncodeToString(sum[:])
	}
	return rawstore.AnalysisWindowSample{RuleID: rule.Metadata.Name, OwnerType: ownerType, OwnerID: ownerID, InstanceKey: rule.Metadata.Version + ":" + groupKey, EventID: observation.EventID, RawID: observation.RawID, Outcome: observation.Kind, SourceKey: resolution.SourceKey, DeviceID: resolution.DeviceID, RuleVersion: rule.Metadata.Version, Severity: rule.Spec.Finding.Severity, State: rule.Spec.Finding.State, Title: rule.Spec.Finding.Title, RecordOrdinal: observation.RecordOrdinal, CountAtLeast: rule.Spec.Window.CountAtLeast, ClearBelow: rule.Spec.Window.ClearBelow, Consecutive: rule.Spec.Window.Consecutive, RatioAtLeast: rule.Spec.Window.RatioAtLeast, ClearRatio: rule.Spec.Window.ClearRatio, Duration: rule.Spec.Window.Duration.Value(), For: rule.Spec.Finding.For.Value(), ClearAfter: rule.Spec.Finding.ClearAfter.Value(), OccurredAt: observation.OccurredAt, EvaluatedAt: now, Matched: matched}
}

func (w *Worker) evaluateTimeRules(ctx context.Context, snapshot *Snapshot, rules []AnalysisRuleResource, now time.Time) error {
	if snapshot == nil {
		return nil
	}
	if err := w.evaluateHeartbeatDeadlines(ctx, snapshot, now); err != nil {
		return err
	}
	ids := make([]string, 0)
	byID := make(map[string]AnalysisRuleResource)
	for _, rule := range rules {
		if (rule.Spec.Enabled == nil || *rule.Spec.Enabled) && (rule.Spec.Kind == "window" || rule.Spec.Kind == "quality") {
			ids = append(ids, rule.Metadata.Name)
			byID[rule.Metadata.Name] = rule
		}
	}
	if len(ids) == 0 {
		return nil
	}
	w.mu.Lock()
	cursor := w.windowCursor
	w.mu.Unlock()
	candidates, err := w.store.ListAnalysisWindowCandidates(ctx, ids, cursor, analysisSweepPage)
	if err != nil {
		return err
	}
	if len(candidates) == 0 {
		w.mu.Lock()
		w.windowCursor = 0
		w.mu.Unlock()
		return nil
	}
	items := make([]rawstore.AnalysisDeadlineFinding, 0, len(candidates))
	for _, c := range candidates {
		rule, ok := byID[c.RuleID]
		if !ok {
			continue
		}
		if !strings.HasPrefix(c.InstanceKey, rule.Metadata.Version+":") {
			continue
		}
		sample := rawstore.AnalysisWindowSample{RuleID: rule.Metadata.Name, OwnerType: c.OwnerType, OwnerID: c.OwnerID, InstanceKey: c.InstanceKey, EventID: c.EventID, RawID: c.RawID, Outcome: c.Outcome, SourceKey: c.SourceKey, DeviceID: c.DeviceID, RuleVersion: rule.Metadata.Version, Severity: rule.Spec.Finding.Severity, State: rule.Spec.Finding.State, Title: rule.Spec.Finding.Title, RecordOrdinal: c.RecordOrdinal, CountAtLeast: rule.Spec.Window.CountAtLeast, ClearBelow: rule.Spec.Window.ClearBelow, Consecutive: rule.Spec.Window.Consecutive, RatioAtLeast: rule.Spec.Window.RatioAtLeast, ClearRatio: rule.Spec.Window.ClearRatio, Duration: rule.Spec.Window.Duration.Value(), For: rule.Spec.Finding.For.Value(), ClearAfter: rule.Spec.Finding.ClearAfter.Value(), OccurredAt: c.OccurredAt, EvaluatedAt: now, Matched: c.Matched}
		items = append(items, rawstore.AnalysisDeadlineFinding{ObservationID: c.ObservationID, WindowSample: &sample})
	}
	w.mu.Lock()
	w.windowCursor = candidates[len(candidates)-1].CursorID
	w.mu.Unlock()
	return w.store.ApplyAnalysisDeadlineFindings(ctx, items)
}

func (w *Worker) evaluateHeartbeatDeadlines(ctx context.Context, snapshot *Snapshot, now time.Time) error {
	w.mu.Lock()
	cursor := w.heartbeatCursor
	w.mu.Unlock()
	evidence, err := w.store.ListAnalysisHeartbeatEvidence(ctx, cursor, analysisSweepPage)
	if err != nil {
		return err
	}
	if len(evidence) == 0 {
		w.mu.Lock()
		w.heartbeatCursor = ""
		w.mu.Unlock()
		return nil
	}
	devices := make(map[string]DeviceResource)
	for _, device := range snapshot.Devices() {
		if device.Spec.Reporting.Mode == "heartbeat" {
			devices[device.Metadata.Name] = device
		}
	}
	items := make([]rawstore.AnalysisDeadlineFinding, 0)
	for _, seen := range evidence {
		device, ok := devices[seen.DeviceID]
		if !ok {
			continue
		}
		rule, ok := snapshot.Rule(device.Spec.Reporting.HeartbeatRule)
		if !ok {
			continue
		}
		maintenance := maintenanceUntil(device.Spec.Maintenance, now) != nil
		age := now.Sub(seen.OccurredAt)
		if !maintenance && age < device.Spec.Reporting.WarningAfter.Value() {
			continue
		}
		e := rawstore.AnalysisFindingEvaluation{RuleID: rule.Metadata.Name, RuleVersion: rule.Metadata.Version, OwnerType: "device", OwnerID: device.Metadata.Name, DeviceID: device.Metadata.Name, SourceKey: seen.SourceKey, EventID: seen.EventID, RawID: seen.RawID, RecordOrdinal: seen.RecordOrdinal, OccurredAt: now, Severity: rule.Spec.Finding.Severity, State: rule.Spec.Finding.State, Title: rule.Spec.Finding.Title}
		if maintenance {
			e.ClearMatched = true
		} else {
			e.Matched = true
			if age >= device.Spec.Reporting.CriticalAfter.Value() {
				e.Severity = "critical"
				e.State = "red"
				e.Title = device.Spec.DisplayName + " exceeded its critical heartbeat deadline"
				e.Action = "escalated"
			} else {
				e.Severity = "medium"
				e.State = "yellow"
				e.Title = device.Spec.DisplayName + " exceeded its warning heartbeat deadline"
			}
		}
		items = append(items, rawstore.AnalysisDeadlineFinding{ObservationID: seen.ObservationID, Finding: e})
	}
	w.mu.Lock()
	w.heartbeatCursor = evidence[len(evidence)-1].DeviceID
	w.mu.Unlock()
	return w.store.ApplyAnalysisDeadlineFindings(ctx, items)
}

func (w *Worker) Status(ctx context.Context) (WorkerStatus, error) {
	queueStatus, err := w.store.AnalysisStatus(ctx)
	if err != nil {
		return WorkerStatus{}, err
	}
	w.mu.Lock()
	lastErr, running := w.lastErr, w.started
	w.mu.Unlock()
	return WorkerStatus{QueueStatus: queueStatus, LastError: lastErr, Running: running}, nil
}

func (w *Worker) Stop() {
	w.mu.Lock()
	if !w.started {
		w.mu.Unlock()
		return
	}
	cancel, done := w.cancel, w.done
	w.mu.Unlock()
	cancel()
	<-done
	w.mu.Lock()
	w.started = false
	w.cancel = nil
	w.done = nil
	w.mu.Unlock()
}
