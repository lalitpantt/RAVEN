package analysis

import (
	"context"
	"errors"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"raven/internal/rawstore"
)

const (
	analysisBatchSize = 64
	analysisPollDelay = 100 * time.Millisecond
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

	mu      sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}
	started bool
	lastErr string
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
	if len(observations) == 0 {
		return 0, nil
	}
	resolutions := make([]rawstore.AnalysisResolution, len(observations))
	config := w.config.Load()
	for i, observation := range observations {
		resolutions[i] = config.resolver.Resolve(observation.IdentityHints)
		snapshot := config.snapshot
		if snapshot == nil || observation.Kind != "normalized" || resolutions[i].Resolution != "matched" {
			continue
		}
		rule, ok := heartbeatRuleFor(snapshot, resolutions[i].DeviceID)
		if !ok {
			continue
		}
		event, err := w.store.GetNormalizedByID(ctx, observation.EventID)
		if err != nil {
			return 0, err
		}
		if matchesRuleFields(rule, event.OCSF) {
			resolutions[i].HeartbeatRule = rule.Metadata.Name
		}
	}
	if err := w.store.CommitAnalysisBatch(ctx, checkpoint, observations, resolutions); err != nil {
		return 0, err
	}
	return len(observations), nil
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
