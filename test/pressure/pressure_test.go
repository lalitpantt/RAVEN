package pressure_test

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"raven/internal/analysis"
	"raven/internal/model"
	"raven/internal/pipeline"
	"raven/internal/rawstore"
)

type LatencyTracker struct {
	mu        sync.Mutex
	durations []time.Duration
}

func (l *LatencyTracker) Record(d time.Duration) {
	l.mu.Lock()
	l.durations = append(l.durations, d)
	l.mu.Unlock()
}

func (l *LatencyTracker) Percentiles() (p50, p95, p99, p999, max time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.durations) == 0 {
		return 0, 0, 0, 0, 0
	}
	sorted := make([]time.Duration, len(l.durations))
	copy(sorted, l.durations)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	p50 = sorted[int(float64(len(sorted))*0.50)]
	p95 = sorted[int(float64(len(sorted))*0.95)]
	p99 = sorted[int(float64(len(sorted))*0.99)]
	p999 = sorted[int(float64(len(sorted))*0.999)]
	max = sorted[len(sorted)-1]
	return
}

type BenchSink struct {
	delivered int64
	tracker   *LatencyTracker
}

func (s *BenchSink) Emit(ctx context.Context, event *model.NormalizedEvent) error {
	atomic.AddInt64(&s.delivered, 1)
	if s.tracker != nil {
		s.tracker.Record(time.Since(event.Raven.ReceivedTime))
	}
	return nil
}

func (s *BenchSink) Flush() error { return nil }
func (s *BenchSink) Close() error { return nil }

func setupBenchPipeline(b *testing.B, workers int, tracker *LatencyTracker) (*pipeline.Pipeline, *rawstore.RawStore, *BenchSink) {
	b.Helper()
	dir := b.TempDir()
	dbPath := filepath.Join(dir, "bench_pipeline.db")
	store, err := rawstore.New(dbPath)
	if err != nil {
		b.Fatalf("failed to create rawstore: %v", err)
	}

	sink := &BenchSink{tracker: tracker}
	cfg := pipeline.Config{
		Workers:    workers,
		BufferSize: 50000,
	}
	p := pipeline.New(cfg, store, sink)
	p.Start()

	b.Cleanup(func() {
		p.Stop()
		_ = store.Close()
	})

	return p, store, sink
}

func setupTestPipeline(t *testing.T, workers int, tracker *LatencyTracker) (*pipeline.Pipeline, *rawstore.RawStore, *BenchSink) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test_pipeline.db")
	store, err := rawstore.New(dbPath)
	if err != nil {
		t.Fatalf("failed to create rawstore: %v", err)
	}

	sink := &BenchSink{tracker: tracker}
	cfg := pipeline.Config{
		Workers:    workers,
		BufferSize: 50000,
	}
	p := pipeline.New(cfg, store, sink)
	p.Start()

	t.Cleanup(func() {
		p.Stop()
		_ = store.Close()
	})

	return p, store, sink
}

var sampleWorkload = [][]byte{
	// Syslog RFC5424
	[]byte(`<14>1 2026-09-24T12:00:00Z pa-fw-01 pan_traffic 1234 - [meta sequence="1"] 10.0.1.50,172.16.0.1,443,allow,web-browsing`),
	// Syslog RFC3164
	[]byte(`<34>Oct 11 22:14:15 server01 sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 43210 ssh2`),
	// JSON payment
	[]byte(`{"timestamp":"2026-09-24T12:00:00Z","severity":"info","transaction_id":"txn_9948271","amount":142.50,"currency":"USD","user_id":"usr_882194","merchant_id":"mch_00129","status":"COMPLETED","processing_time":48}`),
	// LEEF
	[]byte(`LEEF:2.0|IBM|QRadar|7.4|1002|^|src=10.0.0.1^dst=10.0.0.2^usrName=admin^action=login`),
	// CEF
	[]byte(`CEF:0|CrowdStrike|Falcon|7.0.0|1001|Process Rollup|5|src=10.0.1.5 dst=172.16.0.1 cs1=malicious.exe`),
	// XML
	[]byte(`<event><timestamp>2026-09-24T12:00:00Z</timestamp><source>vpn-01</source><action>login</action><src_ip>10.0.0.8</src_ip></event>`),
	// CSV
	[]byte("timestamp,source,action,src_ip\n2026-09-24T12:00:00Z,db-01,query,10.0.0.9\n"),
	// Application-specific key/value text
	[]byte(`timestamp=2026-09-24T12:00:00Z source=iot-gateway action=heartbeat status=ok`),
}

func BenchmarkPipeline_E2E(b *testing.B) {
	workerCounts := []int{1, 4, 8}

	for _, workers := range workerCounts {
		b.Run(fmt.Sprintf("%d_Workers", workers), func(b *testing.B) {
			p, _, sink := setupBenchPipeline(b, workers, nil)
			ctx := context.Background()

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				data := sampleWorkload[i%len(sampleWorkload)]
				rec := model.IngestedRecord{
					Transport:  "http_post",
					SourceIP:   "10.0.1.1",
					SourcePort: 8080,
					RawBytes:   data,
					ReceivedAt: time.Now().UTC(),
				}
				if err := p.SubmitSync(ctx, rec); err != nil {
					b.Fatalf("SubmitSync failed: %v", err)
				}
			}

			p.Stop()

			stats := p.Stats()
			valid, reason := stats.VerifyInvariant()
			if !valid {
				b.Fatalf("loss accounting invariant failed: %s", reason)
			}
			_ = sink
		})
	}
}

func TestPressureProfiles(t *testing.T) {
	tracker := &LatencyTracker{}
	p, _, sink := setupTestPipeline(t, 8, tracker)
	ctx := context.Background()

	// 1. Smoke test: 1,000 mixed events
	t.Log("Starting Smoke Profile (1,000 events)...")
	start := time.Now()
	const smokeEvents = 1000

	var totalBytes int64
	for i := 0; i < smokeEvents; i++ {
		data := sampleWorkload[rand.Intn(len(sampleWorkload))]
		totalBytes += int64(len(data))
		rec := model.IngestedRecord{
			Transport:  "http_post",
			SourceIP:   "10.0.1.1",
			SourcePort: 8080,
			RawBytes:   data,
			ReceivedAt: time.Now().UTC(),
		}
		if err := p.SubmitSync(ctx, rec); err != nil {
			t.Fatalf("SubmitSync failed: %v", err)
		}
	}

	elapsed := time.Since(start)
	eps := float64(smokeEvents) / elapsed.Seconds()
	mibPerSec := (float64(totalBytes) / (1024 * 1024)) / elapsed.Seconds()

	p50, p95, p99, _, max := tracker.Percentiles()
	t.Logf("Smoke Profile Completed: %d events in %v (%.1f EPS, %.2f MiB/s)", smokeEvents, elapsed, eps, mibPerSec)
	t.Logf("Latency Percentiles: p50=%v, p95=%v, p99=%v, max=%v", p50, p95, p99, max)

	// Stop to ensure drain
	p.Stop()

	stats := p.Stats()
	valid, reason := stats.VerifyInvariant()
	if !valid {
		t.Fatalf("loss accounting invariant violated: %s", reason)
	}

	if stats.Accepted != smokeEvents {
		t.Errorf("expected %d accepted, got %d", smokeEvents, stats.Accepted)
	}
	if atomic.LoadInt64(&sink.delivered) < int64(stats.Normalized) {
		t.Errorf("sink received fewer than normalized: %d vs %d", sink.delivered, stats.Normalized)
	}
}

func TestAnalysisPressureGate(t *testing.T) {
	if os.Getenv("RAVEN_ANALYSIS_PRESSURE_GATE") != "1" {
		t.Skip("set RAVEN_ANALYSIS_PRESSURE_GATE=1 to run the Analysis release pressure gate")
	}
	type result struct {
		eps, p95Micros float64
	}
	run := func(enabled bool) result {
		t.Helper()
		tracker := &LatencyTracker{}
		dir := t.TempDir()
		store, err := rawstore.New(filepath.Join(dir, "analysis-pressure.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		var worker *analysis.Worker
		if enabled {
			worker, err = analysis.NewWorker(store, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := worker.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			defer worker.Stop()
		}
		sink := &BenchSink{tracker: tracker}
		p := pipeline.New(pipeline.Config{Workers: 8, BufferSize: 50000}, store, sink)
		p.Start()
		const events = 1000
		started := time.Now()
		for i := 0; i < events; i++ {
			if err := p.SubmitSync(context.Background(), model.IngestedRecord{
				Transport: "http_post", SourceIP: "10.0.1.1", RawBytes: sampleWorkload[i%len(sampleWorkload)], ReceivedAt: time.Now().UTC(),
			}); err != nil {
				t.Fatalf("analysis enabled=%t submit %d: %v", enabled, i, err)
			}
		}
		eps := float64(events) / time.Since(started).Seconds()
		p.Stop()
		if stats := p.Stats(); stats.Accepted != events {
			t.Fatalf("analysis enabled=%t accepted=%d, want %d", enabled, stats.Accepted, events)
		} else if ok, reason := stats.VerifyInvariant(); !ok {
			t.Fatalf("analysis enabled=%t loss accounting: %s", enabled, reason)
		}
		_, p95, _, _, _ := tracker.Percentiles()
		if enabled {
			deadline := time.Now().Add(5 * time.Second)
			for {
				status, err := worker.Status(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if status.QueueStatus.Pending == 0 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("analysis queue did not drain within five seconds: %+v", status.QueueStatus)
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
		return result{eps: eps, p95Micros: float64(p95.Microseconds())}
	}

	baseline := run(false)
	withAnalysis := run(true)
	t.Logf("1,000 mixed events: disabled %.1f EPS / %.0f µs p95; enabled %.1f EPS / %.0f µs p95", baseline.eps, baseline.p95Micros, withAnalysis.eps, withAnalysis.p95Micros)
	if withAnalysis.eps < baseline.eps*0.90 {
		t.Fatalf("analysis throughput %.1f EPS fell below 90%% of disabled %.1f EPS", withAnalysis.eps, baseline.eps)
	}
	if baseline.p95Micros > 0 && withAnalysis.p95Micros > baseline.p95Micros*1.25 {
		t.Fatalf("analysis p95 %.0f µs exceeded 125%% of disabled %.0f µs", withAnalysis.p95Micros, baseline.p95Micros)
	}
}

// TestRigorousPressureMatrix is opt-in because it intentionally writes a large
// durable corpus. It covers every decoder family with concurrent producers and
// fails unless every accepted child is normalized, quarantined, or still pending.
func TestRigorousPressureMatrix(t *testing.T) {
	if os.Getenv("RAVEN_RIGOROUS_BENCH") != "1" {
		t.Skip("set RAVEN_RIGOROUS_BENCH=1 to run the sustained pressure profile")
	}
	total := 100000
	if raw := os.Getenv("RAVEN_BENCH_EVENTS"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < len(sampleWorkload) {
			t.Fatalf("invalid RAVEN_BENCH_EVENTS %q", raw)
		}
		total = n
	}
	tracker := &LatencyTracker{}
	p, _, _ := setupTestPipeline(t, 8, tracker)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	start := time.Now()
	const producers = 8
	var wg sync.WaitGroup
	var submitted atomic.Int64
	for producer := 0; producer < producers; producer++ {
		wg.Add(1)
		go func(offset int) {
			defer wg.Done()
			for i := offset; i < total; i += producers {
				data := sampleWorkload[i%len(sampleWorkload)]
				err := p.SubmitWait(ctx, model.IngestedRecord{Transport: "benchmark", SourceIP: "127.0.0.1", RawBytes: data, ReceivedAt: time.Now().UTC()})
				if err != nil {
					t.Errorf("submit %d: %v", i, err)
					return
				}
				submitted.Add(1)
			}
		}(producer)
	}
	wg.Wait()
	p.Stop()
	elapsed := time.Since(start)
	stats := p.Stats()
	if ok, reason := stats.VerifyInvariant(); !ok {
		t.Fatal(reason)
	}
	if stats.Accepted != submitted.Load() {
		t.Fatalf("accepted=%d submitted=%d", stats.Accepted, submitted.Load())
	}
	p50, p95, p99, p999, max := tracker.Percentiles()
	t.Logf("events=%d elapsed=%s eps=%.1f p50=%s p95=%s p99=%s p99.9=%s max=%s normalized=%d quarantined=%d pending=%d",
		stats.Accepted, elapsed, float64(stats.Accepted)/elapsed.Seconds(), p50, p95, p99, p999, max, stats.Normalized, stats.Quarantined, stats.Pending)
}
