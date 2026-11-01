package analysis

import (
	"testing"
	"time"

	"raven/internal/rawstore"
)

func TestBuildDeviceTelemetryStates(t *testing.T) {
	now := time.Date(2026, time.November, 2, 10, 30, 0, 0, time.UTC)
	freshness := Duration(5 * time.Minute)
	device := DeviceResource{Metadata: ResourceMetadata{Name: "router-1", Version: "1.0.0"}, Spec: DeviceSpec{
		DisplayName: "Router 1", SourceCategory: "network_device", Reporting: ReportingSpec{Mode: "event", FreshnessAfter: freshness},
	}}
	normalized := rawstore.AnalysisDeviceTelemetry{NormalizedCount: 2, QuarantinedCount: 1, LastNormalizedAt: now.Add(-time.Minute), IdentityConfidence: "strong", MatchMethod: "host"}
	type testCase struct {
		name   string
		device DeviceResource
		stored rawstore.AnalysisDeviceTelemetry
		state  DeviceState
	}
	tests := []testCase{
		{name: "never seen", device: device, state: DeviceStateUnknown},
		{name: "fresh normalized signal", device: device, stored: normalized, state: DeviceStateGreen},
		{name: "stale event only source", device: device, stored: rawstore.AnalysisDeviceTelemetry{LastNormalizedAt: now.Add(-6 * time.Minute)}, state: DeviceStateUnknown},
		{name: "latest observation quarantined", device: device, stored: rawstore.AnalysisDeviceTelemetry{LastNormalizedAt: now.Add(-2 * time.Minute), LastQuarantinedAt: now.Add(-time.Minute)}, state: DeviceStateYellow},
		{name: "explicitly disabled", device: disabledDevice(device), stored: normalized, state: DeviceStateDisabled},
	}

	heartbeat := device
	heartbeat.Spec.Reporting = ReportingSpec{Mode: "heartbeat", ExpectedInterval: Duration(time.Minute), WarningAfter: Duration(2 * time.Minute), CriticalAfter: Duration(5 * time.Minute)}
	tests = append(tests,
		testCase{name: "heartbeat recent", device: heartbeat, stored: rawstore.AnalysisDeviceTelemetry{LastHeartbeatAt: now.Add(-time.Minute)}, state: DeviceStateGreen},
		testCase{name: "heartbeat late", device: heartbeat, stored: rawstore.AnalysisDeviceTelemetry{LastHeartbeatAt: now.Add(-3 * time.Minute)}, state: DeviceStateYellow},
		testCase{name: "heartbeat critical", device: heartbeat, stored: rawstore.AnalysisDeviceTelemetry{LastHeartbeatAt: now.Add(-6 * time.Minute)}, state: DeviceStateRed},
	)
	maintenance := heartbeat
	maintenance.Spec.Maintenance = &MaintenanceSpec{TimeZone: "UTC", Windows: []MaintenanceWindow{{Weekdays: []string{"mon"}, Start: "10:00", End: "11:00"}}}
	tests = append(tests, testCase{name: "heartbeat maintenance", device: maintenance, stored: rawstore.AnalysisDeviceTelemetry{LastHeartbeatAt: now.Add(-6 * time.Minute)}, state: DeviceStateDisabled})

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := BuildDeviceTelemetry(test.device, test.stored, now)
			if got.State != test.state || got.Reason == "" || !got.EvaluatedAt.Equal(now) {
				t.Fatalf("telemetry=%+v; want state %q with reason and evaluation time", got, test.state)
			}
			if test.name == "heartbeat maintenance" && (got.MaintenanceUntil == nil || !got.MaintenanceUntil.Equal(time.Date(2026, time.November, 2, 11, 0, 0, 0, time.UTC))) {
				t.Fatalf("maintenance deadline=%v, want 11:00 UTC", got.MaintenanceUntil)
			}
		})
	}
	result := BuildDeviceTelemetry(device, normalized, now)
	if ratio := result.NormalizationRatio; ratio != 2.0/3.0 {
		t.Fatalf("normalization ratio=%v, want 2/3", ratio)
	}
	if result.LastNormalizedAge == nil || *result.LastNormalizedAge != 60 {
		t.Fatalf("last normalized age=%v, want 60 seconds", result.LastNormalizedAge)
	}
}

func disabledDevice(device DeviceResource) DeviceResource {
	value := false
	device.Spec.Enabled = &value
	return device
}
