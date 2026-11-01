package analysis

import (
	"testing"

	"raven/internal/model"
)

func TestResolverMatchesExactAliasesAndReportsUncertainSources(t *testing.T) {
	resolver, err := NewResolver([]Device{
		{ID: "edge-1", Aliases: map[string][]string{"syslog_host": {"edge-1.internal"}, "source_ip": {"10.0.0.1"}}},
		{ID: "server-1", Aliases: map[string][]string{"host": {"server-1"}, "source_ip": {"10.0.0.2"}}},
		{ID: "proxy-2", Aliases: map[string][]string{"source_ip": {"10.0.0.2"}}},
	})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name       string
		hints      model.AnalysisIdentityHints
		resolution string
		deviceID   string
		method     string
		confidence string
	}{
		{"strong hostname and address agree", model.AnalysisIdentityHints{"syslog_host": "edge-1.internal", "source_ip": "10.0.0.1"}, "matched", "edge-1", "source_ip+syslog_host", "strong"},
		{"weak address-only identity", model.AnalysisIdentityHints{"source_ip": "10.0.0.1"}, "matched", "edge-1", "source_ip", "weak"},
		{"conflicting exact aliases", model.AnalysisIdentityHints{"host": "server-1", "source_ip": "10.0.0.2"}, "ambiguous", "", "host+source_ip", "none"},
		{"unregistered source", model.AnalysisIdentityHints{"host": "unknown-host"}, "unknown", "", "none", "none"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolver.Resolve(tc.hints)
			if got.Resolution != tc.resolution || got.DeviceID != tc.deviceID || got.MatchMethod != tc.method || got.Confidence != tc.confidence {
				t.Fatalf("Resolve(%v) = %+v", tc.hints, got)
			}
			if len(got.SourceKey) != 64 {
				t.Fatalf("source key has length %d", len(got.SourceKey))
			}
		})
	}
}

func TestResolverRejectsInvalidInventoryIdentity(t *testing.T) {
	for _, devices := range [][]Device{
		{{Aliases: map[string][]string{"host": {"host"}}}},
		{{ID: "same"}, {ID: "same"}},
		{{ID: "bad", Aliases: map[string][]string{"address": {"10.0.0.1"}}}},
		{{ID: "empty", Aliases: map[string][]string{"host": {""}}}},
	} {
		if _, err := NewResolver(devices); err == nil {
			t.Fatalf("NewResolver(%+v) succeeded", devices)
		}
	}
}
