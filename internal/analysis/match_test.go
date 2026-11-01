package analysis

import (
	"testing"

	"raven/internal/model"
)

func TestEvaluateEventRuleUsesExactNormalizedFields(t *testing.T) {
	snapshot, err := LoadDirectory("../../analysis/examples")
	if err != nil {
		t.Fatal(err)
	}
	rule, _ := snapshot.Rule("interface-down")
	tests := []struct {
		name, activity string
		matched, clear bool
	}{
		{name: "match", activity: "interface_down", matched: true},
		{name: "clear", activity: "interface_up", clear: true},
		{name: "near miss", activity: "interface_down_extra"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := EvaluateEventRule(rule, &model.NormalizedEvent{Raven: model.RavenEnvelope{SourceCategory: "network_device"}, OCSF: map[string]any{"activity_name": tc.activity}})
			if got.Matched != tc.matched || got.ClearMatched != tc.clear {
				t.Fatalf("evaluation=%+v", got)
			}
		})
	}
	if got := EvaluateEventRule(rule, &model.NormalizedEvent{Raven: model.RavenEnvelope{SourceCategory: "server"}, OCSF: map[string]any{"activity_name": "interface_down"}}); got.Matched || got.ClearMatched {
		t.Fatalf("source category filter ignored: %+v", got)
	}
}
