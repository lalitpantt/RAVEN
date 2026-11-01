package main

import (
	"encoding/json"
	"math/rand"
	"testing"
	"time"
)

func TestAppSimulatorHeartbeatScenario(t *testing.T) {
	generated := (&AppSimulator{}).Generate("heartbeat", time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), rand.New(rand.NewSource(1)))
	var event map[string]any
	if err := json.Unmarshal(generated, &event); err != nil {
		t.Fatalf("heartbeat event is not valid JSON: %v", err)
	}
	if event["action"] != "heartbeat" || event["server"] != "pay-srv-heartbeat-01" {
		t.Fatalf("heartbeat identity or action mismatch: %#v", event)
	}
}
