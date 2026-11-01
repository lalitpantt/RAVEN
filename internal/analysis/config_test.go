package analysis

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadDirectoryValidatesExamplesAndKeepsSnapshotImmutable(t *testing.T) {
	directory := filepath.Join("..", "..", "analysis", "examples")
	snapshot, err := LoadDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Enabled() || snapshot.DeviceCount() != 2 || snapshot.RuleCount() != 2 {
		t.Fatalf("unexpected example snapshot: enabled=%v devices=%d rules=%d", snapshot.Enabled(), snapshot.DeviceCount(), snapshot.RuleCount())
	}
	rule, ok := snapshot.Rule("interface-down")
	if !ok || len(rule.Spec.compiled) != 2 || rule.Spec.Finding.ClearAfter.Value() == 0 {
		t.Fatalf("rule was not typed and compiled: %+v", rule)
	}
	rule.Spec.Match.Fields[0].Value = "mutated"
	devices := snapshot.Devices()
	for i := range devices {
		if devices[i].Metadata.Name == "edge-router-01" {
			devices[i].Spec.Aliases["syslog_host"][0] = "mutated.example"
		}
	}
	unchanged, _ := snapshot.Rule("interface-down")
	if unchanged.Spec.Match.Fields[0].Value != "interface_down" {
		t.Fatal("snapshot exposed mutable rule state")
	}
	resolved := snapshot.Resolver().Resolve(map[string]string{"syslog_host": "edge-router-01.example.internal"})
	if resolved.Resolution != "matched" || resolved.DeviceID != "edge-router-01" {
		t.Fatalf("snapshot resolver changed after accessor mutation: %+v", resolved)
	}
}

func TestDisabledDeviceIsNotResolved(t *testing.T) {
	directory := t.TempDir()
	device := strings.Replace(validDevice("edge-1"), "  displayName:", "  enabled: false\n  displayName:", 1)
	writeConfig(t, directory, "devices", "device.yaml", device)
	snapshot, err := LoadDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	if result := snapshot.Resolver().Resolve(map[string]string{"syslog_host": "edge-1.example.internal"}); result.Resolution != "unknown" {
		t.Fatalf("disabled device resolved as active: %+v", result)
	}
}

func TestLoadDirectoryEmptyAndNoneDisableAnalysis(t *testing.T) {
	for _, directory := range []string{"none", t.TempDir(), filepath.Join(t.TempDir(), "missing")} {
		snapshot, err := LoadDirectory(directory)
		if err != nil || snapshot.Enabled() || snapshot.DeviceCount() != 0 || snapshot.RuleCount() != 0 {
			t.Fatalf("LoadDirectory(%q) = %+v, %v", directory, snapshot, err)
		}
	}
}

func TestLoadDirectoryRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name         string
		device       string
		secondDevice string
		rule         string
		secondRule   string
		want         string
	}{
		{name: "invalid resource name", device: validDevice("Edge.Router"), want: "metadata.name"},
		{name: "invalid semver", device: validDeviceWithMetadata("edge-1", "next"), want: "metadata.version"},
		{name: "unsupported category", device: strings.Replace(validDevice("edge-1"), "network_device", "router", 1), want: "sourceCategory"},
		{name: "empty alias", device: strings.Replace(validDevice("edge-1"), "      - edge-1.example.internal", "      - \"\"", 1), want: "aliases.syslog_host"},
		{name: "duplicate alias", device: validDevice("edge-1"), secondDevice: validDevice("edge-2"), want: "duplicate alias"},
		{name: "unknown field", device: strings.Replace(validDevice("edge-1"), "  displayName:", "  unexpected: true\n  displayName:", 1), want: "field unexpected not found"},
		{name: "bad duration", device: strings.Replace(validDevice("edge-1"), "mode: event", "mode: event\n    freshnessAfter: 1ms", 1), want: "freshnessAfter"},
		{name: "unknown heartbeat rule", device: heartbeatDevice("not-installed"), rule: heartbeatRule("valid-heartbeat"), want: "unknown heartbeatRule"},
		{name: "disabled heartbeat rule", device: heartbeatDevice("valid-heartbeat"), rule: strings.Replace(heartbeatRule("valid-heartbeat"), "  kind: heartbeat", "  enabled: false\n  kind: heartbeat", 1), want: "disabled heartbeatRule"},
		{name: "wrong heartbeat rule kind", device: heartbeatDevice("router-down"), rule: eventRule("router-down", "^down$"), want: "expected heartbeat"},
		{name: "malformed regex", device: validDevice("edge-1"), rule: eventRule("regex-rule", "["), want: "invalid Go RE2 regex"},
		{name: "unsupported operator", device: validDevice("edge-1"), rule: strings.Replace(eventRule("bad-op", "^down$"), "op: regex", "op: matches", 1), want: "unsupported operator"},
		{name: "raw payload path", device: validDevice("edge-1"), rule: strings.Replace(eventRule("raw-rule", "^x$"), "path: message", "path: raw.payload", 1), want: "cannot reference raw payload"},
		{name: "duplicate rule ID", device: validDevice("edge-1"), rule: eventRule("same-rule", "^x$"), secondRule: eventRule("same-rule", "^y$"), want: "duplicate rule ID"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			if test.device != "" {
				writeConfig(t, directory, "devices", "one.yaml", test.device)
			}
			if test.secondDevice != "" {
				writeConfig(t, directory, "devices", "two.yaml", test.secondDevice)
			}
			if test.rule != "" {
				writeConfig(t, directory, "rules", "rule.yaml", test.rule)
			}
			if test.secondRule != "" {
				writeConfig(t, directory, "rules", "rule-two.yaml", test.secondRule)
			}
			_, err := LoadDirectory(directory)
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(test.want)) {
				t.Fatalf("LoadDirectory error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestSnapshotStoreReloadIsAtomicAndRetainsLastKnownGood(t *testing.T) {
	valid := t.TempDir()
	writeConfig(t, valid, "devices", "device.yaml", validDevice("edge-1"))
	initial, err := LoadDirectory(valid)
	if err != nil {
		t.Fatal(err)
	}
	store := NewSnapshotStore(initial)
	invalid := t.TempDir()
	writeConfig(t, invalid, "devices", "device.yaml", "apiVersion: raven.io/v1\nkind: Device\nmetadata: {name: BAD, version: 1.0.0}\nspec: {}\n")
	if err := store.Reload(invalid); err == nil {
		t.Fatal("invalid reload succeeded")
	}
	if store.Current() != initial {
		t.Fatal("failed reload replaced the active snapshot")
	}
	replacement := t.TempDir()
	writeConfig(t, replacement, "devices", "device.yaml", validDevice("edge-2"))
	if err := store.Reload(replacement); err != nil {
		t.Fatal(err)
	}
	if store.Current() == initial || store.Current().Devices()[0].Metadata.Name != "edge-2" {
		t.Fatal("successful reload did not atomically replace the snapshot")
	}
}

func TestLoadDirectoryRejectsSymlinksAndMultipleDocuments(t *testing.T) {
	directory := t.TempDir()
	if err := os.MkdirAll(filepath.Join(directory, "devices"), 0755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "device.yaml")
	if err := os.WriteFile(target, []byte(validDevice("edge-1")), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(directory, "devices", "linked.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDirectory(directory); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("symlink config accepted: %v", err)
	}
	if err := os.Remove(filepath.Join(directory, "devices", "linked.yaml")); err != nil {
		t.Fatal(err)
	}
	writeConfig(t, directory, "devices", "multi.yaml", validDevice("edge-1")+"\n---\n"+validDevice("edge-2"))
	if _, err := LoadDirectory(directory); err == nil || !strings.Contains(err.Error(), "exactly one YAML resource") {
		t.Fatalf("multi-document config accepted: %v", err)
	}
}

func writeConfig(t *testing.T, root, subdirectory, name, value string) {
	t.Helper()
	path := filepath.Join(root, subdirectory, name)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
}

func validDevice(name string) string { return validDeviceWithMetadata(name, "1.0.0") }

func validDeviceWithMetadata(name, version string) string {
	return "apiVersion: raven.io/v1\nkind: Device\nmetadata:\n  name: " + name + "\n  version: " + version + "\nspec:\n  displayName: " + name + "\n  sourceCategory: network_device\n  aliases:\n    syslog_host:\n      - edge-1.example.internal\n  reporting:\n    mode: event\n"
}

func heartbeatDevice(rule string) string {
	return strings.Replace(validDevice("edge-1"), "mode: event", "mode: heartbeat\n    heartbeatRule: "+rule+"\n    expectedInterval: 60s\n    warningAfter: 120s\n    criticalAfter: 300s", 1)
}

func heartbeatRule(name string) string {
	return "apiVersion: raven.io/v1\nkind: AnalysisRule\nmetadata:\n  name: " + name + "\n  version: 1.0.0\nspec:\n  kind: heartbeat\n  match:\n    fields:\n      - path: activity_name\n        op: eq\n        value: heartbeat\n  finding:\n    severity: medium\n    state: yellow\n    title: Heartbeat late\n"
}

func eventRule(name, regex string) string {
	return "apiVersion: raven.io/v1\nkind: AnalysisRule\nmetadata:\n  name: " + name + "\n  version: 1.0.0\nspec:\n  kind: event\n  sourceCategory: network_device\n  match:\n    fields:\n      - path: message\n        op: regex\n        value: '" + regex + "'\n  clear:\n    - path: message\n      op: eq\n      value: clear\n  finding:\n    severity: high\n    state: red\n    title: A test finding\n    clearAfter: 30s\n"
}
