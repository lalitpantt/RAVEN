package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunAnalysisCLI(t *testing.T) {
	invalidDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(invalidDir, "devices"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(invalidDir, "devices", "bad.yaml"), []byte("apiVersion: raven.io/v1\nkind: Device\nmetadata: {name: BAD, version: 1.0.0}\nspec: {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		args   []string
		code   int
		output string
	}{
		{name: "valid examples", args: []string{"validate", "--analysis-dir", filepath.Join("..", "..", "analysis", "examples")}, output: "2 device(s), 4 rule(s)"},
		{name: "disabled directory", args: []string{"validate", "--analysis-dir", "none"}, output: "Analysis disabled"},
		{name: "invalid config", args: []string{"validate", "--analysis-dir", invalidDir}, code: 1, output: "Analysis configuration invalid"},
		{name: "unknown subcommand", args: []string{"test"}, code: 2, output: "Usage:"},
		{name: "unexpected argument", args: []string{"validate", "extra"}, code: 2, output: "unexpected arguments"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := RunAnalysisCLI(test.args, &stdout, &stderr)
			if code != test.code {
				t.Fatalf("exit code = %d, want %d; stderr=%s", code, test.code, stderr.String())
			}
			if !strings.Contains(stdout.String()+stderr.String(), test.output) {
				t.Fatalf("output %q does not contain %q", stdout.String()+stderr.String(), test.output)
			}
		})
	}
}

func TestRunAnalysisCLIRulePreviewDoesNotNeedDatabase(t *testing.T) {
	directory := filepath.Join("..", "..", "analysis", "examples")
	sample := filepath.Join(directory, "samples", "interface-down.json")
	var stdout, stderr bytes.Buffer
	code := RunAnalysisCLI([]string{"test", "-rule", "interface-down", "-sample", sample, "--analysis-dir", directory}, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "MATCH rule=interface-down") || !strings.Contains(stdout.String(), "fields=activity_name") || !strings.Contains(stdout.String(), "no database writes") {
		t.Fatalf("preview result: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = RunAnalysisCLI([]string{"test", "-rule", "missing", "-sample", sample, "--analysis-dir", directory}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "not found") {
		t.Fatalf("missing rule result: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}
