package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunIntegrityCLIStatusAndWaitResult(t *testing.T) {
	oldClient := integrityCLIHTTPClient
	t.Cleanup(func() { integrityCLIHTTPClient = oldClient })
	integrityCLIHTTPClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "Bearer cli-secret" && r.Header.Get("Authorization") != "Bearer failed-secret" {
			t.Errorf("missing CLI bearer credential")
		}
		body, status := `{"enabled":true}`, http.StatusOK
		switch r.URL.Path {
		case "/api/v1/integrity/audits":
			var request map[string]string
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request["type"] != "fast" {
				t.Errorf("audit request: %v %v", request, err)
			}
			body, status = `{"run_id":"run-1","state":"running","type":"fast"}`, http.StatusAccepted
			if r.Header.Get("Authorization") == "Bearer failed-secret" {
				body = `{"run_id":"run-failed","state":"running","type":"fast"}`
			}
		case "/api/v1/integrity/audits/run-1":
			body = `{"run_id":"run-1","state":"completed","result":"passed"}`
		case "/api/v1/integrity/audits/run-failed":
			body = `{"run_id":"run-failed","state":"failed","result":"failed"}`
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})}
	var out, errOut bytes.Buffer
	if code := RunIntegrityCLI([]string{"status"}, "http://operator.test", "cli-secret", &out, &errOut); code != 0 || !bytes.Contains(out.Bytes(), []byte(`"enabled": true`)) {
		t.Fatalf("status: code=%d out=%s err=%s", code, out.String(), errOut.String())
	}
	out.Reset()
	errOut.Reset()
	if code := RunIntegrityCLI([]string{"verify", "--type", "fast", "--wait", "--wait-timeout", "1s"}, "http://operator.test", "cli-secret", &out, &errOut); code != 0 || !bytes.Contains(out.Bytes(), []byte("passed")) {
		t.Fatalf("verify: code=%d out=%s err=%s", code, out.String(), errOut.String())
	}
	out.Reset()
	errOut.Reset()
	if code := RunIntegrityCLI([]string{"verify", "--type", "fast", "--wait"}, "http://operator.test", "failed-secret", &out, &errOut); code != 1 || !bytes.Contains(out.Bytes(), []byte("failed")) {
		t.Fatalf("failed audit exit code=%d out=%s err=%s", code, out.String(), errOut.String())
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDaemonStartupBanner(t *testing.T) {
	for _, tc := range []struct {
		name              string
		uiAddr            string
		marketplaceOnline bool
		wantUI            string
		wantMarketplace   string
	}{
		{name: "online", uiAddr: "127.0.0.1:19090", marketplaceOnline: true, wantUI: "http://127.0.0.1:19090", wantMarketplace: "online (network access only for explicit marketplace commands)"},
		{name: "offline and UI disabled", uiAddr: "none", wantUI: "disabled", wantMarketplace: "offline (bundled catalog and verified cache only)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := daemonStartupBanner(123, "./raven", tc.uiAddr, "data/raven.log", "packs", tc.marketplaceOnline, "https://registry.example.test")
			for _, want := range []string{tc.wantUI, tc.wantMarketplace, "./raven packs apply -f <pack.yaml>", "./raven marketplace refresh", "./raven packs install <name>[@version]", "https://registry.example.test"} {
				if !strings.Contains(got, want) {
					t.Errorf("daemon startup banner missing %q:\n%s", want, got)
				}
			}
		})
	}
}

func TestGetBaseURL(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", "http://localhost:9090"},
		{"none", "http://localhost:9090"},
		{":8080", "http://localhost:8080"},
		{"127.0.0.1:9090", "http://127.0.0.1:9090"},
		{"http://localhost:9090", "http://localhost:9090"},
		{"https://example.com", "https://example.com"},
	}

	for _, tc := range tests {
		got := GetBaseURL(tc.input)
		if got != tc.want {
			t.Errorf("GetBaseURL(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestReadPID(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "test.pid")

	// Missing file
	_, err := ReadPID(pidFile)
	if err == nil {
		t.Errorf("expected error for missing PID file")
	}

	// Invalid content
	if err := os.WriteFile(pidFile, []byte("not_a_number"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err = ReadPID(pidFile)
	if err == nil {
		t.Errorf("expected error for invalid PID content")
	}

	// Valid content
	if err := os.WriteFile(pidFile, []byte(" 12345 \n"), 0644); err != nil {
		t.Fatal(err)
	}
	pid, err := ReadPID(pidFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pid != 12345 {
		t.Errorf("ReadPID() = %d, want 12345", pid)
	}
}

func TestIsPIDAlive(t *testing.T) {
	// Current process must be alive
	currentPID := os.Getpid()
	if !IsPIDAlive(currentPID) {
		t.Errorf("expected current PID %d to be alive", currentPID)
	}

	// Non-positive PID
	if IsPIDAlive(0) {
		t.Errorf("expected PID 0 to be dead")
	}
	if IsPIDAlive(-1) {
		t.Errorf("expected negative PID to be dead")
	}

	// Likely non-existent PID
	if IsPIDAlive(99999999) {
		t.Errorf("expected PID 99999999 to be dead")
	}
}
