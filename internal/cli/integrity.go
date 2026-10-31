package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// RunIntegrityCLI executes the operator integrity commands. Exit codes are
// 0 for accepted/passed, 1 for a verified mismatch, and 2 for unavailable work.
func RunIntegrityCLI(args []string, defaultUI string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: raven integrity status | verify --type fast|deep|ledger [--wait]")
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("integrity "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	ui := fs.String("ui", defaultUI, "Management API address")
	typ := fs.String("type", "", "Audit type: fast, deep, or ledger")
	wait := fs.Bool("wait", false, "Wait for the audit result")
	timeout := fs.Duration("wait-timeout", 30*time.Second, "Maximum wait for audit completion")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	base := GetBaseURL(*ui)
	request := func(method, path string, body io.Reader) (*http.Response, error) {
		req, err := http.NewRequest(method, base+path, body)
		if err != nil {
			return nil, err
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		return integrityCLIHTTPClient.Do(req)
	}
	switch sub {
	case "status":
		if fs.NArg() != 0 {
			fmt.Fprintln(stderr, "Usage: raven integrity status [--ui address]")
			return 2
		}
		resp, err := request(http.MethodGet, "/api/v1/integrity/status", nil)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(stderr, resp.Body)
			return 2
		}
		var value any
		if err = json.NewDecoder(resp.Body).Decode(&value); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err = enc.Encode(value); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		return 0
	case "verify":
		if fs.NArg() != 0 || (*typ != "fast" && *typ != "deep" && *typ != "ledger") {
			fmt.Fprintln(stderr, "Usage: raven integrity verify --type fast|deep|ledger [--wait]")
			return 2
		}
		resp, err := request(http.MethodPost, "/api/v1/integrity/audits", strings.NewReader(fmt.Sprintf(`{"type":%q}`, *typ)))
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			_, _ = io.Copy(stderr, resp.Body)
			return 2
		}
		var run struct {
			RunID  string `json:"run_id"`
			State  string `json:"state"`
			Type   string `json:"type"`
			Result string `json:"result"`
		}
		if err = json.NewDecoder(resp.Body).Decode(&run); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		if !*wait {
			fmt.Fprintf(stdout, "Audit %s (%s): %s\n", run.RunID, run.Type, run.State)
			return 0
		}
		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		defer cancel()
		for {
			resp, err = request(http.MethodGet, "/api/v1/integrity/audits/"+run.RunID, nil)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 2
			}
			err = json.NewDecoder(resp.Body).Decode(&run)
			resp.Body.Close()
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 2
			}
			if run.State == "completed" || run.State == "failed" {
				break
			}
			select {
			case <-ctx.Done():
				fmt.Fprintf(stderr, "Audit %s did not finish before timeout\n", run.RunID)
				return 2
			case <-time.After(250 * time.Millisecond):
			}
		}
		fmt.Fprintf(stdout, "Audit %s: %s\n", run.RunID, run.Result)
		switch run.Result {
		case "passed":
			return 0
		case "failed":
			return 1
		default:
			return 2
		}
	default:
		fmt.Fprintln(stderr, "Usage: raven integrity status | verify --type fast|deep|ledger [--wait]")
		return 2
	}
}

var integrityCLIHTTPClient = &http.Client{Timeout: 5 * time.Second}
