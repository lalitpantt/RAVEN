package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"raven/internal/analysis"
	"raven/internal/model"
)

func RunAnalysisCLI(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: raven analysis validate [--analysis-dir <directory>] | test -rule <id> -sample <path> [--analysis-dir <directory>]")
		return 2
	}
	command := args[0]
	if command != "validate" && command != "test" {
		fmt.Fprintln(stderr, "Usage: raven analysis validate [--analysis-dir <directory>] | test -rule <id> -sample <path> [--analysis-dir <directory>]")
		return 2
	}
	flags := flag.NewFlagSet("analysis "+command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("analysis-dir", "analysis", "Path to Analysis inventory and rules")
	ruleID := flags.String("rule", "", "Event rule ID to evaluate")
	samplePath := flags.String("sample", "", "Path to a normalized event JSON sample")
	if err := flags.Parse(args[1:]); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(stderr, "unexpected arguments: %v\n", flags.Args())
		return 2
	}
	if command == "test" {
		if *ruleID == "" || *samplePath == "" {
			fmt.Fprintln(stderr, "Usage: raven analysis test -rule <id> -sample <path> [--analysis-dir <directory>]")
			return 2
		}
		return runAnalysisRuleTest(*directory, *ruleID, *samplePath, stdout, stderr)
	}
	if *ruleID != "" || *samplePath != "" {
		fmt.Fprintln(stderr, "-rule and -sample are only valid with analysis test")
		return 2
	}
	snapshot, err := analysis.LoadDirectory(*directory)
	if err != nil {
		fmt.Fprintf(stderr, "Analysis configuration invalid: %v\n", err)
		return 1
	}
	if !snapshot.Enabled() {
		fmt.Fprintf(stdout, "Analysis disabled: no device or rule resources in %s\n", *directory)
		return 0
	}
	fmt.Fprintf(stdout, "Analysis configuration valid: %d device(s), %d rule(s)\n", snapshot.DeviceCount(), snapshot.RuleCount())
	return 0
}

func runAnalysisRuleTest(directory, ruleID, samplePath string, stdout, stderr io.Writer) int {
	snapshot, err := analysis.LoadDirectory(directory)
	if err != nil {
		fmt.Fprintf(stderr, "Analysis configuration invalid: %v\n", err)
		return 1
	}
	rule, ok := snapshot.Rule(ruleID)
	if !ok || rule.Spec.Kind != "event" {
		fmt.Fprintf(stderr, "Event rule %q not found\n", ruleID)
		return 1
	}
	file, err := os.Open(samplePath)
	if err != nil {
		fmt.Fprintf(stderr, "Open sample: %v\n", err)
		return 1
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		fmt.Fprintln(stderr, "Sample must be a regular file no larger than 1 MiB")
		return 1
	}
	decoder := json.NewDecoder(io.LimitReader(file, (1<<20)+1))
	var event model.NormalizedEvent
	if err := decoder.Decode(&event); err != nil {
		fmt.Fprintf(stderr, "Invalid normalized event sample: %v\n", err)
		return 1
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF || event.Raven.EventID == "" || len(event.OCSF) == 0 {
		fmt.Fprintln(stderr, "Sample must contain exactly one normalized event with raven.event_id and non-empty ocsf fields")
		return 1
	}
	evaluation := analysis.EvaluateEventRule(rule, &event)
	if evaluation.Matched {
		fmt.Fprintf(stdout, "MATCH rule=%s version=%s fields=%s severity=%s state=%s title=%q\n", rule.Metadata.Name, rule.Metadata.Version, strings.Join(evaluation.MatchedFields, ","), rule.Spec.Finding.Severity, rule.Spec.Finding.State, rule.Spec.Finding.Title)
	} else if evaluation.ClearMatched {
		fmt.Fprintf(stdout, "CLEAR rule=%s version=%s fields=%s clearAfter=%s\n", rule.Metadata.Name, rule.Metadata.Version, strings.Join(evaluation.ClearFields, ","), rule.Spec.Finding.ClearAfter.Value())
	} else {
		fmt.Fprintf(stdout, "NO MATCH rule=%s version=%s\n", rule.Metadata.Name, rule.Metadata.Version)
	}
	fmt.Fprintln(stdout, "Preview only; no database writes were made.")
	return 0
}
