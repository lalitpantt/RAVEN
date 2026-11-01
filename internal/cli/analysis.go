package cli

import (
	"flag"
	"fmt"
	"io"

	"raven/internal/analysis"
)

func RunAnalysisCLI(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "validate" {
		fmt.Fprintln(stderr, "Usage: raven analysis validate [--analysis-dir <directory>]")
		return 2
	}
	flags := flag.NewFlagSet("analysis validate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("analysis-dir", "analysis", "Path to Analysis inventory and rules")
	if err := flags.Parse(args[1:]); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(stderr, "unexpected arguments: %v\n", flags.Args())
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
