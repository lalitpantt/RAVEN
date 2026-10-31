package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"testing"
)

func TestParseIntegrityHash(t *testing.T) {
	input := "0x" + fmt.Sprintf("%064x", 42)
	got, err := parseIntegrityHash(input)
	if err != nil || hex.EncodeToString(got[:]) != fmt.Sprintf("%064x", 42) {
		t.Fatalf("valid stream identity: got=%x err=%v", got, err)
	}
	for _, invalid := range []string{"", "0x01", "not-hex"} {
		if _, err := parseIntegrityHash(invalid); err == nil {
			t.Errorf("accepted invalid integrity identity %q", invalid)
		}
	}
}

func TestVersionFlags(t *testing.T) {
	for _, arg := range []string{"-v", "--version"} {
		t.Run(arg, func(t *testing.T) {
			oldArgs, oldStdout := os.Args, os.Stdout
			read, write, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			os.Args = []string{"raven", arg}
			os.Stdout = write
			main()
			_ = write.Close()
			os.Args, os.Stdout = oldArgs, oldStdout
			defer read.Close()

			got, err := io.ReadAll(read)
			if err != nil {
				t.Fatal(err)
			}
			want := fmt.Sprintf("RAVEN CLI Version: %s\n", Version)
			if string(got) != want {
				t.Fatalf("version output = %q, want %q", got, want)
			}
		})
	}
}
