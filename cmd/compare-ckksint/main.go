package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/nc26676027/LCPDTE/internal/benchcmp"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("compare-ckksint", flag.ContinueOnError)
	flags.SetOutput(stderr)
	openFHEPath := flags.String("openfhe-json", "", "focused Gao/OpenFHE canonical benchmark JSON")
	legacyOpenFHEPath := flags.String("openfhe-log", "", "legacy Gao benchmark-full log (descriptive only)")
	lattigoPath := flags.String("lattigo-json", "", "focused Lattigo canonical benchmark JSON")
	outputPath := flags.String("out", "", "optional JSON summary path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *legacyOpenFHEPath != "" {
		fmt.Fprintln(stderr, "compare-ckksint: legacy artifacts are descriptive-only and cannot produce v3 performance ratios; use -openfhe-json with matched canonical artifacts")
		return 2
	}
	if *openFHEPath == "" || *lattigoPath == "" {
		fmt.Fprintln(stderr, "compare-ckksint: -openfhe-json and -lattigo-json are required")
		return 2
	}

	openFHEInput, err := os.Open(*openFHEPath)
	if err != nil {
		fmt.Fprintf(stderr, "compare-ckksint: open Gao OpenFHE JSON: %v\n", err)
		return 1
	}
	openFHE, err := benchcmp.ParseCanonical(openFHEInput, *openFHEPath)
	closeErr := openFHEInput.Close()
	if err != nil {
		fmt.Fprintf(stderr, "compare-ckksint: %v\n", err)
		return 1
	}
	if closeErr != nil {
		fmt.Fprintf(stderr, "compare-ckksint: close Gao OpenFHE JSON: %v\n", closeErr)
		return 1
	}

	lattigoInput, err := os.Open(*lattigoPath)
	if err != nil {
		fmt.Fprintf(stderr, "compare-ckksint: open Lattigo JSON: %v\n", err)
		return 1
	}
	lattigo, err := benchcmp.ParseCanonical(lattigoInput, *lattigoPath)
	closeErr = lattigoInput.Close()
	if err != nil {
		fmt.Fprintf(stderr, "compare-ckksint: %v\n", err)
		return 1
	}
	if closeErr != nil {
		fmt.Fprintf(stderr, "compare-ckksint: close Lattigo JSON: %v\n", closeErr)
		return 1
	}

	summary, err := benchcmp.Compare(openFHE, lattigo)
	if err != nil {
		fmt.Fprintf(stderr, "compare-ckksint: %v\n", err)
		return 1
	}
	if *outputPath != "" {
		encoded, marshalErr := benchcmp.MarshalJSON(summary)
		if marshalErr != nil {
			fmt.Fprintf(stderr, "compare-ckksint: %v\n", marshalErr)
			return 1
		}
		if mkdirErr := os.MkdirAll(filepath.Dir(*outputPath), 0o755); mkdirErr != nil {
			fmt.Fprintf(stderr, "compare-ckksint: create output directory: %v\n", mkdirErr)
			return 1
		}
		if writeErr := os.WriteFile(*outputPath, encoded, 0o644); writeErr != nil {
			fmt.Fprintf(stderr, "compare-ckksint: write JSON summary: %v\n", writeErr)
			return 1
		}
	}
	if _, err = io.WriteString(stdout, benchcmp.FormatText(summary)); err != nil {
		fmt.Fprintf(stderr, "compare-ckksint: write text summary: %v\n", err)
		return 1
	}
	return 0
}
