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
	openFHEPath := flags.String("openfhe-log", "", "Gao benchmark-full text log")
	lattigoPath := flags.String("lattigo-json", "", "Lattigo route-b-l11-a2b-full JSON envelope")
	outputPath := flags.String("out", "", "optional JSON summary path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *openFHEPath == "" || *lattigoPath == "" {
		fmt.Fprintln(stderr, "compare-ckksint: -openfhe-log and -lattigo-json are required")
		return 2
	}

	openFHEInput, err := os.Open(*openFHEPath)
	if err != nil {
		fmt.Fprintf(stderr, "compare-ckksint: open Gao OpenFHE log: %v\n", err)
		return 1
	}
	openFHE, err := benchcmp.ParseGaoOpenFHE(openFHEInput, *openFHEPath)
	closeErr := openFHEInput.Close()
	if err != nil {
		fmt.Fprintf(stderr, "compare-ckksint: %v\n", err)
		return 1
	}
	if closeErr != nil {
		fmt.Fprintf(stderr, "compare-ckksint: close Gao OpenFHE log: %v\n", closeErr)
		return 1
	}

	lattigoInput, err := os.Open(*lattigoPath)
	if err != nil {
		fmt.Fprintf(stderr, "compare-ckksint: open Lattigo JSON: %v\n", err)
		return 1
	}
	lattigo, err := benchcmp.ParseLattigoRouteB(lattigoInput, *lattigoPath)
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
