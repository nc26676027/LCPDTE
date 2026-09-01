package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"dt_go/integer/secureeval"
)

type resultEnvelope struct {
	Schema      string                                 `json:"schema"`
	CompletedAt time.Time                              `json:"completed_at"`
	Result      secureeval.RouteBCanonicalL11MR0Result `json:"result"`
}

func main() {
	outputPath := flag.String("out", "", "absolute or working-directory-relative JSON result path")
	flag.Parse()
	if *outputPath == "" {
		fmt.Fprintln(os.Stderr, "route-b-l11-mr0: -out is required")
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, "route-b-l11-mr0: starting one-process canonical L11 lifecycle")
	result, err := secureeval.RunCanonicalRouteBL11MR0()
	if err != nil {
		fmt.Fprintf(os.Stderr, "route-b-l11-mr0: failed: %v\n", err)
		os.Exit(1)
	}
	absolute, err := filepath.Abs(*outputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "route-b-l11-mr0: resolve output path: %v\n", err)
		os.Exit(1)
	}
	if err = os.MkdirAll(filepath.Dir(absolute), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "route-b-l11-mr0: create output directory: %v\n", err)
		os.Exit(1)
	}
	encoded, err := json.MarshalIndent(resultEnvelope{
		Schema: "lcpdte-route-b-l11-mr0-result-v1", CompletedAt: time.Now().UTC(), Result: result,
	}, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "route-b-l11-mr0: encode result: %v\n", err)
		os.Exit(1)
	}
	encoded = append(encoded, '\n')
	if err = os.WriteFile(absolute, encoded, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "route-b-l11-mr0: write result: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("ROUTE_B_L11_MR0_OK path=%s build_peak_rss=%d post_install_peak_rss=%d post_mr0_peak_rss=%d wall_ns=%d zero_max_abs=%.9g\n",
		absolute, result.BuildReceipt.BuildPeakRSSBytes, result.PostInstallPeakRSSBytes,
		result.PostMR0PeakRSSBytes, result.TotalWallNanoseconds, result.DecodedZeroMaxAbs)
}
