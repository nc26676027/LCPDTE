package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/nc26676027/LCPDTE/integer/secureeval"
)

type resultEnvelope struct {
	Schema      string                                     `json:"schema"`
	CompletedAt time.Time                                  `json:"completed_at"`
	Result      secureeval.RouteBCanonicalL11A2BFullResult `json:"result"`
}

func main() {
	outputPath := flag.String("out", "", "absolute or working-directory-relative JSON result path")
	flag.Parse()
	if *outputPath == "" {
		fmt.Fprintln(os.Stderr, "route-b-l11-a2b-full: -out is required")
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, "route-b-l11-a2b-full: starting one-process canonical L11 lifecycle and complete 8-bit A2B")
	result, err := secureeval.RunCanonicalRouteBL11A2BFull()
	if err != nil {
		fmt.Fprintf(os.Stderr, "route-b-l11-a2b-full: failed: %v\n", err)
		os.Exit(1)
	}
	absolute, err := filepath.Abs(*outputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "route-b-l11-a2b-full: resolve output path: %v\n", err)
		os.Exit(1)
	}
	if err = os.MkdirAll(filepath.Dir(absolute), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "route-b-l11-a2b-full: create output directory: %v\n", err)
		os.Exit(1)
	}
	encoded, err := json.MarshalIndent(resultEnvelope{
		Schema: "lcpdte-route-b-l11-a2b-full-result-v1", CompletedAt: time.Now().UTC(), Result: result,
	}, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "route-b-l11-a2b-full: encode result: %v\n", err)
		os.Exit(1)
	}
	encoded = append(encoded, '\n')
	if err = os.WriteFile(absolute, encoded, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "route-b-l11-a2b-full: write result: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("ROUTE_B_L11_A2B_FULL_OK path=%s build_peak_rss=%d post_install_peak_rss=%d post_full_peak_rss=%d wall_ns=%d low_max_error=%.9g high_max_error=%.9g imag_max=%.9g mismatches=%d full_digest=%s second_stc_digest=%s\n",
		absolute, result.BuildReceipt.BuildPeakRSSBytes, result.PostInstallPeakRSSBytes,
		result.PostFullA2BPeakRSSBytes, result.TotalWallNanoseconds,
		result.MaxLowAbsError, result.MaxHighAbsError, result.MaxImaginaryAbs,
		result.MismatchCount, result.FullA2B.Digest, result.FullA2B.SecondSTC.Digest)
}
