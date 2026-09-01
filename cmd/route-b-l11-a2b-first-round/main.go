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
	Schema      string                                           `json:"schema"`
	CompletedAt time.Time                                        `json:"completed_at"`
	Result      secureeval.RouteBCanonicalL11A2BFirstRoundResult `json:"result"`
}

func main() {
	outputPath := flag.String("out", "", "absolute or working-directory-relative JSON result path")
	flag.Parse()
	if *outputPath == "" {
		fmt.Fprintln(os.Stderr, "route-b-l11-a2b-first-round: -out is required")
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, "route-b-l11-a2b-first-round: starting one-process canonical L11 lifecycle")
	result, err := secureeval.RunCanonicalRouteBL11A2BFirstRound()
	if err != nil {
		fmt.Fprintf(os.Stderr, "route-b-l11-a2b-first-round: failed: %v\n", err)
		os.Exit(1)
	}
	absolute, err := filepath.Abs(*outputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "route-b-l11-a2b-first-round: resolve output path: %v\n", err)
		os.Exit(1)
	}
	if err = os.MkdirAll(filepath.Dir(absolute), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "route-b-l11-a2b-first-round: create output directory: %v\n", err)
		os.Exit(1)
	}
	encoded, err := json.MarshalIndent(resultEnvelope{
		Schema: "lcpdte-route-b-l11-a2b-first-round-result-v1", CompletedAt: time.Now().UTC(), Result: result,
	}, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "route-b-l11-a2b-first-round: encode result: %v\n", err)
		os.Exit(1)
	}
	encoded = append(encoded, '\n')
	if err = os.WriteFile(absolute, encoded, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "route-b-l11-a2b-first-round: write result: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("ROUTE_B_L11_A2B_FIRST_ROUND_OK path=%s build_peak_rss=%d post_install_peak_rss=%d post_round_peak_rss=%d wall_ns=%d id_max_error=%.9g msb_max_error=%.9g imag_max=%.9g mismatches=%d\n",
		absolute, result.BuildReceipt.BuildPeakRSSBytes, result.PostInstallPeakRSSBytes,
		result.PostFirstRoundPeakRSSBytes, result.TotalWallNanoseconds,
		result.MaxIdentityAbsError, result.MaxMSBAbsError, result.MaxImaginaryAbs, result.MismatchCount)
}
