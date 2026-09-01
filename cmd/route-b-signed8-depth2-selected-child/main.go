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
	Schema      string                                                     `json:"schema"`
	CompletedAt time.Time                                                  `json:"completed_at"`
	Result      secureeval.RouteBCanonicalSigned8Depth2SelectedChildResult `json:"result"`
}

func main() {
	outputPath := flag.String("out", "", "absolute or working-directory-relative JSON result path")
	flag.Parse()
	if *outputPath == "" {
		fmt.Fprintln(os.Stderr, "route-b-signed8-depth2-selected-child: -out is required")
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, "route-b-signed8-depth2-selected-child: starting canonical encrypted selected-child Route-B lifecycle")
	result, err := secureeval.RunCanonicalRouteBSigned8Depth2SelectedChild()
	if err != nil {
		fmt.Fprintf(os.Stderr, "route-b-signed8-depth2-selected-child: failed: %v\n", err)
		os.Exit(1)
	}
	absolute, err := filepath.Abs(*outputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "route-b-signed8-depth2-selected-child: resolve output path: %v\n", err)
		os.Exit(1)
	}
	if err = os.MkdirAll(filepath.Dir(absolute), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "route-b-signed8-depth2-selected-child: create output directory: %v\n", err)
		os.Exit(1)
	}
	encoded, err := json.MarshalIndent(resultEnvelope{
		Schema: "lcpdte-route-b-signed8-depth2-selected-child-result-v1", CompletedAt: time.Now().UTC(), Result: result,
	}, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "route-b-signed8-depth2-selected-child: encode result: %v\n", err)
		os.Exit(1)
	}
	encoded = append(encoded, '\n')
	if err = os.WriteFile(absolute, encoded, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "route-b-signed8-depth2-selected-child: write result: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("ROUTE_B_SIGNED8_DEPTH2_SELECTED_CHILD_OK path=%s build_peak_rss=%d post_install_peak_rss=%d post_eval_peak_rss=%d setup_ns=%d online_ns=%d post_ns=%d total_ns=%d max_error=%.9g imag_max=%.9g mismatches=%d paths=%v report_digest=%s a2sign_digest=%s periodic_digest=%s\n",
		absolute, result.BuildReceipt.BuildPeakRSSBytes, result.PostInstallPeakRSSBytes,
		result.PostEvaluationPeakRSSBytes, result.SetupWallNanoseconds, result.OnlineWallNanoseconds,
		result.PostprocessWallNanoseconds, result.TotalWallNanoseconds,
		result.MaxAbsError, result.MaxImaginaryAbs, result.MismatchCount, result.PathCounts,
		result.SelectedChild.Digest, result.SelectedChild.ChildA2Sign.Digest, result.SelectedChild.RootPeriodic.Digest)
}
