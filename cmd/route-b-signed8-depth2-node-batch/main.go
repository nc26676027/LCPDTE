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
	Schema      string                                                 `json:"schema"`
	CompletedAt time.Time                                              `json:"completed_at"`
	Result      secureeval.RouteBCanonicalSigned8Depth2NodeBatchResult `json:"result"`
}

func main() {
	outputPath := flag.String("out", "", "absolute or working-directory-relative JSON result path")
	flag.Parse()
	if *outputPath == "" {
		fmt.Fprintln(os.Stderr, "route-b-signed8-depth2-node-batch: -out is required")
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, "route-b-signed8-depth2-node-batch: starting canonical L11 lifecycle and 170-query all-node depth-2 evaluation")
	result, err := secureeval.RunCanonicalRouteBSigned8Depth2NodeBatch()
	if err != nil {
		fmt.Fprintf(os.Stderr, "route-b-signed8-depth2-node-batch: failed: %v\n", err)
		os.Exit(1)
	}
	absolute, err := filepath.Abs(*outputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "route-b-signed8-depth2-node-batch: resolve output path: %v\n", err)
		os.Exit(1)
	}
	if err = os.MkdirAll(filepath.Dir(absolute), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "route-b-signed8-depth2-node-batch: create output directory: %v\n", err)
		os.Exit(1)
	}
	encoded, err := json.MarshalIndent(resultEnvelope{
		Schema: "lcpdte-route-b-signed8-depth2-node-batch-result-v1", CompletedAt: time.Now().UTC(), Result: result,
	}, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "route-b-signed8-depth2-node-batch: encode result: %v\n", err)
		os.Exit(1)
	}
	encoded = append(encoded, '\n')
	if err = os.WriteFile(absolute, encoded, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "route-b-signed8-depth2-node-batch: write result: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("ROUTE_B_SIGNED8_DEPTH2_NODE_BATCH_OK path=%s build_peak_rss=%d post_install_peak_rss=%d post_depth2_peak_rss=%d wall_ns=%d depth2_wall_ns=%d active_max=%.9g inactive_max=%.9g imag_max=%.9g active_mismatches=%d inactive_mismatches=%d depth2_digest=%s full_a2b_digest=%s\n",
		absolute, result.BuildReceipt.BuildPeakRSSBytes, result.PostInstallPeakRSSBytes,
		result.PostDepth2PeakRSSBytes, result.TotalWallNanoseconds, result.Depth2.WallNanoseconds,
		result.MaxActiveAbsError, result.MaxInactiveAbs, result.MaxImaginaryAbs,
		result.ActiveMismatchCount, result.InactiveMismatchCount,
		result.Depth2.Digest, result.Depth2.FullA2B.Digest)
}
