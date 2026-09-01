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
	Schema      string                                          `json:"schema"`
	CompletedAt time.Time                                       `json:"completed_at"`
	Result      secureeval.RouteBCanonicalSigned8RootTreeResult `json:"result"`
}

func main() {
	outputPath := flag.String("out", "", "absolute or working-directory-relative JSON result path")
	flag.Parse()
	if *outputPath == "" {
		fmt.Fprintln(os.Stderr, "route-b-signed8-root-tree: -out is required")
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, "route-b-signed8-root-tree: starting canonical L11 lifecycle, signed-int8 root comparison, and real-leaf selection")
	result, err := secureeval.RunCanonicalRouteBSigned8RootTree()
	if err != nil {
		fmt.Fprintf(os.Stderr, "route-b-signed8-root-tree: failed: %v\n", err)
		os.Exit(1)
	}
	absolute, err := filepath.Abs(*outputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "route-b-signed8-root-tree: resolve output path: %v\n", err)
		os.Exit(1)
	}
	if err = os.MkdirAll(filepath.Dir(absolute), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "route-b-signed8-root-tree: create output directory: %v\n", err)
		os.Exit(1)
	}
	encoded, err := json.MarshalIndent(resultEnvelope{
		Schema: "lcpdte-route-b-signed8-root-tree-result-v1", CompletedAt: time.Now().UTC(), Result: result,
	}, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "route-b-signed8-root-tree: encode result: %v\n", err)
		os.Exit(1)
	}
	encoded = append(encoded, '\n')
	if err = os.WriteFile(absolute, encoded, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "route-b-signed8-root-tree: write result: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("ROUTE_B_SIGNED8_ROOT_TREE_OK path=%s build_peak_rss=%d post_install_peak_rss=%d post_tree_peak_rss=%d wall_ns=%d tree_wall_ns=%d max_error=%.9g imag_max=%.9g mismatches=%d tree_digest=%s full_a2b_digest=%s broadcast_digest=%s\n",
		absolute, result.BuildReceipt.BuildPeakRSSBytes, result.PostInstallPeakRSSBytes,
		result.PostRootTreePeakRSSBytes, result.TotalWallNanoseconds, result.RootTree.WallNanoseconds,
		result.MaxAbsError, result.MaxImaginaryAbs, result.MismatchCount,
		result.RootTree.Digest, result.RootTree.FullA2B.Digest, result.RootTree.BroadcastCompiledDigest)
}
