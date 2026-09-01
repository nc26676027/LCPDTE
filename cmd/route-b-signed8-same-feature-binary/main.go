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
	Schema      string                                                   `json:"schema"`
	CompletedAt time.Time                                                `json:"completed_at"`
	Result      secureeval.RouteBCanonicalSigned8SameFeatureBinaryResult `json:"result"`
}

func main() {
	outputPath := flag.String("out", "", "new absolute or working-directory-relative JSON result path")
	flag.Parse()
	if *outputPath == "" {
		fmt.Fprintln(os.Stderr, "route-b-signed8-same-feature-binary: -out is required")
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, "route-b-signed8-same-feature-binary: starting canonical L11 lifecycle and 170-query equivalent binary control")
	result, err := secureeval.RunCanonicalRouteBSigned8SameFeatureBinary()
	if err != nil {
		fmt.Fprintf(os.Stderr, "route-b-signed8-same-feature-binary: failed: %v\n", err)
		os.Exit(1)
	}
	absolute, err := filepath.Abs(*outputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "route-b-signed8-same-feature-binary: resolve output path: %v\n", err)
		os.Exit(1)
	}
	if err = os.MkdirAll(filepath.Dir(absolute), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "route-b-signed8-same-feature-binary: create output directory: %v\n", err)
		os.Exit(1)
	}
	encoded, err := json.MarshalIndent(resultEnvelope{
		Schema: "lcpdte-route-b-signed8-same-feature-binary-result-v1", CompletedAt: time.Now().UTC(), Result: result,
	}, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "route-b-signed8-same-feature-binary: encode result: %v\n", err)
		os.Exit(1)
	}
	encoded = append(encoded, '\n')
	file, err := os.OpenFile(absolute, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "route-b-signed8-same-feature-binary: create result without overwrite: %v\n", err)
		os.Exit(1)
	}
	if _, err = file.Write(encoded); err != nil {
		_ = file.Close()
		fmt.Fprintf(os.Stderr, "route-b-signed8-same-feature-binary: write result: %v\n", err)
		os.Exit(1)
	}
	if err = file.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "route-b-signed8-same-feature-binary: close result: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("ROUTE_B_SIGNED8_SAME_FEATURE_BINARY_OK path=%s build_peak_rss=%d post_install_peak_rss=%d post_binary_peak_rss=%d wall_ns=%d circuit_ns=%d prefix_ns=%d terminal_ns=%d active_max=%.9g inactive_max=%.9g imag_max=%.9g active_mismatches=%d inactive_mismatches=%d binary_digest=%s full_a2b_digest=%s\n",
		absolute, result.BuildReceipt.BuildPeakRSSBytes, result.PostInstallPeakRSSBytes,
		result.PostBinaryPeakRSSBytes, result.TotalWallNanoseconds, result.SameFeatureBinary.WallNanoseconds,
		result.SameFeatureBinary.CommonPrefixWallNanoseconds, result.SameFeatureBinary.TerminalWallNanoseconds,
		result.MaxActiveAbsError, result.MaxInactiveAbs, result.MaxImaginaryAbs,
		result.ActiveMismatchCount, result.InactiveMismatchCount, result.SameFeatureBinary.Digest,
		result.SameFeatureBinary.Base.FullA2B.Digest)
}
