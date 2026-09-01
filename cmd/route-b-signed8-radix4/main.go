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
	Schema      string                                        `json:"schema"`
	CompletedAt time.Time                                     `json:"completed_at"`
	Result      secureeval.RouteBCanonicalSigned8Radix4Result `json:"result"`
}

func main() {
	outputPath := flag.String("out", "", "new absolute or working-directory-relative JSON result path")
	flag.Parse()
	if *outputPath == "" {
		fmt.Fprintln(os.Stderr, "route-b-signed8-radix4: -out is required")
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, "route-b-signed8-radix4: starting canonical L11 lifecycle and 170-query same-feature radix-4 evaluation")
	result, err := secureeval.RunCanonicalRouteBSigned8Radix4()
	if err != nil {
		fmt.Fprintf(os.Stderr, "route-b-signed8-radix4: failed: %v\n", err)
		os.Exit(1)
	}
	absolute, err := filepath.Abs(*outputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "route-b-signed8-radix4: resolve output path: %v\n", err)
		os.Exit(1)
	}
	if err = os.MkdirAll(filepath.Dir(absolute), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "route-b-signed8-radix4: create output directory: %v\n", err)
		os.Exit(1)
	}
	encoded, err := json.MarshalIndent(resultEnvelope{
		Schema: "lcpdte-route-b-signed8-radix4-result-v1", CompletedAt: time.Now().UTC(), Result: result,
	}, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "route-b-signed8-radix4: encode result: %v\n", err)
		os.Exit(1)
	}
	encoded = append(encoded, '\n')
	file, err := os.OpenFile(absolute, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "route-b-signed8-radix4: create result without overwrite: %v\n", err)
		os.Exit(1)
	}
	if _, err = file.Write(encoded); err != nil {
		_ = file.Close()
		fmt.Fprintf(os.Stderr, "route-b-signed8-radix4: write result: %v\n", err)
		os.Exit(1)
	}
	if err = file.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "route-b-signed8-radix4: close result: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("ROUTE_B_SIGNED8_RADIX4_OK path=%s build_peak_rss=%d post_install_peak_rss=%d post_radix_peak_rss=%d wall_ns=%d circuit_ns=%d prefix_ns=%d terminal_ns=%d active_max=%.9g inactive_max=%.9g imag_max=%.9g active_mismatches=%d inactive_mismatches=%d radix_digest=%s full_a2b_digest=%s\n",
		absolute, result.BuildReceipt.BuildPeakRSSBytes, result.PostInstallPeakRSSBytes,
		result.PostRadixPeakRSSBytes, result.TotalWallNanoseconds, result.Radix4.WallNanoseconds,
		result.Radix4.CommonPrefixWallNanoseconds, result.Radix4.TerminalWallNanoseconds,
		result.MaxActiveAbsError, result.MaxInactiveAbs, result.MaxImaginaryAbs,
		result.ActiveMismatchCount, result.InactiveMismatchCount, result.Radix4.Digest, result.Radix4.FullA2B.Digest)
}
