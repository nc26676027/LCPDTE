package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/nc26676027/LCPDTE/integer/homchain"
)

type resultEnvelope struct {
	Schema      string                                              `json:"schema"`
	CompletedAt time.Time                                           `json:"completed_at"`
	Result      homchain.Signed8Depth2SelectedChildExperimentResult `json:"result"`
}

func main() {
	outputPath := flag.String("out", "", "absolute or working-directory-relative JSON result path")
	flag.Parse()
	if *outputPath == "" {
		fmt.Fprintln(os.Stderr, "signed8-depth2-selected-child: -out is required")
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, "signed8-depth2-selected-child: starting functional-profile source-faithful depth-2 lifecycle")
	result, err := homchain.RunSigned8Depth2SelectedChildExperiment()
	if err != nil {
		fmt.Fprintf(os.Stderr, "signed8-depth2-selected-child: failed: %v\n", err)
		os.Exit(1)
	}
	absolute, err := filepath.Abs(*outputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "signed8-depth2-selected-child: resolve output path: %v\n", err)
		os.Exit(1)
	}
	if err = os.MkdirAll(filepath.Dir(absolute), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "signed8-depth2-selected-child: create output directory: %v\n", err)
		os.Exit(1)
	}
	encoded, err := json.MarshalIndent(resultEnvelope{
		Schema: "lcpdte-signed8-depth2-selected-child-result-v1", CompletedAt: time.Now().UTC(), Result: result,
	}, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "signed8-depth2-selected-child: encode result: %v\n", err)
		os.Exit(1)
	}
	encoded = append(encoded, '\n')
	if err = os.WriteFile(absolute, encoded, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "signed8-depth2-selected-child: write result: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("SIGNED8_DEPTH2_SELECTED_CHILD_OK path=%s lifecycle_ns=%d online_ns=%d max_real=%.9g max_imag=%.9g mismatches=%d profile=%s result=%s trace=%s linkage=%s digest=%s\n",
		absolute, result.Timing.LifecycleNanoseconds, result.Timing.OnlineNanoseconds,
		result.MaxRealAbsError, result.MaxImaginaryAbs, result.MismatchCount,
		result.ProfileDigest, result.ResultDigest, result.TraceDigest, result.LinkageDigest, result.Digest)
}
