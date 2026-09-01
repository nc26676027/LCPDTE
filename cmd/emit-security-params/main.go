// Command emit-security-params writes an exact, deterministic Lattigo CKKS
// parameter manifest. It refuses to overwrite evidence by default.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nc26676027/LCPDTE/integer/securityparams"
)

func main() {
	out := flag.String("out", "", "new output JSON path (required)")
	tuple := flag.String("tuple", securityparams.GaoCompatibleTupleID, "tuple id: "+securityparams.GaoCompatibleTupleID+" or "+securityparams.FunctionalA2BTupleID)
	flag.Parse()
	if *out == "" {
		fatalf("-out is required")
	}

	var (
		manifest securityparams.ParameterManifest
		err      error
	)
	switch *tuple {
	case securityparams.GaoCompatibleTupleID:
		manifest, err = securityparams.GaoCompatibleN16Manifest()
	case securityparams.FunctionalA2BTupleID:
		manifest, err = securityparams.FunctionalA2BN8Manifest()
	default:
		fatalf("unsupported -tuple %q", *tuple)
	}
	if err != nil {
		fatalf("construct manifest: %v", err)
	}
	encoded, err := securityparams.CanonicalJSON(manifest)
	if err != nil {
		fatalf("encode manifest: %v", err)
	}

	directory := filepath.Dir(*out)
	if err = os.MkdirAll(directory, 0o755); err != nil {
		fatalf("create output directory: %v", err)
	}
	file, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		fatalf("create output without overwrite: %v", err)
	}
	if _, err = file.Write(encoded); err != nil {
		_ = file.Close()
		fatalf("write output: %v", err)
	}
	if err = file.Close(); err != nil {
		fatalf("close output: %v", err)
	}
	fmt.Printf("tuple=%s\nmanifest_digest=%s\noutput=%s\n", manifest.TupleID, manifest.CanonicalJSONSHA256, *out)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "emit-security-params: "+format+"\n", args...)
	os.Exit(1)
}
