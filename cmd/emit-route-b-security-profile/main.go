// Command emit-route-b-security-profile writes the deterministic application-
// security exposure and decision record for the hash-bound C75 circuit.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nc26676027/LCPDTE/integer/secureeval"
)

func main() {
	out := flag.String("out", "", "new output JSON path (required)")
	flag.Parse()
	if *out == "" {
		fatalf("-out is required")
	}
	profile, err := secureeval.NewRouteBApplicationSecurityProfile()
	if err != nil {
		fatalf("construct profile: %v", err)
	}
	payload, err := secureeval.CanonicalRouteBApplicationSecurityProfileJSON(profile)
	if err != nil {
		fatalf("encode profile: %v", err)
	}
	if err = os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		fatalf("create output directory: %v", err)
	}
	file, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		fatalf("create output without overwrite: %v", err)
	}
	if _, err = file.Write(payload); err != nil {
		_ = file.Close()
		fatalf("write output: %v", err)
	}
	if err = file.Close(); err != nil {
		fatalf("close output: %v", err)
	}
	fmt.Printf("decision=%s\nprofile_digest=%s\noutput=%s\n", profile.Decision.Status, profile.CanonicalJSONSHA256, *out)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "emit-route-b-security-profile: "+format+"\n", args...)
	os.Exit(1)
}
