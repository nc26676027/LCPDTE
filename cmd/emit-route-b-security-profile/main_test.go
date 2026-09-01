package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"dt_go/integer/secureeval"
)

func TestCanonicalProfileIsJSONRoundTrippable(t *testing.T) {
	profile, err := secureeval.NewRouteBApplicationSecurityProfile()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := secureeval.CanonicalRouteBApplicationSecurityProfileJSON(profile)
	if err != nil {
		t.Fatal(err)
	}
	var decoded secureeval.RouteBApplicationSecurityProfile
	if err = json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if err = decoded.Validate(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "profile.json")
	if err = os.WriteFile(path, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	if stat, statErr := os.Stat(path); statErr != nil || stat.Size() == 0 {
		t.Fatalf("profile artifact was not written: stat=%v err=%v", stat, statErr)
	}
}
