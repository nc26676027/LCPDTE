package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const acceptedRouteBL11MR0SHA256 = "4f963b88bca8dbb078362483d38b06699daae93f53d929e1810435fef8221b28"

func TestAcceptedRouteBL11MR0ArtifactReplaysAllInertValidation(t *testing.T) {
	path := filepath.Join("..", "..", "research", "reproduction", "route_b", "route_b_l11_mr0_2026-09-01.json")
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	if got := hex.EncodeToString(digest[:]); got != acceptedRouteBL11MR0SHA256 {
		t.Fatalf("canonical Route-B result digest=%s, want %s", got, acceptedRouteBL11MR0SHA256)
	}
	var envelope resultEnvelope
	if err = json.Unmarshal(payload, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Schema != "lcpdte-route-b-l11-mr0-result-v1" || envelope.CompletedAt.IsZero() {
		t.Fatalf("canonical Route-B envelope changed: %+v", envelope)
	}
	if err = envelope.Result.Validate(); err != nil {
		t.Fatalf("canonical Route-B inert evidence failed replay: %v", err)
	}
	result := envelope.Result
	if result.BuildReceipt.BuildPeakRSSBytes != 3_273_887_744 ||
		result.PostInstallPeakRSSBytes != 6_568_656_896 ||
		result.PostMR0PeakRSSBytes != 7_184_281_600 ||
		result.TotalWallNanoseconds != 34_996_007_900 ||
		result.DecodedZeroMaxAbs != 0.37500000002891437 ||
		result.OverallConstructionDelta != [4]uint64{0, 0, 0, 2} {
		t.Fatalf("canonical Route-B measured row changed: build=%d install=%d mr0=%d wall=%d max-abs=%.17g delta=%v",
			result.BuildReceipt.BuildPeakRSSBytes, result.PostInstallPeakRSSBytes,
			result.PostMR0PeakRSSBytes, result.TotalWallNanoseconds,
			result.DecodedZeroMaxAbs, result.OverallConstructionDelta)
	}
}
