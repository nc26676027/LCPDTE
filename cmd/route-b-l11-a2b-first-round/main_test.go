package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const acceptedRouteBL11A2BFirstRoundSHA256 = "2728fc0b5e8084fb56573ad87ef7da9f64a6ca87517e87744cea309ec6f572a0"

func TestAcceptedRouteBL11A2BFirstRoundArtifactReplaysEverySlot(t *testing.T) {
	path := filepath.Join("..", "..", "research", "reproduction", "route_b", "route_b_l11_a2b_first_round_2026-09-01.json")
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	if got := hex.EncodeToString(digest[:]); got != acceptedRouteBL11A2BFirstRoundSHA256 {
		t.Fatalf("canonical Route-B first-A2B-round digest=%s, want %s", got, acceptedRouteBL11A2BFirstRoundSHA256)
	}
	var envelope resultEnvelope
	if err = json.Unmarshal(payload, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Schema != "lcpdte-route-b-l11-a2b-first-round-result-v1" || envelope.CompletedAt.IsZero() {
		t.Fatalf("canonical Route-B first-A2B-round envelope changed: %+v", envelope)
	}
	if err = envelope.Result.Validate(); err != nil {
		t.Fatalf("canonical Route-B first-A2B-round evidence failed replay: %v", err)
	}
	result := envelope.Result
	if result.BuildReceipt.BuildPeakRSSBytes != 3_202_564_096 ||
		result.PostInstallPeakRSSBytes != 6_568_886_272 ||
		result.PostFirstRoundPeakRSSBytes != 9_819_832_320 ||
		result.TotalWallNanoseconds != 39_860_389_200 ||
		result.MaxIdentityAbsError != 9.1463878420219515e-08 ||
		result.MaxMSBAbsError != 9.2368428526136832e-08 ||
		result.MaxImaginaryAbs != 8.9380092211797199e-11 ||
		result.MismatchCount != 0 ||
		result.OverallConstructionDelta != [4]uint64{0, 0, 0, 2} ||
		result.FirstRound.Digest != "364484ba05658deb20a6915840a8cfe130238f9be90b8a980f83b04c01d05729" {
		t.Fatalf(
			"canonical Route-B first-A2B-round measured row changed: build=%d install=%d round=%d wall=%d id=%.17g msb=%.17g imag=%.17g mismatches=%d delta=%v round-digest=%s",
			result.BuildReceipt.BuildPeakRSSBytes, result.PostInstallPeakRSSBytes,
			result.PostFirstRoundPeakRSSBytes, result.TotalWallNanoseconds,
			result.MaxIdentityAbsError, result.MaxMSBAbsError, result.MaxImaginaryAbs,
			result.MismatchCount, result.OverallConstructionDelta, result.FirstRound.Digest,
		)
	}
}
