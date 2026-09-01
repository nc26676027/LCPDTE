package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const acceptedRouteBL11A2BFullSHA256 = "e97f81488cb6f042046379121b53c6fbefb208d417bfbd18fa3845839eef785d"

func TestAcceptedRouteBL11A2BFullArtifactReplaysEverySlot(t *testing.T) {
	path := filepath.Join("..", "..", "research", "reproduction", "route_b", "route_b_l11_a2b_full_2026-09-01.json")
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != 455_026 {
		t.Fatalf("canonical Route-B full-A2B bytes=%d, want 455026", len(payload))
	}
	digest := sha256.Sum256(payload)
	if got := hex.EncodeToString(digest[:]); got != acceptedRouteBL11A2BFullSHA256 {
		t.Fatalf("canonical Route-B full-A2B digest=%s, want %s", got, acceptedRouteBL11A2BFullSHA256)
	}
	var envelope resultEnvelope
	if err = json.Unmarshal(payload, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Schema != "lcpdte-route-b-l11-a2b-full-result-v1" || envelope.CompletedAt.IsZero() {
		t.Fatalf("canonical Route-B full-A2B envelope changed: %+v", envelope)
	}
	if err = envelope.Result.Validate(); err != nil {
		t.Fatalf("canonical Route-B full-A2B evidence failed replay: %v", err)
	}
	result := envelope.Result
	if result.BuildReceipt.BuildPeakRSSBytes != 3_273_900_032 ||
		result.PostInstallPeakRSSBytes != 6_569_345_024 ||
		result.PostFullA2BPeakRSSBytes != 12_827_648_000 ||
		result.TotalWallNanoseconds != 54_297_321_400 ||
		result.MaxLowAbsError != 1.3688218578875624e-07 ||
		result.MaxHighAbsError != 8.4026492208622017e-08 ||
		result.MaxImaginaryAbs != 8.5500948344336645e-11 ||
		result.MismatchCount != 0 || result.OverallConstructionDelta != [4]uint64{0, 0, 0, 3} ||
		result.FullA2B.Digest != "764715f2e34c85cc379b0815744642f9ba55a3dcb058c99ed45c7b73d6919d42" ||
		result.FullA2B.SecondSTC.Digest != "bf47f946a1378636f1568a594d8414fc0fe196b2b724b3a66333f598dd252d4a" ||
		result.FullA2B.CapacityPlanDigest != "77a10014ceb20204ace65393e5f7d99cbf3171883345d298e1c6b0b693ef56ec" {
		t.Fatalf(
			"canonical Route-B full-A2B measured row changed: build=%d install=%d full=%d wall=%d low=%.17g high=%.17g imag=%.17g mismatches=%d delta=%v full-digest=%s second-stc=%s capacity=%s",
			result.BuildReceipt.BuildPeakRSSBytes, result.PostInstallPeakRSSBytes,
			result.PostFullA2BPeakRSSBytes, result.TotalWallNanoseconds,
			result.MaxLowAbsError, result.MaxHighAbsError, result.MaxImaginaryAbs,
			result.MismatchCount, result.OverallConstructionDelta, result.FullA2B.Digest,
			result.FullA2B.SecondSTC.Digest, result.FullA2B.CapacityPlanDigest,
		)
	}
	factors := result.FullA2B.SecondSTC.Factors
	if len(factors) != 2 ||
		factors[0].NumericDigest != "bf8fbcb7774e62cab94c9ab07fcbbdf0894753379749872469bbd3538f5bdd81" ||
		factors[0].NumericBytes != 12_971_990 ||
		factors[0].EncodedDigest != "28045ac2cd0e3ea2c4d634fe7d4123f0d0ec96d8c8b344f96461492dcabc7e9a" ||
		factors[0].EncodedBytes != 363_339_287 ||
		factors[1].NumericDigest != "81d9c29e88fb959829ebcad8a45e19f2646269957583bf1dd881311cb2b1fd1a" ||
		factors[1].NumericBytes != 21_566_574 ||
		factors[1].EncodedDigest != "2324862950916738884c9e6561f77240c929e587af54308a3ea15b3e7d3d5332" ||
		factors[1].EncodedBytes != 369_106_575 {
		t.Fatalf("canonical Route-B full-A2B second-STC factor evidence changed: %+v", factors)
	}
}
