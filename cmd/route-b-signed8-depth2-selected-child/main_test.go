package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const acceptedRouteBSigned8Depth2SelectedChildSHA256 = "4a7fbd447dc8e127ff5392c3b3f22bf4a9f420edf4c30622445db76e965abbb2"

func TestAcceptedRouteBSigned8Depth2SelectedChildArtifactReplaysEverySlot(t *testing.T) {
	path := filepath.Join("..", "..", "research", "reproduction", "route_b", "route_b_signed8_depth2_selected_child_2026-09-01.json")
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != 296_089 {
		t.Fatalf("canonical Route-B selected-child bytes=%d, want 296089", len(payload))
	}
	digest := sha256.Sum256(payload)
	if got := hex.EncodeToString(digest[:]); got != acceptedRouteBSigned8Depth2SelectedChildSHA256 {
		t.Fatalf("canonical Route-B selected-child digest=%s, want %s", got, acceptedRouteBSigned8Depth2SelectedChildSHA256)
	}
	var envelope resultEnvelope
	if err = json.Unmarshal(payload, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Schema != "lcpdte-route-b-signed8-depth2-selected-child-result-v1" || envelope.CompletedAt.IsZero() {
		t.Fatalf("canonical Route-B selected-child envelope changed: %+v", envelope)
	}
	if err = envelope.Result.Validate(); err != nil {
		t.Fatalf("canonical Route-B selected-child evidence failed replay: %v", err)
	}
	result := envelope.Result
	if result.BuildReceipt.BuildPeakRSSBytes != 3_273_859_072 ||
		result.PostInstallPeakRSSBytes != 6_613_004_288 ||
		result.PostEvaluationPeakRSSBytes != 13_889_568_768 ||
		result.SetupWallNanoseconds != 26_403_039_000 ||
		result.OnlineWallNanoseconds != 73_776_209_100 ||
		result.PostprocessWallNanoseconds != 622_247_200 ||
		result.TotalWallNanoseconds != 101_746_462_700 ||
		result.MaxAbsError != 5.917360885732137e-07 ||
		result.MaxImaginaryAbs != 3.2190798723753435e-07 ||
		result.PathCounts != [4]uint32{127, 129, 130, 126} ||
		result.RootEqualityCount != 2 || result.LeftEqualitySelectedCount != 2 ||
		result.RightEqualitySelectedCount != 2 || result.MismatchCount != 0 ||
		result.OverallConstructionDelta != [4]uint64{0, 0, 0, 4} {
		t.Fatal("canonical Route-B selected-child measured row changed")
	}
	report := result.SelectedChild
	if report.Digest != "93876cd488dc3b9b7d9e1535ceec34c82a80a537391a2240fd52b31ca5036d1d" ||
		report.CapacityPlanDigest != "4b5b8c4a936182f636e8cffb09c1aa848c8e4d851bfa83fc84aeee0aaf9a83cc" ||
		report.OutputPayloadDigest != "f2a8f02c896d6823740ea2e75b664030c5910ed75128a124a048334707f266c8" ||
		report.ChildA2Sign.Digest != "19fab5ebc007a4d181b614c403280cfec62286f566a155c6b73eabafc27724c4" ||
		report.RootPeriodic.Digest != "ddfac852459bfdcbceee6ebff6f2accbdf811d15f6e5b628779920a4127def2a" ||
		report.SupplementalSecondSTC.Digest != "bf47f946a1378636f1568a594d8414fc0fe196b2b724b3a66333f598dd252d4a" ||
		report.PhaseBroadcastSourceDigest != "c69767e8c57d7ac30e45f439444f98a151110612c86093987782204820c88a25" ||
		report.PhaseBroadcastCompiledDigest != "f9b7cad75ec046891cb4dd065634661bcd94102a3690f21aa2d7cf6088abb556" ||
		report.PhaseBroadcastEncodedBytes != 25_166_272 ||
		report.RootOneDigest != "0e248d133273acb5fe9161b2653aecd8d3bd783e3d6bac1c6f476d6268dc10d9" ||
		len(report.States) != 32 || report.OperationCounts.DecryptionOracles != 0 ||
		report.OperationCounts.PlaintextBranchDecisions != 0 {
		t.Fatalf("canonical Route-B selected-child identity changed: %+v", report)
	}
	mutated := envelope.Result
	mutated.SelectedChild.RootOneDigest = mutated.SelectedChild.ConditionerDigest
	if err = mutated.Validate(); err == nil {
		t.Fatal("canonical Route-B selected-child replay accepted a root sign-complement operand mutation")
	}
}
