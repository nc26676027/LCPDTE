package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"dt_go/integer/homchain"
)

const acceptedSigned8Depth2SelectedChildSHA256 = "4dc5d51f0cc8034d8a57ee5b64bee1cfe7041eabeb78aca4ea14adcfde012b97"

func TestAcceptedSigned8Depth2SelectedChildArtifactReplaysEverySlot(t *testing.T) {
	path := filepath.Join("..", "..", "research", "reproduction", "selected_child", "signed8_depth2_selected_child_2026-09-01.json")
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != 9_047 {
		t.Fatalf("canonical selected-child artifact bytes=%d, want 9047", len(payload))
	}
	digest := sha256.Sum256(payload)
	if got := hex.EncodeToString(digest[:]); got != acceptedSigned8Depth2SelectedChildSHA256 {
		t.Fatalf("canonical selected-child artifact digest=%s, want %s", got, acceptedSigned8Depth2SelectedChildSHA256)
	}
	var envelope resultEnvelope
	if err = json.Unmarshal(payload, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Schema != "lcpdte-signed8-depth2-selected-child-result-v1" || envelope.CompletedAt.IsZero() {
		t.Fatalf("canonical selected-child envelope changed: %+v", envelope)
	}
	if err = envelope.Result.Validate(); err != nil {
		t.Fatalf("canonical selected-child evidence failed replay: %v", err)
	}
	result := envelope.Result
	if result.SchemaVersion != homchain.Signed8Depth2SelectedChildExperimentSchema ||
		result.ProfileDigest != "25141ea2f596c5b51fe22342a98c48733d0fccb321436eefbae1bd248ac751c7" ||
		result.ResultDigest != "f727af0ae92ca0de3777f5babffaa2d715c0e762a9038a0b38377aad96bca10a" ||
		result.TraceDigest != "866d8c849ddcc99417da0e99583503c226e849fdaa828011e786a0e4b414285c" ||
		result.LinkageDigest != "70e9657e86346eed2c28c4dbddbc8d1cf92ddb5880439dbb4aac570f842f3836" ||
		result.OutputPayloadDigest != "ead81a39fcea71c4dba9a1c18769b23465a81eae064975c143d5bb94c7c29ffa" ||
		result.Digest != "575f1d2167f16ed5a2b599e5b6a29e71213627e8da59f3f5b64b27e23bf33850" {
		t.Fatalf("canonical selected-child provenance changed: %+v", result)
	}
	if result.ParameterDigest != "085e0a9b826d469ac5514d3db988672f41ab0a4f1bb2fe82705842226a8eacc2" ||
		result.RangeDigest != "a8819b509766568b8f68c744363cf90ef9aa6c1a1f2936b7328787228138d9e4" ||
		result.TreeDigest != "159524f29e92ab489c001764785bc42a783d6668b67f69452a81c4dc96090a84" ||
		result.ScheduleDigest != "550c50a6d877016ab99000326dec150a6a425ff4501703720899d8dc220f3c41" ||
		result.KeyProfileDigest != "db329a1a25007dcd644ef6e12502e35cc7759213a7a1a39be5a361049eb52188" ||
		result.InputPatternDigest != "a7cebb62e56eaaeff9e2145321228d67d06acc118ca558ce3f075080ec96bde6" ||
		!reflect.DeepEqual(result.RequiredGaloisElements, []uint64{5, 17, 25, 33, 41, 49, 63}) {
		t.Fatalf("canonical selected-child model/key identity changed: %+v", result)
	}
	if result.Timing.SetupNanoseconds != 43_025_374_700 ||
		result.Timing.RootComparatorNanoseconds != 637_806_500 ||
		result.Timing.RootSelectorNanoseconds != 1_086_005_100 ||
		result.Timing.SourcePrefixNanoseconds != 2_731_703_000 ||
		result.Timing.ChildComparatorNanoseconds != 2_941_713_200 ||
		result.Timing.TerminalNanoseconds != 35_517_831_300 ||
		result.Timing.OnlineNanoseconds != 70_444_052_900 ||
		result.Timing.PostOnlineVerificationNanoseconds != 46_049_806_700 ||
		result.Timing.LifecycleNanoseconds != 159_519_234_300 ||
		result.ModuleReportedByteSum != 296_178 || result.Bytes.TerminalComposedUnique != 106_662 {
		t.Fatalf("canonical selected-child timing/byte row changed: timing=%+v bytes=%+v", result.Timing, result.Bytes)
	}
	if result.ExpectedPaths != [4]int{0, 1, 2, 3} ||
		result.ExpectedLeaves != [4]float64{-1.25, 2.5, -3.75, 5} ||
		result.MaxRealAbsError != 7.007895456823121e-06 ||
		result.MaxImaginaryAbs != 4.618971947066847e-06 ||
		result.MismatchCount != 0 || result.AcceptanceTolerance != 1e-3 ||
		result.CertificateTolerance != 0.0689849853515625 {
		t.Fatalf("canonical selected-child accuracy row changed: %+v", result)
	}
	if result.Operations.RootWrapper.CiphertextPlaintextSubtractions != 1 ||
		result.Operations.RootWrapper.CiphertextCiphertextSubtractions != 0 ||
		result.Operations.RootSelector.LinearTransformations != 7 ||
		result.Operations.ChildComparator.CiphertextCiphertextSubtractions != 1 ||
		result.Operations.ChildDecoder.LinearTransformations != 7 ||
		result.Operations.TerminalMux.CiphertextCiphertextMultiplications != 1 {
		t.Fatalf("canonical selected-child operation row changed: %+v", result.Operations)
	}

	mutated := result
	mutated.DecodedOutput = append([]homchain.Signed8Depth2SelectedChildComplexSample(nil), result.DecodedOutput...)
	mutated.DecodedOutput[0].Real++
	if err = mutated.Validate(); err == nil {
		t.Fatal("mutated canonical selected-child output replayed")
	}
}
