package secureeval

import (
	"slices"
	"testing"

	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/bootstrapping"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
)

func TestRouteBA2BFirstRoundOracleMatchesAuditedLowNibblePrefixes(t *testing.T) {
	tests := []struct {
		word uint64
		id   [4]float64
		msb  [4]float64
	}{
		{word: 0x00, id: [4]float64{0, 0, 0, 0}, msb: [4]float64{0, 0, 0, 0}},
		{word: 0x01, id: [4]float64{-0.5, -0.25, -0.125, -0.0625}, msb: [4]float64{1, 0, 0, 0}},
		{word: 0x0f, id: [4]float64{-0.5, -0.75, -0.875, -0.9375}, msb: [4]float64{1, 1, 1, 1}},
	}
	for _, test := range tests {
		id, msb, err := routeBA2BFirstRoundOracle(test.word)
		if err != nil {
			t.Fatal(err)
		}
		if id != test.id || msb != test.msb {
			t.Fatalf("word %#02x oracle ID/MSB=%v/%v, want %v/%v", test.word, id, msb, test.id, test.msb)
		}
	}
	words := routeBA2BFirstRoundInputWords()
	if len(words) != 512 || !slices.Equal(words[:256], words[256:]) || words[0] != 0 || words[255] != 255 {
		t.Fatalf("canonical first-round word pattern changed: len=%d first/last=%d/%d", len(words), words[0], words[255])
	}
}

func TestRouteBCanonicalL11A2BFirstRoundResultReplaysEveryDecodedSlot(t *testing.T) {
	admitted := scriptedPhysicalMemoryResult{
		totals: physicalMemoryTotals{total: 33_617_782_768, available: 17_151_951_897},
	}
	sampler := &scriptedPhysicalMemorySampler{results: []scriptedPhysicalMemoryResult{
		admitted, admitted, admitted, admitted, admitted,
	}}
	fixture := newSmallRouteBInstalledFixture(t, sampler)
	residentCalls := 0
	_, firstOperation, err := fixture.installed.runFirstOperationWithHooks(
		new(rlwe.Ciphertext), routeBCapacityGateA2BFirstRound, routeBRuntimeOperationA2BFirstRound,
		fixture.installedResidentValidator(&residentCalls),
		func(*bootstrapping.Evaluator, bootstrapping.PreparedParameters) error { return nil },
		func(*bootstrapping.Evaluator, *rlwe.Ciphertext) (*rlwe.Ciphertext, routeBFirstOperationObservation, error) {
			return new(rlwe.Ciphertext), canonicalTestRouteBFirstOperationObservation(), nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	identity := make([]RouteBComplexSample, routeBA2BFirstRoundSlots)
	msb := make([]RouteBComplexSample, routeBA2BFirstRoundSlots)
	for wordIndex, word := range routeBA2BFirstRoundInputWords() {
		identityOracle, msbOracle, oracleErr := routeBA2BFirstRoundOracle(word)
		if oracleErr != nil {
			t.Fatal(oracleErr)
		}
		for slot := 0; slot < 4; slot++ {
			index := 4*wordIndex + slot
			identity[index].Real = identityOracle[slot]
			msb[index].Real = msbOracle[slot]
		}
	}
	result := RouteBCanonicalL11A2BFirstRoundResult{
		BuildSpec: fixture.permit.report.Spec, BuildReceipt: fixture.receipt.report,
		ReadySpec: fixture.readyPermit.report.Spec, FirstOperation: firstOperation,
		FirstRound:   canonicalTestRouteBA2BFirstRoundReport(t),
		BuildRuntime: fixture.receipt.runtime, ReadyRuntime: fixture.readyPermit.runtime,
		InstallRuntime:           fixture.installed.cell.install,
		OverallConstructionDelta: [4]uint64{0, 0, 0, 2},
		PostInstallPeakRSSBytes:  1, PostFirstRoundPeakRSSBytes: 1, TotalWallNanoseconds: 1,
		InputWords: routeBA2BFirstRoundWords, InputDistinctWords: 256, OutputSlots: routeBA2BFirstRoundSlots,
		InputPatternDigest: routeBA2BFirstRoundInputPatternDigest(),
		DecodedIdentity:    identity, DecodedMSB: msb,
		AccuracyTolerance: RouteBA2BFirstRoundAccuracyTolerance,
	}
	if err = result.Validate(); err != nil {
		t.Fatal(err)
	}
	result.DecodedMSB[len(result.DecodedMSB)-1].Real = 0.25
	if err = result.Validate(); err == nil {
		t.Fatal("tampered last decoded MSB slot validated")
	}
}
