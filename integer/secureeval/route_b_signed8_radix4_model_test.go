package secureeval

import (
	"math"
	"slices"
	"testing"

	"github.com/nc26676027/LCPDTE/integer/homchain"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

func TestRouteBSigned8Radix4OracleIsExhaustivelyEquivalentToBinaryDepth2(t *testing.T) {
	model, ranges, binaryModel, binaryRanges, err := routeBSigned8Radix4CanonicalModelsAndRanges()
	if err != nil {
		t.Fatal(err)
	}
	var paths [4]int
	var equalities [3]int
	for value := int64(-96); value <= 95; value++ {
		got, path, predicates, oracleErr := routeBSigned8Radix4Oracle(value, ranges, model)
		if oracleErr != nil {
			t.Fatal(oracleErr)
		}
		want, binaryPath, branches, binaryErr := routeBSigned8Depth2NodeBatchOracle(
			[3]int64{value, value, value}, binaryRanges, binaryModel,
		)
		if binaryErr != nil {
			t.Fatal(binaryErr)
		}
		if path != binaryPath || math.Float64bits(got) != math.Float64bits(want) ||
			predicates != [3]uint8{branches[1], branches[0], branches[2]} {
			t.Fatalf("radix/binary mismatch at x=%d: radix=%g/%d/%v binary=%g/%d/%v", value, got, path, predicates, want, binaryPath, branches)
		}
		if predicates[0] < predicates[1] || predicates[1] < predicates[2] {
			t.Fatalf("non-monotone unary code at x=%d: %v", value, predicates)
		}
		paths[path]++
		for index, threshold := range model.Thresholds() {
			if value == threshold {
				equalities[index]++
			}
		}
	}
	if paths != [4]int{64, 32, 32, 64} || equalities != [3]int{1, 1, 1} {
		t.Fatalf("exhaustive interval counts drifted: paths=%v equality=%v", paths, equalities)
	}
	if model.Thresholds() != [3]int64{-32, 0, 32} || model.Leaves() != [4]float64{-3.25, -0.75, 2.5, 5.125} || model.Digest() != routeBSigned8Radix4ExpectedModelDigest {
		t.Fatalf("canonical radix model drifted: thresholds=%v leaves=%v digest=%q", model.Thresholds(), model.Leaves(), model.Digest())
	}
}

func TestRouteBSigned8Radix4ArtifactsAndTerminalLedger(t *testing.T) {
	model, _, _, _, err := routeBSigned8Radix4CanonicalModelsAndRanges()
	if err != nil {
		t.Fatal(err)
	}
	params, err := canonicalRouteBSigned8RootTreeParameters()
	if err != nil {
		t.Fatal(err)
	}
	artifacts, err := newRouteBSigned8Radix4Artifacts(params, model)
	if err != nil {
		t.Fatal(err)
	}
	if artifacts.threshold.Level() != 20 || artifacts.globalOne.Level() != 3 || artifacts.baseLeaf.Level() != 1 ||
		!artifacts.baseLeaf.Scale.Equal(params.DefaultScale()) ||
		!slices.Equal(artifacts.broadcastRotationIndexes, []int{1, 2}) ||
		!slices.Equal(artifacts.alignmentRotationIndexes, []int{4, 8}) ||
		!slices.Equal(artifacts.alignmentGaloisElements, []uint64{625, 128481}) {
		t.Fatalf("radix artifacts changed: threshold=%d one=%d base=%d/%g broadcast=%v alignment=%v/%v",
			artifacts.threshold.Level(), artifacts.globalOne.Level(), artifacts.baseLeaf.Level(), artifacts.baseLeaf.Scale.Float64(),
			artifacts.broadcastRotationIndexes, artifacts.alignmentRotationIndexes, artifacts.alignmentGaloisElements)
	}
	for index, delta := range artifacts.leafDeltas {
		if delta.Level() != 2 || !delta.Scale.Equal(rlwe.NewScale(params.Q()[2])) {
			t.Fatalf("leaf delta %d state=%d/%g, want L2/q2", index, delta.Level(), delta.Scale.Float64())
		}
	}
	counts := routeBSigned8Radix4ExpectedCounts(artifacts)
	if counts.PathCiphertextProducts != 0 || counts.PathRelinearizations != 0 || counts.PathRescales != 0 ||
		counts.SelectorComplements != 0 || counts.LeafPlaintextProducts != 3 || counts.LeafRescales != 3 ||
		counts.LeafCiphertextAdditions != 2 || counts.BaseLeafPlaintextAdditions != 1 {
		t.Fatalf("radix terminal operation ledger drifted: %+v", counts)
	}
	states, err := routeBSigned8Radix4ExpectedStates(params)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 21 || states[len(states)-1].Stage != RouteBSigned8Radix4StageOutput || states[len(states)-1].Level != 1 {
		t.Fatalf("radix state ledger changed: len=%d tail=%+v", len(states), states[len(states)-1])
	}
	ablation, err := routeBSigned8Radix4ExpectedAblation(model)
	if err != nil {
		t.Fatal(err)
	}
	if ablation.RemovedCiphertextProducts != 3 || ablation.RemovedRelinearizations != 3 ||
		ablation.RemovedPathRescales != 3 || ablation.OutputLevelsSaved != 1 ||
		ablation.ExhaustiveEquivalenceProofDigest == "" {
		t.Fatalf("radix ablation ledger drifted: %+v", ablation)
	}
	plan, err := canonicalRouteBCapacityPlan(routeBCapacityGateSigned8Radix4Node)
	if err != nil {
		t.Fatal(err)
	}
	if plan.ProjectedIncrementalPeakBytes() != 2_517_438_208 {
		t.Fatalf("radix capacity upper bound=%d, want C73 bound", plan.ProjectedIncrementalPeakBytes())
	}
	t.Logf("radix model=%s proof=%s capacity=%s", model.Digest(), ablation.ExhaustiveEquivalenceProofDigest, plan.Digest())
}

func TestRouteBSigned8Radix4CanonicalInputPatternCoversBoundaries(t *testing.T) {
	values := routeBSigned8Radix4InputValues()
	if len(values) != routeBSigned8Radix4Queries {
		t.Fatalf("input query count=%d, want %d", len(values), routeBSigned8Radix4Queries)
	}
	wantPrefix := []int64{-96, -32, -31, -1, 0, 1, 31, 32, 33, 95}
	for index, want := range wantPrefix {
		if values[index] != want {
			t.Fatalf("input prefix[%d]=%d, want %d", index, values[index], want)
		}
	}
	words := routeBSigned8Radix4InputWords()
	if len(words) != routeBSigned8Radix4Words || words[len(words)-1] != 0 || words[len(words)-2] != 0 {
		t.Fatalf("packed word count or padding drifted: len=%d tail=%v", len(words), words[len(words)-2:])
	}
	for query, value := range values {
		for role := 0; role < 3; role++ {
			if words[3*query+role] != value {
				t.Fatalf("query %d role %d=%d, want %d", query, role, words[3*query+role], value)
			}
		}
	}
	model, ranges, _, _, err := routeBSigned8Radix4CanonicalModelsAndRanges()
	if err != nil {
		t.Fatal(err)
	}
	var paths [4]uint32
	var equalities [3]uint32
	for _, value := range values {
		_, path, _, oracleErr := routeBSigned8Radix4Oracle(value, ranges, model)
		if oracleErr != nil {
			t.Fatal(oracleErr)
		}
		paths[path]++
		for index, threshold := range model.Thresholds() {
			if value == threshold {
				equalities[index]++
			}
		}
	}
	if got := routeBSigned8Radix4InputPatternDigest(); got != routeBSigned8Radix4ExpectedInputDigest {
		t.Fatalf("input-pattern digest=%s, want %s", got, routeBSigned8Radix4ExpectedInputDigest)
	}
	t.Logf("radix input digest=%s paths=%v equality=%v", routeBSigned8Radix4InputPatternDigest(), paths, equalities)
}

func TestRouteBSigned8Radix4RejectsInvalidModelsRangesAndInputs(t *testing.T) {
	valid, ranges, _, _, err := routeBSigned8Radix4CanonicalModelsAndRanges()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name       string
		thresholds [3]int64
		leaves     [4]float64
	}{
		{"unordered", [3]int64{0, -1, 1}, [4]float64{}},
		{"duplicate", [3]int64{-1, -1, 1}, [4]float64{}},
		{"low", [3]int64{-129, 0, 1}, [4]float64{}},
		{"high", [3]int64{-1, 0, 128}, [4]float64{}},
		{"nan leaf", [3]int64{-1, 0, 1}, [4]float64{math.NaN()}},
		{"infinite leaf", [3]int64{-1, 0, 1}, [4]float64{0, math.Inf(1)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, modelErr := NewRouteBSigned8Radix4Model(test.thresholds, test.leaves); modelErr == nil {
				t.Fatal("invalid radix model was admitted")
			}
		})
	}
	tampered := valid
	tampered.digest = "foreign"
	if _, _, _, err = routeBSigned8Radix4Oracle(0, ranges, tampered); err == nil {
		t.Fatal("tampered model was admitted")
	}
	foreignRanges := ranges
	foreignRanges[0], err = homchain.NewSigned8NoOverflowRange(-95, 95, -31, -31)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = routeBSigned8Radix4Oracle(0, foreignRanges, valid); err == nil {
		t.Fatal("foreign threshold/range binding was admitted")
	}
	if _, _, _, err = routeBSigned8Radix4Oracle(96, ranges, valid); err == nil {
		t.Fatal("out-of-range feature was admitted")
	}
}
