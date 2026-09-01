package homchain

import (
	"math"
	"math/big"
	"reflect"
	"testing"

	"dt_go/integer/treeplan"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

func TestSigned8Depth2SourcePrefixConstructorSealsSourceSchedule(t *testing.T) {
	params, err := GaoA2BKernelFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	ranges, err := NewSigned8NoOverflowRange(-8, 7, -8, 7)
	if err != nil {
		t.Fatal(err)
	}
	producer, err := NewSigned8ComparatorCircuit(
		params,
		ckks.NewEncoder(params, signed8RefreshEncoderPrecision),
		ckks.NewEncoder(params, signed8IntegerEncoderPrecision),
		ranges,
	)
	if err != nil {
		t.Fatal(err)
	}
	selector, err := NewSelectorReraiseDecodeCircuit(producer)
	if err != nil {
		t.Fatal(err)
	}
	tree := signed8Depth2TestTree()

	circuit, err := NewSigned8Depth2SourcePrefixCircuit(selector, tree)
	if err != nil {
		t.Fatal(err)
	}
	profile := circuit.Profile()
	if profile.Fidelity() != Signed8Depth2SourcePrefixFunctionalNotSecure ||
		profile.SourceKind() != Signed8Depth2PrefixL6V1 ||
		profile.LogicalSelectionForm() != Signed8Depth2LogicalWidthTwoSourceControl ||
		profile.PhysicalSelectionForm() != Signed8Depth2PhysicalLeftPlusSelectorTimesDelta ||
		profile.ParameterDigest() != selector.Profile().ParameterDigest() ||
		profile.RangeDigest() != ranges.Digest() || profile.TreeDigest() == "" ||
		profile.ScheduleDigest() == "" || profile.SelectorProfileDigest() != selector.Profile().Digest() ||
		profile.Digest() == "" {
		t.Fatalf("depth2 source-prefix profile is incomplete: %+v", profile)
	}
	if got := profile.Schedule(); got.Schedule != treeplan.R0SequentialSourceFaithfulOBO ||
		got.BinaryDepth != 2 || got.GroupWidth != 2 || len(got.Groups) != 1 {
		t.Fatalf("source-faithful schedule changed: %+v", got)
	}
	group := profile.Schedule().Groups[0]
	if group.StartDepth != 0 || group.Height != 2 || group.LogicalComparisons != 2 ||
		!reflect.DeepEqual(group.FeatureSelectorWidths, []int{2}) ||
		!reflect.DeepEqual(group.ThresholdSelectorWidths, []int{2}) ||
		len(group.ComparatorCharges) != 2 ||
		group.ComparatorCharges[0].Provenance != treeplan.ComparatorCTPlaintext ||
		group.ComparatorCharges[0].LogicalComparisons != 1 ||
		group.ComparatorCharges[1].Provenance != treeplan.ComparatorCTCT ||
		group.ComparatorCharges[1].LogicalComparisons != 1 {
		t.Fatalf("depth2 source schedule ledger changed: %+v", group)
	}
	wantCounts := Signed8Depth2SourcePrefixOperationCounts{
		Conditioner: ScalarSelectorConditionOperationCounts{
			CiphertextPlaintextMultiplications: 1,
			Rescales:                           1,
		},
		Feature: Signed8Depth2FeatureSelectionCounts{
			CiphertextCiphertextMultiplications: 1,
			Relinearizations:                    1,
			Rescales:                            1,
			CiphertextSubtractions:              1,
			CiphertextAdditions:                 1,
			LevelAlignments:                     1,
		},
		Threshold: Signed8Depth2ThresholdSelectionCounts{
			CiphertextPlaintextMultiplications: 1,
			Rescales:                           1,
			PlaintextVectorAdditions:           1,
		},
	}
	if got := profile.OperationCounts(); got != wantCounts || got.Rotations != 0 {
		t.Fatalf("depth2 source-prefix operation ledger=%+v, want %+v", got, wantCounts)
	}
	condition := profile.Conditioner()
	if condition.InputLevel() != 8 || condition.OutputLevel() != 7 ||
		!condition.OutputScale().EqualScale(rlwe.NewScale(params.Q()[7])) {
		t.Fatalf("selector conditioner state changed: %+v", condition)
	}
	t.Logf("depth2 prefix profile=%s tree=%s schedule=%s logical=%s physical=%s",
		profile.Digest(), profile.TreeDigest(), profile.ScheduleDigest(),
		profile.LogicalSelectionForm(), profile.PhysicalSelectionForm())
}

func TestSigned8Depth2ThresholdDeltaUsesIntegralLiftDifference(t *testing.T) {
	params, err := GaoA2BKernelFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	ranges, err := NewSigned8NoOverflowRange(-8, 7, -8, 7)
	if err != nil {
		t.Fatal(err)
	}
	producer, err := NewSigned8ComparatorCircuit(
		params,
		ckks.NewEncoder(params, signed8RefreshEncoderPrecision),
		ckks.NewEncoder(params, signed8IntegerEncoderPrecision),
		ranges,
	)
	if err != nil {
		t.Fatal(err)
	}
	selector, err := NewSelectorReraiseDecodeCircuit(producer)
	if err != nil {
		t.Fatal(err)
	}
	circuit, err := NewSigned8Depth2SourcePrefixCircuit(selector, signed8Depth2TestTree())
	if err != nil {
		t.Fatal(err)
	}

	leftAt7, err := newSigned8RepeatedWordPlaintext(params, circuit.integerEncoder, 7, -4)
	if err != nil {
		t.Fatal(err)
	}
	rightAt7, err := newSigned8RepeatedWordPlaintext(params, circuit.integerEncoder, 7, 3)
	if err != nil {
		t.Fatal(err)
	}
	leftDecoded := make([]*bignum.Complex, signed8Slots)
	rightDecoded := make([]*bignum.Complex, signed8Slots)
	deltaDecoded := make([]*bignum.Complex, signed8Slots)
	if err = circuit.integerEncoder.Decode(leftAt7, leftDecoded); err != nil {
		t.Fatal(err)
	}
	if err = circuit.integerEncoder.Decode(rightAt7, rightDecoded); err != nil {
		t.Fatal(err)
	}
	if err = circuit.integerEncoder.Decode(circuit.thresholdDelta, deltaDecoded); err != nil {
		t.Fatal(err)
	}
	canonicalModulo, err := newSigned8RepeatedWordPlaintext(params, circuit.integerEncoder, 7, int8(uint8(int16(3)-int16(-4))))
	if err != nil {
		t.Fatal(err)
	}
	canonicalDecoded := make([]*bignum.Complex, signed8Slots)
	if err = circuit.integerEncoder.Decode(canonicalModulo, canonicalDecoded); err != nil {
		t.Fatal(err)
	}
	differentialObserved := false
	for slot := 0; slot < signed8Slots; slot++ {
		want := &bignum.Complex{
			new(big.Float).SetPrec(256).Sub(rightDecoded[slot].Real(), leftDecoded[slot].Real()),
			new(big.Float).SetPrec(256).Sub(rightDecoded[slot].Imag(), leftDecoded[slot].Imag()),
		}
		if distanceBigComplex(deltaDecoded[slot], want) > 1e-30 {
			t.Fatalf("threshold delta slot %d is not E(TR)-E(TL)", slot)
		}
		if distanceBigComplex(deltaDecoded[slot], canonicalDecoded[slot]) > 1 {
			differentialObserved = true
		}
	}
	if !differentialObserved {
		t.Fatal("integral-lift threshold delta collapsed to E(TR-TL mod 256)")
	}
	if circuit.Profile().ThresholdDeltaSourceDigest() == "" ||
		circuit.Profile().ThresholdDeltaPayloadDigest() == "" {
		t.Fatal("threshold integral-lift provenance is missing")
	}
}

func TestScalarSelectorConditionProfileUsesExactBigScaleAlgebra(t *testing.T) {
	params, err := GaoA2BKernelFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	ranges, err := NewSigned8NoOverflowRange(-8, 7, -8, 7)
	if err != nil {
		t.Fatal(err)
	}
	producer, err := NewSigned8ComparatorCircuit(
		params,
		ckks.NewEncoder(params, signed8RefreshEncoderPrecision),
		ckks.NewEncoder(params, signed8IntegerEncoderPrecision),
		ranges,
	)
	if err != nil {
		t.Fatal(err)
	}
	selector, err := NewSelectorReraiseDecodeCircuit(producer)
	if err != nil {
		t.Fatal(err)
	}
	conditioner, err := NewScalarSelectorConditionCircuit(selector)
	if err != nil {
		t.Fatal(err)
	}
	profile := conditioner.Profile()
	squared := params.DefaultScale().Mul(params.DefaultScale())
	wantR := squared.Mul(squared).
		Div(rlwe.NewScale(params.Q()[11]).Mul(rlwe.NewScale(params.Q()[11])).Mul(rlwe.NewScale(params.Q()[10])))
	wantA := rlwe.NewScale(params.Q()[8]).Mul(rlwe.NewScale(params.Q()[7])).Div(wantR)
	wantRaw := rlwe.NewScale(params.Q()[8]).Mul(rlwe.NewScale(params.Q()[7]))
	if !profile.InputScale().EqualScale(wantR) || !profile.MultiplierScale().EqualScale(wantA) ||
		!profile.RawScale().EqualScale(wantRaw) ||
		!profile.OutputScale().EqualScale(rlwe.NewScale(params.Q()[7])) {
		t.Fatalf("exact conditioner scale algebra changed: R=%s A=%s raw=%s out=%s",
			profile.InputScale().ValueHex(), profile.MultiplierScale().ValueHex(),
			profile.RawScale().ValueHex(), profile.OutputScale().ValueHex())
	}
	if profile.MultiplierSourceDigest() == "" || profile.MultiplierPayloadDigest() == "" ||
		profile.SelectorResultSchema() != selectorReraiseDecodeResultSchema ||
		profile.OperationCounts() != (ScalarSelectorConditionOperationCounts{
			CiphertextPlaintextMultiplications: 1, Rescales: 1,
		}) {
		t.Fatalf("conditioner profile evidence is incomplete: %+v", profile)
	}
	decoded := make([]complex128, signed8Slots)
	if err = conditioner.encoder.Decode(conditioner.multiplier, decoded); err != nil {
		t.Fatal(err)
	}
	for slot, value := range decoded {
		if math.Abs(real(value)-1) > 1e-12 || math.Abs(imag(value)) > 1e-12 {
			t.Fatalf("conditioner multiplier slot %d=%v, want one", slot, value)
		}
	}
	t.Logf("conditioner exact scales R=%s A=%s raw=%s output=%s profile=%s",
		profile.InputScale().ValueHex(), profile.MultiplierScale().ValueHex(),
		profile.RawScale().ValueHex(), profile.OutputScale().ValueHex(), profile.Digest())
}

func TestSigned8Depth2ProfileAccessorsAreDetached(t *testing.T) {
	params, err := GaoA2BKernelFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	ranges, err := NewSigned8NoOverflowRange(-8, 7, -8, 7)
	if err != nil {
		t.Fatal(err)
	}
	producer, err := NewSigned8ComparatorCircuit(
		params,
		ckks.NewEncoder(params, signed8RefreshEncoderPrecision),
		ckks.NewEncoder(params, signed8IntegerEncoderPrecision),
		ranges,
	)
	if err != nil {
		t.Fatal(err)
	}
	selector, err := NewSelectorReraiseDecodeCircuit(producer)
	if err != nil {
		t.Fatal(err)
	}
	circuit, err := NewSigned8Depth2SourcePrefixCircuit(selector, signed8Depth2TestTree())
	if err != nil {
		t.Fatal(err)
	}
	profile := circuit.Profile()
	tree := profile.Tree()
	schedule := profile.Schedule()
	tree.Splits[1].Threshold = 7
	tree.Leaves[0] = 99
	schedule.Groups[0].FeatureSelectorWidths[0] = 99
	if circuit.Profile().Tree().Splits[1].Threshold != -4 || circuit.Profile().Tree().Leaves[0] != -1.25 ||
		!reflect.DeepEqual(circuit.Profile().Schedule().Groups[0].FeatureSelectorWidths, []int{2}) {
		t.Fatal("depth2 tree or schedule accessor aliases sealed profile state")
	}

	tampered := *circuit
	tampered.profile = cloneSigned8Depth2Profile(circuit.profile)
	tampered.profile.schedule.Groups[0].FeatureSelectorWidths[0] = 99
	tampered.graph.circuit = &tampered
	if err := tampered.validate(); err == nil {
		t.Fatal("depth2 circuit admitted a profile schedule whose logical width differs from the verified source schedule")
	}
}

func distanceBigComplex(left, right *bignum.Complex) float64 {
	realDelta, _ := new(big.Float).SetPrec(256).Sub(left.Real(), right.Real()).Float64()
	imagDelta, _ := new(big.Float).SetPrec(256).Sub(left.Imag(), right.Imag()).Float64()
	return math.Hypot(realDelta, imagDelta)
}

func signed8Depth2TestTree() treeplan.BinaryTree[int8, float64] {
	return treeplan.BinaryTree[int8, float64]{
		Depth: 2,
		Splits: []treeplan.BinarySplit[int8]{
			{Feature: 0, Threshold: 0},
			{Feature: 1, Threshold: -4},
			{Feature: 2, Threshold: 3},
		},
		Leaves: []float64{-1.25, 2.5, -3.75, 5},
	}
}

func TestSigned8Depth2SourcePrefixRejectsMalformedTree(t *testing.T) {
	params, err := GaoA2BKernelFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	ranges, err := NewSigned8NoOverflowRange(-8, 7, -8, 7)
	if err != nil {
		t.Fatal(err)
	}
	producer, err := NewSigned8ComparatorCircuit(
		params,
		ckks.NewEncoder(params, signed8RefreshEncoderPrecision),
		ckks.NewEncoder(params, signed8IntegerEncoderPrecision),
		ranges,
	)
	if err != nil {
		t.Fatal(err)
	}
	selector, err := NewSelectorReraiseDecodeCircuit(producer)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name string
		tree treeplan.BinaryTree[int8, float64]
	}{
		{name: "depth", tree: treeplan.BinaryTree[int8, float64]{Depth: 1, Splits: []treeplan.BinarySplit[int8]{{Threshold: 0}}, Leaves: []float64{0, 1}}},
		{name: "non-finite leaf", tree: func() treeplan.BinaryTree[int8, float64] {
			tree := signed8Depth2TestTree()
			tree.Leaves[2] = math.Inf(1)
			return tree
		}()},
		{name: "NaN leaf", tree: func() treeplan.BinaryTree[int8, float64] {
			tree := signed8Depth2TestTree()
			tree.Leaves[1] = math.NaN()
			return tree
		}()},
		{name: "threshold outside range", tree: func() treeplan.BinaryTree[int8, float64] {
			tree := signed8Depth2TestTree()
			tree.Splits[2].Threshold = 8
			return tree
		}()},
	} {
		t.Run(test.name, func(t *testing.T) {
			if circuit, err := NewSigned8Depth2SourcePrefixCircuit(selector, test.tree); err == nil || circuit != nil {
				t.Fatalf("malformed depth2 tree admitted: circuit=%p err=%v", circuit, err)
			}
		})
	}
}
