package homchain

import (
	"reflect"
	"testing"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func TestSigned8Depth2ChildSelectorDecodeConstructorFreezesProfile(t *testing.T) {
	child, err := NewSigned8Depth2ChildComparatorCircuit(newSigned8Depth2ChildPrefixForTest(t))
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := NewSigned8Depth2ChildSelectorDecodeCircuit(child)
	if err != nil {
		t.Fatal(err)
	}
	if decoder == nil {
		t.Fatal("nil child selector decoder")
	}
	if decoder.affineMultiplierSeal == decoder.base.affineMultiplier ||
		decoder.affineOffsetSeal == decoder.base.affineOffset ||
		!decoder.affineMultiplierSeal.Equal(decoder.base.affineMultiplier) ||
		!decoder.affineOffsetSeal.Equal(decoder.base.affineOffset) {
		t.Fatal("child decoder did not retain detached exact affine cache seals")
	}

	profile := decoder.Profile()
	childProfile := child.Profile()
	baseProfile := child.prefix.selector.Profile()
	if profile.Fidelity() != SelectorReraiseDecodeFunctionalNotSecure ||
		profile.WordBits() != baseProfile.WordBits() || profile.Words() != 4 || profile.Slots() != 16 ||
		profile.EncoderPrecision() != baseProfile.EncoderPrecision() ||
		profile.IntegerPrecision() != baseProfile.IntegerPrecision() ||
		profile.ParameterDigest() != childProfile.ParameterDigest() ||
		profile.ProtocolRangeDigest() != childProfile.ProtocolRangeDigest() ||
		profile.TreeDigest() != childProfile.TreeDigest() ||
		profile.ScheduleDigest() != childProfile.ScheduleDigest() ||
		profile.ChildProfileDigest() != childProfile.Digest() ||
		profile.PrefixProfileDigest() != childProfile.PrefixProfileDigest() ||
		profile.BaseSelectorProfileDigest() != baseProfile.Digest() ||
		profile.ProducerPublicProfileDigest() != baseProfile.ProducerPublicProfileDigest() ||
		profile.ProducerOpaqueProfileDigest() != baseProfile.ProducerOpaqueProfileDigest() ||
		profile.SelectorRepresentation() != SelectorArithmeticRootCoefficientsToPeriodicBooleanScalarRepeated ||
		profile.ResultSchema() != signed8Depth2ChildSelectorDecodeResultSchema ||
		profile.LogicalPeakLiveCiphertexts() != 8 || profile.Digest() == "" {
		t.Fatalf("incomplete child decoder profile: %+v", profile)
	}

	wantCounts := Signed8Depth2ChildSelectorDecodeOperationCounts{
		LinearTransformations: 7, DiagonalPlaintextProducts: 35,
		NonConjugationRotations: 19, Conjugations: 3, KeySwitches: 22,
		CiphertextAdditionsSubtractions: 34, ScalarMultiplicationsPlusMinusI: 2,
		ExplicitRescales: 10, ScaleDown: 1, ModUp: 1,
		ExponentialPolynomialEvaluations: 1, CiphertextCiphertextProducts: 2,
		Relinearizations: 2, CiphertextPlaintextProducts: 1,
		PlaintextVectorAdditions: 1, IDMSBLUTEvaluations: 0,
	}
	if got := profile.OperationCounts(); got != wantCounts {
		t.Fatalf("operation ledger=%+v, want %+v", got, wantCounts)
	}
	wantBytes := Signed8Depth2ChildSelectorDecodeSerializedBytes{
		ChildArithmeticInput: 2942, RetainedNormalVLow: 2414, RetainedNormalVHigh: 2414,
		RetainedSlotsToCoeffs: 1358, RetainedRaisedCoefficients: 11390,
		RetainedCoeffsToSlotsLow: 9806, RetainedCoeffsToSlotsHigh: 9806,
		RetainedExponentialBase: 6638, RetainedPeriodicRootOfUnity: 5582,
		DecodedChildSelector: 5054,
	}
	if got := profile.ExpectedSerializedBytes(); got != wantBytes || got.RetainedTraceTotal() != 49408 || got.ModuleTotal() != 57404 {
		t.Fatalf("serialized ledger=%+v retained=%d total=%d", got, got.RetainedTraceTotal(), got.ModuleTotal())
	}

	states := profile.States()
	if len(states) != 19 {
		t.Fatalf("states=%d, want 19", len(states))
	}
	wantLevels := []int{4, 4, 4, 3, 3, 2, 1, 0, 20, 19, 18, 17, 17, 17, 11, 10, 9, 9, 8}
	for i, want := range wantLevels {
		if states[i].Level() != want {
			t.Fatalf("state %d level=%d, want %d", i, states[i].Level(), want)
		}
	}
	if got := decoder.RequiredKeyProfile(); !reflect.DeepEqual(got.All(), []uint64{5, 17, 25, 33, 41, 49, 63}) || !got.RelinearizationRequired() {
		t.Fatalf("key profile=%v relin=%v", got.All(), got.RelinearizationRequired())
	}

	states[0].level = 99
	keys := decoder.RequiredKeyProfile().All()
	keys[0] = 0
	if decoder.Profile().States()[0].Level() != 4 || decoder.RequiredKeyProfile().All()[0] != 5 {
		t.Fatal("profile or key accessor aliases sealed data")
	}
	if got, err := NewSigned8Depth2ChildSelectorDecodeCircuit(nil); err == nil || got != nil {
		t.Fatalf("nil child admitted: decoder=%p err=%v", got, err)
	}
}

func TestSigned8Depth2ChildSelectorDecodeCircuitGraphMutationMatrixFailsClosed(t *testing.T) {
	child, err := NewSigned8Depth2ChildComparatorCircuit(newSigned8Depth2ChildPrefixForTest(t))
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := NewSigned8Depth2ChildSelectorDecodeCircuit(child)
	if err != nil {
		t.Fatal(err)
	}
	foreignChild, err := NewSigned8Depth2ChildComparatorCircuit(newSigned8Depth2ChildPrefixForTest(t))
	if err != nil {
		t.Fatal(err)
	}
	foreignDecoder, err := NewSigned8Depth2ChildSelectorDecodeCircuit(foreignChild)
	if err != nil {
		t.Fatal(err)
	}
	type mutation struct {
		name   string
		mutate func(*Signed8Depth2ChildSelectorDecodeCircuit) func()
	}
	noRestore := func() {}
	mutations := []mutation{
		{"nil-child", func(value *Signed8Depth2ChildSelectorDecodeCircuit) func() { value.child = nil; return noRestore }},
		{"nil-prefix", func(value *Signed8Depth2ChildSelectorDecodeCircuit) func() { value.prefix = nil; return noRestore }},
		{"nil-base-selector", func(value *Signed8Depth2ChildSelectorDecodeCircuit) func() { value.base = nil; return noRestore }},
		{"nil-affine-multiplier-seal", func(value *Signed8Depth2ChildSelectorDecodeCircuit) func() {
			value.affineMultiplierSeal = nil
			return noRestore
		}},
		{"nil-affine-offset-seal", func(value *Signed8Depth2ChildSelectorDecodeCircuit) func() {
			value.affineOffsetSeal = nil
			return noRestore
		}},
		{"foreign-child", func(value *Signed8Depth2ChildSelectorDecodeCircuit) func() {
			value.child = foreignDecoder.child
			return noRestore
		}},
		{"foreign-prefix", func(value *Signed8Depth2ChildSelectorDecodeCircuit) func() {
			value.prefix = foreignDecoder.prefix
			return noRestore
		}},
		{"foreign-base-selector", func(value *Signed8Depth2ChildSelectorDecodeCircuit) func() {
			value.base = foreignDecoder.base
			return noRestore
		}},
		{"graph-circuit", func(value *Signed8Depth2ChildSelectorDecodeCircuit) func() {
			value.graph.circuit = nil
			return noRestore
		}},
		{"graph-child", func(value *Signed8Depth2ChildSelectorDecodeCircuit) func() { value.graph.child = nil; return noRestore }},
		{"graph-prefix", func(value *Signed8Depth2ChildSelectorDecodeCircuit) func() {
			value.graph.prefix = nil
			return noRestore
		}},
		{"graph-base", func(value *Signed8Depth2ChildSelectorDecodeCircuit) func() { value.graph.base = nil; return noRestore }},
		{"graph-profile", func(value *Signed8Depth2ChildSelectorDecodeCircuit) func() {
			value.graph.profileDigest = "tampered"
			return noRestore
		}},
		{"graph-key", func(value *Signed8Depth2ChildSelectorDecodeCircuit) func() {
			value.graph.keyDigest = "tampered"
			return noRestore
		}},
		{"profile-tree", func(value *Signed8Depth2ChildSelectorDecodeCircuit) func() {
			value.profile.treeDigest = "tampered"
			return noRestore
		}},
		{"key-inventory", func(value *Signed8Depth2ChildSelectorDecodeCircuit) func() {
			value.keyProfile.all = append([]uint64(nil), value.keyProfile.all...)
			value.keyProfile.all[0] = 1
			return noRestore
		}},
		{"live-affine-multiplier-payload", func(value *Signed8Depth2ChildSelectorDecodeCircuit) func() {
			coefficient := &value.base.affineMultiplier.Value.Coeffs[0][0]
			before := *coefficient
			*coefficient ^= 1
			return func() { *coefficient = before }
		}},
		{"live-affine-offset-payload", func(value *Signed8Depth2ChildSelectorDecodeCircuit) func() {
			coefficient := &value.base.affineOffset.Value.Coeffs[0][0]
			before := *coefficient
			*coefficient ^= 1
			return func() { *coefficient = before }
		}},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			changed := *decoder
			restore := test.mutate(&changed)
			defer restore()
			if err := changed.validate(); err == nil {
				t.Fatal("mutated child decoder circuit graph validated")
			}
		})
	}
	if err := decoder.validate(); err != nil {
		t.Fatalf("accepted child decoder graph changed after rejected mutations: %v", err)
	}
	if got := len(mutations); got != 18 {
		t.Fatalf("circuit graph cases=%d, want 18", got)
	}
}

func TestSigned8Depth2ChildSelectorDecodeBindChildResultClosesPairAndMode(t *testing.T) {
	child, err := NewSigned8Depth2ChildComparatorCircuit(newSigned8Depth2ChildPrefixForTest(t))
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := NewSigned8Depth2ChildSelectorDecodeCircuit(child)
	if err != nil {
		t.Fatal(err)
	}

	for _, mode := range []Signed8ComparatorOperandMode{Signed8PublicThresholdCTPT, Signed8OpaqueThresholdCTCT} {
		t.Run(string(mode), func(t *testing.T) {
			childInput, childResult := newSigned8Depth2ChildDecodeAdmissionPair(t, child, mode, 1)
			bound, bindErr := decoder.BindChildResult(childInput, childResult)
			if bindErr != nil {
				t.Fatal(bindErr)
			}
			if bound.OperandMode() != mode ||
				bound.ChildInputBindingDigest() != childInput.BindingDigest() ||
				bound.ChildResultProvenanceDigest() != childResult.ProvenanceDigest() ||
				bound.OperandsProvenanceDigest() != childInput.OperandsProvenanceDigest() ||
				bound.ProducerProfileDigest() != childInput.operands.producerProfileDigest ||
				bound.ProvenanceDigest() == "" {
				t.Fatalf("incomplete child decoder input binding: %+v", bound)
			}
			if err := decoder.validateInput(bound); err != nil {
				t.Fatalf("bound input did not revalidate: %v", err)
			}
			if bound.branch == childResult.branch || bound.childResult.branch == childResult.branch ||
				bound.branch == bound.childResult.branch ||
				bound.childInput.operands.conditionedSelector == childInput.operands.conditionedSelector {
				t.Fatal("binder retained or aliased caller-owned ciphertexts")
			}

			childResult.branch.Value[0].Coeffs[0][0] ^= 1
			childInput.operands.conditionedSelector.Value[0].Coeffs[0][0] ^= 1
			if err := decoder.validateInput(bound); err != nil {
				t.Fatalf("caller mutation escaped owned binding: %v", err)
			}
		})
	}

	inputA, resultA := newSigned8Depth2ChildDecodeAdmissionPair(t, child, Signed8PublicThresholdCTPT, 7)
	inputB, resultB := newSigned8Depth2ChildDecodeAdmissionPair(t, child, Signed8PublicThresholdCTPT, 11)
	if got, err := decoder.BindChildResult(inputA, resultB); err == nil || !reflect.DeepEqual(got, Signed8Depth2ChildSelectorDecodeInput{}) {
		t.Fatalf("cross-paired input/result admitted: input=%+v err=%v", got, err)
	}
	replaced := resultA
	replaced.branch = ckks.NewCiphertext(child.params, 1, signed8OutputLevel)
	if got, err := decoder.BindChildResult(inputA, replaced); err == nil || !reflect.DeepEqual(got, Signed8Depth2ChildSelectorDecodeInput{}) {
		t.Fatalf("same-state child result replacement admitted: input=%+v err=%v", got, err)
	}
	if got, err := decoder.BindChildResult(inputB, Signed8Depth2ChildComparatorResult{}); err == nil || !reflect.DeepEqual(got, Signed8Depth2ChildSelectorDecodeInput{}) {
		t.Fatalf("zero child result admitted: input=%+v err=%v", got, err)
	}
}

func TestSigned8Depth2ChildSelectorDecodeNilEvaluatorFailsWithZeroEvidence(t *testing.T) {
	child, err := NewSigned8Depth2ChildComparatorCircuit(newSigned8Depth2ChildPrefixForTest(t))
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := NewSigned8Depth2ChildSelectorDecodeCircuit(child)
	if err != nil {
		t.Fatal(err)
	}
	if evaluator, bindErr := decoder.BindEvaluator(nil); bindErr == nil || evaluator != nil {
		t.Fatalf("nil source admitted: evaluator=%p err=%v", evaluator, bindErr)
	}
	var evaluator *Signed8Depth2ChildSelectorDecodeEvaluator
	result, trace, evalErr := evaluator.EvaluateNew(Signed8Depth2ChildSelectorDecodeInput{})
	if evalErr == nil || !reflect.DeepEqual(result, Signed8Depth2ChildSelectorDecodeResult{}) ||
		!reflect.DeepEqual(trace, Signed8Depth2ChildSelectorDecodeTrace{}) {
		t.Fatalf("nil evaluator did not fail with zero evidence: result=%+v trace=%+v err=%v", result, trace, evalErr)
	}
}

func TestFinalizeSigned8Depth2ChildSelectorDecodeFailurePreservesPartialEvidence(t *testing.T) {
	child, err := NewSigned8Depth2ChildComparatorCircuit(newSigned8Depth2ChildPrefixForTest(t))
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := NewSigned8Depth2ChildSelectorDecodeCircuit(child)
	if err != nil {
		t.Fatal(err)
	}
	childInput, childResult := newSigned8Depth2ChildDecodeAdmissionPair(
		t, child, Signed8PublicThresholdCTPT, 23,
	)
	input, err := decoder.BindChildResult(childInput, childResult)
	if err != nil {
		t.Fatal(err)
	}
	profile := decoder.Profile()
	stages, lanes := selectorReraiseDecodeExpectedStateOrder()
	newCheckpoint := func(stateIndex int) *rlwe.Ciphertext {
		ciphertext := ckks.NewCiphertext(child.params, 1, profile.states[stateIndex].level)
		scale, scaleErr := profile.states[stateIndex].scale.Scale()
		if scaleErr != nil {
			t.Fatal(scaleErr)
		}
		ciphertext.Scale = scale
		return ciphertext
	}
	withStates := func(helper SelectorReraiseDecodeTrace, count int) SelectorReraiseDecodeTrace {
		helper.states = make([]SelectorReraiseDecodeCiphertextState, count)
		for index := 0; index < count; index++ {
			helper.states[index] = SelectorReraiseDecodeCiphertextState{
				Stage: stages[index], Lane: lanes[index], Level: profile.states[index].level,
				Degree: 1, LogDimensions: input.branch.LogDimensions, Scale: profile.states[index].scale,
			}
		}
		return helper
	}
	preflight := A2BRefreshKeyPreflight{
		Checked: true, GraphChecked: true, GraphMatched: true,
		RelinearizationPresent: true, RelinearizationMatched: true, DenseNoSwitchingMatched: true,
	}
	tests := []struct {
		name                string
		stage               Signed8Depth2ChildSelectorDecodeStage
		helper              SelectorReraiseDecodeTrace
		attemptedLowerBound Signed8Depth2ChildSelectorDecodeOperationCounts
		wantStates          int
		wantModuleByte      int
	}{
		{
			name: "first-normal-v-dispatch", stage: Signed8Depth2ChildSelectorStageVRaw,
			helper:              withStates(SelectorReraiseDecodeTrace{}, 1),
			attemptedLowerBound: Signed8Depth2ChildSelectorDecodeOperationCounts{LinearTransformations: 2},
			wantStates:          1, wantModuleByte: 2942,
		},
		{
			name: "after-scale-down", stage: Signed8Depth2ChildSelectorStageModUp,
			helper: withStates(SelectorReraiseDecodeTrace{
				normalVLow: newCheckpoint(3), normalVHigh: newCheckpoint(4), stc: newCheckpoint(6),
				operationCounts: SelectorReraiseDecodeOperationCounts{LinearTransformations: 4, ScaleDown: 1},
				logicalPeakLive: 8,
			}, 8),
			attemptedLowerBound: Signed8Depth2ChildSelectorDecodeOperationCounts{
				LinearTransformations: 4, ScaleDown: 1, ModUp: 1,
			},
			wantStates: 8, wantModuleByte: 9128,
		},
		{
			name: "after-coeffs-to-slots", stage: Signed8Depth2ChildSelectorStagePeriodicExp,
			helper: withStates(SelectorReraiseDecodeTrace{
				normalVLow: newCheckpoint(3), normalVHigh: newCheckpoint(4), stc: newCheckpoint(6),
				raised: newCheckpoint(8), ctsLow: newCheckpoint(12), ctsHigh: newCheckpoint(13),
				operationCounts: SelectorReraiseDecodeOperationCounts{
					LinearTransformations: 7, DiagonalPlaintextProducts: 35,
					NonConjugationRotations: 19, Conjugations: 3, KeySwitches: 22,
					CiphertextAdditionsSubtractions: 33, ScalarMultiplicationsPlusMinusI: 2,
					ExplicitRescales: 7, ScaleDown: 1, ModUp: 1,
				},
				logicalPeakLive: 8,
			}, 14),
			attemptedLowerBound: Signed8Depth2ChildSelectorDecodeOperationCounts{
				LinearTransformations: 7, DiagonalPlaintextProducts: 35,
				NonConjugationRotations: 19, Conjugations: 3, KeySwitches: 22,
				CiphertextAdditionsSubtractions: 33, ScalarMultiplicationsPlusMinusI: 2,
				ExplicitRescales: 7, ScaleDown: 1, ModUp: 1,
				ExponentialPolynomialEvaluations: 1,
			},
			wantStates: 14, wantModuleByte: 40130,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, trace, finalizeErr := finalizeSigned8Depth2ChildSelectorDecodeFailure(
				decoder, input, test.helper, preflight, test.stage, test.attemptedLowerBound, time.Millisecond,
			)
			if finalizeErr != nil {
				t.Fatal(finalizeErr)
			}
			if !reflect.DeepEqual(result, Signed8Depth2ChildSelectorDecodeResult{}) ||
				trace.FailureStage() != test.stage || len(trace.States()) != test.wantStates ||
				trace.AttemptedOperationLowerBound() != test.attemptedLowerBound ||
				trace.OperationCounts() != childSelectorDecodeCountsFromBase(test.helper.operationCounts) ||
				trace.SerializedBytes().ModuleTotal() != test.wantModuleByte ||
				trace.InputProvenanceDigest() != input.ProvenanceDigest() ||
				trace.WallTime() != time.Millisecond || trace.Digest() == "" {
				t.Fatalf("incomplete partial failure evidence: result=%+v trace=%+v", result, trace)
			}
			if err = decoder.validateFailureTrace(input, trace); err != nil {
				t.Fatalf("partial failure trace did not validate: %v", err)
			}
			states := trace.States()
			states[0].Level = 99
			if trace.States()[0].Level == 99 {
				t.Fatal("partial failure state accessor aliases sealed evidence")
			}
			if checkpoint := trace.NormalVLow(); checkpoint != nil {
				checkpoint.Value[0].Coeffs[0][0] ^= 1
				if trace.NormalVLow().Equal(checkpoint) {
					t.Fatal("partial failure checkpoint accessor aliases sealed evidence")
				}
			}
		})
	}
}

func TestFinalizeSigned8Depth2ChildSelectorDecodeFailureReturnsBestEffortEvidenceOnFinalizationError(t *testing.T) {
	child, err := NewSigned8Depth2ChildComparatorCircuit(newSigned8Depth2ChildPrefixForTest(t))
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := NewSigned8Depth2ChildSelectorDecodeCircuit(child)
	if err != nil {
		t.Fatal(err)
	}
	childInput, childResult := newSigned8Depth2ChildDecodeAdmissionPair(
		t, child, Signed8PublicThresholdCTPT, 27,
	)
	input, err := decoder.BindChildResult(childInput, childResult)
	if err != nil {
		t.Fatal(err)
	}
	stateScale, err := NewExactScaleSnapshot(input.branch.Scale)
	if err != nil {
		t.Fatal(err)
	}
	baseHelper := SelectorReraiseDecodeTrace{states: []SelectorReraiseDecodeCiphertextState{{
		Stage: SelectorStageInput, Lane: SelectorReraiseDecodeWhole,
		Level: input.branch.Level(), Degree: input.branch.Degree(),
		LogDimensions: input.branch.LogDimensions, Scale: stateScale,
	}}}
	preflight := A2BRefreshKeyPreflight{
		Checked: true, GraphChecked: true, GraphMatched: true,
		RelinearizationPresent: true, RelinearizationMatched: true, DenseNoSwitchingMatched: true,
	}
	tests := []struct {
		name                string
		helper              SelectorReraiseDecodeTrace
		attemptedLowerBound Signed8Depth2ChildSelectorDecodeOperationCounts
	}{
		{name: "validator-rejects-zero-attempt-ledger", helper: baseHelper},
		{
			name: "byte-ledger-rejects-input-checkpoint-alias",
			helper: func() SelectorReraiseDecodeTrace {
				value := baseHelper
				value.normalVLow = input.branch
				return value
			}(),
			attemptedLowerBound: Signed8Depth2ChildSelectorDecodeOperationCounts{LinearTransformations: 2},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, trace, finalizeErr := finalizeSigned8Depth2ChildSelectorDecodeFailure(
				decoder, input, test.helper, preflight, Signed8Depth2ChildSelectorStageVRaw,
				test.attemptedLowerBound, time.Millisecond,
			)
			if finalizeErr == nil {
				t.Fatal("malformed partial evidence unexpectedly finalized")
			}
			if !reflect.DeepEqual(result, Signed8Depth2ChildSelectorDecodeResult{}) ||
				reflect.DeepEqual(trace, Signed8Depth2ChildSelectorDecodeTrace{}) ||
				trace.FailureStage() != Signed8Depth2ChildSelectorStageVRaw || len(trace.States()) != 1 ||
				trace.SerializedBytes().ChildArithmeticInput == 0 || trace.WallTime() != time.Millisecond ||
				trace.Digest() == "" {
				t.Fatalf("finalization error erased attempted-work evidence: result=%+v trace=%+v err=%v", result, trace, finalizeErr)
			}
		})
	}
}

func TestSigned8Depth2ChildSelectorDecodeInputMutationMatrixFailsBeforeWork(t *testing.T) {
	child, err := NewSigned8Depth2ChildComparatorCircuit(newSigned8Depth2ChildPrefixForTest(t))
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := NewSigned8Depth2ChildSelectorDecodeCircuit(child)
	if err != nil {
		t.Fatal(err)
	}
	childInput, childResult := newSigned8Depth2ChildDecodeAdmissionPair(t, child, Signed8PublicThresholdCTPT, 17)
	input, err := decoder.BindChildResult(childInput, childResult)
	if err != nil {
		t.Fatal(err)
	}
	partialEvaluator := &Signed8Depth2ChildSelectorDecodeEvaluator{circuit: decoder}
	mutations := []struct {
		name   string
		mutate func(*Signed8Depth2ChildSelectorDecodeInput)
	}{
		{"zero-input", func(value *Signed8Depth2ChildSelectorDecodeInput) { *value = Signed8Depth2ChildSelectorDecodeInput{} }},
		{"nil-branch", func(value *Signed8Depth2ChildSelectorDecodeInput) { value.branch = nil }},
		{"same-state-branch-replacement", func(value *Signed8Depth2ChildSelectorDecodeInput) {
			foreign := ckks.NewCiphertext(child.params, 1, 4)
			foreign.MetaData = value.branch.MetaData.CopyNew()
			value.branch = foreign
		}},
		{"branch-payload", func(value *Signed8Depth2ChildSelectorDecodeInput) { value.branch.Value[0].Coeffs[0][0] ^= 1 }},
		{"nil-child-feature", func(value *Signed8Depth2ChildSelectorDecodeInput) { value.childInput.operands.feature = nil }},
		{"nil-child-threshold", func(value *Signed8Depth2ChildSelectorDecodeInput) { value.childInput.operands.threshold = nil }},
		{"nil-root-selector", func(value *Signed8Depth2ChildSelectorDecodeInput) {
			value.childInput.operands.conditionedSelector = nil
		}},
		{"root-selector-payload", func(value *Signed8Depth2ChildSelectorDecodeInput) {
			value.childInput.operands.conditionedSelector.Value[0].Coeffs[0][0] ^= 1
		}},
		{"child-input-binding", func(value *Signed8Depth2ChildSelectorDecodeInput) { value.childInput.bindingDigest = "tampered" }},
		{"child-input-operands", func(value *Signed8Depth2ChildSelectorDecodeInput) { value.childInput.operandsProvenance = "tampered" }},
		{"nil-child-result", func(value *Signed8Depth2ChildSelectorDecodeInput) { value.childResult.branch = nil }},
		{"child-result-payload", func(value *Signed8Depth2ChildSelectorDecodeInput) {
			value.childResult.branch.Value[0].Coeffs[0][0] ^= 1
		}},
		{"child-result-binding", func(value *Signed8Depth2ChildSelectorDecodeInput) { value.childResult.inputBindingDigest = "tampered" }},
		{"child-result-provenance", func(value *Signed8Depth2ChildSelectorDecodeInput) { value.childResult.provenanceDigest = "tampered" }},
		{"profile", func(value *Signed8Depth2ChildSelectorDecodeInput) { value.profileDigest = "tampered" }},
		{"child-profile", func(value *Signed8Depth2ChildSelectorDecodeInput) { value.childProfileDigest = "tampered" }},
		{"prefix-profile", func(value *Signed8Depth2ChildSelectorDecodeInput) { value.prefixProfileDigest = "tampered" }},
		{"parameters", func(value *Signed8Depth2ChildSelectorDecodeInput) { value.parameterDigest = "tampered" }},
		{"protocol-range", func(value *Signed8Depth2ChildSelectorDecodeInput) { value.protocolRangeDigest = "tampered" }},
		{"tree", func(value *Signed8Depth2ChildSelectorDecodeInput) { value.treeDigest = "tampered" }},
		{"schedule", func(value *Signed8Depth2ChildSelectorDecodeInput) { value.scheduleDigest = "tampered" }},
		{"producer", func(value *Signed8Depth2ChildSelectorDecodeInput) { value.producerProfileDigest = "tampered" }},
		{"mode", func(value *Signed8Depth2ChildSelectorDecodeInput) { value.operandMode = Signed8OpaqueThresholdCTCT }},
		{"input-binding-seal", func(value *Signed8Depth2ChildSelectorDecodeInput) { value.childInputBindingDigest = "tampered" }},
		{"result-provenance-seal", func(value *Signed8Depth2ChildSelectorDecodeInput) { value.childResultProvenanceDigest = "tampered" }},
		{"operands-provenance-seal", func(value *Signed8Depth2ChildSelectorDecodeInput) { value.operandsProvenanceDigest = "tampered" }},
		{"payload-seal", func(value *Signed8Depth2ChildSelectorDecodeInput) { value.payloadDigest = "tampered" }},
		{"input-provenance", func(value *Signed8Depth2ChildSelectorDecodeInput) { value.provenanceDigest = "tampered" }},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			changed := cloneSigned8Depth2ChildSelectorDecodeInput(input)
			test.mutate(&changed)
			if err := decoder.validateInput(changed); err == nil {
				t.Fatal("mutated decoder input validated")
			}
			result, trace, evalErr := partialEvaluator.EvaluateNew(changed)
			if evalErr == nil || !reflect.DeepEqual(result, Signed8Depth2ChildSelectorDecodeResult{}) ||
				!reflect.DeepEqual(trace, Signed8Depth2ChildSelectorDecodeTrace{}) {
				t.Fatalf("pre-operation failure exposed work: result=%+v trace=%+v err=%v", result, trace, evalErr)
			}
		})
	}
	if err := decoder.validateInput(input); err != nil {
		t.Fatalf("accepted input changed after rejected mutations: %v", err)
	}
	if got := len(mutations); got != 28 {
		t.Fatalf("mutation cases=%d, want 28", got)
	}
}

func newSigned8Depth2ChildDecodeAdmissionPair(
	t *testing.T,
	child *Signed8Depth2ChildComparatorCircuit,
	mode Signed8ComparatorOperandMode,
	marker uint64,
) (Signed8Depth2ChildComparatorInput, Signed8Depth2ChildComparatorResult) {
	t.Helper()
	prefix := child.prefix
	newCiphertext := func(level int) *rlwe.Ciphertext {
		ciphertext := ckks.NewCiphertext(child.params, 1, level)
		ciphertext.Value[0].Coeffs[0][0] = marker
		return ciphertext
	}
	feature := newCiphertext(signed8Depth2OutputLevel)
	threshold := newCiphertext(signed8Depth2OutputLevel)
	threshold.Value[0].Coeffs[0][1] = marker + 1
	conditioned := newCiphertext(signed8Depth2ConditionedLevel)
	conditionedScale, err := prefix.conditioner.profile.outputScale.Scale()
	if err != nil {
		t.Fatal(err)
	}
	conditioned.Scale = conditionedScale
	conditioned.Value[0].Coeffs[0][2] = marker + 2
	featureDigest, err := signed8CiphertextDigest(feature)
	if err != nil {
		t.Fatal(err)
	}
	thresholdDigest, err := signed8CiphertextDigest(threshold)
	if err != nil {
		t.Fatal(err)
	}
	conditionedDigest, err := signed8CiphertextDigest(conditioned)
	if err != nil {
		t.Fatal(err)
	}
	producer := prefix.selector.producer.profileForMode(mode)
	if producer.digest == "" {
		t.Fatalf("unsupported mode %q", mode)
	}
	operands := Signed8Depth2Operands{
		feature: feature, threshold: threshold, conditionedSelector: conditioned,
		sourceKind: Signed8Depth2PrefixL6V1, profileDigest: prefix.profile.digest,
		parameterDigest: prefix.profile.parameterDigest, rangeDigest: prefix.profile.rangeDigest,
		treeDigest: prefix.profile.treeDigest, scheduleDigest: prefix.profile.scheduleDigest,
		selectorProfileDigest: prefix.selector.profile.digest, producerProfileDigest: producer.digest,
		conditionerProfileDigest:      prefix.conditioner.profile.digest,
		selectorInputProvenanceDigest: digestString("child-decoder-test-selector-input"),
		featureInputPayloadDigests:    [2]string{digestString("child-decoder-test-feature-left"), digestString("child-decoder-test-feature-right")},
		featurePayloadDigest:          featureDigest, thresholdPayloadDigest: thresholdDigest,
		conditionedSelectorPayloadDigest: conditionedDigest,
	}
	operands.provenanceDigest = digestSigned8Depth2Operands(operands)
	input, err := child.BindOperands(operands)
	if err != nil {
		t.Fatal(err)
	}
	branch := newCiphertext(signed8OutputLevel)
	branch.Value[0].Coeffs[0][3] = marker + 3
	payload, err := signed8CiphertextDigest(branch)
	if err != nil {
		t.Fatal(err)
	}
	profile := child.profile
	result := Signed8Depth2ChildComparatorResult{
		branch: branch, profileDigest: profile.digest, parameterDigest: profile.parameter,
		protocolRangeDigest: profile.protocolRange, treeDigest: profile.tree, scheduleDigest: profile.schedule,
		inputBindingDigest: input.bindingDigest, operandsProvenanceDigest: input.operandsProvenance,
		ingressProfileDigest: profile.ingressProfile, ingressRangeDigest: profile.ingressRange,
		ingressAdmissionDigest:    profile.ingressAdmission,
		ingressInputBindingDigest: digestString("child-decoder-test-ingress-input"),
		ingressTraceDigest:        digestString("child-decoder-test-ingress-trace"),
		signProfileDigest:         profile.signProfile, signSourceDigest: profile.signSource,
		signCompiledDigest: profile.signCompiled, signTraceDigest: digestString("child-decoder-test-sign-trace"),
		outputPayloadDigest: payload,
	}
	result.provenanceDigest = digestSigned8Depth2ChildComparatorResult(result)
	if err := child.validateResult(result); err != nil {
		t.Fatalf("test child result is invalid: %v", err)
	}
	return input, result
}
