package homchain

import (
	"fmt"
	"math/big"
	"math/cmplx"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/nc26676027/LCPDTE/integer/treeplan"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	ckkslintrans "github.com/tuneinsight/lattigo/v6/circuits/ckks/lintrans"
	ckkspolynomial "github.com/tuneinsight/lattigo/v6/circuits/ckks/polynomial"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func TestSigned8Depth2ChildComparatorEncryptedSelectedChildren(t *testing.T) {
	ranges, err := NewSigned8NoOverflowRange(-8, 7, -8, 7)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newSigned8ComparatorFixture(t, ranges)
	selectorCircuit, err := NewSelectorReraiseDecodeCircuit(fixture.circuit)
	if err != nil {
		t.Fatal(err)
	}
	prefixCircuit, err := NewSigned8Depth2SourcePrefixCircuit(selectorCircuit, signed8Depth2TestTree())
	if err != nil {
		t.Fatal(err)
	}
	selectorEvaluator, err := selectorCircuit.BindEvaluator(fixture.source)
	if err != nil {
		t.Fatal(err)
	}
	prefixEvaluator, err := prefixCircuit.BindEvaluator(fixture.source)
	if err != nil {
		t.Fatal(err)
	}

	rootFeature, err := fixture.circuit.BindFeature(
		fixture.encryptSigned(t, [4]int64{-1, 1, -2, 2}), fixture.params,
	)
	if err != nil {
		t.Fatal(err)
	}
	rootComparison, _, err := fixture.evaluator.CompareGEPublicNew(rootFeature, [4]int64{})
	if err != nil {
		t.Fatal(err)
	}
	selectorInput, err := selectorCircuit.BindComparatorResult(rootComparison)
	if err != nil {
		t.Fatal(err)
	}
	selectorResult, _, err := selectorEvaluator.EvaluateNew(selectorInput)
	if err != nil {
		t.Fatal(err)
	}
	conditionInput, err := prefixCircuit.BindSelectorResult(selectorResult)
	if err != nil {
		t.Fatal(err)
	}
	leftFeature, err := fixture.circuit.BindFeature(
		fixture.encryptSigned(t, [4]int64{-3, -2, -1, 0}), fixture.params,
	)
	if err != nil {
		t.Fatal(err)
	}
	rightFeature, err := fixture.circuit.BindFeature(
		fixture.encryptSigned(t, [4]int64{1, 2, 3, 4}), fixture.params,
	)
	if err != nil {
		t.Fatal(err)
	}
	operands, _, err := prefixEvaluator.EvaluateNew(
		conditionInput,
		[2]Signed8FeatureInput{leftFeature, rightFeature},
	)
	if err != nil {
		t.Fatal(err)
	}

	circuit, err := NewSigned8Depth2ChildComparatorCircuit(prefixCircuit)
	if err != nil {
		t.Fatal(err)
	}
	input, err := circuit.BindOperands(operands)
	if err != nil {
		t.Fatal(err)
	}
	if input.operands.feature == operands.feature || input.operands.threshold == operands.threshold ||
		input.operands.conditionedSelector == operands.conditionedSelector ||
		!input.operands.feature.Equal(operands.feature) || !input.operands.threshold.Equal(operands.threshold) ||
		!input.operands.conditionedSelector.Equal(operands.conditionedSelector) {
		t.Fatal("child input does not own detached exact prefix operand copies")
	}
	evaluator, err := circuit.BindEvaluator(fixture.source)
	if err != nil {
		t.Fatal(err)
	}
	featureBefore, thresholdBefore := input.FeatureCiphertext(), input.ThresholdCiphertext()
	result, trace, err := evaluator.EvaluateNew(input)
	if err != nil {
		t.Fatal(err)
	}
	if err = evaluator.preflight(); err != nil {
		t.Fatalf("runtime identity snapshots changed after accepted scratch use: %v", err)
	}
	if got, want := fixture.decryptWords(t, result.Ciphertext()), ([4]uint64{1, 0, 1, 1}); got != want {
		t.Fatalf("selected child GE=%v, want %v", got, want)
	}
	legacyFeature, err := fixture.circuit.BindFeature(
		fixture.encryptSigned(t, [4]int64{-3, 2, -1, 4}), fixture.params,
	)
	if err != nil {
		t.Fatal(err)
	}
	legacyResult, _, err := fixture.evaluator.CompareGEPublicNew(legacyFeature, [4]int64{-4, 3, -4, 3})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fixture.decryptWords(t, result.Ciphertext()), fixture.decryptWords(t, legacyResult.Ciphertext()); got != want {
		t.Fatalf("fixed-L6 child/legacy-L20 comparator differential=%v/%v", got, want)
	}
	acceptedA2B, _, err := fixture.evaluator.a2b.EvaluateNew(
		fixture.encryptSigned(t, [4]int64{1, -1, 3, 1}),
	)
	if err != nil {
		t.Fatal(err)
	}
	childHigh, ok := trace.RetainedCiphertext(Signed8Depth2ChildStageIngressHigh)
	if !ok {
		t.Fatal("child trace omitted its authenticated ingress high")
	}
	childHighValues := decodeSigned8Depth2Child(t, fixture.integerEncoder, fixture.decryptor, childHigh)
	acceptedHighValues := decodeSigned8Depth2Child(t, fixture.integerEncoder, fixture.decryptor, acceptedA2B.HighMSB())
	for slot := range childHighValues {
		if distance := cmplx.Abs(childHighValues[slot] - acceptedHighValues[slot]); distance > 3e-3 {
			t.Fatalf("fixed-L6/L20 A2B-high differential slot %d=%g", slot, distance)
		}
	}
	if !input.FeatureCiphertext().Equal(featureBefore) || !input.ThresholdCiphertext().Equal(thresholdBefore) {
		t.Fatal("child comparator mutated its owned input")
	}
	if err = circuit.validateResult(result); err != nil {
		t.Fatalf("sealed child result did not validate: %v", err)
	}
	if result.ProfileDigest() != circuit.Profile().Digest() ||
		result.OperandsProvenanceDigest() != operands.ProvenanceDigest() ||
		result.OutputPayloadDigest() == "" || result.ProvenanceDigest() == "" {
		t.Fatalf("child result provenance is incomplete: %+v", result)
	}
	assertSigned8Depth2ChildTrace(t, circuit, input, result, trace)

	t.Run("sealed result mutation matrix", func(t *testing.T) {
		for _, test := range []struct {
			name   string
			mutate func(*Signed8Depth2ChildComparatorResult)
		}{
			{"zero-result-seam", func(value *Signed8Depth2ChildComparatorResult) { *value = Signed8Depth2ChildComparatorResult{} }},
			{"nil-branch", func(value *Signed8Depth2ChildComparatorResult) { value.branch = nil }},
			{"same-state-branch-replacement", func(value *Signed8Depth2ChildComparatorResult) {
				foreign := ckks.NewCiphertext(fixture.params, 1, 4)
				foreign.MetaData = value.branch.MetaData.CopyNew()
				value.branch = foreign
			}},
			{"branch-payload", func(value *Signed8Depth2ChildComparatorResult) { value.branch.Value[0].Coeffs[0][0] ^= 1 }},
			{"profile", func(value *Signed8Depth2ChildComparatorResult) { value.profileDigest = "tampered" }},
			{"protocol-range", func(value *Signed8Depth2ChildComparatorResult) { value.protocolRangeDigest = "tampered" }},
			{"tree", func(value *Signed8Depth2ChildComparatorResult) { value.treeDigest = "tampered" }},
			{"schedule", func(value *Signed8Depth2ChildComparatorResult) { value.scheduleDigest = "tampered" }},
			{"input-binding", func(value *Signed8Depth2ChildComparatorResult) { value.inputBindingDigest = "tampered" }},
			{"operands", func(value *Signed8Depth2ChildComparatorResult) { value.operandsProvenanceDigest = "tampered" }},
			{"ingress-trace", func(value *Signed8Depth2ChildComparatorResult) { value.ingressTraceDigest = "tampered" }},
			{"sign-trace", func(value *Signed8Depth2ChildComparatorResult) { value.signTraceDigest = "tampered" }},
			{"output-payload", func(value *Signed8Depth2ChildComparatorResult) { value.outputPayloadDigest = "tampered" }},
			{"provenance", func(value *Signed8Depth2ChildComparatorResult) { value.provenanceDigest = "tampered" }},
		} {
			t.Run(test.name, func(t *testing.T) {
				changed := result
				changed.branch = copyA2BRefreshCiphertext(result.branch)
				test.mutate(&changed)
				if err := circuit.validateResult(changed); err == nil {
					t.Fatal("mutated child result admitted")
				}
			})
		}
		if err := circuit.validateResult(result); err != nil {
			t.Fatalf("accepted result changed after rejected mutations: %v", err)
		}
	})

	t.Run("defensive accessors", func(t *testing.T) {
		branch := result.Ciphertext()
		branch.Value[0].Coeffs[0][0] ^= 1
		states := trace.States()
		states[0].Level = 99
		keys := trace.RuntimeGaloisElements()
		keys[0] = 0
		ingress := trace.IngressTrace()
		ingress.states[0].Level = 99
		sign := trace.SignProvenance()
		sign.states[0].Level = 99
		if err := circuit.validateResult(result); err != nil || trace.States()[0].Level != 6 ||
			trace.RuntimeGaloisElements()[0] != 5 || trace.IngressTrace().States()[0].Level != 6 ||
			trace.SignProvenance().States()[0].Level != 5 {
			t.Fatal("child result or trace accessor aliases sealed evidence")
		}
	})
}

func decodeSigned8Depth2Child(
	t *testing.T,
	encoder *ckks.Encoder,
	decryptor *rlwe.Decryptor,
	ciphertext *rlwe.Ciphertext,
) []complex128 {
	t.Helper()
	if ciphertext == nil {
		t.Fatal("nil depth2 child ciphertext")
	}
	values := make([]complex128, ciphertext.Slots())
	if err := encoder.Decode(decryptor.DecryptNew(ciphertext), values); err != nil {
		t.Fatal(err)
	}
	return values
}

func assertSigned8Depth2ChildTrace(
	t *testing.T,
	circuit *Signed8Depth2ChildComparatorCircuit,
	input Signed8Depth2ChildComparatorInput,
	result Signed8Depth2ChildComparatorResult,
	trace Signed8Depth2ChildComparatorTrace,
) {
	t.Helper()
	if trace.ProfileDigest() != circuit.Profile().Digest() ||
		trace.InputBindingDigest() != input.BindingDigest() ||
		trace.OperandsProvenanceDigest() != input.OperandsProvenanceDigest() ||
		trace.ResultProvenanceDigest() != result.ProvenanceDigest() ||
		trace.FailureStage() != "" ||
		trace.OperationCounts() != circuit.Profile().OperationCounts() ||
		!equalUint64Slices(trace.RuntimeGaloisElements(), circuit.RequiredKeyProfile().All()) ||
		!trace.RelinearizationKeyMatched() || len(trace.States()) != 7 ||
		!trace.SerializedBytes().Complete() || trace.IngressTrace().FailureStage() != "" ||
		trace.SignProvenance().ProfileDigest() != circuit.Profile().SignProfileDigest() {
		t.Fatalf("child trace evidence changed: %+v", trace)
	}
	preflight := trace.KeyPreflight()
	if !preflight.Checked || !preflight.GraphChecked || !preflight.GraphMatched ||
		!preflight.RelinearizationPresent || !preflight.RelinearizationMatched ||
		!preflight.DenseNoSwitchingMatched || len(preflight.MissingGaloisElements) != 0 ||
		len(preflight.InvalidGaloisElements) != 0 || len(preflight.UnexpectedGaloisElements) != 0 {
		t.Fatalf("child key preflight evidence changed: %+v", preflight)
	}
	wantBytes := Signed8Depth2ChildComparatorSerializedBytes{
		Feature: 3998, Threshold: 3998, Difference: 3998, IngressHigh: 3470,
		ArithmeticSign: 2942, NegatedSign: 2942, GreaterEqualOutput: 2942,
	}
	if got := trace.SerializedBytes(); got != wantBytes ||
		circuit.Profile().ExpectedSerializedBytes() != wantBytes ||
		got.OnlineInputBytes() != 7996 || got.RetainedLocalBytes() != 13352 ||
		got.OnlineOutputBytes() != 2942 || got.TotalBytes() != 24290 {
		t.Fatalf("child exact serialized-byte ledger changed: runtime=%+v profile=%+v", got, circuit.Profile().ExpectedSerializedBytes())
	}
	wantStages := []Signed8Depth2ChildComparatorStage{
		Signed8Depth2ChildStageFeature, Signed8Depth2ChildStageThreshold,
		Signed8Depth2ChildStageDifference, Signed8Depth2ChildStageIngressHigh,
		Signed8Depth2ChildStageArithmeticSign, Signed8Depth2ChildStageNegatedSign,
		Signed8Depth2ChildStageGreaterEqual,
	}
	wantLevels := []int{6, 6, 6, 5, 4, 4, 4}
	for index, state := range trace.States() {
		if state.Stage != wantStages[index] || state.Level != wantLevels[index] ||
			state.Degree != 1 || state.SerializedBytes != circuit.Profile().ExpectedStates()[index].SerializedBytes {
			t.Fatalf("child ordered state %d changed: %+v", index, state)
		}
	}
}

type signed8Depth2ChildIntegrationFixture struct {
	base      signed8ComparatorFixture
	prefix    *Signed8Depth2SourcePrefixCircuit
	operands  Signed8Depth2Operands
	circuit   *Signed8Depth2ChildComparatorCircuit
	input     Signed8Depth2ChildComparatorInput
	evaluator *Signed8Depth2ChildComparatorEvaluator
}

func newSigned8Depth2ChildIntegrationFixture(t *testing.T) signed8Depth2ChildIntegrationFixture {
	t.Helper()
	ranges, err := NewSigned8NoOverflowRange(-8, 7, -8, 7)
	if err != nil {
		t.Fatal(err)
	}
	base := newSigned8ComparatorFixture(t, ranges)
	selector, err := NewSelectorReraiseDecodeCircuit(base.circuit)
	if err != nil {
		t.Fatal(err)
	}
	prefix, err := NewSigned8Depth2SourcePrefixCircuit(selector, signed8Depth2TestTree())
	if err != nil {
		t.Fatal(err)
	}
	selectorEvaluator, err := selector.BindEvaluator(base.source)
	if err != nil {
		t.Fatal(err)
	}
	prefixEvaluator, err := prefix.BindEvaluator(base.source)
	if err != nil {
		t.Fatal(err)
	}
	root, err := base.circuit.BindFeature(base.encryptSigned(t, [4]int64{-1, 1, -2, 2}), base.params)
	if err != nil {
		t.Fatal(err)
	}
	rootResult, _, err := base.evaluator.CompareGEPublicNew(root, [4]int64{})
	if err != nil {
		t.Fatal(err)
	}
	selectorInput, err := selector.BindComparatorResult(rootResult)
	if err != nil {
		t.Fatal(err)
	}
	selectorResult, _, err := selectorEvaluator.EvaluateNew(selectorInput)
	if err != nil {
		t.Fatal(err)
	}
	condition, err := prefix.BindSelectorResult(selectorResult)
	if err != nil {
		t.Fatal(err)
	}
	left, err := base.circuit.BindFeature(base.encryptSigned(t, [4]int64{-3, -2, -1, 0}), base.params)
	if err != nil {
		t.Fatal(err)
	}
	right, err := base.circuit.BindFeature(base.encryptSigned(t, [4]int64{1, 2, 3, 4}), base.params)
	if err != nil {
		t.Fatal(err)
	}
	operands, _, err := prefixEvaluator.EvaluateNew(condition, [2]Signed8FeatureInput{left, right})
	if err != nil {
		t.Fatal(err)
	}
	circuit, err := NewSigned8Depth2ChildComparatorCircuit(prefix)
	if err != nil {
		t.Fatal(err)
	}
	input, err := circuit.BindOperands(operands)
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := circuit.BindEvaluator(base.source)
	if err != nil {
		t.Fatal(err)
	}
	return signed8Depth2ChildIntegrationFixture{
		base: base, prefix: prefix, operands: operands, circuit: circuit, input: input, evaluator: evaluator,
	}
}

func TestSigned8Depth2ChildComparatorBindEvaluatorCapturesCanonicalBootstrapGroups(t *testing.T) {
	prefix := newSigned8Depth2ChildPrefixForTest(t)
	circuit, err := NewSigned8Depth2ChildComparatorCircuit(prefix)
	if err != nil {
		t.Fatal(err)
	}
	keyGenerator := ckks.NewKeyGenerator(circuit.params)
	secretKey := keyGenerator.GenSecretKeyNew()
	keySet := rlwe.NewMemEvaluationKeySet(
		keyGenerator.GenRelinearizationKeyNew(secretKey),
		keyGenerator.GenGaloisKeysNew(circuit.RequiredKeyProfile().All(), secretKey)...,
	)
	source, err := newSigned8Depth2ChildBootstrapSource(circuit, keySet)
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := circuit.BindEvaluator(source)
	if err != nil {
		t.Fatal(err)
	}
	_, wantS2C, err := digestA2BFullIngress6EncodedFactorGroup(
		"first-stc", evaluator.ingressSource.S2CDFTMatrix.Matrices,
	)
	if err != nil {
		t.Fatal(err)
	}
	_, wantC2S, err := digestA2BFullIngress6EncodedFactorGroup(
		"shared-cts", evaluator.ingressSource.C2SDFTMatrix.Matrices,
	)
	if err != nil {
		t.Fatal(err)
	}
	binding := evaluator.graph.ingressBinding
	if binding.refreshS2CPayload == "" || binding.refreshC2SPayload == "" ||
		binding.refreshS2CPayload != wantS2C || binding.refreshC2SPayload != wantC2S {
		t.Fatalf("canonical child bootstrap payload capture changed: s2c=%s/%s c2s=%s/%s",
			binding.refreshS2CPayload, wantS2C, binding.refreshC2SPayload, wantC2S)
	}

	cloneSource := func() *bootstrapping.Evaluator {
		clone := *source
		if source.Evaluator != nil {
			ckksClone := *source.Evaluator
			if source.Evaluator.Encoder != nil {
				encoderClone := *source.Evaluator.Encoder
				ckksClone.Encoder = &encoderClone
			}
			if source.Evaluator.Evaluator != nil {
				rlweClone := *source.Evaluator.Evaluator
				ckksClone.Evaluator = &rlweClone
			}
			clone.Evaluator = &ckksClone
		}
		return &clone
	}
	alternateEvaluationKeys := &bootstrapping.EvaluationKeys{MemEvaluationKeySet: source.MemEvaluationKeySet}
	for _, test := range []struct {
		name   string
		mutate func(*bootstrapping.Evaluator)
	}{
		{"evaluation-keys-nil", func(value *bootstrapping.Evaluator) { value.EvaluationKeys = nil }},
		{"ckks-evaluator-nil", func(value *bootstrapping.Evaluator) { value.Evaluator = nil }},
		{"ckks-encoder-nil", func(value *bootstrapping.Evaluator) { value.Evaluator.Encoder = nil }},
		{"rlwe-evaluator-nil", func(value *bootstrapping.Evaluator) { value.Evaluator.Evaluator = nil }},
		{"rlwe-buffers-nil", func(value *bootstrapping.Evaluator) { value.Evaluator.Evaluator.EvaluatorBuffers = nil }},
		{"basis-extender-nil", func(value *bootstrapping.Evaluator) { value.Evaluator.Evaluator.BasisExtender = nil }},
		{"decomposer-nil", func(value *bootstrapping.Evaluator) { value.Evaluator.Evaluator.Decomposer = nil }},
		{"embedded-evaluation-key-wrapper-replaced", func(value *bootstrapping.Evaluator) {
			value.Evaluator.Evaluator.EvaluationKeySet = alternateEvaluationKeys
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := cloneSource()
			test.mutate(changed)
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("BindEvaluator panicked for %s: %v", test.name, recovered)
				}
			}()
			bound, bindErr := circuit.BindEvaluator(changed)
			if bindErr == nil || bound != nil {
				t.Fatalf("incomplete source %s admitted: evaluator=%p err=%v", test.name, bound, bindErr)
			}
		})
	}
}

func TestSigned8Depth2ChildComparatorCompletePreHEMutationMatrix(t *testing.T) {
	fixture := newSigned8Depth2ChildIntegrationFixture(t)
	foreignNested := newSigned8Depth2ChildForeignNestedEvaluators(t, &fixture)
	sameKeyNested := newSigned8Depth2ChildNestedEvaluatorsWithKeySet(t, &fixture, fixture.evaluator.ingressKeySet)
	type mutation struct {
		name   string
		mutate func(*signed8Depth2ChildIntegrationFixture, *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func())
	}
	noRestore := func() {}
	firstElement := fixture.circuit.RequiredKeyProfile().All()[0]
	mutations := []mutation{
		{"nil-evaluator-result-seam", func(_ *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			return nil, noRestore
		}},
		{"zero-input-seam", func(f *signed8Depth2ChildIntegrationFixture, input *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			*input = Signed8Depth2ChildComparatorInput{}
			return f.evaluator, noRestore
		}},
		{"nil-feature", func(f *signed8Depth2ChildIntegrationFixture, input *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			input.operands.feature = nil
			return f.evaluator, noRestore
		}},
		{"nil-threshold", func(f *signed8Depth2ChildIntegrationFixture, input *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			input.operands.threshold = nil
			return f.evaluator, noRestore
		}},
		{"nil-conditioned-selector", func(f *signed8Depth2ChildIntegrationFixture, input *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			input.operands.conditionedSelector = nil
			return f.evaluator, noRestore
		}},
		{"same-state-feature-replacement", func(f *signed8Depth2ChildIntegrationFixture, input *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			foreign := ckks.NewCiphertext(f.base.params, 1, 6)
			foreign.MetaData = input.operands.feature.MetaData.CopyNew()
			input.operands.feature = foreign
			return f.evaluator, noRestore
		}},
		{"feature-payload", func(f *signed8Depth2ChildIntegrationFixture, input *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			input.operands.feature.Value[0].Coeffs[0][0] ^= 1
			return f.evaluator, noRestore
		}},
		{"same-state-threshold-replacement", func(f *signed8Depth2ChildIntegrationFixture, input *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			foreign := ckks.NewCiphertext(f.base.params, 1, 6)
			foreign.MetaData = input.operands.threshold.MetaData.CopyNew()
			input.operands.threshold = foreign
			return f.evaluator, noRestore
		}},
		{"operand-payload-certificate", func(f *signed8Depth2ChildIntegrationFixture, input *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			input.operands.featurePayloadDigest = "tampered"
			return f.evaluator, noRestore
		}},
		{"operand-provenance", func(f *signed8Depth2ChildIntegrationFixture, input *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			input.operands.provenanceDigest = "tampered"
			return f.evaluator, noRestore
		}},
		{"input-binding", func(f *signed8Depth2ChildIntegrationFixture, input *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			input.bindingDigest = "tampered"
			return f.evaluator, noRestore
		}},
		{"operand-range-field", func(f *signed8Depth2ChildIntegrationFixture, input *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			input.operands.rangeDigest = "tampered"
			return f.evaluator, noRestore
		}},
		{"operand-tree-field", func(f *signed8Depth2ChildIntegrationFixture, input *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			input.operands.treeDigest = "tampered"
			return f.evaluator, noRestore
		}},
		{"operand-schedule-field", func(f *signed8Depth2ChildIntegrationFixture, input *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			input.operands.scheduleDigest = "tampered"
			return f.evaluator, noRestore
		}},
		{"prefix-range-field", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := f.prefix.profile.rangeDigest
			f.prefix.profile.rangeDigest = "tampered"
			return f.evaluator, func() { f.prefix.profile.rangeDigest = before }
		}},
		{"prefix-tree-field", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := f.prefix.profile.treeDigest
			f.prefix.profile.treeDigest = "tampered"
			return f.evaluator, func() { f.prefix.profile.treeDigest = before }
		}},
		{"prefix-schedule-field", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := f.prefix.profile.scheduleDigest
			f.prefix.profile.scheduleDigest = "tampered"
			return f.evaluator, func() { f.prefix.profile.scheduleDigest = before }
		}},
		{"prefix-threshold-cache", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			coefficient := &f.prefix.thresholdLeft.Value.Coeffs[0][0]
			before := *coefficient
			*coefficient ^= 1
			return f.evaluator, func() { *coefficient = before }
		}},
		{"child-graph-profile", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := f.circuit.graph.profileDigest
			f.circuit.graph.profileDigest = "tampered"
			return f.evaluator, func() { f.circuit.graph.profileDigest = before }
		}},
		{"ingress-profile", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := f.circuit.ingress.profile.digest
			f.circuit.ingress.profile.digest = "tampered"
			return f.evaluator, func() { f.circuit.ingress.profile.digest = before }
		}},
		{"ingress-evaluator-graph-profile", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := f.evaluator.ingress.graph.profileDigest
			f.evaluator.ingress.graph.profileDigest = "tampered"
			return f.evaluator, func() { f.evaluator.ingress.graph.profileDigest = before }
		}},
		{"ingress-mask-cache", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			coefficient := &f.circuit.ingress.lowMask.Value.Coeffs[0][0]
			before := *coefficient
			*coefficient ^= 1
			return f.evaluator, func() { *coefficient = before }
		}},
		{"ingress-first-stc-actual-payload", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			_, _, restore := mutateA2BFullIngress6EncodedDiagonalCoefficient(t, &f.circuit.ingress.firstSTC.Matrices[0])
			return f.evaluator, restore
		}},
		{"ingress-shared-cts-actual-payload", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			_, _, restore := mutateA2BFullIngress6EncodedDiagonalCoefficient(t, &f.circuit.ingress.suffix.refresh.cts.Matrices[0])
			return f.evaluator, restore
		}},
		{"ingress-second-stc-actual-payload", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			_, _, restore := mutateA2BFullIngress6EncodedDiagonalCoefficient(t, &f.circuit.ingress.suffix.secondSTC.Matrices[0])
			return f.evaluator, restore
		}},
		{"ingress-first-stc-cache-truncated", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := f.circuit.ingress.graph.firstSTCFactors
			f.circuit.ingress.graph.firstSTCFactors = before[:1]
			return f.evaluator, func() { f.circuit.ingress.graph.firstSTCFactors = before }
		}},
		{"ingress-cts-cache-appended", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := f.circuit.ingress.graph.sharedCTSFactors
			f.circuit.ingress.graph.sharedCTSFactors = append(append([]uintptr(nil), before...), 1)
			return f.evaluator, func() { f.circuit.ingress.graph.sharedCTSFactors = before }
		}},
		{"ingress-second-stc-cache-truncated", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := f.circuit.ingress.graph.secondSTCFactors
			f.circuit.ingress.graph.secondSTCFactors = before[:1]
			return f.evaluator, func() { f.circuit.ingress.graph.secondSTCFactors = before }
		}},
		{"sign-compiled-profile", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := f.circuit.sign.profile.compiledDigest
			f.circuit.sign.profile.compiledDigest = "tampered"
			return f.evaluator, func() { f.circuit.sign.profile.compiledDigest = before }
		}},
		{"sign-actual-compiled-payload", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			_, _, restore := mutateA2BFullIngress6EncodedDiagonalCoefficient(t, &f.circuit.sign.transform)
			return f.evaluator, restore
		}},
		{"sign-evaluator-graph", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := f.evaluator.sign.linear
			f.evaluator.sign.linear = nil
			return f.evaluator, func() { f.evaluator.sign.linear = before }
		}},
		{"arithmetic-one-cache", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			coefficient := &f.circuit.arithmeticOne.Value.Coeffs[0][0]
			before := *coefficient
			*coefficient ^= 1
			return f.evaluator, func() { *coefficient = before }
		}},
		{"arithmetic-one-seal", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			coefficient := &f.circuit.arithmeticOneSeal.Value.Coeffs[0][0]
			before := *coefficient
			*coefficient ^= 1
			return f.evaluator, func() { *coefficient = before }
		}},
		{"arithmetic-one-pointer", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := f.circuit.arithmeticOne
			f.circuit.arithmeticOne = before.CopyNew()
			return f.evaluator, func() { f.circuit.arithmeticOne = before }
		}},
		{"relinearization-deleted", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := f.base.source.MemEvaluationKeySet.RelinearizationKey
			f.base.source.MemEvaluationKeySet.RelinearizationKey = nil
			return f.evaluator, func() { f.base.source.MemEvaluationKeySet.RelinearizationKey = before }
		}},
		{"relinearization-replaced", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := f.base.source.MemEvaluationKeySet.RelinearizationKey
			foreignSecret := f.base.keyGenerator.GenSecretKeyNew()
			f.base.source.MemEvaluationKeySet.RelinearizationKey = f.base.keyGenerator.GenRelinearizationKeyNew(foreignSecret)
			return f.evaluator, func() { f.base.source.MemEvaluationKeySet.RelinearizationKey = before }
		}},
		{"relinearization-value-nil", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			key := f.base.source.MemEvaluationKeySet.RelinearizationKey
			before := key.GadgetCiphertext.Value
			key.GadgetCiphertext.Value = nil
			return f.evaluator, func() { key.GadgetCiphertext.Value = before }
		}},
		{"galois-deleted", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := f.base.source.MemEvaluationKeySet.GaloisKeys[firstElement]
			delete(f.base.source.MemEvaluationKeySet.GaloisKeys, firstElement)
			return f.evaluator, func() { f.base.source.MemEvaluationKeySet.GaloisKeys[firstElement] = before }
		}},
		{"galois-same-element-pointer-replaced", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := f.base.source.MemEvaluationKeySet.GaloisKeys[firstElement]
			foreignSecret := f.base.keyGenerator.GenSecretKeyNew()
			f.base.source.MemEvaluationKeySet.GaloisKeys[firstElement] = f.base.keyGenerator.GenGaloisKeyNew(firstElement, foreignSecret)
			return f.evaluator, func() { f.base.source.MemEvaluationKeySet.GaloisKeys[firstElement] = before }
		}},
		{"galois-wrong-element-pointer", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			elements := f.circuit.RequiredKeyProfile().All()
			before := f.base.source.MemEvaluationKeySet.GaloisKeys[elements[0]]
			f.base.source.MemEvaluationKeySet.GaloisKeys[elements[0]] = f.base.source.MemEvaluationKeySet.GaloisKeys[elements[1]]
			return f.evaluator, func() { f.base.source.MemEvaluationKeySet.GaloisKeys[elements[0]] = before }
		}},
		{"galois-value-nil", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			key := f.base.source.MemEvaluationKeySet.GaloisKeys[firstElement]
			before := key.GadgetCiphertext.Value
			key.GadgetCiphertext.Value = nil
			return f.evaluator, func() { key.GadgetCiphertext.Value = before }
		}},
		{"galois-decomposition-outer-truncated", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			key := f.base.source.MemEvaluationKeySet.GaloisKeys[firstElement]
			before := key.GadgetCiphertext.Value
			key.GadgetCiphertext.Value = before[:1]
			return f.evaluator, func() { key.GadgetCiphertext.Value = before }
		}},
		{"galois-decomposition-row-empty", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			key := f.base.source.MemEvaluationKeySet.GaloisKeys[firstElement]
			before := key.GadgetCiphertext.Value[0]
			key.GadgetCiphertext.Value[0] = nil
			return f.evaluator, func() { key.GadgetCiphertext.Value[0] = before }
		}},
		{"galois-degree-zero-vector", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			key := f.base.source.MemEvaluationKeySet.GaloisKeys[firstElement]
			before := key.GadgetCiphertext.Value[0][0]
			key.GadgetCiphertext.Value[0][0] = before[:1]
			return f.evaluator, func() { key.GadgetCiphertext.Value[0][0] = before }
		}},
		{"galois-q-coefficient-row-truncated", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			key := f.base.source.MemEvaluationKeySet.GaloisKeys[firstElement]
			before := key.GadgetCiphertext.Value[0][0][0].Q.Coeffs[0]
			key.GadgetCiphertext.Value[0][0][0].Q.Coeffs[0] = before[:1]
			return f.evaluator, func() { key.GadgetCiphertext.Value[0][0][0].Q.Coeffs[0] = before }
		}},
		{"galois-nth-root", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			key := f.base.source.MemEvaluationKeySet.GaloisKeys[firstElement]
			before := key.NthRoot
			key.NthRoot++
			return f.evaluator, func() { key.NthRoot = before }
		}},
		{"galois-base-two-decomposition", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			key := f.base.source.MemEvaluationKeySet.GaloisKeys[firstElement]
			before := key.GadgetCiphertext.BaseTwoDecomposition
			key.GadgetCiphertext.BaseTwoDecomposition++
			return f.evaluator, func() { key.GadgetCiphertext.BaseTwoDecomposition = before }
		}},
		{"filtered-galois-pointer-replaced", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := f.evaluator.ingressKeySet.GaloisKeys[firstElement]
			foreignSecret := f.base.keyGenerator.GenSecretKeyNew()
			f.evaluator.ingressKeySet.GaloisKeys[firstElement] = f.base.keyGenerator.GenGaloisKeyNew(firstElement, foreignSecret)
			return f.evaluator, func() { f.evaluator.ingressKeySet.GaloisKeys[firstElement] = before }
		}},
		{"filtered-relinearization-deleted", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := f.evaluator.ingressKeySet.RelinearizationKey
			f.evaluator.ingressKeySet.RelinearizationKey = nil
			return f.evaluator, func() { f.evaluator.ingressKeySet.RelinearizationKey = before }
		}},
		{"child-evaluator-graph", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := f.evaluator.graph.profileDigest
			f.evaluator.graph.profileDigest = "tampered"
			return f.evaluator, func() { f.evaluator.graph.profileDigest = before }
		}},
		{"foreign-valid-ingress-suffix", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := f.evaluator.ingress.suffix
			f.evaluator.ingress.suffix = foreignNested.ingress.suffix
			return f.evaluator, func() { f.evaluator.ingress.suffix = before }
		}},
		{"same-current-key-valid-ingress-suffix", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := f.evaluator.ingress.suffix
			f.evaluator.ingress.suffix = sameKeyNested.ingress.suffix
			return f.evaluator, func() { f.evaluator.ingress.suffix = before }
		}},
		{"foreign-valid-sign-group", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := *f.evaluator.sign
			*f.evaluator.sign = *foreignNested.sign
			return f.evaluator, func() { *f.evaluator.sign = before }
		}},
		{"same-current-key-valid-sign-group", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := *f.evaluator.sign
			*f.evaluator.sign = *sameKeyNested.sign
			return f.evaluator, func() { *f.evaluator.sign = before }
		}},
		{"foreign-refresh-triangle-only", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := f.evaluator.ingress.suffix.refresh.triangle
			f.evaluator.ingress.suffix.refresh.triangle = NewEvaluator(foreignNested.source.Evaluator)
			return f.evaluator, func() { f.evaluator.ingress.suffix.refresh.triangle = before }
		}},
		{"same-current-key-refresh-triangle-only", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := f.evaluator.ingress.suffix.refresh.triangle
			f.evaluator.ingress.suffix.refresh.triangle = NewEvaluator(sameKeyNested.source.Evaluator)
			return f.evaluator, func() { f.evaluator.ingress.suffix.refresh.triangle = before }
		}},
		{"refresh-dft-whole-value", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			target := f.evaluator.ingress.suffix.refresh.bootstrap.DFTEvaluator
			before := *target
			*target = *sameKeyNested.ingress.suffix.refresh.bootstrap.DFTEvaluator
			return f.evaluator, func() { *target = before }
		}},
		{"kernel-polynomial-whole-value", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			target := f.evaluator.ingress.suffix.kernel0.polynomial
			before := *target
			*target = *ckkspolynomial.NewEvaluator(f.base.params, f.evaluator.ingress.suffix.kernel0.ckks)
			return f.evaluator, func() { *target = before }
		}},
		{"kernel-polynomial-coefficient-getter-backing", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			target := f.evaluator.ingress.suffix.kernel0.polynomial
			before := target.Evaluator.CoefficientGetter
			replacement := ckkspolynomial.NewEvaluator(f.base.params, f.evaluator.ingress.suffix.kernel0.ckks)
			target.Evaluator.CoefficientGetter = replacement.Evaluator.CoefficientGetter
			return f.evaluator, func() { target.Evaluator.CoefficientGetter = before }
		}},
		{"source-ckks-encoder-nil", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := f.evaluator.sourceCKKS.Encoder
			f.evaluator.sourceCKKS.Encoder = nil
			return f.evaluator, func() { f.evaluator.sourceCKKS.Encoder = before }
		}},
		{"source-ckks-rlwe-evaluator-nil", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := f.evaluator.sourceCKKS.Evaluator
			f.evaluator.sourceCKKS.Evaluator = nil
			return f.evaluator, func() { f.evaluator.sourceCKKS.Evaluator = before }
		}},
		{"source-rlwe-buffers-nil", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := f.evaluator.sourceCKKS.Evaluator.EvaluatorBuffers
			f.evaluator.sourceCKKS.Evaluator.EvaluatorBuffers = nil
			return f.evaluator, func() { f.evaluator.sourceCKKS.Evaluator.EvaluatorBuffers = before }
		}},
		{"source-basis-extender-nil", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := f.evaluator.sourceCKKS.Evaluator.BasisExtender
			f.evaluator.sourceCKKS.Evaluator.BasisExtender = nil
			return f.evaluator, func() { f.evaluator.sourceCKKS.Evaluator.BasisExtender = before }
		}},
		{"source-decomposer-nil", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := f.evaluator.sourceCKKS.Evaluator.Decomposer
			f.evaluator.sourceCKKS.Evaluator.Decomposer = nil
			return f.evaluator, func() { f.evaluator.sourceCKKS.Evaluator.Decomposer = before }
		}},
		{"source-evaluation-keys-nil", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := f.evaluator.source.EvaluationKeys
			f.evaluator.source.EvaluationKeys = nil
			return f.evaluator, func() { f.evaluator.source.EvaluationKeys = before }
		}},
		{"ingress-evaluation-keys-nil", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := f.evaluator.ingressSource.EvaluationKeys
			f.evaluator.ingressSource.EvaluationKeys = nil
			return f.evaluator, func() { f.evaluator.ingressSource.EvaluationKeys = before }
		}},
		{"sign-source-encoder-nil", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := f.evaluator.signSource.Encoder
			f.evaluator.signSource.Encoder = nil
			return f.evaluator, func() { f.evaluator.signSource.Encoder = before }
		}},
		{"refresh-dft-nil", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := f.evaluator.ingress.suffix.refresh.bootstrap.DFTEvaluator
			f.evaluator.ingress.suffix.refresh.bootstrap.DFTEvaluator = nil
			return f.evaluator, func() { f.evaluator.ingress.suffix.refresh.bootstrap.DFTEvaluator = before }
		}},
		{"refresh-dft-linear-nil", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := f.evaluator.ingress.suffix.refresh.bootstrap.DFTEvaluator.LTEvaluator
			f.evaluator.ingress.suffix.refresh.bootstrap.DFTEvaluator.LTEvaluator = nil
			return f.evaluator, func() { f.evaluator.ingress.suffix.refresh.bootstrap.DFTEvaluator.LTEvaluator = before }
		}},
		{"refresh-mod1-polynomial-nil", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := f.evaluator.ingress.suffix.refresh.bootstrap.Mod1Evaluator.PolynomialEvaluator
			f.evaluator.ingress.suffix.refresh.bootstrap.Mod1Evaluator.PolynomialEvaluator = nil
			return f.evaluator, func() { f.evaluator.ingress.suffix.refresh.bootstrap.Mod1Evaluator.PolynomialEvaluator = before }
		}},
		{"kernel-polynomial-nil", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := f.evaluator.ingress.suffix.kernel0.polynomial
			f.evaluator.ingress.suffix.kernel0.polynomial = nil
			return f.evaluator, func() { f.evaluator.ingress.suffix.kernel0.polynomial = before }
		}},
		{"sign-source-rlwe-evaluator-nil", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := f.evaluator.signSource.Evaluator
			f.evaluator.signSource.Evaluator = nil
			return f.evaluator, func() { f.evaluator.signSource.Evaluator = before }
		}},
		{"source-ckks-foreign-internals", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := *f.evaluator.sourceCKKS
			*f.evaluator.sourceCKKS = *foreignNested.source.Evaluator
			return f.evaluator, func() { *f.evaluator.sourceCKKS = before }
		}},
		{"source-ckks-foreign-rlwe-evaluator", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := f.evaluator.sourceCKKS.Evaluator
			f.evaluator.sourceCKKS.Evaluator = foreignNested.source.Evaluator.Evaluator
			return f.evaluator, func() { f.evaluator.sourceCKKS.Evaluator = before }
		}},
		{"source-ckks-foreign-rlwe-buffers", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := f.evaluator.sourceCKKS.Evaluator.EvaluatorBuffers
			f.evaluator.sourceCKKS.Evaluator.EvaluatorBuffers = foreignNested.source.Evaluator.Evaluator.EvaluatorBuffers
			return f.evaluator, func() { f.evaluator.sourceCKKS.Evaluator.EvaluatorBuffers = before }
		}},
		{"source-ckks-foreign-basis-extender", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := f.evaluator.sourceCKKS.Evaluator.BasisExtender
			f.evaluator.sourceCKKS.Evaluator.BasisExtender = foreignNested.source.Evaluator.Evaluator.BasisExtender
			return f.evaluator, func() { f.evaluator.sourceCKKS.Evaluator.BasisExtender = before }
		}},
		{"source-ckks-foreign-decomposer", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			before := f.evaluator.sourceCKKS.Evaluator.Decomposer
			f.evaluator.sourceCKKS.Evaluator.Decomposer = foreignNested.source.Evaluator.Evaluator.Decomposer
			return f.evaluator, func() { f.evaluator.sourceCKKS.Evaluator.Decomposer = before }
		}},
		{"source-encoder-whole-value", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			target := f.evaluator.sourceCKKS.Encoder
			before := *target
			*target = *ckks.NewEncoder(f.base.params)
			return f.evaluator, func() { *target = before }
		}},
		{"source-basis-extender-whole-value", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			target := f.evaluator.sourceCKKS.Evaluator.BasisExtender
			before := *target
			*target = *sameKeyNested.source.Evaluator.Evaluator.BasisExtender
			return f.evaluator, func() { *target = before }
		}},
		{"source-rlwe-buffer-topology", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			buffers := f.evaluator.sourceCKKS.Evaluator.EvaluatorBuffers
			before := buffers.BuffBitDecomp
			buffers.BuffBitDecomp = append([]uint64(nil), before...)
			return f.evaluator, func() { buffers.BuffBitDecomp = before }
		}},
		{"source-rotation-index-value", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			indexes := f.evaluator.sourceCKKS.Evaluator.AutomorphismIndex(firstElement)
			before := indexes[0]
			indexes[0] ^= 1
			return f.evaluator, func() { indexes[0] = before }
		}},
		{"refresh-mod1-execution-ratio", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			parameters := &f.evaluator.ingress.suffix.refresh.bootstrap.Mod1Parameters
			before := parameters.LogMessageRatio
			parameters.LogMessageRatio++
			return f.evaluator, func() { parameters.LogMessageRatio = before }
		}},
		{"refresh-mod1-polynomial-coefficient-in-place", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			parameters := &f.evaluator.ingress.suffix.refresh.bootstrap.Mod1Parameters
			var coefficient *big.Float
			for _, candidate := range parameters.Mod1Poly.Coeffs {
				if candidate != nil && candidate[0] != nil {
					coefficient = candidate[0]
					break
				}
			}
			if coefficient == nil {
				panic("test fixture has no real Mod1 polynomial coefficient")
			}
			before := new(big.Float).Copy(coefficient)
			coefficient.Add(coefficient, new(big.Float).SetInt64(1))
			return f.evaluator, func() { coefficient.Copy(before) }
		}},
		{"refresh-residual-parameters", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			parameters := &f.evaluator.ingress.suffix.refresh.bootstrap.Parameters
			before := parameters.ResidualParameters
			parameters.ResidualParameters = ckks.Parameters{}
			return f.evaluator, func() { parameters.ResidualParameters = before }
		}},
		{"refresh-bootstrapping-parameters", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			parameters := &f.evaluator.ingress.suffix.refresh.bootstrap.Parameters
			before := parameters.BootstrappingParameters
			parameters.BootstrappingParameters = ckks.Parameters{}
			return f.evaluator, func() { parameters.BootstrappingParameters = before }
		}},
		{"refresh-mod1-literal", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			literal := &f.evaluator.ingress.suffix.refresh.bootstrap.Mod1ParametersLiteral
			before := literal.LogMessageRatio
			literal.LogMessageRatio++
			return f.evaluator, func() { literal.LogMessageRatio = before }
		}},
		{"refresh-stc-levels-in-place", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			levels := f.evaluator.ingress.suffix.refresh.bootstrap.SlotsToCoeffsParameters.Levels
			before := levels[0]
			levels[0]++
			return f.evaluator, func() { levels[0] = before }
		}},
		{"refresh-stc-scaling-in-place", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			scaling := f.evaluator.ingress.suffix.refresh.bootstrap.SlotsToCoeffsParameters.Scaling
			before := new(big.Float).Copy(scaling)
			scaling.SetInt64(3)
			return f.evaluator, func() { scaling.Copy(before) }
		}},
		{"refresh-stc-scaling-precision-in-place", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			scaling := f.evaluator.ingress.suffix.refresh.bootstrap.SlotsToCoeffsParameters.Scaling
			before := new(big.Float).Copy(scaling)
			scaling.SetPrec(scaling.Prec() + 1)
			return f.evaluator, func() { scaling.Copy(before) }
		}},
		{"refresh-cts-levels-in-place", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			levels := f.evaluator.ingress.suffix.refresh.bootstrap.CoeffsToSlotsParameters.Levels
			before := levels[0]
			levels[0]++
			return f.evaluator, func() { levels[0] = before }
		}},
		{"refresh-cts-scaling-in-place", func(f *signed8Depth2ChildIntegrationFixture, _ *Signed8Depth2ChildComparatorInput) (*Signed8Depth2ChildComparatorEvaluator, func()) {
			scaling := f.evaluator.ingress.suffix.refresh.bootstrap.CoeffsToSlotsParameters.Scaling
			before := new(big.Float).Copy(scaling)
			scaling.SetInt64(3)
			return f.evaluator, func() { scaling.Copy(before) }
		}},
	}

	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			input := fixture.input
			input.operands = cloneSigned8Depth2ChildOperands(input.operands)
			evaluator, restore := test.mutate(&fixture, &input)
			defer restore()
			before := signed8Depth2ChildMutationFingerprint(&fixture, input)
			var result Signed8Depth2ChildComparatorResult
			var trace Signed8Depth2ChildComparatorTrace
			var err error
			if evaluator == nil {
				var nilEvaluator *Signed8Depth2ChildComparatorEvaluator
				result, trace, err = nilEvaluator.EvaluateNew(input)
			} else {
				result, trace, err = evaluator.EvaluateNew(input)
			}
			requireSigned8Depth2ChildZeroOperationFailure(t, result, trace, err)
			after := signed8Depth2ChildMutationFingerprint(&fixture, input)
			if before != after {
				t.Fatalf("pre-HE failure mutated input/graph/cache/key state: before=%s after=%s", before, after)
			}
		})
	}

	t.Run("same-pointer-key-coefficient-payload-is-outside-identity-contract", func(t *testing.T) {
		key := fixture.base.source.MemEvaluationKeySet.GaloisKeys[firstElement]
		coefficient := &key.GadgetCiphertext.Value[0][0][0].Q.Coeffs[0][0]
		before := *coefficient
		*coefficient ^= 1
		defer func() { *coefficient = before }()
		if err := fixture.evaluator.preflight(); err != nil {
			t.Fatalf("identity-only key contract unexpectedly hashed same-pointer key coefficients: %v", err)
		}
	})
}

type signed8Depth2ChildForeignNested struct {
	source     *bootstrapping.Evaluator
	ingress    *A2BFullIngress6Evaluator
	signSource *ckks.Evaluator
	sign       *SignFusionEvaluator
}

func newSigned8Depth2ChildForeignNestedEvaluators(
	t *testing.T,
	fixture *signed8Depth2ChildIntegrationFixture,
) signed8Depth2ChildForeignNested {
	t.Helper()
	keyGenerator := ckks.NewKeyGenerator(fixture.base.params)
	secret := keyGenerator.GenSecretKeyNew()
	keyProfile := fixture.circuit.RequiredKeyProfile()
	keySet := rlwe.NewMemEvaluationKeySet(
		keyGenerator.GenRelinearizationKeyNew(secret),
		keyGenerator.GenGaloisKeysNew(keyProfile.All(), secret)...,
	)
	return newSigned8Depth2ChildNestedEvaluatorsWithKeySet(t, fixture, keySet)
}

func newSigned8Depth2ChildNestedEvaluatorsWithKeySet(
	t *testing.T,
	fixture *signed8Depth2ChildIntegrationFixture,
	keySet *rlwe.MemEvaluationKeySet,
) signed8Depth2ChildForeignNested {
	t.Helper()
	if keySet == nil {
		t.Fatal("nil depth2 child nested evaluator key set")
	}
	source, err := newSigned8Depth2ChildBootstrapSource(fixture.circuit, keySet)
	if err != nil {
		t.Fatal(err)
	}
	ingress, err := fixture.circuit.ingress.BindEvaluator(source)
	if err != nil {
		t.Fatal(err)
	}
	signSource := ckks.NewEvaluator(fixture.base.params, keySet)
	sign, err := fixture.circuit.sign.BindEvaluator(signSource)
	if err != nil {
		t.Fatal(err)
	}
	return signed8Depth2ChildForeignNested{source: source, ingress: ingress, signSource: signSource, sign: sign}
}

func TestSigned8Depth2ChildComparatorAllowsUnrelatedValidCallerGaloisKey(t *testing.T) {
	fixture := newSigned8Depth2ChildIntegrationFixture(t)
	required := make(map[uint64]bool)
	for _, element := range fixture.circuit.RequiredKeyProfile().All() {
		required[element] = true
	}
	var extra uint64
	for rotation := 1; rotation < fixture.base.params.MaxSlots(); rotation++ {
		candidate := fixture.base.params.GaloisElement(rotation)
		if !required[candidate] {
			extra = candidate
			break
		}
	}
	if extra == 0 {
		t.Fatal("no unrelated Galois element available")
	}
	fixture.base.source.MemEvaluationKeySet.GaloisKeys[extra] =
		fixture.base.keyGenerator.GenGaloisKeyNew(extra, fixture.base.secretKey)
	before := signed8Depth2ChildMutationFingerprint(&fixture, fixture.input)
	result, trace, err := fixture.evaluator.EvaluateNew(fixture.input)
	if err != nil {
		t.Fatalf("unrelated valid caller Galois key was rejected: %v", err)
	}
	if got, want := fixture.base.decryptWords(t, result.Ciphertext()), ([4]uint64{1, 0, 1, 1}); got != want {
		t.Fatalf("child GE with unrelated caller key=%v, want %v", got, want)
	}
	if !equalUint64Slices(trace.RuntimeGaloisElements(), fixture.circuit.RequiredKeyProfile().All()) {
		t.Fatalf("wrapper runtime key ledger included unrelated key: %v", trace.RuntimeGaloisElements())
	}
	after := signed8Depth2ChildMutationFingerprint(&fixture, fixture.input)
	if before != after {
		t.Fatalf("accepted evaluation mutated input/cache/key state: before=%s after=%s", before, after)
	}
}

func TestSigned8Depth2ChildComparatorEncryptedOpaqueRoot(t *testing.T) {
	ranges, err := NewSigned8NoOverflowRange(-8, 7, -8, 7)
	if err != nil {
		t.Fatal(err)
	}
	base := newSigned8ComparatorFixture(t, ranges)
	selector, err := NewSelectorReraiseDecodeCircuit(base.circuit)
	if err != nil {
		t.Fatal(err)
	}
	prefix, err := NewSigned8Depth2SourcePrefixCircuit(selector, signed8Depth2TestTree())
	if err != nil {
		t.Fatal(err)
	}
	selectorEvaluator, err := selector.BindEvaluator(base.source)
	if err != nil {
		t.Fatal(err)
	}
	prefixEvaluator, err := prefix.BindEvaluator(base.source)
	if err != nil {
		t.Fatal(err)
	}
	rootFeature, err := base.circuit.BindFeature(base.encryptSigned(t, [4]int64{-1, 1, -2, 2}), base.params)
	if err != nil {
		t.Fatal(err)
	}
	rootThreshold, err := base.circuit.BindOpaqueThreshold(base.encryptSigned(t, [4]int64{}), base.params)
	if err != nil {
		t.Fatal(err)
	}
	comparison, _, err := base.evaluator.CompareGEOpaqueNew(rootFeature, rootThreshold)
	if err != nil {
		t.Fatal(err)
	}
	selectorInput, err := selector.BindComparatorResult(comparison)
	if err != nil {
		t.Fatal(err)
	}
	selectorResult, _, err := selectorEvaluator.EvaluateNew(selectorInput)
	if err != nil {
		t.Fatal(err)
	}
	condition, err := prefix.BindSelectorResult(selectorResult)
	if err != nil {
		t.Fatal(err)
	}
	left, err := base.circuit.BindFeature(base.encryptSigned(t, [4]int64{-3, -2, -1, 0}), base.params)
	if err != nil {
		t.Fatal(err)
	}
	right, err := base.circuit.BindFeature(base.encryptSigned(t, [4]int64{1, 2, 3, 4}), base.params)
	if err != nil {
		t.Fatal(err)
	}
	operands, _, err := prefixEvaluator.EvaluateNew(condition, [2]Signed8FeatureInput{left, right})
	if err != nil {
		t.Fatal(err)
	}
	circuit, err := NewSigned8Depth2ChildComparatorCircuit(prefix)
	if err != nil {
		t.Fatal(err)
	}
	input, err := circuit.BindOperands(operands)
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := circuit.BindEvaluator(base.source)
	if err != nil {
		t.Fatal(err)
	}
	result, trace, err := evaluator.EvaluateNew(input)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := base.decryptWords(t, result.Ciphertext()), ([4]uint64{1, 0, 1, 1}); got != want {
		t.Fatalf("opaque-root child GE=%v, want %v", got, want)
	}
	if input.operands.producerProfileDigest != base.circuit.OpaqueProfile().Digest() ||
		trace.OperandsProvenanceDigest() != operands.ProvenanceDigest() {
		t.Fatal("opaque-root producer provenance was not preserved")
	}
}

func TestSigned8Depth2ChildComparatorEncryptedDifferenceEndpointsAndEquality(t *testing.T) {
	ranges, err := NewSigned8NoOverflowRange(-128, 127, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	base := newSigned8ComparatorFixture(t, ranges)
	selector, err := NewSelectorReraiseDecodeCircuit(base.circuit)
	if err != nil {
		t.Fatal(err)
	}
	tree := treeplan.BinaryTree[int8, float64]{
		Depth: 2,
		Splits: []treeplan.BinarySplit[int8]{
			{Feature: 0, Threshold: 0}, {Feature: 1, Threshold: 0}, {Feature: 2, Threshold: 0},
		},
		Leaves: []float64{-1, 0, 1, 2},
	}
	prefix, err := NewSigned8Depth2SourcePrefixCircuit(selector, tree)
	if err != nil {
		t.Fatal(err)
	}
	selectorEvaluator, err := selector.BindEvaluator(base.source)
	if err != nil {
		t.Fatal(err)
	}
	prefixEvaluator, err := prefix.BindEvaluator(base.source)
	if err != nil {
		t.Fatal(err)
	}
	root, err := base.circuit.BindFeature(base.encryptSigned(t, [4]int64{-1, 1, -1, 1}), base.params)
	if err != nil {
		t.Fatal(err)
	}
	comparison, _, err := base.evaluator.CompareGEPublicNew(root, [4]int64{})
	if err != nil {
		t.Fatal(err)
	}
	selectorInput, err := selector.BindComparatorResult(comparison)
	if err != nil {
		t.Fatal(err)
	}
	selectorResult, _, err := selectorEvaluator.EvaluateNew(selectorInput)
	if err != nil {
		t.Fatal(err)
	}
	condition, err := prefix.BindSelectorResult(selectorResult)
	if err != nil {
		t.Fatal(err)
	}
	left, err := base.circuit.BindFeature(base.encryptSigned(t, [4]int64{-128, 99, 0, 99}), base.params)
	if err != nil {
		t.Fatal(err)
	}
	right, err := base.circuit.BindFeature(base.encryptSigned(t, [4]int64{99, 127, 99, 1}), base.params)
	if err != nil {
		t.Fatal(err)
	}
	operands, _, err := prefixEvaluator.EvaluateNew(condition, [2]Signed8FeatureInput{left, right})
	if err != nil {
		t.Fatal(err)
	}
	circuit, err := NewSigned8Depth2ChildComparatorCircuit(prefix)
	if err != nil {
		t.Fatal(err)
	}
	input, err := circuit.BindOperands(operands)
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := circuit.BindEvaluator(base.source)
	if err != nil {
		t.Fatal(err)
	}
	result, _, err := evaluator.EvaluateNew(input)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := base.decryptWords(t, result.Ciphertext()), ([4]uint64{0, 1, 1, 1}); got != want {
		t.Fatalf("endpoint/equality child GE=%v, want %v", got, want)
	}
}

func requireSigned8Depth2ChildZeroOperationFailure(
	t *testing.T,
	result Signed8Depth2ChildComparatorResult,
	trace Signed8Depth2ChildComparatorTrace,
	err error,
) {
	t.Helper()
	ingress := trace.IngressTrace()
	sign := trace.SignProvenance()
	keyPreflight := trace.KeyPreflight()
	if err == nil || !reflect.DeepEqual(result, Signed8Depth2ChildComparatorResult{}) ||
		len(trace.States()) != 0 || trace.OperationCounts() != (Signed8Depth2ChildComparatorOperationCounts{}) ||
		trace.SerializedBytes() != (Signed8Depth2ChildComparatorSerializedBytes{}) ||
		len(trace.RuntimeGaloisElements()) != 0 || trace.RelinearizationKeyMatched() ||
		ingress.ProfileDigest() != "" || ingress.RangeDigest() != "" || ingress.AdmissionDigest() != "" ||
		ingress.InputBindingDigest() != "" || ingress.FailureStage() != "" || len(ingress.States()) != 0 ||
		ingress.OperationCounts() != (A2BFullIngress6OperationCounts{}) || len(ingress.RuntimeGaloisElements()) != 0 ||
		ingress.RelinearizationKeyMatched() || ingress.SerializedBytes().Complete() ||
		sign.ProfileDigest() != "" || sign.SourceDigest() != "" || sign.CompiledDigest() != "" ||
		len(sign.States()) != 0 || sign.OperationCounts() != (SignFusionOperationCounts{}) ||
		!reflect.DeepEqual(keyPreflight, A2BRefreshKeyPreflight{}) ||
		trace.Digest() != "" || trace.WallTime() != 0 || len(trace.retainedCiphertexts) != 0 {
		t.Fatalf("failure was not pre-HE zero-operation: result=%+v trace=%+v err=%v", result, trace, err)
	}
}

func signed8Depth2ChildMutationFingerprint(
	fixture *signed8Depth2ChildIntegrationFixture,
	input Signed8Depth2ChildComparatorInput,
) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "input=%s/%s/%s/%s/%s", a2bFullIngress6TestCiphertextFingerprint(input.operands.feature),
		a2bFullIngress6TestCiphertextFingerprint(input.operands.threshold),
		a2bFullIngress6TestCiphertextFingerprint(input.operands.conditionedSelector),
		input.operands.provenanceDigest, input.bindingDigest)
	if fixture == nil || fixture.circuit == nil || fixture.evaluator == nil {
		return digestString(builder.String())
	}
	circuit, evaluator := fixture.circuit, fixture.evaluator
	first, firstGroup, firstErr := digestA2BFullIngress6EncodedFactorGroup("first", circuit.ingress.firstSTC.Matrices)
	shared, sharedGroup, sharedErr := digestA2BFullIngress6EncodedFactorGroup("shared", circuit.ingress.suffix.refresh.cts.Matrices)
	second, secondGroup, secondErr := digestA2BFullIngress6EncodedFactorGroup("second", circuit.ingress.suffix.secondSTC.Matrices)
	sign, signGroup, signErr := digestA2BFullIngress6EncodedFactorGroup("sign", []ckkslintrans.LinearTransformation{circuit.sign.transform})
	fmt.Fprintf(&builder, "|circuit=%p|profile=%+v|graph=%+v|prefix=%+v|ingress=%+v|sign=%+v|one=%s|one-seal=%s|payloads=%v/%s/%v;%v/%s/%v;%v/%s/%v;%v/%s/%v",
		circuit, circuit.profile, circuit.graph, circuit.prefix.profile, circuit.ingress.profile,
		circuit.sign.profile, a2bFullIngress6TestPlaintextFingerprint(circuit.arithmeticOne),
		a2bFullIngress6TestPlaintextFingerprint(circuit.arithmeticOneSeal),
		first, firstGroup, firstErr, shared, sharedGroup, sharedErr, second, secondGroup, secondErr,
		sign, signGroup, signErr)
	fmt.Fprintf(&builder, "|evaluator=%p|graph=%+v|source=%p|source-keys=%s|filtered-keys=%s",
		evaluator, evaluator.graph, evaluator.source, signed8Depth2ChildKeyFingerprint(evaluator.sourceKeySet),
		signed8Depth2ChildKeyFingerprint(evaluator.ingressKeySet))
	return digestString(builder.String())
}

func signed8Depth2ChildKeyFingerprint(keySet *rlwe.MemEvaluationKeySet) string {
	if keySet == nil {
		return "nil"
	}
	var builder strings.Builder
	fmt.Fprintf(&builder, "set=%p|relin=%p", keySet, keySet.RelinearizationKey)
	if keySet.RelinearizationKey != nil {
		fmt.Fprintf(&builder, "/%s", signed8Depth2ChildKeyPayloadFingerprint(keySet.RelinearizationKey))
	}
	elements := append([]uint64(nil), keySet.GetGaloisKeysList()...)
	sort.Slice(elements, func(i, j int) bool { return elements[i] < elements[j] })
	for _, element := range elements {
		key := keySet.GaloisKeys[element]
		fmt.Fprintf(&builder, "|%d=%p", element, key)
		if key != nil {
			fmt.Fprintf(&builder, "/%s", signed8Depth2ChildKeyPayloadFingerprint(key))
		}
	}
	return digestString(builder.String())
}

func signed8Depth2ChildKeyPayloadFingerprint(value interface {
	MarshalBinary() ([]byte, error)
}) (fingerprint string) {
	defer func() {
		if recovered := recover(); recovered != nil {
			fingerprint = fmt.Sprintf("panic:%v", recovered)
		}
	}()
	payload, err := value.MarshalBinary()
	if err != nil {
		return "error:" + err.Error()
	}
	return sha256Hex(payload)
}
