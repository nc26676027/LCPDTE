package homchain

import (
	"math"
	"math/big"
	"reflect"
	"testing"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

func TestSelectorReraiseDecodeEncryptedPeriodicPublicSmoke(t *testing.T) {
	selectorTestEncryptedPeriodicSmoke(t, Signed8PublicThresholdCTPT)
}

func TestSelectorReraiseDecodeEncryptedPeriodicOpaqueSmoke(t *testing.T) {
	selectorTestEncryptedPeriodicSmoke(t, Signed8OpaqueThresholdCTCT)
}

func TestSelectorReraiseDecodeEncryptedAll16PatternsPublicAndOpaque(t *testing.T) {
	ranges, err := NewSigned8NoOverflowRange(-8, 7, -8, 7)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newSigned8ComparatorFixture(t, ranges)
	circuit, err := NewSelectorReraiseDecodeCircuit(fixture.circuit)
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := circuit.BindEvaluator(fixture.source)
	if err != nil {
		t.Fatal(err)
	}
	threshold, err := fixture.circuit.BindOpaqueThreshold(fixture.encryptSigned(t, [4]int64{}), fixture.params)
	if err != nil {
		t.Fatal(err)
	}
	for pattern := 0; pattern < 1<<selectorReraiseDecodeWords; pattern++ {
		var features [selectorReraiseDecodeWords]int64
		var want [selectorReraiseDecodeWords]float64
		for word := range features {
			if (pattern>>word)&1 == 1 {
				features[word], want[word] = 1, 1
			} else {
				features[word] = -1
			}
		}
		feature, bindErr := fixture.circuit.BindFeature(fixture.encryptSigned(t, features), fixture.params)
		if bindErr != nil {
			t.Fatalf("pattern=%04b: %v", pattern, bindErr)
		}
		featureDigest, digestErr := signed8CiphertextDigest(feature.ciphertext)
		if digestErr != nil {
			t.Fatal(digestErr)
		}
		publicComparison, _, compareErr := fixture.evaluator.CompareGEPublicNew(feature, [4]int64{})
		if compareErr != nil {
			t.Fatalf("pattern=%04b public comparator: %v", pattern, compareErr)
		}
		opaqueComparison, _, compareErr := fixture.evaluator.CompareGEOpaqueNew(feature, threshold)
		if compareErr != nil {
			t.Fatalf("pattern=%04b opaque comparator: %v", pattern, compareErr)
		}
		if afterDigest, digestErr := signed8CiphertextDigest(feature.ciphertext); digestErr != nil || afterDigest != featureDigest {
			t.Fatalf("pattern=%04b comparator mutated the shared feature handle", pattern)
		}
		var decodedByMode [2][]complex128
		for modeIndex, item := range []struct {
			mode       Signed8ComparatorOperandMode
			comparison Signed8ComparatorResult
		}{
			{Signed8PublicThresholdCTPT, publicComparison},
			{Signed8OpaqueThresholdCTCT, opaqueComparison},
		} {
			input, bindErr := circuit.BindComparatorResult(item.comparison)
			if bindErr != nil {
				t.Fatalf("pattern=%04b mode=%s bind: %v", pattern, item.mode, bindErr)
			}
			if input.branch == item.comparison.branch || !input.branch.Equal(item.comparison.branch) {
				t.Fatalf("pattern=%04b mode=%s selector input is not an owned comparator-result copy", pattern, item.mode)
			}
			inputBefore := input.branch.CopyNew()
			result, trace, evalErr := evaluator.EvaluateNew(input)
			if evalErr != nil {
				t.Fatalf("pattern=%04b mode=%s evaluate: %v", pattern, item.mode, evalErr)
			}
			if !input.branch.Equal(inputBefore) {
				t.Fatalf("pattern=%04b mode=%s selector evaluation mutated its owned input", pattern, item.mode)
			}
			decodedByMode[modeIndex] = selectorTestAssertPeriodicDecoded(t, fixture, circuit, input, result, trace, item.mode, want)
		}
		for slot := range decodedByMode[0] {
			if cmplxDistanceA2BKernel(decodedByMode[0][slot], decodedByMode[1][slot]) > 3e-3 {
				t.Fatalf("pattern=%04b slot=%d public/opaque outputs diverged: %v vs %v", pattern, slot,
					decodedByMode[0][slot], decodedByMode[1][slot])
			}
		}
	}
}

func TestSelectorReraiseDecodeFailClosedBeforeAnySelectorOperation(t *testing.T) {
	ranges, err := NewSigned8NoOverflowRange(-8, 7, -8, 7)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newSigned8ComparatorFixture(t, ranges)
	circuit, err := NewSelectorReraiseDecodeCircuit(fixture.circuit)
	if err != nil {
		t.Fatal(err)
	}
	feature, err := fixture.circuit.BindFeature(fixture.encryptSigned(t, [4]int64{-1, 1, -1, 1}), fixture.params)
	if err != nil {
		t.Fatal(err)
	}
	comparison, _, err := fixture.evaluator.CompareGEPublicNew(feature, [4]int64{})
	if err != nil {
		t.Fatal(err)
	}
	valid, err := circuit.BindComparatorResult(comparison)
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := circuit.BindEvaluator(fixture.source)
	if err != nil {
		t.Fatal(err)
	}

	assertZeroOperationReject := func(t *testing.T, candidate *SelectorReraiseDecodeEvaluator, input SelectorReraiseDecodeInput) {
		t.Helper()
		result, trace, evalErr := candidate.EvaluateNew(input)
		if evalErr == nil || !reflect.DeepEqual(result, SelectorReraiseDecodeResult{}) ||
			!reflect.DeepEqual(trace, SelectorReraiseDecodeTrace{}) {
			t.Fatalf("invalid selector graph/input did not fail before operations: err=%v result=%+v trace=%+v", evalErr, result, trace)
		}
	}
	assertNilBoundEvaluatorReject := func(t *testing.T, candidate *SelectorReraiseDecodeEvaluator) {
		t.Helper()
		inputBefore := valid
		inputBefore.branch = valid.branch.CopyNew()

		var candidateBefore *SelectorReraiseDecodeEvaluator
		var graphBefore selectorReraiseDecodeEvaluatorGraphIdentity
		var cacheBefore map[uint64]*rlwe.GaloisKey
		if candidate != nil {
			copyBefore := *candidate
			candidateBefore = &copyBefore
			graphBefore = candidate.graph
			graphBefore.galoisElements = append([]uint64(nil), candidate.graph.galoisElements...)
			graphBefore.galoisKeyIdentities = append([]*rlwe.GaloisKey(nil), candidate.graph.galoisKeyIdentities...)
			cacheBefore = make(map[uint64]*rlwe.GaloisKey, len(candidate.galoisKeys))
			for element, key := range candidate.galoisKeys {
				cacheBefore[element] = key
			}
		}

		result, trace, evalErr := candidate.EvaluateNew(valid)
		const wantError = "homchain: nil bound selector evaluator"
		if evalErr == nil || evalErr.Error() != wantError || result.Ciphertext() != nil ||
			!reflect.DeepEqual(result, SelectorReraiseDecodeResult{}) ||
			!reflect.DeepEqual(trace, SelectorReraiseDecodeTrace{}) {
			t.Fatalf("nil bound evaluator rejection changed: err=%v result=%+v trace=%+v", evalErr, result, trace)
		}
		if valid.branch == nil || !valid.branch.Equal(inputBefore.branch) ||
			valid.pathProfileDigest != inputBefore.pathProfileDigest ||
			valid.producerProfileDigest != inputBefore.producerProfileDigest ||
			valid.rangeDigest != inputBefore.rangeDigest || valid.operandMode != inputBefore.operandMode ||
			valid.payloadDigest != inputBefore.payloadDigest || valid.provenanceDigest != inputBefore.provenanceDigest {
			t.Fatal("nil bound evaluator rejection mutated the authenticated selector input")
		}
		if candidate != nil {
			if candidate.circuit != candidateBefore.circuit || candidate.source != candidateBefore.source ||
				candidate.linear != candidateBefore.linear || candidate.producer != candidateBefore.producer ||
				candidate.kernel != candidateBefore.kernel || candidate.keySet != candidateBefore.keySet ||
				candidate.relinearizationKey != candidateBefore.relinearizationKey ||
				!reflect.DeepEqual(candidate.sourceGraph, candidateBefore.sourceGraph) ||
				!reflect.DeepEqual(candidate.graph, graphBefore) || len(candidate.galoisKeys) != len(cacheBefore) {
				t.Fatal("nil bound evaluator rejection mutated evaluator internal state")
			}
			for element, key := range cacheBefore {
				if candidate.galoisKeys[element] != key {
					t.Fatalf("nil bound evaluator rejection mutated cached Galois key %d", element)
				}
			}
		}
	}

	t.Run("evaluator/nil receiver", func(t *testing.T) {
		var nilEvaluator *SelectorReraiseDecodeEvaluator
		assertNilBoundEvaluatorReject(t, nilEvaluator)
	})

	t.Run("evaluator/nil circuit", func(t *testing.T) {
		changed := *evaluator
		changed.circuit = nil
		assertNilBoundEvaluatorReject(t, &changed)
	})

	inputCases := []struct {
		name   string
		mutate func(*SelectorReraiseDecodeInput)
	}{
		{"nil branch", func(input *SelectorReraiseDecodeInput) { input.branch = nil }},
		{"foreign selector profile", func(input *SelectorReraiseDecodeInput) { input.pathProfileDigest = "foreign" }},
		{"foreign producer profile", func(input *SelectorReraiseDecodeInput) { input.producerProfileDigest = "foreign" }},
		{"foreign range", func(input *SelectorReraiseDecodeInput) { input.rangeDigest = "foreign" }},
		{"foreign mode", func(input *SelectorReraiseDecodeInput) { input.operandMode = Signed8OpaqueThresholdCTCT }},
		{"foreign payload pin", func(input *SelectorReraiseDecodeInput) { input.payloadDigest = "foreign" }},
		{"foreign provenance", func(input *SelectorReraiseDecodeInput) { input.provenanceDigest = "foreign" }},
		{"nil metadata", func(input *SelectorReraiseDecodeInput) { input.branch.MetaData = nil }},
		{"coefficient payload tamper", func(input *SelectorReraiseDecodeInput) { input.branch.Value[0].Coeffs[0][0] ^= 1 }},
	}
	for _, test := range inputCases {
		t.Run("input/"+test.name, func(t *testing.T) {
			changed := valid
			changed.branch = valid.branch.CopyNew()
			test.mutate(&changed)
			assertZeroOperationReject(t, evaluator, changed)
		})
	}

	evaluatorCases := []struct {
		name   string
		mutate func(*SelectorReraiseDecodeEvaluator)
	}{
		{"nil source", func(e *SelectorReraiseDecodeEvaluator) { e.source = nil }},
		{"nil linear evaluator", func(e *SelectorReraiseDecodeEvaluator) { e.linear = nil }},
		{"nil comparator producer", func(e *SelectorReraiseDecodeEvaluator) { e.producer = nil }},
		{"nil periodic kernel", func(e *SelectorReraiseDecodeEvaluator) { e.kernel = nil }},
		{"nil keyset", func(e *SelectorReraiseDecodeEvaluator) { e.keySet = nil }},
		{"nil relinearization identity", func(e *SelectorReraiseDecodeEvaluator) { e.relinearizationKey = nil }},
		{"nil Galois identity map", func(e *SelectorReraiseDecodeEvaluator) { e.galoisKeys = nil }},
		{"foreign evaluator profile", func(e *SelectorReraiseDecodeEvaluator) { e.graph.profileDigest = "foreign" }},
		{"foreign Galois map pointer", func(e *SelectorReraiseDecodeEvaluator) { e.graph.galoisKeyMapPointer = 0 }},
		{"foreign source graph", func(e *SelectorReraiseDecodeEvaluator) { e.sourceGraph = a2aiEvaluatorGraphIdentity{} }},
		{"foreign periodic child", func(e *SelectorReraiseDecodeEvaluator) {
			child := *e.kernel
			e.kernel = &child
		}},
		{"foreign sealed Galois inventory", func(e *SelectorReraiseDecodeEvaluator) {
			e.graph.galoisElements = append([]uint64(nil), e.graph.galoisElements...)
			e.graph.galoisElements[0] = 7
		}},
		{"foreign sealed Galois identity", func(e *SelectorReraiseDecodeEvaluator) {
			e.graph.galoisKeyIdentities = append([]*rlwe.GaloisKey(nil), e.graph.galoisKeyIdentities...)
			e.graph.galoisKeyIdentities[0] = e.graph.galoisKeyIdentities[1]
		}},
	}
	for _, test := range evaluatorCases {
		t.Run("evaluator/"+test.name, func(t *testing.T) {
			changed := *evaluator
			changed.graph.evaluator = &changed
			test.mutate(&changed)
			assertZeroOperationReject(t, &changed, valid)
		})
	}

	t.Run("evaluator/same map deletion with intact source keyset", func(t *testing.T) {
		const element = uint64(5)
		cached := evaluator.galoisKeys[element]
		fromSource, keyErr := evaluator.keySet.GetGaloisKey(element)
		if keyErr != nil || cached == nil || fromSource != cached {
			t.Fatal("test requires the sealed cache key to remain present in the source keyset")
		}
		delete(evaluator.galoisKeys, element)
		defer func() { evaluator.galoisKeys[element] = cached }()
		if stillPresent, keyErr := evaluator.keySet.GetGaloisKey(element); keyErr != nil || stillPresent != cached {
			t.Fatal("deleting the evaluator cache entry unexpectedly changed the source keyset")
		}
		assertZeroOperationReject(t, evaluator, valid)
	})

	t.Run("evaluator/same map substitution", func(t *testing.T) {
		const element = uint64(5)
		cached := evaluator.galoisKeys[element]
		substituted := *cached
		evaluator.galoisKeys[element] = &substituted
		defer func() { evaluator.galoisKeys[element] = cached }()
		assertZeroOperationReject(t, evaluator, valid)
	})

	t.Run("evaluator/same map extra entry", func(t *testing.T) {
		const foreignElement = uint64(7)
		if _, exists := evaluator.galoisKeys[foreignElement]; exists {
			t.Fatal("test foreign Galois element unexpectedly belongs to the sealed inventory")
		}
		evaluator.galoisKeys[foreignElement] = evaluator.galoisKeys[5]
		defer delete(evaluator.galoisKeys, foreignElement)
		assertZeroOperationReject(t, evaluator, valid)
	})
}

func TestSelectorReraiseDecodeBridgesToRealScalarLeafSelection(t *testing.T) {
	ranges, err := NewSigned8NoOverflowRange(-8, 7, -8, 7)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newSigned8ComparatorFixture(t, ranges)
	circuit, err := NewSelectorReraiseDecodeCircuit(fixture.circuit)
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := circuit.BindEvaluator(fixture.source)
	if err != nil {
		t.Fatal(err)
	}
	feature, err := fixture.circuit.BindFeature(fixture.encryptSigned(t, [4]int64{-1, 1, -1, 1}), fixture.params)
	if err != nil {
		t.Fatal(err)
	}
	comparison, _, err := fixture.evaluator.CompareGEPublicNew(feature, [4]int64{})
	if err != nil {
		t.Fatal(err)
	}
	input, err := circuit.BindComparatorResult(comparison)
	if err != nil {
		t.Fatal(err)
	}
	selector, _, err := evaluator.EvaluateNew(input)
	if err != nil {
		t.Fatal(err)
	}
	selectorCiphertext := selector.Ciphertext()
	selectorBefore := selectorCiphertext.CopyNew()
	left := [4]int64{-3, 2, 1, -4}
	right := [4]int64{5, -1, 3, 4}
	deltaValues := make([]*bignum.Complex, fixture.params.MaxSlots())
	leftValues := make([]*bignum.Complex, fixture.params.MaxSlots())
	for word := 0; word < selectorReraiseDecodeWords; word++ {
		for slot := 0; slot < selectorReraiseDecodeHalfWidth; slot++ {
			index := word*selectorReraiseDecodeHalfWidth + slot
			deltaValues[index] = &bignum.Complex{
				new(big.Float).SetPrec(256).SetInt64(right[word] - left[word]), new(big.Float).SetPrec(256),
			}
			leftValues[index] = &bignum.Complex{
				new(big.Float).SetPrec(256).SetInt64(left[word]), new(big.Float).SetPrec(256),
			}
		}
	}
	delta, err := newSelectorPeriodicPlaintext(
		fixture.params, fixture.integerEncoder, deltaValues, selectorCiphertext.Level(),
		rlwe.NewScale(fixture.params.Q()[selectorCiphertext.Level()]),
	)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := evaluator.kernel.ckks.MulNew(selectorCiphertext, delta)
	if err != nil {
		t.Fatal(err)
	}
	if err = evaluator.kernel.ckks.Rescale(selected, selected); err != nil {
		t.Fatal(err)
	}
	leftPlaintext, err := newSelectorPeriodicPlaintext(
		fixture.params, fixture.integerEncoder, leftValues, selected.Level(), selectorCiphertext.Scale,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err = evaluator.kernel.ckks.Add(selected, leftPlaintext, selected); err != nil {
		t.Fatal(err)
	}
	if !selectorCiphertext.Equal(selectorBefore) || selected.Level() != circuit.Profile().Periodic().OutputLevel()-1 ||
		!selected.Scale.Equal(selectorCiphertext.Scale) {
		t.Fatalf("scalar leaf bridge mutated selector or changed source schedule: selector=L%d selected=L%d", selectorCiphertext.Level(), selected.Level())
	}
	decoded := make([]complex128, selected.Slots())
	if err = fixture.integerEncoder.Decode(fixture.decryptor.DecryptNew(selected), decoded); err != nil {
		t.Fatal(err)
	}
	want := [4]int64{left[0], right[1], left[2], right[3]}
	for word := range want {
		for slot := 0; slot < selectorReraiseDecodeHalfWidth; slot++ {
			value := decoded[word*selectorReraiseDecodeHalfWidth+slot]
			if math.Abs(real(value)-float64(want[word])) > 3e-2 || math.Abs(imag(value)) > 3e-2 {
				t.Fatalf("leaf bridge word=%d slot=%d got=%v want=%d", word, slot, value, want[word])
			}
		}
	}
}

func selectorTestEncryptedPeriodicSmoke(t *testing.T, mode Signed8ComparatorOperandMode) {
	t.Helper()
	ranges, err := NewSigned8NoOverflowRange(-8, 7, -8, 7)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newSigned8ComparatorFixture(t, ranges)
	circuit, err := NewSelectorReraiseDecodeCircuit(fixture.circuit)
	if err != nil {
		t.Fatal(err)
	}
	features := [4]int64{-8, -1, 0, 7}
	feature, err := fixture.circuit.BindFeature(fixture.encryptSigned(t, features), fixture.params)
	if err != nil {
		t.Fatal(err)
	}
	var comparison Signed8ComparatorResult
	switch mode {
	case Signed8PublicThresholdCTPT:
		comparison, _, err = fixture.evaluator.CompareGEPublicNew(feature, [4]int64{})
	case Signed8OpaqueThresholdCTCT:
		threshold, bindErr := fixture.circuit.BindOpaqueThreshold(fixture.encryptSigned(t, [4]int64{}), fixture.params)
		if bindErr != nil {
			t.Fatal(bindErr)
		}
		comparison, _, err = fixture.evaluator.CompareGEOpaqueNew(feature, threshold)
	default:
		t.Fatalf("unsupported smoke mode %q", mode)
	}
	if err != nil {
		t.Fatal(err)
	}
	comparisonBefore := comparison.Ciphertext()
	input, err := circuit.BindComparatorResult(comparison)
	if err != nil {
		t.Fatal(err)
	}
	if input.branch == comparison.branch || !input.branch.Equal(comparison.branch) {
		t.Fatal("selector input is not an owned comparator-result copy")
	}
	inputBefore := input.branch.CopyNew()
	evaluator, err := circuit.BindEvaluator(fixture.source)
	if err != nil {
		t.Fatal(err)
	}
	result, trace, err := evaluator.EvaluateNew(input)
	if err != nil {
		t.Fatal(err)
	}
	if !comparison.Ciphertext().Equal(comparisonBefore) {
		t.Fatal("periodic selector mutated the accepted comparator result")
	}
	if !input.branch.Equal(inputBefore) {
		t.Fatal("periodic selector mutated its owned comparator-result input")
	}
	want := [4]float64{0, 0, 1, 1}
	selectorTestAssertPeriodicDecoded(t, fixture, circuit, input, result, trace, mode, want)
	tamperedLedger := trace
	tamperedLedger.serializedBytes.OnlineOutput++
	if validateSelectorReraiseDecodeRuntimeEvidence(circuit.profile, input, tamperedLedger, result.scalar) == nil {
		t.Fatal("tampered selector serialized-byte ledger was accepted")
	}
	aliasedEvidence := trace
	aliasedEvidence.normalVLow = aliasedEvidence.normalVHigh
	if validateSelectorReraiseDecodeRuntimeEvidence(circuit.profile, input, aliasedEvidence, result.scalar) == nil {
		t.Fatal("aliased retained selector evidence was double counted")
	}
	tamperedOutputSeal := trace
	tamperedOutputSeal.outputPayloadDigest = "foreign"
	if validateSelectorReraiseDecodeRuntimeEvidence(circuit.profile, input, tamperedOutputSeal, result.scalar) == nil {
		t.Fatal("tampered selector runtime output payload seal was accepted")
	}
	tamperedResultSeal := trace
	tamperedResultSeal.resultProvenanceDigest = "foreign"
	if validateSelectorReraiseDecodeRuntimeEvidence(circuit.profile, input, tamperedResultSeal, result.scalar) == nil {
		t.Fatal("tampered selector runtime result provenance seal was accepted")
	}
}

func selectorTestAssertPeriodicDecoded(
	t *testing.T,
	fixture signed8ComparatorFixture,
	circuit *SelectorReraiseDecodeCircuit,
	input SelectorReraiseDecodeInput,
	result SelectorReraiseDecodeResult,
	trace SelectorReraiseDecodeTrace,
	mode Signed8ComparatorOperandMode,
	want [selectorReraiseDecodeWords]float64,
) []complex128 {
	t.Helper()
	profile := circuit.Profile()
	periodic := profile.Periodic()
	if result.Path() != SelectorReraiseDecodePeriodicPath || trace.Path() != SelectorReraiseDecodePeriodicPath ||
		result.OperandMode() != mode || trace.OperandMode() != mode ||
		result.ProfileDigest() != profile.Digest() || trace.ProfileDigest() != profile.Digest() ||
		profile.ResultSchema() != selectorReraiseDecodeResultSchema ||
		trace.OperationCounts() != profile.OperationCounts() ||
		trace.LogicalPeakLiveCiphertexts() != profile.LogicalPeakLiveCiphertexts() {
		t.Fatalf("periodic selector provenance or runtime ledger changed: result=%+v trace=%+v", result, trace)
	}
	outputPayloadDigest, err := signed8CiphertextDigest(result.Ciphertext())
	if err != nil {
		t.Fatal(err)
	}
	if result.OutputPayloadDigest() != outputPayloadDigest || trace.OutputPayloadDigest() != outputPayloadDigest ||
		result.ProvenanceDigest() == "" || result.ProvenanceDigest() != trace.ResultProvenanceDigest() ||
		circuit.validateResult(result) != nil {
		t.Fatalf("selector result/trace output seal changed: result=%+v trace=%+v", result, trace)
	}
	serialized := trace.SerializedBytes()
	wantSerialized := selectorTestMarshalReraiseDecodeBoundaries(t, input, result, trace)
	if serialized != profile.ExpectedSerializedBytes() || serialized != wantSerialized || !serialized.complete() {
		t.Fatalf("selector serialization evidence=%+v, profile=%+v, independently marshaled=%+v",
			serialized, profile.ExpectedSerializedBytes(), wantSerialized)
	}
	serialized.OnlineInput = 0
	if trace.SerializedBytes().OnlineInput == 0 {
		t.Fatal("selector serialized-byte accessor aliases sealed runtime evidence")
	}
	output := result.Ciphertext()
	outputCopy := result.Ciphertext()
	if output == outputCopy || !output.Equal(outputCopy) {
		t.Fatal("selector result accessor does not return an independent ciphertext copy")
	}
	output.Value[0].Coeffs[0][0] ^= 1
	if result.Ciphertext().Equal(output) {
		t.Fatal("selector result accessor aliases sealed output state")
	}
	output = outputCopy
	if output.Level() != periodic.OutputLevel() || !periodic.OutputScale().EqualScale(output.Scale) {
		t.Fatalf("periodic output state=L%d/%s, want L%d/%s", output.Level(), output.Scale.Value.Text('x', -1),
			periodic.OutputLevel(), periodic.OutputScale().ValueHex())
	}
	if trace.ExponentialBase() == nil || trace.ExponentialBase().Level() != periodic.ExponentialLevel() ||
		trace.PeriodicRootOfUnity() == nil || trace.PeriodicRootOfUnity().Level() != periodic.RootLevel() {
		t.Fatal("periodic exponential checkpoints are missing or have the wrong levels")
	}
	states, profileStates := trace.States(), profile.States()
	if len(states) != len(profileStates) {
		t.Fatalf("runtime states=%d, profile states=%d", len(states), len(profileStates))
	}
	for index := range states {
		if states[index].Level != profileStates[index].Level() || !states[index].Scale.Equal(profileStates[index].Scale()) {
			t.Fatalf("runtime state %d differs from source-scheduled profile: %+v", index, states[index])
		}
	}
	states[0].Level = -1
	if trace.States()[0].Level == -1 {
		t.Fatal("selector trace state accessor aliases sealed runtime evidence")
	}
	decoded := make([]complex128, output.Slots())
	if err := fixture.integerEncoder.Decode(fixture.decryptor.DecryptNew(output), decoded); err != nil {
		t.Fatal(err)
	}
	for word := range want {
		for slot := 0; slot < selectorReraiseDecodeHalfWidth; slot++ {
			value := decoded[word*selectorReraiseDecodeHalfWidth+slot]
			if math.Abs(real(value)-want[word]) > 2e-3 || math.Abs(imag(value)) > 2e-3 {
				t.Fatalf("mode=%s word=%d slot=%d scalar=%v, want %.0f", mode, word, slot, value, want[word])
			}
		}
	}
	return decoded
}

func selectorTestMarshalReraiseDecodeBoundaries(
	t *testing.T,
	input SelectorReraiseDecodeInput,
	result SelectorReraiseDecodeResult,
	trace SelectorReraiseDecodeTrace,
) SelectorReraiseDecodeSerializedBytes {
	t.Helper()
	boundaries := []struct {
		name       string
		ciphertext *rlwe.Ciphertext
	}{
		{"online input", input.branch},
		{"online output", result.Ciphertext()},
		{"retained normal-V low", trace.NormalVLow()},
		{"retained normal-V high", trace.NormalVHigh()},
		{"retained SlotsToCoeffs", trace.SlotsToCoeffs()},
		{"retained raised coefficients", trace.RaisedCoefficients()},
		{"retained CoeffsToSlots low", trace.CoeffsToSlotsLow()},
		{"retained CoeffsToSlots high", trace.CoeffsToSlotsHigh()},
		{"retained exponential base", trace.ExponentialBase()},
		{"retained periodic root", trace.PeriodicRootOfUnity()},
	}
	sizes := make([]int, len(boundaries))
	for index, boundary := range boundaries {
		if boundary.ciphertext == nil {
			t.Fatalf("nil selector %s serialization boundary", boundary.name)
		}
		payload, err := boundary.ciphertext.MarshalBinary()
		if err != nil {
			t.Fatalf("marshal selector %s: %v", boundary.name, err)
		}
		sizes[index] = len(payload)
	}
	return SelectorReraiseDecodeSerializedBytes{
		OnlineInput: sizes[0], OnlineOutput: sizes[1],
		RetainedNormalVLow: sizes[2], RetainedNormalVHigh: sizes[3],
		RetainedSlotsToCoeffs: sizes[4], RetainedRaisedCoefficients: sizes[5],
		RetainedCoeffsToSlotsLow: sizes[6], RetainedCoeffsToSlotsHigh: sizes[7],
		RetainedExponentialBase: sizes[8], RetainedPeriodicRootOfUnity: sizes[9],
	}
}
