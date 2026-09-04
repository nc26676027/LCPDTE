package homchain

import (
	"math"
	"reflect"
	"testing"

	"github.com/nc26676027/LCPDTE/integer/z2n"

	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
)

func TestSigned8Depth2SourcePrefixEncryptedFourQueries(t *testing.T) {
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

	rootFeature, err := fixture.circuit.BindFeature(fixture.encryptSigned(t, [4]int64{-1, 1, -2, 2}), fixture.params)
	if err != nil {
		t.Fatal(err)
	}
	comparison, _, err := fixture.evaluator.CompareGEPublicNew(rootFeature, [4]int64{})
	if err != nil {
		t.Fatal(err)
	}
	selectorInput, err := selectorCircuit.BindComparatorResult(comparison)
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
	t.Run("selector result payload seal rejects pre-bind replacement", func(t *testing.T) {
		resultBefore := selectorResult.scalar.CopyNew()
		for _, test := range []struct {
			name   string
			mutate func(*SelectorReraiseDecodeResult)
		}{
			{"nil ciphertext", func(value *SelectorReraiseDecodeResult) { value.scalar = nil }},
			{"coefficient tamper", func(value *SelectorReraiseDecodeResult) {
				value.scalar = value.scalar.CopyNew()
				value.scalar.Value[0].Coeffs[0][0] ^= 1
			}},
			{"same-state foreign ciphertext", func(value *SelectorReraiseDecodeResult) {
				foreign := ckks.NewCiphertext(fixture.params, value.scalar.Degree(), value.scalar.Level())
				foreign.MetaData = value.scalar.MetaData.CopyNew()
				value.scalar = foreign
			}},
			{"output payload pin", func(value *SelectorReraiseDecodeResult) { value.outputPayloadDigest = "foreign" }},
			{"result provenance", func(value *SelectorReraiseDecodeResult) { value.provenanceDigest = "foreign" }},
			{"selector profile", func(value *SelectorReraiseDecodeResult) { value.profileDigest = "foreign" }},
			{"producer profile", func(value *SelectorReraiseDecodeResult) { value.producerProfileDigest = "foreign" }},
			{"range", func(value *SelectorReraiseDecodeResult) { value.rangeDigest = "foreign" }},
			{"mode", func(value *SelectorReraiseDecodeResult) { value.operandMode = Signed8OpaqueThresholdCTCT }},
			{"path", func(value *SelectorReraiseDecodeResult) { value.path = "foreign" }},
		} {
			t.Run(test.name, func(t *testing.T) {
				changed := selectorResult
				test.mutate(&changed)
				got, bindErr := prefixCircuit.BindSelectorResult(changed)
				if bindErr == nil || !reflect.DeepEqual(got, ScalarSelectorConditionInput{}) {
					t.Fatalf("pre-bind selector result replacement admitted: input=%+v err=%v", got, bindErr)
				}
			})
		}
		if !selectorResult.scalar.Equal(resultBefore) {
			t.Fatal("selector result rejection mutated the accepted producer result")
		}
		if rebound, bindErr := prefixCircuit.BindSelectorResult(selectorResult); bindErr != nil ||
			!reflect.DeepEqual(rebound, conditionInput) {
			t.Fatalf("accepted selector result no longer binds after rejected replacements: %v", bindErr)
		}
	})
	t.Run("selector result binding rejects malformed upstream provenance", func(t *testing.T) {
		foreign := selectorResult
		foreign.inputProvenanceDigest = "foreign"
		got, bindErr := prefixCircuit.BindSelectorResult(foreign)
		if bindErr == nil || !reflect.DeepEqual(got, ScalarSelectorConditionInput{}) {
			t.Fatalf("foreign selector-result provenance admitted: input=%+v err=%v", got, bindErr)
		}
	})
	leftValues := [4]int64{-3, -2, -1, 0}
	rightValues := [4]int64{1, 2, 3, 4}
	leftFeature, err := fixture.circuit.BindFeature(fixture.encryptSigned(t, leftValues), fixture.params)
	if err != nil {
		t.Fatal(err)
	}
	rightFeature, err := fixture.circuit.BindFeature(fixture.encryptSigned(t, rightValues), fixture.params)
	if err != nil {
		t.Fatal(err)
	}
	selectorBefore := selectorResult.scalar.CopyNew()
	conditionInputBefore := conditionInput.selector.CopyNew()
	leftBefore, rightBefore := leftFeature.ciphertext.CopyNew(), rightFeature.ciphertext.CopyNew()

	operands, trace, err := prefixEvaluator.EvaluateNew(conditionInput, [2]Signed8FeatureInput{leftFeature, rightFeature})
	if err != nil {
		t.Fatal(err)
	}
	if !selectorResult.scalar.Equal(selectorBefore) || !conditionInput.selector.Equal(conditionInputBefore) ||
		!leftFeature.ciphertext.Equal(leftBefore) ||
		!rightFeature.ciphertext.Equal(rightBefore) {
		t.Fatal("depth2 source prefix mutated an admitted selector or feature candidate")
	}
	if operands.SourceKind() != Signed8Depth2PrefixL6V1 ||
		operands.ProfileDigest() != prefixCircuit.Profile().Digest() ||
		operands.ParameterDigest() != prefixCircuit.Profile().ParameterDigest() ||
		operands.RangeDigest() != ranges.Digest() || operands.TreeDigest() == "" ||
		operands.ScheduleDigest() == "" || operands.ProvenanceDigest() == "" {
		t.Fatalf("depth2 operands provenance is incomplete: %+v", operands)
	}
	featureOutput, thresholdOutput := operands.FeatureCiphertext(), operands.ThresholdCiphertext()
	conditioned := operands.ConditionedSelectorCiphertext()
	if featureOutput == nil || thresholdOutput == nil || conditioned == nil ||
		featureOutput.Level() != 6 || thresholdOutput.Level() != 6 || conditioned.Level() != 7 ||
		!featureOutput.Scale.Equal(fixture.params.DefaultScale()) ||
		!thresholdOutput.Scale.Equal(fixture.params.DefaultScale()) ||
		!conditioned.Scale.Equal(rlwe.NewScale(fixture.params.Q()[7])) {
		t.Fatalf("depth2 output states changed: F=L%d/%s T=L%d/%s b=L%d/%s",
			featureOutput.Level(), featureOutput.Scale.Value.Text('x', -1),
			thresholdOutput.Level(), thresholdOutput.Scale.Value.Text('x', -1),
			conditioned.Level(), conditioned.Scale.Value.Text('x', -1))
	}
	featureCopy, thresholdCopy := operands.FeatureCiphertext(), operands.ThresholdCiphertext()
	conditionedCopy := operands.ConditionedSelectorCiphertext()
	featureOutput.Value[0].Coeffs[0][0] ^= 1
	thresholdOutput.Value[0].Coeffs[0][0] ^= 1
	conditioned.Value[0].Coeffs[0][0] ^= 1
	if operands.FeatureCiphertext().Equal(featureOutput) || operands.ThresholdCiphertext().Equal(thresholdOutput) ||
		operands.ConditionedSelectorCiphertext().Equal(conditioned) ||
		!operands.FeatureCiphertext().Equal(featureCopy) || !operands.ThresholdCiphertext().Equal(thresholdCopy) ||
		!operands.ConditionedSelectorCiphertext().Equal(conditionedCopy) {
		t.Fatal("depth2 operand accessors alias sealed outputs")
	}

	t.Run("typed operand admission rejects tampering", func(t *testing.T) {
		for _, test := range []struct {
			name   string
			mutate func(*Signed8Depth2Operands)
		}{
			{"source kind", func(value *Signed8Depth2Operands) { value.sourceKind = 0 }},
			{"parameter", func(value *Signed8Depth2Operands) { value.parameterDigest = "foreign" }},
			{"range", func(value *Signed8Depth2Operands) { value.rangeDigest = "foreign" }},
			{"tree", func(value *Signed8Depth2Operands) { value.treeDigest = "foreign" }},
			{"schedule", func(value *Signed8Depth2Operands) { value.scheduleDigest = "foreign" }},
			{"producer", func(value *Signed8Depth2Operands) { value.producerProfileDigest = "foreign" }},
			{"feature payload pin", func(value *Signed8Depth2Operands) { value.featurePayloadDigest = "foreign" }},
			{"feature ciphertext", func(value *Signed8Depth2Operands) { value.feature.Value[0].Coeffs[0][0] ^= 1 }},
			{"threshold ciphertext", func(value *Signed8Depth2Operands) { value.threshold.Value[0].Coeffs[0][0] ^= 1 }},
			{"conditioned selector ciphertext", func(value *Signed8Depth2Operands) { value.conditionedSelector.Value[0].Coeffs[0][0] ^= 1 }},
			{"provenance", func(value *Signed8Depth2Operands) { value.provenanceDigest = "foreign" }},
		} {
			t.Run(test.name, func(t *testing.T) {
				changed := operands
				changed.feature = operands.feature.CopyNew()
				changed.threshold = operands.threshold.CopyNew()
				changed.conditionedSelector = operands.conditionedSelector.CopyNew()
				test.mutate(&changed)
				if err := prefixCircuit.validateOperands(changed); err == nil {
					t.Fatal("tampered typed depth2 operands admitted")
				}
				if err := prefixCircuit.validateOperands(operands); err != nil ||
					!operands.feature.Equal(featureCopy) || !operands.threshold.Equal(thresholdCopy) ||
					!operands.conditionedSelector.Equal(conditionedCopy) {
					t.Fatalf("typed operand rejection mutated the valid source: %v", err)
				}
			})
		}
	})

	ringZ, err := z2n.NewWithPrecision(z2n.Word8, signed8IntegerEncoderPrecision)
	if err != nil {
		t.Fatal(err)
	}
	featureDecoded := make([]complex128, signed8Slots)
	thresholdDecoded := make([]complex128, signed8Slots)
	if err = fixture.integerEncoder.Decode(fixture.decryptor.DecryptNew(featureCopy), featureDecoded); err != nil {
		t.Fatal(err)
	}
	if err = fixture.integerEncoder.Decode(fixture.decryptor.DecryptNew(thresholdCopy), thresholdDecoded); err != nil {
		t.Fatal(err)
	}
	branches := [4]uint64{0, 1, 0, 1}
	leftThreshold, rightThreshold := int8(-4), int8(3)
	maxFeatureError, maxThresholdError := 0.0, 0.0
	for word, branch := range branches {
		leftRoots := ringZ.ArithmeticRootSlots(uint64(uint8(leftValues[word])))
		rightRoots := ringZ.ArithmeticRootSlots(uint64(uint8(rightValues[word])))
		leftThresholdRoots := ringZ.ArithmeticRootSlots(uint64(uint8(leftThreshold)))
		rightThresholdRoots := ringZ.ArithmeticRootSlots(uint64(uint8(rightThreshold)))
		for slot := 0; slot < 4; slot++ {
			wantFeature := leftRoots[slot].Complex128() + complex(float64(branch), 0)*(rightRoots[slot].Complex128()-leftRoots[slot].Complex128())
			wantThreshold := leftThresholdRoots[slot].Complex128() + complex(float64(branch), 0)*(rightThresholdRoots[slot].Complex128()-leftThresholdRoots[slot].Complex128())
			index := 4*word + slot
			featureError := cmplxDistanceA2BKernel(featureDecoded[index], wantFeature)
			thresholdError := cmplxDistanceA2BKernel(thresholdDecoded[index], wantThreshold)
			maxFeatureError = math.Max(maxFeatureError, featureError)
			maxThresholdError = math.Max(maxThresholdError, thresholdError)
			if featureError > 1e-3 || thresholdError > 1e-3 {
				t.Fatalf("word=%d slot=%d branch=%d errors feature=%.3g threshold=%.3g", word, slot, branch, featureError, thresholdError)
			}
		}
	}
	if trace.ProfileDigest() != prefixCircuit.Profile().Digest() ||
		trace.OperandsProvenanceDigest() != operands.ProvenanceDigest() ||
		trace.OperationCounts() != prefixCircuit.Profile().OperationCounts() {
		t.Fatalf("depth2 trace provenance or counts changed: %+v", trace)
	}
	conditionerTrace := trace.ConditionerTrace()
	conditionerStates := conditionerTrace.States()
	if conditionerTrace.OperationCounts() != (ScalarSelectorConditionOperationCounts{
		CiphertextPlaintextMultiplications: 1, Rescales: 1,
	}) || len(conditionerStates) != 2 || conditionerStates[0].Level != 8 || conditionerStates[1].Level != 7 ||
		!conditionerStates[0].Scale.EqualScale(rlwe.NewScale(fixture.params.Q()[8]).Mul(rlwe.NewScale(fixture.params.Q()[7]))) ||
		!conditionerStates[1].Scale.EqualScale(rlwe.NewScale(fixture.params.Q()[7])) {
		t.Fatalf("selector conditioner runtime ledger changed: %+v", conditionerTrace)
	}
	states := trace.States()
	wantStages := []string{
		"conditioned-selector", "feature-delta", "feature-raw-product", "feature-rescaled-product",
		"feature-left-aligned", "selected-feature", "threshold-raw-product", "threshold-rescaled-product",
		"selected-threshold",
	}
	wantLevels := []int{7, 20, 7, 6, 6, 6, 7, 6, 6}
	wantScales := []rlwe.Scale{
		rlwe.NewScale(fixture.params.Q()[7]), fixture.params.DefaultScale(),
		rlwe.NewScale(fixture.params.Q()[7]).Mul(fixture.params.DefaultScale()), fixture.params.DefaultScale(),
		fixture.params.DefaultScale(), fixture.params.DefaultScale(),
		rlwe.NewScale(fixture.params.Q()[7]).Mul(fixture.params.DefaultScale()), fixture.params.DefaultScale(),
		fixture.params.DefaultScale(),
	}
	if len(states) != len(wantStages) {
		t.Fatalf("depth2 runtime recorded %d states, want %d", len(states), len(wantStages))
	}
	for index, state := range states {
		if state.Stage != wantStages[index] || state.Level != wantLevels[index] || state.Degree != 1 ||
			state.LogDimensions != fixture.params.LogMaxDimensions() || !state.Scale.EqualScale(wantScales[index]) {
			t.Fatalf("depth2 runtime state %d changed: %+v", index, state)
		}
	}
	bytes := trace.SerializedBytes()
	if bytes.ExternalInputTotal() <= 0 || bytes.InternalSelectorTotal() <= 0 ||
		bytes.OutputOperandTotal() <= 0 || bytes.RetainedEvidenceTotal() <= 0 ||
		bytes.ExternalFeatureLeft <= 0 || bytes.ExternalFeatureRight <= 0 ||
		bytes.InternalSelectorInput <= 0 || bytes.InternalConditionedSelector <= 0 ||
		bytes.OutputFeature <= 0 || bytes.OutputThreshold <= 0 || bytes.RetainedConditionerRaw <= 0 ||
		bytes.RetainedFeatureDelta <= 0 || bytes.RetainedFeatureRaw <= 0 ||
		bytes.RetainedFeatureLeftAligned <= 0 || bytes.RetainedThresholdRaw <= 0 {
		t.Fatalf("depth2 byte classification is incomplete: %+v", bytes)
	}
	t.Logf("depth2 source prefix max errors feature=%.3g threshold=%.3g; bytes external=%d internal-selector=%d outputs=%d retained=%d",
		maxFeatureError, maxThresholdError, bytes.ExternalInputTotal(), bytes.InternalSelectorTotal(),
		bytes.OutputOperandTotal(), bytes.RetainedEvidenceTotal())

	assertReject := func(
		t *testing.T,
		candidate *Signed8Depth2SourcePrefixEvaluator,
		selectorCandidate ScalarSelectorConditionInput,
		featureCandidates [2]Signed8FeatureInput,
	) {
		t.Helper()
		selectorSnapshot := selectorCandidate.selector.CopyNew()
		featureSnapshots := [2]*rlwe.Ciphertext{
			featureCandidates[0].ciphertext.CopyNew(), featureCandidates[1].ciphertext.CopyNew(),
		}
		leftSnapshot, deltaSnapshot := prefixCircuit.thresholdLeft.CopyNew(), prefixCircuit.thresholdDelta.CopyNew()
		got, gotTrace, evalErr := candidate.EvaluateNew(selectorCandidate, featureCandidates)
		if evalErr == nil || got.FeatureCiphertext() != nil || got.ThresholdCiphertext() != nil ||
			got.ConditionedSelectorCiphertext() != nil || !reflect.DeepEqual(got, Signed8Depth2Operands{}) ||
			!reflect.DeepEqual(gotTrace, Signed8Depth2SourcePrefixTrace{}) {
			t.Fatalf("invalid depth2 input/graph did not fail closed: err=%v operands=%+v trace=%+v", evalErr, got, gotTrace)
		}
		if !selectorCandidate.selector.Equal(selectorSnapshot) ||
			!featureCandidates[0].ciphertext.Equal(featureSnapshots[0]) ||
			!featureCandidates[1].ciphertext.Equal(featureSnapshots[1]) ||
			!prefixCircuit.thresholdLeft.Equal(leftSnapshot) || !prefixCircuit.thresholdDelta.Equal(deltaSnapshot) {
			t.Fatal("depth2 rejection mutated an admitted or cached operand")
		}
	}

	t.Run("fail-close before operations", func(t *testing.T) {
		validFeatures := [2]Signed8FeatureInput{leftFeature, rightFeature}
		for _, test := range []struct {
			name   string
			mutate func(*ScalarSelectorConditionInput)
		}{
			{"selector profile", func(value *ScalarSelectorConditionInput) { value.profileDigest = "foreign" }},
			{"selector producer", func(value *ScalarSelectorConditionInput) { value.producerProfileDigest = "foreign" }},
			{"selector range", func(value *ScalarSelectorConditionInput) { value.rangeDigest = "foreign" }},
			{"selector source provenance", func(value *ScalarSelectorConditionInput) { value.selectorInputProvenanceDigest = "foreign" }},
			{"selector result provenance", func(value *ScalarSelectorConditionInput) { value.selectorResultProvenanceDigest = "foreign" }},
			{"selector path", func(value *ScalarSelectorConditionInput) { value.selectorPath = "foreign" }},
			{"selector payload pin", func(value *ScalarSelectorConditionInput) { value.payloadDigest = "foreign" }},
			{"selector provenance", func(value *ScalarSelectorConditionInput) { value.provenanceDigest = "foreign" }},
			{"selector ciphertext payload", func(value *ScalarSelectorConditionInput) { value.selector.Value[0].Coeffs[0][0] ^= 1 }},
			{"selector level", func(value *ScalarSelectorConditionInput) { value.selector.Resize(value.selector.Degree(), 7) }},
			{"selector scale", func(value *ScalarSelectorConditionInput) {
				value.selector.Scale = value.selector.Scale.Mul(rlwe.NewScale(2))
			}},
		} {
			t.Run(test.name, func(t *testing.T) {
				changed := conditionInput
				changed.selector = conditionInput.selector.CopyNew()
				test.mutate(&changed)
				assertReject(t, prefixEvaluator, changed, validFeatures)
			})
		}

		for _, test := range []struct {
			name   string
			index  int
			mutate func(*Signed8FeatureInput)
		}{
			{"left role", 0, func(value *Signed8FeatureInput) { value.role = signed8ThresholdRole }},
			{"left range", 0, func(value *Signed8FeatureInput) { value.rangeDigest = "foreign" }},
			{"left source", 0, func(value *Signed8FeatureInput) { value.sourceParameterDigest = "foreign" }},
			{"left provenance", 0, func(value *Signed8FeatureInput) { value.provenanceDigest = "foreign" }},
			{"left payload", 0, func(value *Signed8FeatureInput) { value.ciphertext.Value[0].Coeffs[0][0] ^= 1 }},
			{"right profile", 1, func(value *Signed8FeatureInput) { value.profileDigest = "foreign" }},
			{"right level", 1, func(value *Signed8FeatureInput) { value.ciphertext.Resize(value.ciphertext.Degree(), 19) }},
		} {
			t.Run(test.name, func(t *testing.T) {
				changed := validFeatures
				changed[test.index] = validFeatures[test.index]
				changed[test.index].ciphertext = validFeatures[test.index].ciphertext.CopyNew()
				test.mutate(&changed[test.index])
				assertReject(t, prefixEvaluator, conditionInput, changed)
			})
		}

		for _, test := range []struct {
			name   string
			mutate func(*Signed8Depth2SourcePrefixEvaluator)
		}{
			{"source", func(value *Signed8Depth2SourcePrefixEvaluator) { value.source = nil }},
			{"keyset", func(value *Signed8Depth2SourcePrefixEvaluator) { value.keySet = nil }},
			{"relinearization key", func(value *Signed8Depth2SourcePrefixEvaluator) { value.relinearizationKey = nil }},
			{"profile binding", func(value *Signed8Depth2SourcePrefixEvaluator) { value.graph.profileDigest = "foreign" }},
			{"conditioner graph", func(value *Signed8Depth2SourcePrefixEvaluator) {
				child := *value.conditioner
				value.conditioner = &child
				value.graph.conditioner = &child
			}},
		} {
			t.Run(test.name, func(t *testing.T) {
				changed := *prefixEvaluator
				changed.graph.evaluator = &changed
				test.mutate(&changed)
				assertReject(t, &changed, conditionInput, validFeatures)
			})
		}

		t.Run("tampered tree", func(t *testing.T) {
			changedCircuit := *prefixCircuit
			changedCircuit.tree = cloneSigned8Depth2Tree(prefixCircuit.tree)
			changedCircuit.tree.Splits[1].Threshold++
			changedCircuit.graph.circuit = &changedCircuit
			changed := *prefixEvaluator
			changed.circuit = &changedCircuit
			changed.graph.evaluator = &changed
			changed.graph.circuit = &changedCircuit
			assertReject(t, &changed, conditionInput, validFeatures)
		})
	})
}
