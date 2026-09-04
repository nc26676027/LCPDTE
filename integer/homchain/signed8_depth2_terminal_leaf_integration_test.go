package homchain

import (
	"errors"
	"maps"
	"math"
	"math/big"
	"math/cmplx"
	"reflect"
	"testing"
	"time"

	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
)

func TestSigned8Depth2TerminalLeafEncryptedFourPathsPublic(t *testing.T) {
	ranges, err := NewSigned8NoOverflowRange(-8, 7, -8, 7)
	if err != nil {
		t.Fatal(err)
	}
	base := newSigned8ComparatorFixture(t, ranges)
	tree := signed8Depth2TestTree()
	selector, err := NewSelectorReraiseDecodeCircuit(base.circuit)
	if err != nil {
		t.Fatal(err)
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

	rootWords := [4]int64{-1, -1, 1, 1}
	leftWords := [4]int64{-5, -4, 0, 0}
	rightWords := [4]int64{0, 0, 2, 3}
	rootFeature, err := base.circuit.BindFeature(base.encryptSigned(t, rootWords), base.params)
	if err != nil {
		t.Fatal(err)
	}
	rootComparison, _, err := base.evaluator.CompareGEPublicNew(rootFeature, [4]int64{})
	if err != nil {
		t.Fatal(err)
	}
	selectorInput, err := selector.BindComparatorResult(rootComparison)
	if err != nil {
		t.Fatal(err)
	}
	selectorResult, _, err := selectorEvaluator.EvaluateNew(selectorInput)
	if err != nil {
		t.Fatal(err)
	}
	conditionInput, err := prefix.BindSelectorResult(selectorResult)
	if err != nil {
		t.Fatal(err)
	}
	leftFeature, err := base.circuit.BindFeature(base.encryptSigned(t, leftWords), base.params)
	if err != nil {
		t.Fatal(err)
	}
	rightFeature, err := base.circuit.BindFeature(base.encryptSigned(t, rightWords), base.params)
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
	child, err := NewSigned8Depth2ChildComparatorCircuit(prefix)
	if err != nil {
		t.Fatal(err)
	}
	childInput, err := child.BindOperands(operands)
	if err != nil {
		t.Fatal(err)
	}
	childEvaluator, err := child.BindEvaluator(base.source)
	if err != nil {
		t.Fatal(err)
	}
	childResult, _, err := childEvaluator.EvaluateNew(childInput)
	if err != nil {
		t.Fatal(err)
	}

	circuit, err := NewSigned8Depth2TerminalLeafCircuit(child)
	if err != nil {
		t.Fatal(err)
	}
	input, err := circuit.BindChildResult(childInput, childResult)
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
	if _, err = evaluator.preflight(); err != nil {
		t.Fatalf("terminal runtime identity snapshots changed after accepted scratch use: %v", err)
	}
	if err = circuit.validateResult(result); err != nil {
		t.Fatalf("terminal result did not validate: %v", err)
	}
	if err = circuit.validateTrace(input, result, trace); err != nil {
		t.Fatalf("terminal trace did not validate: %v", err)
	}

	// Exercise the terminal adapter/lifting path with a synthetic authenticated
	// decoder post-dispatch partial produced by the decoder's real finalizer.
	// This covers terminal preflight, admission, composition and validation; it
	// does not claim to inject a failure inside evaluateNormalV itself.
	decoderInputScale, err := NewExactScaleSnapshot(input.decoderInput.branch.Scale)
	if err != nil {
		t.Fatal(err)
	}
	decoderHelper := SelectorReraiseDecodeTrace{
		states: []SelectorReraiseDecodeCiphertextState{{
			Stage: SelectorStageInput, Lane: SelectorReraiseDecodeWhole,
			Level: input.decoderInput.branch.Level(), Degree: input.decoderInput.branch.Degree(),
			LogDimensions: input.decoderInput.branch.LogDimensions, Scale: decoderInputScale,
		}},
		logicalPeakLive: 2,
	}
	decoderPreflight := trace.DecoderTrace().KeyPreflight()
	_, decoderPartial, err := finalizeSigned8Depth2ChildSelectorDecodeFailure(
		circuit.decoder, input.decoderInput, decoderHelper, decoderPreflight,
		Signed8Depth2ChildSelectorStageVRaw,
		Signed8Depth2ChildSelectorDecodeOperationCounts{LinearTransformations: 2},
		time.Millisecond,
	)
	if err != nil {
		t.Fatal(err)
	}
	injectedDecoderFailure := errors.New("injected authenticated decoder post-dispatch failure")
	liftedResult, liftedTrace, liftedErr := evaluator.evaluateNew(input, func(got Signed8Depth2ChildSelectorDecodeInput) (
		Signed8Depth2ChildSelectorDecodeResult, Signed8Depth2ChildSelectorDecodeTrace, error,
	) {
		if got.ProvenanceDigest() != input.decoderInput.ProvenanceDigest() {
			t.Fatal("terminal decoder adapter received a foreign input")
		}
		return Signed8Depth2ChildSelectorDecodeResult{}, cloneSigned8Depth2ChildSelectorDecodeTrace(decoderPartial), injectedDecoderFailure
	})
	if liftedErr == nil || !errors.Is(liftedErr, injectedDecoderFailure) ||
		!reflect.DeepEqual(liftedResult, Signed8Depth2TerminalLeafResult{}) ||
		reflect.DeepEqual(liftedTrace, Signed8Depth2TerminalLeafTrace{}) ||
		liftedTrace.FailureStage() != Signed8Depth2TerminalStageDecoderFailure ||
		liftedTrace.DecoderTraceDigest() != decoderPartial.Digest() ||
		liftedTrace.UniqueComposedMeasuredBytes() != decoderPartial.SerializedBytes().ModuleTotal() ||
		circuit.validateFailureTrace(input, liftedTrace) != nil {
		t.Fatalf("terminal adapter decoder-partial lifting failed: trace=%+v err=%v", liftedTrace, liftedErr)
	}
	preOpResult, preOpTrace, preOpErr := evaluator.evaluateNew(input, func(Signed8Depth2ChildSelectorDecodeInput) (
		Signed8Depth2ChildSelectorDecodeResult, Signed8Depth2ChildSelectorDecodeTrace, error,
	) {
		return Signed8Depth2ChildSelectorDecodeResult{}, Signed8Depth2ChildSelectorDecodeTrace{}, errors.New("injected decoder pre-op rejection")
	})
	if preOpErr == nil || !reflect.DeepEqual(preOpResult, Signed8Depth2TerminalLeafResult{}) ||
		!reflect.DeepEqual(preOpTrace, Signed8Depth2TerminalLeafTrace{}) {
		t.Fatalf("terminal decoder pre-op rejection was not exact-zero: result=%+v trace=%+v err=%v", preOpResult, preOpTrace, preOpErr)
	}

	retainTerminalPrefix := func(value *Signed8Depth2TerminalLeafTrace, source Signed8Depth2TerminalLeafTrace, length int) {
		value.states = append([]Signed8Depth2TerminalLeafState(nil), source.states[:length]...)
		value.retainedCiphertexts = make(map[Signed8Depth2TerminalLeafStage]*rlwe.Ciphertext, length)
		value.retainedPayloadDigests = make(map[Signed8Depth2TerminalLeafStage]string, length)
		for _, state := range value.states {
			value.retainedCiphertexts[state.Stage] = copyA2BRefreshCiphertext(source.retainedCiphertexts[state.Stage])
			value.retainedPayloadDigests[state.Stage] = source.retainedPayloadDigests[state.Stage]
		}
		value.serializedBytes, _ = signed8Depth2TerminalBytesFromStatePrefix(value.states)
	}
	localSeed := cloneSigned8Depth2TerminalLeafTrace(trace)
	localSeed.counts = Signed8Depth2TerminalLeafOperationCounts{}
	localSeed.attemptedOperationLowerBound.TerminalMux = Signed8Depth2TerminalLeafOperationCounts{
		CiphertextPlaintextMultiplications: 1,
	}
	retainTerminalPrefix(&localSeed, trace, 2)
	localResult, localPartial, err := finalizeSigned8Depth2TerminalLeafFailure(
		circuit, input, localSeed, Signed8Depth2TerminalStageRawA, time.Millisecond,
	)
	if err != nil || !reflect.DeepEqual(localResult, Signed8Depth2TerminalLeafResult{}) ||
		localPartial.FailureStage() != Signed8Depth2TerminalStageRawA || len(localPartial.States()) != 2 ||
		localPartial.SerializedBytes().TotalBytes() != 9580 || localPartial.UniqueComposedMeasuredBytes() != 61930 ||
		localPartial.OperationCounts() != (Signed8Depth2TerminalLeafOperationCounts{}) ||
		circuit.validateFailureTrace(input, localPartial) != nil {
		t.Fatalf("terminal local partial fixture failed: trace=%+v err=%v", localPartial, err)
	}

	fusedSeed := cloneSigned8Depth2TerminalLeafTrace(trace)
	fusedSeed.counts = Signed8Depth2TerminalLeafOperationCounts{
		CiphertextPlaintextMultiplications: 2, Rescales: 2, PlaintextVectorAdditions: 2,
	}
	fusedSeed.attemptedOperationLowerBound.TerminalMux = fusedSeed.counts
	fusedSeed.attemptedOperationLowerBound.TerminalMux.CiphertextCiphertextMultiplications++
	retainTerminalPrefix(&fusedSeed, trace, 8)
	_, fusedPartial, err := finalizeSigned8Depth2TerminalLeafFailure(
		circuit, input, fusedSeed, Signed8Depth2TerminalStageRawY, time.Millisecond,
	)
	if err != nil || fusedPartial.AttemptedOperationLowerBound().TerminalMux.Relinearizations != 0 ||
		circuit.validateFailureTrace(input, fusedPartial) != nil {
		t.Fatalf("terminal fused MulRelin failure lower bound is not conservative: trace=%+v err=%v", fusedPartial, err)
	}

	type localPartialMutation struct {
		name   string
		mutate func(*Signed8Depth2TerminalLeafTrace)
	}
	localMutations := []localPartialMutation{
		{"stage", func(value *Signed8Depth2TerminalLeafTrace) { value.failureStage = Signed8Depth2TerminalStageRawD }},
		{"admission-stage", func(value *Signed8Depth2TerminalLeafTrace) { value.failureStage = Signed8Depth2TerminalStageAdmission }},
		{"completed", func(value *Signed8Depth2TerminalLeafTrace) { value.counts.Rescales++ }},
		{"attempted-zero", func(value *Signed8Depth2TerminalLeafTrace) {
			value.attemptedOperationLowerBound.TerminalMux = Signed8Depth2TerminalLeafOperationCounts{}
		}},
		{"attempted-full", func(value *Signed8Depth2TerminalLeafTrace) {
			value.attemptedOperationLowerBound.TerminalMux = circuit.profile.counts
		}},
		{"prefix-short", func(value *Signed8Depth2TerminalLeafTrace) { retainTerminalPrefix(value, trace, 1) }},
		{"prefix-long", func(value *Signed8Depth2TerminalLeafTrace) { retainTerminalPrefix(value, trace, 3) }},
		{"bytes", func(value *Signed8Depth2TerminalLeafTrace) { value.serializedBytes.RootSelector++ }},
		{"result-provenance", func(value *Signed8Depth2TerminalLeafTrace) { value.resultProvenanceDigest = "tampered" }},
	}
	for _, mutation := range localMutations {
		t.Run("terminal-local-partial-"+mutation.name, func(t *testing.T) {
			changed := cloneSigned8Depth2TerminalLeafTrace(localPartial)
			mutation.mutate(&changed)
			changed.traceDigest = digestSigned8Depth2TerminalLeafTrace(changed)
			if err := circuit.validateFailureTrace(input, changed); err == nil {
				t.Fatal("resealed terminal-local progress mutation validated")
			}
		})
	}
	fusedOverclaim := cloneSigned8Depth2TerminalLeafTrace(fusedPartial)
	fusedOverclaim.attemptedOperationLowerBound.TerminalMux.Relinearizations++
	fusedOverclaim.traceDigest = digestSigned8Depth2TerminalLeafTrace(fusedOverclaim)
	if err = circuit.validateFailureTrace(input, fusedOverclaim); err == nil {
		t.Fatal("resealed pre-relinearization fused-dispatch overclaim validated")
	}
	if len(localMutations) != 9 {
		t.Fatalf("terminal-local partial mutation cases=%d, want 9", len(localMutations))
	}

	b0, ok := trace.RetainedCiphertext(Signed8Depth2TerminalStageRootSelector)
	if !ok {
		t.Fatal("terminal trace omitted root b0")
	}
	b1, ok := trace.RetainedCiphertext(Signed8Depth2TerminalStageDecodedChild)
	if !ok {
		t.Fatal("terminal trace omitted decoded child b1")
	}
	b0Values := decodeSigned8Depth2Child(t, base.integerEncoder, base.decryptor, b0)
	b1Values := decodeSigned8Depth2Child(t, base.integerEncoder, base.decryptor, b1)
	wantB0 := [4]float64{0, 0, 1, 1}
	wantB1 := [4]float64{0, 1, 0, 1}
	eps := 1.0 / 256.0
	maxB0Error, maxB1Error := 0.0, 0.0
	for word := 0; word < signed8Words; word++ {
		for slot := 4 * word; slot < 4*(word+1); slot++ {
			b0Error := cmplx.Abs(b0Values[slot] - complex(wantB0[word], 0))
			b1Error := cmplx.Abs(b1Values[slot] - complex(wantB1[word], 0))
			maxB0Error = math.Max(maxB0Error, b0Error)
			maxB1Error = math.Max(maxB1Error, b1Error)
			if b0Error > eps || b1Error > eps {
				t.Fatalf("selector gate word=%d slot=%d: b0=%g b1=%g, want <=%g", word, slot, b0Error, b1Error, eps)
			}
		}
	}

	got := decodeSigned8Depth2Child(t, base.integerEncoder, base.decryptor, result.Ciphertext())
	tolerance := circuit.Profile().MagnitudeCertificate().OutputToleranceFloat64Up()
	if math.IsNaN(tolerance) || math.IsInf(tolerance, 0) || tolerance <= 0 {
		t.Fatalf("invalid terminal tolerance %g", tolerance)
	}
	maxRealError, maxImagError := 0.0, 0.0
	for word := 0; word < signed8Words; word++ {
		want, oracleErr := tree.Evaluate([]int8{int8(rootWords[word]), int8(leftWords[word]), int8(rightWords[word])})
		if oracleErr != nil {
			t.Fatal(oracleErr)
		}
		for slot := 4 * word; slot < 4*(word+1); slot++ {
			realError := math.Abs(real(got[slot]) - want)
			imagError := math.Abs(imag(got[slot]))
			maxRealError = math.Max(maxRealError, realError)
			maxImagError = math.Max(maxImagError, imagError)
			if realError > tolerance || imagError > tolerance {
				t.Fatalf("terminal word=%d slot=%d got=%v want=%g errors=%g/%g tolerance=%g", word, slot, got[slot], want, realError, imagError, tolerance)
			}
		}
	}

	wantCounts := Signed8Depth2TerminalLeafOperationCounts{
		CiphertextPlaintextMultiplications: 2, CiphertextCiphertextMultiplications: 1,
		Relinearizations: 1, Rescales: 3, PlaintextVectorAdditions: 2,
		CiphertextAdditions: 1, LevelDrops: 1,
	}
	wantComposedCounts := Signed8Depth2TerminalLeafComposedOperationCounts{
		ChildDecoder: circuit.decoder.Profile().OperationCounts(),
		TerminalMux:  wantCounts,
	}
	bytes := trace.SerializedBytes()
	if trace.OperationCounts() != wantCounts || trace.CompletedComposedOperationCounts() != wantComposedCounts ||
		trace.AttemptedOperationLowerBound() != wantComposedCounts || len(trace.States()) != 12 || bytes != circuit.Profile().ExpectedSerializedBytes() ||
		bytes.TotalBytes() != 54312 || trace.UniqueComposedMeasuredBytes() != 106662 ||
		trace.DecoderTrace().SerializedBytes().ModuleTotal() != 57404 ||
		!equalUint64Slices(trace.RuntimeGaloisElements(), []uint64{5, 17, 25, 33, 41, 49, 63}) ||
		!trace.RelinearizationKeyMatched() || trace.FailureStage() != "" || result.OperandMode() != Signed8PublicThresholdCTPT {
		t.Fatalf("terminal runtime evidence changed: counts=%+v states=%d bytes=%+v unique=%d mode=%s",
			trace.OperationCounts(), len(trace.States()), bytes, trace.UniqueComposedMeasuredBytes(), result.OperandMode())
	}

	// A self-digested result is still bound to the exact supplied input by
	// validateTrace. This regression prevents a foreign tuple from being
	// laundered by recomputing only the outer result/trace digests.
	foreign := cloneSigned8Depth2TerminalLeafResult(result)
	foreign.inputProvenanceDigest = digestString("terminal-foreign-input")
	foreign.provenanceDigest = digestSigned8Depth2TerminalLeafResult(foreign, foreign.outputPayloadDigest)
	if err = circuit.validateResult(foreign); err != nil {
		t.Fatalf("resealed standalone result unexpectedly failed before tuple linkage: %v", err)
	}
	foreignTrace := cloneSigned8Depth2TerminalLeafTrace(trace)
	foreignTrace.inputProvenanceDigest = foreign.inputProvenanceDigest
	foreignTrace.resultProvenanceDigest = foreign.provenanceDigest
	foreignTrace.traceDigest = digestSigned8Depth2TerminalLeafTrace(foreignTrace)
	if err = circuit.validateTrace(input, foreign, foreignTrace); err == nil {
		t.Fatal("resealed foreign terminal input/result/trace tuple admitted")
	}

	// Same shape and a fresh outer seal do not establish boundary identity.
	// Both an aliased intermediate and a foreign output must be rejected after
	// their mutable payload seals have been recomputed.
	aliasedRawD := cloneSigned8Depth2TerminalLeafTrace(trace)
	aliasedRawD.retainedCiphertexts[Signed8Depth2TerminalStageRawD] = aliasedRawD.retainedCiphertexts[Signed8Depth2TerminalStageRawA]
	aliasedRawD.retainedPayloadDigests[Signed8Depth2TerminalStageRawD] = aliasedRawD.retainedPayloadDigests[Signed8Depth2TerminalStageRawA]
	aliasedRawD.traceDigest = digestSigned8Depth2TerminalLeafTrace(aliasedRawD)
	if err = circuit.validateTrace(input, result, aliasedRawD); err == nil {
		t.Fatal("resealed RawD-to-RawA retained alias admitted")
	}

	foreignOutput := cloneSigned8Depth2TerminalLeafTrace(trace)
	currentOutput := foreignOutput.retainedCiphertexts[Signed8Depth2TerminalStageOutput]
	replacementOutput := ckks.NewCiphertext(circuit.params, currentOutput.Degree(), currentOutput.Level())
	replacementOutput.MetaData = currentOutput.MetaData.CopyNew()
	foreignOutput.retainedCiphertexts[Signed8Depth2TerminalStageOutput] = replacementOutput
	foreignOutput.retainedPayloadDigests[Signed8Depth2TerminalStageOutput], err = signed8CiphertextDigest(replacementOutput)
	if err != nil {
		t.Fatal(err)
	}
	foreignOutput.traceDigest = digestSigned8Depth2TerminalLeafTrace(foreignOutput)
	if err = circuit.validateTrace(input, result, foreignOutput); err == nil {
		t.Fatal("resealed same-state foreign retained output admitted")
	}

	resultCopy := result.Ciphertext()
	resultCopy.Value[0].Coeffs[0][0] ^= 1
	retainedCopy, _ := trace.RetainedCiphertext(Signed8Depth2TerminalStageOutput)
	retainedCopy.Value[0].Coeffs[0][0] ^= 1
	nestedCopy := trace.DecoderTrace().PeriodicRootOfUnity()
	nestedCopy.Value[0].Coeffs[0][0] ^= 1
	if err = circuit.validateResult(result); err != nil || circuit.validateTrace(input, result, trace) != nil {
		t.Fatal("terminal result/trace accessor aliases sealed evidence")
	}

	type preOperationMutation struct {
		name         string
		nilEvaluator bool
		mutate       func(*Signed8Depth2TerminalLeafEvaluator, *Signed8Depth2TerminalLeafCircuit, *Signed8Depth2TerminalLeafInput)
	}
	newCandidate := func() (*Signed8Depth2TerminalLeafEvaluator, *Signed8Depth2TerminalLeafCircuit, Signed8Depth2TerminalLeafInput) {
		changedCircuit := *circuit
		changedCircuit.profile = cloneSigned8Depth2TerminalLeafProfile(circuit.profile)
		changedCircuit.graph = circuit.graph
		changedCircuit.graph.circuit = &changedCircuit
		changedCircuit.graph.circuitSeal = &changedCircuit
		changedEvaluator := *evaluator
		changedEvaluator.circuit = &changedCircuit
		changedEvaluator.graph = evaluator.graph
		changedEvaluator.graph.evaluator = &changedEvaluator
		changedEvaluator.graph.circuit = &changedCircuit
		return &changedEvaluator, &changedCircuit, cloneSigned8Depth2TerminalLeafInput(input)
	}
	assertZeroWork := func(t *testing.T, mutation preOperationMutation) {
		t.Helper()
		changedEvaluator, changedCircuit, changedInput := newCandidate()
		mutation.mutate(changedEvaluator, changedCircuit, &changedInput)
		if mutation.nilEvaluator {
			changedEvaluator = nil
		}
		gotResult, gotTrace, gotErr := changedEvaluator.EvaluateNew(changedInput)
		if gotErr == nil || !reflect.DeepEqual(gotResult, Signed8Depth2TerminalLeafResult{}) ||
			!reflect.DeepEqual(gotTrace, Signed8Depth2TerminalLeafTrace{}) {
			t.Fatalf("invalid terminal object reached mux work: result=%+v trace=%+v err=%v", gotResult, gotTrace, gotErr)
		}
	}
	noPreOperationMutation := func(*Signed8Depth2TerminalLeafEvaluator, *Signed8Depth2TerminalLeafCircuit, *Signed8Depth2TerminalLeafInput) {
	}
	circuitMutations := []preOperationMutation{
		{"nil-child", false, func(_ *Signed8Depth2TerminalLeafEvaluator, value *Signed8Depth2TerminalLeafCircuit, _ *Signed8Depth2TerminalLeafInput) {
			value.child = nil
		}},
		{"graph-profile", false, func(_ *Signed8Depth2TerminalLeafEvaluator, value *Signed8Depth2TerminalLeafCircuit, _ *Signed8Depth2TerminalLeafInput) {
			value.graph.profileDigest = "tampered"
		}},
		{"cache-plaintext-payload", false, func(_ *Signed8Depth2TerminalLeafEvaluator, value *Signed8Depth2TerminalLeafCircuit, _ *Signed8Depth2TerminalLeafInput) {
			value.deltaL = value.deltaL.CopyNew()
			value.graph.deltaL = value.deltaL
			value.deltaL.Value.Coeffs[0][0] ^= 1
		}},
		{"cache-source-value", false, func(_ *Signed8Depth2TerminalLeafEvaluator, value *Signed8Depth2TerminalLeafCircuit, _ *Signed8Depth2TerminalLeafInput) {
			value.cacheSources[0] = new(big.Float).Copy(value.cacheSources[0])
			value.graph.cacheSources[0] = value.cacheSources[0]
			value.cacheSources[0].Add(value.cacheSources[0], new(big.Float).SetPrec(256).SetInt64(1))
		}},
		{"encoder-runtime", false, func(_ *Signed8Depth2TerminalLeafEvaluator, value *Signed8Depth2TerminalLeafCircuit, _ *Signed8Depth2TerminalLeafInput) {
			replacement := *value.encoder
			value.encoder = &replacement
			value.graph.encoder = &replacement
		}},
		{"certificate-digest", false, func(_ *Signed8Depth2TerminalLeafEvaluator, value *Signed8Depth2TerminalLeafCircuit, _ *Signed8Depth2TerminalLeafInput) {
			value.profile.certificate.digest = "tampered"
		}},
	}
	inputMutations := []preOperationMutation{
		{"zero-input", false, func(_ *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, value *Signed8Depth2TerminalLeafInput) {
			*value = Signed8Depth2TerminalLeafInput{}
		}},
		{"nil-root-selector", false, func(_ *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, value *Signed8Depth2TerminalLeafInput) {
			value.rootSelector = nil
		}},
		{"same-state-root-selector-replacement", false, func(_ *Signed8Depth2TerminalLeafEvaluator, circuit *Signed8Depth2TerminalLeafCircuit, value *Signed8Depth2TerminalLeafInput) {
			foreign := ckks.NewCiphertext(circuit.params, value.rootSelector.Degree(), value.rootSelector.Level())
			foreign.MetaData = value.rootSelector.MetaData.CopyNew()
			value.rootSelector = foreign
		}},
		{"root-selector-payload", false, func(_ *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, value *Signed8Depth2TerminalLeafInput) {
			value.rootSelector.Value[0].Coeffs[0][0] ^= 1
		}},
		{"profile", false, func(_ *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, value *Signed8Depth2TerminalLeafInput) {
			value.profileDigest = "tampered"
		}},
		{"parameters", false, func(_ *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, value *Signed8Depth2TerminalLeafInput) {
			value.parameterDigest = "tampered"
		}},
		{"child-profile", false, func(_ *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, value *Signed8Depth2TerminalLeafInput) {
			value.childProfileDigest = "tampered"
		}},
		{"decoder-profile", false, func(_ *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, value *Signed8Depth2TerminalLeafInput) {
			value.decoderProfileDigest = "tampered"
		}},
		{"prefix-profile", false, func(_ *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, value *Signed8Depth2TerminalLeafInput) {
			value.prefixProfileDigest = "tampered"
		}},
		{"protocol-range", false, func(_ *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, value *Signed8Depth2TerminalLeafInput) {
			value.protocolRangeDigest = "tampered"
		}},
		{"tree", false, func(_ *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, value *Signed8Depth2TerminalLeafInput) {
			value.treeDigest = "tampered"
		}},
		{"schedule", false, func(_ *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, value *Signed8Depth2TerminalLeafInput) {
			value.scheduleDigest = "tampered"
		}},
		{"child-input-binding", false, func(_ *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, value *Signed8Depth2TerminalLeafInput) {
			value.childInputBindingDigest = "tampered"
		}},
		{"child-result-provenance", false, func(_ *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, value *Signed8Depth2TerminalLeafInput) {
			value.childResultProvenanceDigest = "tampered"
		}},
		{"operands-provenance", false, func(_ *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, value *Signed8Depth2TerminalLeafInput) {
			value.operandsProvenanceDigest = "tampered"
		}},
		{"decoder-input-provenance", false, func(_ *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, value *Signed8Depth2TerminalLeafInput) {
			value.decoderInputProvenanceDigest = "tampered"
		}},
		{"mode", false, func(_ *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, value *Signed8Depth2TerminalLeafInput) {
			value.operandMode = Signed8OpaqueThresholdCTCT
		}},
		{"producer", false, func(_ *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, value *Signed8Depth2TerminalLeafInput) {
			value.producerProfileDigest = "tampered"
		}},
		{"root-payload-seal", false, func(_ *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, value *Signed8Depth2TerminalLeafInput) {
			value.rootPayloadDigest = "tampered"
		}},
		{"input-provenance", false, func(_ *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, value *Signed8Depth2TerminalLeafInput) {
			value.provenanceDigest = "tampered"
		}},
		{"decoder-input-branch-payload", false, func(_ *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, value *Signed8Depth2TerminalLeafInput) {
			value.decoderInput.branch.Value[0].Coeffs[0][0] ^= 1
		}},
		{"decoder-input-branch-replacement", false, func(_ *Signed8Depth2TerminalLeafEvaluator, circuit *Signed8Depth2TerminalLeafCircuit, value *Signed8Depth2TerminalLeafInput) {
			foreign := ckks.NewCiphertext(circuit.params, value.decoderInput.branch.Degree(), value.decoderInput.branch.Level())
			foreign.MetaData = value.decoderInput.branch.MetaData.CopyNew()
			value.decoderInput.branch = foreign
		}},
		{"decoder-input-profile", false, func(_ *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, value *Signed8Depth2TerminalLeafInput) {
			value.decoderInput.profileDigest = "tampered"
		}},
		{"decoder-input-payload-seal", false, func(_ *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, value *Signed8Depth2TerminalLeafInput) {
			value.decoderInput.payloadDigest = "tampered"
		}},
		{"decoder-input-provenance-seal", false, func(_ *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, value *Signed8Depth2TerminalLeafInput) {
			value.decoderInput.provenanceDigest = "tampered"
		}},
	}
	evaluatorMutations := []preOperationMutation{
		{"nil-evaluator", true, noPreOperationMutation},
		{"nil-circuit", false, func(value *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, _ *Signed8Depth2TerminalLeafInput) {
			value.circuit = nil
		}},
		{"nil-source", false, func(value *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, _ *Signed8Depth2TerminalLeafInput) {
			value.source = nil
		}},
		{"nil-ckks", false, func(value *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, _ *Signed8Depth2TerminalLeafInput) {
			value.ckks = nil
		}},
		{"nil-decoder", false, func(value *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, _ *Signed8Depth2TerminalLeafInput) {
			value.decoder = nil
		}},
		{"nil-key-set", false, func(value *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, _ *Signed8Depth2TerminalLeafInput) {
			value.keySet = nil
		}},
		{"nil-relinearization", false, func(value *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, _ *Signed8Depth2TerminalLeafInput) {
			value.relinearizationKey = nil
		}},
		{"nil-galois-map", false, func(value *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, _ *Signed8Depth2TerminalLeafInput) {
			value.galoisKeys = nil
		}},
		{"replacement-galois-map", false, func(value *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, _ *Signed8Depth2TerminalLeafInput) {
			value.galoisKeys = maps.Clone(value.galoisKeys)
		}},
		{"graph-evaluator", false, func(value *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, _ *Signed8Depth2TerminalLeafInput) {
			value.graph.evaluator = nil
		}},
		{"graph-circuit", false, func(value *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, _ *Signed8Depth2TerminalLeafInput) {
			value.graph.circuit = nil
		}},
		{"graph-source", false, func(value *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, _ *Signed8Depth2TerminalLeafInput) {
			value.graph.source = nil
		}},
		{"graph-ckks", false, func(value *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, _ *Signed8Depth2TerminalLeafInput) {
			value.graph.ckks = nil
		}},
		{"graph-decoder", false, func(value *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, _ *Signed8Depth2TerminalLeafInput) {
			value.graph.decoder = nil
		}},
		{"graph-key-set", false, func(value *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, _ *Signed8Depth2TerminalLeafInput) {
			value.graph.keySet = nil
		}},
		{"graph-relinearization", false, func(value *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, _ *Signed8Depth2TerminalLeafInput) {
			value.graph.relinearizationKey = nil
		}},
		{"graph-galois-map", false, func(value *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, _ *Signed8Depth2TerminalLeafInput) {
			value.graph.galoisKeys = nil
		}},
		{"graph-profile", false, func(value *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, _ *Signed8Depth2TerminalLeafInput) {
			value.graph.profileDigest = "tampered"
		}},
		{"graph-ckks-runtime", false, func(value *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, _ *Signed8Depth2TerminalLeafInput) {
			value.graph.ckksRuntime = ckks.EvaluatorRuntimeIdentity{}
		}},
		{"graph-rlwe-buffers-runtime", false, func(value *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, _ *Signed8Depth2TerminalLeafInput) {
			value.graph.rlweBuffersRuntime = rlwe.EvaluatorBuffersRuntimeIdentity{}
		}},
		{"graph-rlwe-runtime", false, func(value *Signed8Depth2TerminalLeafEvaluator, _ *Signed8Depth2TerminalLeafCircuit, _ *Signed8Depth2TerminalLeafInput) {
			value.graph.rlweRuntime = rlwe.EvaluatorRuntimeIdentity{}
		}},
	}
	for category, mutations := range map[string][]preOperationMutation{
		"circuit-cache": circuitMutations,
		"input":         inputMutations,
		"evaluator":     evaluatorMutations,
	} {
		t.Run("pre-operation-zero-work-"+category, func(t *testing.T) {
			for _, mutation := range mutations {
				t.Run(mutation.name, func(t *testing.T) { assertZeroWork(t, mutation) })
			}
		})
	}
	if len(circuitMutations) != 6 || len(inputMutations) != 25 || len(evaluatorMutations) != 21 {
		t.Fatalf("terminal pre-operation matrix changed: circuit/cache=%d input=%d evaluator=%d",
			len(circuitMutations), len(inputMutations), len(evaluatorMutations))
	}

	resultMutations := []struct {
		name   string
		mutate func(*Signed8Depth2TerminalLeafResult)
	}{
		{"nil-output", func(value *Signed8Depth2TerminalLeafResult) { value.output = nil }},
		{"output-payload", func(value *Signed8Depth2TerminalLeafResult) { value.output.Value[0].Coeffs[0][0] ^= 1 }},
		{"same-state-output-replacement", func(value *Signed8Depth2TerminalLeafResult) {
			foreign := ckks.NewCiphertext(circuit.params, value.output.Degree(), value.output.Level())
			foreign.MetaData = value.output.MetaData.CopyNew()
			value.output = foreign
		}},
		{"profile", func(value *Signed8Depth2TerminalLeafResult) { value.profileDigest = "tampered" }},
		{"certificate", func(value *Signed8Depth2TerminalLeafResult) { value.certificateDigest = "tampered" }},
		{"decoder-result-link", func(value *Signed8Depth2TerminalLeafResult) { value.decoderResultDigest = "tampered" }},
		{"output-payload-seal", func(value *Signed8Depth2TerminalLeafResult) { value.outputPayloadDigest = "tampered" }},
		{"provenance", func(value *Signed8Depth2TerminalLeafResult) { value.provenanceDigest = "tampered" }},
	}
	for _, mutation := range resultMutations {
		t.Run("post-operation-result-"+mutation.name, func(t *testing.T) {
			changed := cloneSigned8Depth2TerminalLeafResult(result)
			mutation.mutate(&changed)
			if err := circuit.validateResult(changed); err == nil {
				t.Fatal("mutated post-operation terminal result validated")
			}
		})
	}
	traceMutations := []struct {
		name   string
		mutate func(*Signed8Depth2TerminalLeafTrace)
	}{
		{"profile", func(value *Signed8Depth2TerminalLeafTrace) { value.profileDigest = "tampered" }},
		{"retained-output-nil", func(value *Signed8Depth2TerminalLeafTrace) {
			value.retainedCiphertexts[Signed8Depth2TerminalStageOutput] = nil
		}},
		{"retained-output-payload", func(value *Signed8Depth2TerminalLeafTrace) {
			value.retainedCiphertexts[Signed8Depth2TerminalStageOutput].Value[0].Coeffs[0][0] ^= 1
		}},
		{"same-state-retained-output-replacement", func(value *Signed8Depth2TerminalLeafTrace) {
			current := value.retainedCiphertexts[Signed8Depth2TerminalStageOutput]
			foreign := ckks.NewCiphertext(circuit.params, current.Degree(), current.Level())
			foreign.MetaData = current.MetaData.CopyNew()
			value.retainedCiphertexts[Signed8Depth2TerminalStageOutput] = foreign
		}},
		{"retained-output-payload-seal", func(value *Signed8Depth2TerminalLeafTrace) {
			value.retainedPayloadDigests[Signed8Depth2TerminalStageOutput] = "tampered"
		}},
		{"state-level", func(value *Signed8Depth2TerminalLeafTrace) { value.states[0].Level++ }},
		{"operation-count", func(value *Signed8Depth2TerminalLeafTrace) { value.counts.CiphertextAdditions++ }},
		{"attempted-child-lower-bound", func(value *Signed8Depth2TerminalLeafTrace) {
			value.attemptedOperationLowerBound.ChildDecoder.LinearTransformations++
		}},
		{"attempted-terminal-lower-bound", func(value *Signed8Depth2TerminalLeafTrace) {
			value.attemptedOperationLowerBound.TerminalMux.Rescales++
		}},
		{"serialized-bytes", func(value *Signed8Depth2TerminalLeafTrace) { value.serializedBytes.Output++ }},
		{"runtime-galois", func(value *Signed8Depth2TerminalLeafTrace) {
			value.runtimeGalois = append([]uint64(nil), value.runtimeGalois...)
			value.runtimeGalois[0] = 0
		}},
		{"relinearization", func(value *Signed8Depth2TerminalLeafTrace) { value.relinearizationMatched = false }},
		{"result-provenance", func(value *Signed8Depth2TerminalLeafTrace) { value.resultProvenanceDigest = "tampered" }},
		{"child-input-binding", func(value *Signed8Depth2TerminalLeafTrace) { value.childInputBindingDigest = "tampered" }},
		{"child-result-provenance", func(value *Signed8Depth2TerminalLeafTrace) { value.childResultProvenanceDigest = "tampered" }},
		{"operands-provenance", func(value *Signed8Depth2TerminalLeafTrace) { value.operandsProvenanceDigest = "tampered" }},
		{"decoder-input-provenance", func(value *Signed8Depth2TerminalLeafTrace) { value.decoderInputProvenanceDigest = "tampered" }},
		{"producer-profile", func(value *Signed8Depth2TerminalLeafTrace) { value.producerProfileDigest = "tampered" }},
		{"operand-mode", func(value *Signed8Depth2TerminalLeafTrace) { value.operandMode = Signed8OpaqueThresholdCTCT }},
		{"wall-time", func(value *Signed8Depth2TerminalLeafTrace) { value.wallTime = 0 }},
		{"trace-digest", func(value *Signed8Depth2TerminalLeafTrace) { value.traceDigest = "tampered" }},
		{"decoder-result-payload", func(value *Signed8Depth2TerminalLeafTrace) {
			value.decoderResult.selector.Value[0].Coeffs[0][0] ^= 1
		}},
		{"decoder-trace-payload", func(value *Signed8Depth2TerminalLeafTrace) {
			value.decoderTrace.periodicRoot.Value[0].Coeffs[0][0] ^= 1
		}},
		{"decoder-trace-digest", func(value *Signed8Depth2TerminalLeafTrace) {
			value.decoderTrace.traceDigest = "tampered"
		}},
		{"decoder-result-link", func(value *Signed8Depth2TerminalLeafTrace) { value.decoderResultDigest = "tampered" }},
	}
	for _, mutation := range traceMutations {
		t.Run("post-operation-trace-"+mutation.name, func(t *testing.T) {
			changed := cloneSigned8Depth2TerminalLeafTrace(trace)
			mutation.mutate(&changed)
			if err := circuit.validateTrace(input, result, changed); err == nil {
				t.Fatal("mutated post-operation terminal trace validated")
			}
		})
	}
	if len(resultMutations) != 8 || len(traceMutations) != 25 {
		t.Fatalf("terminal post-operation matrix changed: result=%d trace=%d", len(resultMutations), len(traceMutations))
	}

	t.Logf("terminal public four-paths: profile=%s certificate=%s result=%s trace=%s bytes=%+v unique=%d b0-max=%g b1-max=%g real-max=%g imag-max=%g tolerance=%g pre-op=%d/%d/%d post-op=%d/%d",
		circuit.Profile().Digest(), circuit.Profile().MagnitudeCertificate().Digest(), result.ProvenanceDigest(), trace.Digest(),
		bytes, trace.UniqueComposedMeasuredBytes(), maxB0Error, maxB1Error, maxRealError, maxImagError, tolerance,
		len(circuitMutations), len(inputMutations), len(evaluatorMutations), len(resultMutations), len(traceMutations))
}

func TestSigned8Depth2TerminalLeafEncryptedFourPathsOpaque(t *testing.T) {
	ranges, err := NewSigned8NoOverflowRange(-8, 7, -8, 7)
	if err != nil {
		t.Fatal(err)
	}
	base := newSigned8ComparatorFixture(t, ranges)
	tree := signed8Depth2TestTree()
	selector, err := NewSelectorReraiseDecodeCircuit(base.circuit)
	if err != nil {
		t.Fatal(err)
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

	rootWords := [4]int64{-1, -1, 1, 1}
	leftWords := [4]int64{-5, -4, 0, 0}
	rightWords := [4]int64{0, 0, 2, 3}
	rootFeature, err := base.circuit.BindFeature(base.encryptSigned(t, rootWords), base.params)
	if err != nil {
		t.Fatal(err)
	}
	rootThreshold, err := base.circuit.BindOpaqueThreshold(base.encryptSigned(t, [4]int64{}), base.params)
	if err != nil {
		t.Fatal(err)
	}
	rootComparison, _, err := base.evaluator.CompareGEOpaqueNew(rootFeature, rootThreshold)
	if err != nil {
		t.Fatal(err)
	}
	selectorInput, err := selector.BindComparatorResult(rootComparison)
	if err != nil {
		t.Fatal(err)
	}
	selectorResult, _, err := selectorEvaluator.EvaluateNew(selectorInput)
	if err != nil {
		t.Fatal(err)
	}
	conditionInput, err := prefix.BindSelectorResult(selectorResult)
	if err != nil {
		t.Fatal(err)
	}
	leftFeature, err := base.circuit.BindFeature(base.encryptSigned(t, leftWords), base.params)
	if err != nil {
		t.Fatal(err)
	}
	rightFeature, err := base.circuit.BindFeature(base.encryptSigned(t, rightWords), base.params)
	if err != nil {
		t.Fatal(err)
	}
	operands, _, err := prefixEvaluator.EvaluateNew(conditionInput, [2]Signed8FeatureInput{leftFeature, rightFeature})
	if err != nil {
		t.Fatal(err)
	}
	child, err := NewSigned8Depth2ChildComparatorCircuit(prefix)
	if err != nil {
		t.Fatal(err)
	}
	childInput, err := child.BindOperands(operands)
	if err != nil {
		t.Fatal(err)
	}
	childEvaluator, err := child.BindEvaluator(base.source)
	if err != nil {
		t.Fatal(err)
	}
	childResult, _, err := childEvaluator.EvaluateNew(childInput)
	if err != nil {
		t.Fatal(err)
	}
	circuit, err := NewSigned8Depth2TerminalLeafCircuit(child)
	if err != nil {
		t.Fatal(err)
	}
	input, err := circuit.BindChildResult(childInput, childResult)
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
	if _, err = evaluator.preflight(); err != nil {
		t.Fatalf("opaque terminal runtime identity snapshots changed after accepted scratch use: %v", err)
	}
	if err = circuit.validateResult(result); err != nil {
		t.Fatalf("opaque terminal result did not validate: %v", err)
	}
	if err = circuit.validateTrace(input, result, trace); err != nil {
		t.Fatalf("opaque terminal trace did not validate: %v", err)
	}

	b0, ok := trace.RetainedCiphertext(Signed8Depth2TerminalStageRootSelector)
	if !ok {
		t.Fatal("opaque terminal trace omitted root b0")
	}
	b1, ok := trace.RetainedCiphertext(Signed8Depth2TerminalStageDecodedChild)
	if !ok {
		t.Fatal("opaque terminal trace omitted decoded child b1")
	}
	b0Values := decodeSigned8Depth2Child(t, base.integerEncoder, base.decryptor, b0)
	b1Values := decodeSigned8Depth2Child(t, base.integerEncoder, base.decryptor, b1)
	wantB0 := [4]float64{0, 0, 1, 1}
	wantB1 := [4]float64{0, 1, 0, 1}
	eps := 1.0 / 256.0
	maxB0Error, maxB1Error := 0.0, 0.0
	for word := 0; word < signed8Words; word++ {
		for slot := 4 * word; slot < 4*(word+1); slot++ {
			b0Error := cmplx.Abs(b0Values[slot] - complex(wantB0[word], 0))
			b1Error := cmplx.Abs(b1Values[slot] - complex(wantB1[word], 0))
			maxB0Error = math.Max(maxB0Error, b0Error)
			maxB1Error = math.Max(maxB1Error, b1Error)
			if b0Error > eps || b1Error > eps {
				t.Fatalf("opaque selector gate word=%d slot=%d: b0=%g b1=%g, want <=%g", word, slot, b0Error, b1Error, eps)
			}
		}
	}

	got := decodeSigned8Depth2Child(t, base.integerEncoder, base.decryptor, result.Ciphertext())
	tolerance := circuit.Profile().MagnitudeCertificate().OutputToleranceFloat64Up()
	maxRealError, maxImagError := 0.0, 0.0
	for word := 0; word < signed8Words; word++ {
		want, oracleErr := tree.Evaluate([]int8{int8(rootWords[word]), int8(leftWords[word]), int8(rightWords[word])})
		if oracleErr != nil {
			t.Fatal(oracleErr)
		}
		for slot := 4 * word; slot < 4*(word+1); slot++ {
			realError := math.Abs(real(got[slot]) - want)
			imagError := math.Abs(imag(got[slot]))
			maxRealError = math.Max(maxRealError, realError)
			maxImagError = math.Max(maxImagError, imagError)
			if realError > tolerance || imagError > tolerance {
				t.Fatalf("opaque terminal word=%d slot=%d got=%v want=%g errors=%g/%g tolerance=%g", word, slot, got[slot], want, realError, imagError, tolerance)
			}
		}
	}
	bytes := trace.SerializedBytes()
	wantCounts := Signed8Depth2TerminalLeafOperationCounts{
		CiphertextPlaintextMultiplications: 2, CiphertextCiphertextMultiplications: 1,
		Relinearizations: 1, Rescales: 3, PlaintextVectorAdditions: 2,
		CiphertextAdditions: 1, LevelDrops: 1,
	}
	wantComposedCounts := Signed8Depth2TerminalLeafComposedOperationCounts{
		ChildDecoder: circuit.decoder.Profile().OperationCounts(),
		TerminalMux:  wantCounts,
	}
	if result.OperandMode() != Signed8OpaqueThresholdCTCT || input.operandMode != Signed8OpaqueThresholdCTCT ||
		trace.DecoderResult().OperandMode() != Signed8OpaqueThresholdCTCT ||
		trace.DecoderTrace().OperandMode() != Signed8OpaqueThresholdCTCT ||
		trace.OperationCounts() != wantCounts || trace.CompletedComposedOperationCounts() != wantComposedCounts ||
		trace.AttemptedOperationLowerBound() != wantComposedCounts || len(trace.States()) != 12 ||
		bytes != circuit.Profile().ExpectedSerializedBytes() || bytes.TotalBytes() != 54312 ||
		trace.UniqueComposedMeasuredBytes() != 106662 || trace.FailureStage() != "" {
		t.Fatalf("opaque terminal runtime evidence changed: mode=%s counts=%+v states=%d bytes=%+v unique=%d",
			result.OperandMode(), trace.OperationCounts(), len(trace.States()), bytes, trace.UniqueComposedMeasuredBytes())
	}
	t.Logf("terminal opaque four-paths: profile=%s certificate=%s result=%s trace=%s bytes=%+v unique=%d b0-max=%g b1-max=%g real-max=%g imag-max=%g tolerance=%g",
		circuit.Profile().Digest(), circuit.Profile().MagnitudeCertificate().Digest(), result.ProvenanceDigest(), trace.Digest(),
		bytes, trace.UniqueComposedMeasuredBytes(), maxB0Error, maxB1Error, maxRealError, maxImagError, tolerance)
}
