package homchain

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/nc26676027/LCPDTE/integer/z2n"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func TestSigned8RootTreeEvaluatorFailsClosedBeforeComparatorWork(t *testing.T) {
	var evaluator *Signed8RootTreeEvaluator
	result, trace, err := evaluator.EvaluatePublicNew(Signed8FeatureInput{}, [signed8RootTreeWords]int64{})
	assertSigned8RootTreeFailureIsExactZero(t, "nil evaluator", result, trace, err)
	result, trace, err = evaluator.EvaluateOpaqueNew(Signed8FeatureInput{}, Signed8OpaqueThresholdInput{})
	assertSigned8RootTreeFailureIsExactZero(t, "nil opaque evaluator", result, trace, err)

	ranges, err := NewSigned8NoOverflowRange(-8, 7, -8, 7)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newSigned8ComparatorFixture(t, ranges)
	leaves := Signed8PackedLeaves{
		{Left: -128, Right: 127},
		{Left: 127, Right: -128},
		{Left: -7, Right: 19},
		{Left: 42, Right: -99},
	}
	circuit, err := NewSigned8RootTreeCircuit(
		fixture.params, fixture.refreshEncoder, fixture.integerEncoder, ranges, leaves,
	)
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err = circuit.BindEvaluator(fixture.source)
	if err != nil {
		t.Fatal(err)
	}
	featureCaller := fixture.encryptSigned(t, [signed8RootTreeWords]int64{-8, -1, 0, 7})
	thresholdCaller := fixture.encryptSigned(t, [signed8RootTreeWords]int64{-8, 0, -1, 7})
	feature, err := circuit.BindFeature(featureCaller, fixture.params)
	if err != nil {
		t.Fatal(err)
	}
	threshold, err := circuit.BindOpaqueThreshold(thresholdCaller, fixture.params)
	if err != nil {
		t.Fatal(err)
	}
	publicThresholds := [signed8RootTreeWords]int64{-8, 0, -1, 7}

	assertPublicRejected := func(t *testing.T, name string, handle Signed8FeatureInput, thresholds [signed8RootTreeWords]int64) {
		t.Helper()
		before := snapshotSigned8RootTreeOwnedState(circuit, featureCaller, thresholdCaller, handle.ciphertext, threshold.ciphertext)
		gotResult, gotTrace, evaluationErr := evaluator.EvaluatePublicNew(handle, thresholds)
		assertSigned8RootTreeFailureIsExactZero(t, name, gotResult, gotTrace, evaluationErr)
		before.assertUnchanged(t, name, circuit, featureCaller, thresholdCaller, handle.ciphertext, threshold.ciphertext)
	}
	assertOpaqueRejected := func(t *testing.T, name string, featureHandle Signed8FeatureInput, thresholdHandle Signed8OpaqueThresholdInput) {
		t.Helper()
		before := snapshotSigned8RootTreeOwnedState(circuit, featureCaller, thresholdCaller, featureHandle.ciphertext, thresholdHandle.ciphertext)
		gotResult, gotTrace, evaluationErr := evaluator.EvaluateOpaqueNew(featureHandle, thresholdHandle)
		assertSigned8RootTreeFailureIsExactZero(t, name, gotResult, gotTrace, evaluationErr)
		before.assertUnchanged(t, name, circuit, featureCaller, thresholdCaller, featureHandle.ciphertext, thresholdHandle.ciphertext)
	}

	for _, test := range []struct {
		name   string
		mutate func(*Signed8FeatureInput)
	}{
		{name: "nil feature ciphertext", mutate: func(h *Signed8FeatureInput) { h.ciphertext = nil }},
		{name: "foreign feature role", mutate: func(h *Signed8FeatureInput) { h.role = signed8ThresholdRole }},
		{name: "foreign feature range", mutate: func(h *Signed8FeatureInput) { h.rangeDigest = "foreign" }},
		{name: "foreign feature profile", mutate: func(h *Signed8FeatureInput) { h.profileDigest = "foreign" }},
		{name: "foreign feature source", mutate: func(h *Signed8FeatureInput) { h.sourceParameterDigest = "foreign" }},
		{name: "foreign feature payload pin", mutate: func(h *Signed8FeatureInput) { h.payloadDigest = "foreign" }},
		{name: "foreign feature provenance", mutate: func(h *Signed8FeatureInput) { h.provenanceDigest = "foreign" }},
		{name: "feature coefficient payload tamper", mutate: func(h *Signed8FeatureInput) {
			h.ciphertext = h.ciphertext.CopyNew()
			h.ciphertext.Value[0].Coeffs[0][0]++
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := feature
			test.mutate(&changed)
			assertPublicRejected(t, test.name, changed, publicThresholds)
		})
	}

	for _, test := range []struct {
		name   string
		mutate func(*Signed8OpaqueThresholdInput)
	}{
		{name: "nil opaque ciphertext", mutate: func(h *Signed8OpaqueThresholdInput) { h.ciphertext = nil }},
		{name: "foreign opaque role", mutate: func(h *Signed8OpaqueThresholdInput) { h.role = signed8FeatureRole }},
		{name: "foreign opaque range", mutate: func(h *Signed8OpaqueThresholdInput) { h.rangeDigest = "foreign" }},
		{name: "foreign opaque profile", mutate: func(h *Signed8OpaqueThresholdInput) { h.profileDigest = "foreign" }},
		{name: "foreign opaque source", mutate: func(h *Signed8OpaqueThresholdInput) { h.sourceParameterDigest = "foreign" }},
		{name: "foreign opaque payload pin", mutate: func(h *Signed8OpaqueThresholdInput) { h.payloadDigest = "foreign" }},
		{name: "foreign opaque provenance", mutate: func(h *Signed8OpaqueThresholdInput) { h.provenanceDigest = "foreign" }},
		{name: "opaque coefficient payload tamper", mutate: func(h *Signed8OpaqueThresholdInput) {
			h.ciphertext = h.ciphertext.CopyNew()
			h.ciphertext.Value[0].Coeffs[0][0]++
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := threshold
			test.mutate(&changed)
			assertOpaqueRejected(t, test.name, feature, changed)
		})
	}
	assertPublicRejected(t, "zero feature handle", Signed8FeatureInput{}, publicThresholds)
	assertOpaqueRejected(t, "zero opaque feature handle", Signed8FeatureInput{}, threshold)
	assertOpaqueRejected(t, "zero opaque threshold handle", feature, Signed8OpaqueThresholdInput{})
	assertPublicRejected(t, "out-of-range public threshold", feature, [signed8RootTreeWords]int64{-9, 0, 0, 0})

	foreignRanges, err := NewSigned8NoOverflowRange(-128, 127, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	foreignCircuit, err := NewSigned8RootTreeCircuit(
		fixture.params, fixture.refreshEncoder, fixture.integerEncoder, foreignRanges, leaves,
	)
	if err != nil {
		t.Fatal(err)
	}
	foreignFeature, err := foreignCircuit.BindFeature(featureCaller, fixture.params)
	if err != nil {
		t.Fatal(err)
	}
	foreignThreshold, err := foreignCircuit.BindOpaqueThreshold(thresholdCaller, fixture.params)
	if err != nil {
		t.Fatal(err)
	}
	assertPublicRejected(t, "foreign-range circuit feature", foreignFeature, publicThresholds)
	assertOpaqueRejected(t, "foreign-range circuit opaque threshold", feature, foreignThreshold)

	otherLeaves := leaves
	otherLeaves[0].Left++
	otherCircuit, err := NewSigned8RootTreeCircuit(
		fixture.params, fixture.refreshEncoder, fixture.integerEncoder, ranges, otherLeaves,
	)
	if err != nil {
		t.Fatal(err)
	}
	otherEvaluator, err := otherCircuit.BindEvaluator(fixture.source)
	if err != nil {
		t.Fatal(err)
	}

	type graphMutation struct {
		name   string
		mutate func() func()
	}
	mutations := []graphMutation{
		{name: "nil root circuit", mutate: func() func() {
			original := evaluator.circuit
			evaluator.circuit = nil
			return func() { evaluator.circuit = original }
		}},
		{name: "foreign root circuit", mutate: func() func() {
			original := evaluator.circuit
			evaluator.circuit = otherCircuit
			return func() { evaluator.circuit = original }
		}},
		{name: "root public profile", mutate: func() func() {
			original := circuit.publicProfile.digest
			circuit.publicProfile.digest = "foreign"
			return func() { circuit.publicProfile.digest = original }
		}},
		{name: "root opaque profile", mutate: func() func() {
			original := circuit.opaqueProfile.digest
			circuit.opaqueProfile.digest = "foreign"
			return func() { circuit.opaqueProfile.digest = original }
		}},
		{name: "root range certificate", mutate: func() func() {
			original := circuit.ranges
			circuit.ranges.digest = "foreign"
			return func() { circuit.ranges = original }
		}},
		{name: "root leaves", mutate: func() func() {
			original := circuit.leaves
			circuit.leaves[0].Left++
			return func() { circuit.leaves = original }
		}},
		{name: "cached left pointer", mutate: func() func() {
			original := circuit.left
			circuit.left = original.CopyNew()
			return func() { circuit.left = original }
		}},
		{name: "cached delta pointer", mutate: func() func() {
			original := circuit.correctedDelta
			circuit.correctedDelta = original.CopyNew()
			return func() { circuit.correctedDelta = original }
		}},
		{name: "cached left payload", mutate: func() func() {
			original := circuit.left.Value.Coeffs[0][0]
			circuit.left.Value.Coeffs[0][0]++
			return func() { circuit.left.Value.Coeffs[0][0] = original }
		}},
		{name: "cached delta payload", mutate: func() func() {
			original := circuit.correctedDelta.Value.Coeffs[0][0]
			circuit.correctedDelta.Value.Coeffs[0][0]++
			return func() { circuit.correctedDelta.Value.Coeffs[0][0] = original }
		}},
		{name: "cached left seal pointer", mutate: func() func() {
			original := circuit.graph.leftSaved
			circuit.graph.leftSaved = original.CopyNew()
			return func() { circuit.graph.leftSaved = original }
		}},
		{name: "cached delta seal pointer", mutate: func() func() {
			original := circuit.graph.deltaSaved
			circuit.graph.deltaSaved = original.CopyNew()
			return func() { circuit.graph.deltaSaved = original }
		}},
		{name: "owned left seal pointer", mutate: func() func() {
			original := circuit.leftSeal
			circuit.leftSeal = original.CopyNew()
			return func() { circuit.leftSeal = original }
		}},
		{name: "owned delta seal pointer", mutate: func() func() {
			original := circuit.deltaSeal
			circuit.deltaSeal = original.CopyNew()
			return func() { circuit.deltaSeal = original }
		}},
		{name: "root circuit graph", mutate: func() func() {
			original := circuit.graph
			circuit.graph.publicDigest = "foreign"
			return func() { circuit.graph = original }
		}},
		{name: "root evaluator graph", mutate: func() func() {
			original := evaluator.graph
			evaluator.graph.publicDigest = "foreign"
			return func() { evaluator.graph = original }
		}},
		{name: "bootstrap source", mutate: func() func() {
			original := evaluator.source
			evaluator.source = &bootstrapping.Evaluator{}
			return func() { evaluator.source = original }
		}},
		{name: "bootstrap source CKKS evaluator", mutate: func() func() {
			original := fixture.source.Evaluator
			fixture.source.Evaluator = ckks.NewEvaluator(fixture.params, fixture.source.MemEvaluationKeySet)
			return func() { fixture.source.Evaluator = original }
		}},
		{name: "source MemEvaluationKeySet", mutate: func() func() {
			original := fixture.source.MemEvaluationKeySet
			fixture.source.MemEvaluationKeySet = rlwe.NewMemEvaluationKeySet(original.RelinearizationKey)
			return func() { fixture.source.MemEvaluationKeySet = original }
		}},
		{name: "bound MemEvaluationKeySet", mutate: func() func() {
			original := evaluator.keySet
			evaluator.keySet = rlwe.NewMemEvaluationKeySet(original.RelinearizationKey)
			return func() { evaluator.keySet = original }
		}},
		{name: "captured relinearization pointer", mutate: func() func() {
			original := evaluator.relinearizationKey
			evaluator.relinearizationKey = fixture.keyGenerator.GenRelinearizationKeyNew(fixture.secretKey)
			return func() { evaluator.relinearizationKey = original }
		}},
		{name: "root comparator evaluator replacement", mutate: func() func() {
			original := evaluator.comparator
			evaluator.comparator = otherEvaluator.comparator
			return func() { evaluator.comparator = original }
		}},
		{name: "nested sign evaluator replacement", mutate: func() func() {
			original := evaluator.comparator.sign
			evaluator.comparator.sign = otherEvaluator.comparator.sign
			return func() { evaluator.comparator.sign = original }
		}},
	}

	keySet := fixture.source.MemEvaluationKeySet
	originalRelinearization := keySet.RelinearizationKey
	foreignSecret := fixture.keyGenerator.GenSecretKeyNew()
	mutations = append(mutations,
		graphMutation{name: "missing relinearization key", mutate: func() func() {
			keySet.RelinearizationKey = nil
			return func() { keySet.RelinearizationKey = originalRelinearization }
		}},
		graphMutation{name: "same-secret foreign relinearization key", mutate: func() func() {
			keySet.RelinearizationKey = fixture.keyGenerator.GenRelinearizationKeyNew(fixture.secretKey)
			return func() { keySet.RelinearizationKey = originalRelinearization }
		}},
		graphMutation{name: "foreign-secret relinearization key", mutate: func() func() {
			keySet.RelinearizationKey = fixture.keyGenerator.GenRelinearizationKeyNew(foreignSecret)
			return func() { keySet.RelinearizationKey = originalRelinearization }
		}},
	)

	elements := circuit.PublicProfile().RequiredGaloisElements()
	for _, element := range elements {
		element := element
		mutations = append(mutations,
			graphMutation{name: fmt.Sprintf("missing Galois key %d", element), mutate: func() func() {
				original := keySet.GaloisKeys[element]
				keySet.GaloisKeys[element] = nil
				return func() { keySet.GaloisKeys[element] = original }
			}},
			graphMutation{name: fmt.Sprintf("same-element foreign Galois key %d", element), mutate: func() func() {
				original := keySet.GaloisKeys[element]
				keySet.GaloisKeys[element] = fixture.keyGenerator.GenGaloisKeyNew(element, foreignSecret)
				return func() { keySet.GaloisKeys[element] = original }
			}},
			graphMutation{name: fmt.Sprintf("captured Galois pointer %d", element), mutate: func() func() {
				original := evaluator.galoisKeys[element]
				evaluator.galoisKeys[element] = fixture.keyGenerator.GenGaloisKeyNew(element, fixture.secretKey)
				return func() { evaluator.galoisKeys[element] = original }
			}},
		)
	}
	if len(elements) < 2 {
		t.Fatal("root-tree key profile has fewer than two Galois elements")
	}
	first, second := elements[0], elements[1]
	mutations = append(mutations, graphMutation{name: "swapped Galois keys", mutate: func() func() {
		keySet.GaloisKeys[first], keySet.GaloisKeys[second] = keySet.GaloisKeys[second], keySet.GaloisKeys[first]
		return func() {
			keySet.GaloisKeys[first], keySet.GaloisKeys[second] = keySet.GaloisKeys[second], keySet.GaloisKeys[first]
		}
	}})
	required := make(map[uint64]bool, len(elements))
	for _, element := range elements {
		required[element] = true
	}
	var extraElement uint64
	for rotation := 1; rotation < fixture.params.MaxSlots(); rotation++ {
		candidate := fixture.params.GaloisElementForRotation(rotation)
		if !required[candidate] {
			extraElement = candidate
			break
		}
	}
	if extraElement == 0 {
		t.Fatal("could not select an unexpected valid Galois element")
	}
	mutations = append(mutations, graphMutation{name: "unexpected extra Galois key", mutate: func() func() {
		keySet.GaloisKeys[extraElement] = fixture.keyGenerator.GenGaloisKeyNew(extraElement, fixture.secretKey)
		return func() { delete(keySet.GaloisKeys, extraElement) }
	}}, graphMutation{name: "unexpected captured Galois key", mutate: func() func() {
		evaluator.galoisKeys[extraElement] = fixture.keyGenerator.GenGaloisKeyNew(extraElement, fixture.secretKey)
		return func() { delete(evaluator.galoisKeys, extraElement) }
	}})

	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			restore := test.mutate()
			defer restore()
			assertPublicRejected(t, test.name, feature, publicThresholds)
		})
		if _, preflightErr := evaluator.preflightGraphAndKeys(); preflightErr != nil {
			t.Fatalf("restoring %s did not recover root-tree preflight: %v", test.name, preflightErr)
		}
	}

	recoveredResult, recoveredTrace, err := evaluator.EvaluatePublicNew(feature, publicThresholds)
	if err != nil || recoveredResult.Ciphertext() == nil || recoveredTrace.OperationCounts() != circuit.PublicProfile().OperationCounts() {
		t.Fatalf("restored root-tree graph did not recover: result=%+v trace=%+v err=%v", recoveredResult, recoveredTrace, err)
	}
}

func assertSigned8RootTreeFailureIsExactZero(
	t *testing.T,
	name string,
	result Signed8RootTreeResult,
	trace Signed8RootTreeTrace,
	err error,
) {
	t.Helper()
	if err == nil || !reflect.DeepEqual(result, Signed8RootTreeResult{}) ||
		!reflect.DeepEqual(trace, Signed8RootTreeTrace{}) || result.Ciphertext() != nil ||
		len(trace.States()) != 0 || trace.OperationCounts() != (Signed8RootTreeOperationCounts{}) ||
		!reflect.DeepEqual(trace.ComparatorTrace(), Signed8ComparatorTrace{}) ||
		!reflect.DeepEqual(trace.KeyPreflight(), A2BRefreshKeyPreflight{}) ||
		trace.SerializedBytes() != (Signed8RootTreeSerializedBytes{}) || trace.TimingMeasured() ||
		trace.TotalWallTime() != 0 || trace.ComparatorWallTime() != 0 || trace.LeafSelectionWallTime() != 0 {
		t.Fatalf("%s did not fail closed with an exact zero result/trace: result=%+v trace=%+v err=%v", name, result, trace, err)
	}
}

type signed8RootTreeOwnedSnapshot struct {
	featureCaller, thresholdCaller *rlwe.Ciphertext
	featureHandle, thresholdHandle *rlwe.Ciphertext
	left, delta                    *rlwe.Plaintext
	leftSeal, deltaSeal            *rlwe.Plaintext
	leftOwnedSeal, deltaOwnedSeal  *rlwe.Plaintext
	one, oneSeal                   *rlwe.Plaintext
}

func snapshotSigned8RootTreeOwnedState(
	circuit *Signed8RootTreeCircuit,
	featureCaller, thresholdCaller, featureHandle, thresholdHandle *rlwe.Ciphertext,
) signed8RootTreeOwnedSnapshot {
	result := signed8RootTreeOwnedSnapshot{
		featureCaller:   cloneSigned8CiphertextForTest(featureCaller),
		thresholdCaller: cloneSigned8CiphertextForTest(thresholdCaller),
		featureHandle:   cloneSigned8CiphertextForTest(featureHandle),
		thresholdHandle: cloneSigned8CiphertextForTest(thresholdHandle),
	}
	if circuit == nil {
		return result
	}
	result.left = cloneSigned8RootTreePlaintext(circuit.left)
	result.delta = cloneSigned8RootTreePlaintext(circuit.correctedDelta)
	result.leftSeal = cloneSigned8RootTreePlaintext(circuit.graph.leftSaved)
	result.deltaSeal = cloneSigned8RootTreePlaintext(circuit.graph.deltaSaved)
	result.leftOwnedSeal = cloneSigned8RootTreePlaintext(circuit.leftSeal)
	result.deltaOwnedSeal = cloneSigned8RootTreePlaintext(circuit.deltaSeal)
	if circuit.comparator != nil {
		result.one = cloneSigned8RootTreePlaintext(circuit.comparator.arithmeticOne)
		result.oneSeal = cloneSigned8RootTreePlaintext(circuit.comparator.arithmeticOneSeal)
	}
	return result
}

func (s signed8RootTreeOwnedSnapshot) assertUnchanged(
	t *testing.T,
	name string,
	circuit *Signed8RootTreeCircuit,
	featureCaller, thresholdCaller, featureHandle, thresholdHandle *rlwe.Ciphertext,
) {
	t.Helper()
	if !signed8CiphertextMatchesTestSnapshot(featureCaller, s.featureCaller) ||
		!signed8CiphertextMatchesTestSnapshot(thresholdCaller, s.thresholdCaller) ||
		!signed8CiphertextMatchesTestSnapshot(featureHandle, s.featureHandle) ||
		!signed8CiphertextMatchesTestSnapshot(thresholdHandle, s.thresholdHandle) {
		t.Fatalf("%s rejection mutated a caller or owned ciphertext", name)
	}
	if circuit == nil {
		return
	}
	if !signed8RootTreePlaintextMatches(circuit.left, s.left) ||
		!signed8RootTreePlaintextMatches(circuit.correctedDelta, s.delta) ||
		!signed8RootTreePlaintextMatches(circuit.graph.leftSaved, s.leftSeal) ||
		!signed8RootTreePlaintextMatches(circuit.graph.deltaSaved, s.deltaSeal) ||
		!signed8RootTreePlaintextMatches(circuit.leftSeal, s.leftOwnedSeal) ||
		!signed8RootTreePlaintextMatches(circuit.deltaSeal, s.deltaOwnedSeal) {
		t.Fatalf("%s rejection mutated a root-tree cached operand or seal", name)
	}
	if circuit.comparator != nil &&
		(!signed8RootTreePlaintextMatches(circuit.comparator.arithmeticOne, s.one) ||
			!signed8RootTreePlaintextMatches(circuit.comparator.arithmeticOneSeal, s.oneSeal)) {
		t.Fatalf("%s rejection mutated a comparator cached operand or seal", name)
	}
}

func cloneSigned8RootTreePlaintext(plaintext *rlwe.Plaintext) *rlwe.Plaintext {
	if plaintext == nil {
		return nil
	}
	if plaintext.MetaData != nil {
		return plaintext.CopyNew()
	}
	temporary := *plaintext
	temporary.MetaData = &rlwe.MetaData{}
	clone := temporary.CopyNew()
	clone.MetaData = nil
	return clone
}

func signed8RootTreePlaintextMatches(plaintext, snapshot *rlwe.Plaintext) bool {
	if plaintext == nil || snapshot == nil {
		return plaintext == snapshot
	}
	if plaintext.MetaData == nil || snapshot.MetaData == nil {
		return plaintext.MetaData == nil && snapshot.MetaData == nil && reflect.DeepEqual(plaintext.Value, snapshot.Value)
	}
	return plaintext.Equal(snapshot)
}

func TestSigned8RootTreeEncryptedPublicAndOpaqueTracer(t *testing.T) {
	ranges, err := NewSigned8NoOverflowRange(-8, 7, -8, 7)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newSigned8ComparatorFixture(t, ranges)
	leaves := Signed8PackedLeaves{
		{Left: -128, Right: 127},
		{Left: 5, Right: 7},
		{Left: -7, Right: 19},
		{Left: 42, Right: -99},
	}
	circuit, err := NewSigned8RootTreeCircuit(
		fixture.params, fixture.refreshEncoder, fixture.integerEncoder, ranges, leaves,
	)
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := circuit.BindEvaluator(fixture.source)
	if err != nil {
		t.Fatal(err)
	}

	features := [signed8RootTreeWords]int64{-8, 0, 0, 7}
	thresholds := [signed8RootTreeWords]int64{-8, 0, -1, 7}
	featureCiphertext := fixture.encryptSigned(t, features)
	thresholdCiphertext := fixture.encryptSigned(t, thresholds)
	feature, err := circuit.BindFeature(featureCiphertext, fixture.params)
	if err != nil {
		t.Fatal(err)
	}
	threshold, err := circuit.BindOpaqueThreshold(thresholdCiphertext, fixture.params)
	if err != nil {
		t.Fatal(err)
	}

	publicStarted := time.Now()
	publicResult, publicTrace, err := evaluator.EvaluatePublicNew(feature, thresholds)
	publicElapsed := time.Since(publicStarted)
	if err != nil {
		t.Fatal(err)
	}
	opaqueStarted := time.Now()
	opaqueResult, opaqueTrace, err := evaluator.EvaluateOpaqueNew(feature, threshold)
	opaqueElapsed := time.Since(opaqueStarted)
	if err != nil {
		t.Fatal(err)
	}
	assertSigned8WallTimeCoversCall(t, "signed8 root-tree public", publicElapsed, publicTrace.TotalWallTime())
	assertSigned8WallTimeCoversCall(t, "signed8 root-tree opaque", opaqueElapsed, opaqueTrace.TotalWallTime())
	assertSigned8RootTreeRuntimeAccessorsAreDefensive(t, publicResult, publicTrace)
	assertSigned8RootTreeRuntimeAccessorsAreDefensive(t, opaqueResult, opaqueTrace)
	want := [signed8RootTreeWords]uint64{127, 7, 19, 157}
	if got := fixture.decryptWords(t, publicResult.Ciphertext()); got != want {
		t.Fatalf("public selected leaves=%v, want %v", got, want)
	}
	if got := fixture.decryptWords(t, opaqueResult.Ciphertext()); got != want {
		t.Fatalf("opaque selected leaves=%v, want %v", got, want)
	}
	for _, evidence := range []struct {
		result Signed8RootTreeResult
		trace  Signed8RootTreeTrace
		mode   Signed8ComparatorOperandMode
	}{{publicResult, publicTrace, Signed8PublicThresholdCTPT}, {opaqueResult, opaqueTrace, Signed8OpaqueThresholdCTCT}} {
		wrapDistinguished, nonWrapAgreement, _ := assertSigned8RootTreeEncryptedEvidence(
			t, fixture, circuit, evidence.result, evidence.trace, evidence.mode, features, thresholds,
		)
		if !wrapDistinguished || !nonWrapAgreement {
			t.Fatalf("mode=%s did not exercise both canonical controls: wrap=%t non-wrap=%t", evidence.mode, wrapDistinguished, nonWrapAgreement)
		}
	}
}

func TestSigned8RootTreeAllNarrowPairsPublicAndOpaque(t *testing.T) {
	ranges, err := NewSigned8NoOverflowRange(-8, 7, -8, 7)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newSigned8ComparatorFixture(t, ranges)
	leaves := Signed8PackedLeaves{
		{Left: -128, Right: 127},
		{Left: 5, Right: 7},
		{Left: -7, Right: 19},
		{Left: 42, Right: -99},
	}
	circuit, err := NewSigned8RootTreeCircuit(
		fixture.params, fixture.refreshEncoder, fixture.integerEncoder, ranges, leaves,
	)
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := circuit.BindEvaluator(fixture.source)
	if err != nil {
		t.Fatal(err)
	}
	if evaluator.source != fixture.source || evaluator.keySet != fixture.source.MemEvaluationKeySet ||
		evaluator.comparator.source != fixture.source || evaluator.comparator.keySet != evaluator.keySet ||
		evaluator.relinearizationKey != evaluator.comparator.relinearizationKey {
		t.Fatal("root-tree and comparator do not share the exact source, MemEvaluationKeySet, and relinearization pointer")
	}
	for element, key := range evaluator.galoisKeys {
		if evaluator.comparator.galoisKeys[element] != key {
			t.Fatalf("root-tree and comparator Galois key %d pointers differ", element)
		}
	}

	pairs := make([][2]int64, 0, 256)
	for feature := int64(-8); feature <= 7; feature++ {
		for threshold := int64(-8); threshold <= 7; threshold++ {
			pairs = append(pairs, [2]int64{feature, threshold})
		}
	}
	leftBefore, deltaBefore := circuit.left.CopyNew(), circuit.correctedDelta.CopyNew()
	wrapDistinguished, nonWrapAgreement := false, false
	maxRootError := 0.0
	for batch := 0; batch < len(pairs)/signed8RootTreeWords; batch++ {
		var features, thresholds [signed8RootTreeWords]int64
		for lane := 0; lane < signed8RootTreeWords; lane++ {
			features[lane], thresholds[lane] = pairs[signed8RootTreeWords*batch+lane][0], pairs[signed8RootTreeWords*batch+lane][1]
		}
		featureCiphertext := fixture.encryptSigned(t, features)
		thresholdCiphertext := fixture.encryptSigned(t, thresholds)
		featureCallerBefore, thresholdCallerBefore := featureCiphertext.CopyNew(), thresholdCiphertext.CopyNew()
		feature, bindErr := circuit.BindFeature(featureCiphertext, fixture.params)
		if bindErr != nil {
			t.Fatal(bindErr)
		}
		threshold, bindErr := circuit.BindOpaqueThreshold(thresholdCiphertext, fixture.params)
		if bindErr != nil {
			t.Fatal(bindErr)
		}
		featureHandleBefore, thresholdHandleBefore := feature.ciphertext.CopyNew(), threshold.ciphertext.CopyNew()

		publicResult, publicTrace, publicErr := evaluator.EvaluatePublicNew(feature, thresholds)
		if publicErr != nil {
			t.Fatalf("batch=%d public features=%v thresholds=%v: %v", batch, features, thresholds, publicErr)
		}
		opaqueResult, opaqueTrace, opaqueErr := evaluator.EvaluateOpaqueNew(feature, threshold)
		if opaqueErr != nil {
			t.Fatalf("batch=%d opaque features=%v thresholds=%v: %v", batch, features, thresholds, opaqueErr)
		}
		if !featureCiphertext.Equal(featureCallerBefore) || !thresholdCiphertext.Equal(thresholdCallerBefore) ||
			!feature.ciphertext.Equal(featureHandleBefore) || !threshold.ciphertext.Equal(thresholdHandleBefore) ||
			!circuit.left.Equal(leftBefore) || !circuit.correctedDelta.Equal(deltaBefore) {
			t.Fatalf("batch=%d evaluation mutated a caller input, admitted handle, or cached public operand", batch)
		}

		for _, evidence := range []struct {
			result Signed8RootTreeResult
			trace  Signed8RootTreeTrace
			mode   Signed8ComparatorOperandMode
		}{{publicResult, publicTrace, Signed8PublicThresholdCTPT}, {opaqueResult, opaqueTrace, Signed8OpaqueThresholdCTCT}} {
			gotWords := fixture.decryptWords(t, evidence.result.Ciphertext())
			for lane, pair := range leaves {
				want := uint64(uint8(pair.Left))
				if signed8GEZ256Oracle(features[lane], thresholds[lane]) == 1 {
					want = uint64(uint8(pair.Right))
				}
				if gotWords[lane] != want {
					t.Fatalf("batch=%d mode=%s lane=%d [%d >= %d] selected residue=%d, want %d",
						batch, evidence.mode, lane, features[lane], thresholds[lane], gotWords[lane], want)
				}
			}
			wrap, nonWrap, rootError := assertSigned8RootTreeEncryptedEvidence(
				t, fixture, circuit, evidence.result, evidence.trace, evidence.mode, features, thresholds,
			)
			wrapDistinguished = wrapDistinguished || wrap
			nonWrapAgreement = nonWrapAgreement || nonWrap
			if rootError > maxRootError {
				maxRootError = rootError
			}
		}
	}
	if !wrapDistinguished || !nonWrapAgreement {
		t.Fatalf("all-pairs gate missed canonical controls: wrap=%t non-wrap=%t", wrapDistinguished, nonWrapAgreement)
	}
	t.Logf("signed8 root-tree all-pairs maximum source-scheduled root error=%.9g", maxRootError)
}

func TestSigned8RootTreeSignedBoundariesAndBlockIsolation(t *testing.T) {
	ranges, err := NewSigned8NoOverflowRange(-128, 127, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newSigned8ComparatorFixture(t, ranges)
	leaves := Signed8PackedLeaves{
		{Left: -128, Right: 127},
		{Left: 127, Right: -128},
		{Left: -7, Right: 19},
		{Left: 42, Right: -99},
	}
	circuit, err := NewSigned8RootTreeCircuit(
		fixture.params, fixture.refreshEncoder, fixture.integerEncoder, ranges, leaves,
	)
	if err != nil {
		t.Fatal(err)
	}
	if circuit.PublicProfile().ComparatorRangeInstanceProfileDigest() == signed8RootTreeAcceptedComparatorPublicDigest ||
		circuit.OpaqueProfile().ComparatorRangeInstanceProfileDigest() == signed8RootTreeAcceptedComparatorOpaqueDigest {
		t.Fatal("full-range instance was silently retagged with the narrow audit-anchor profile")
	}
	substituted := *circuit
	substituted.graph.circuit = &substituted
	substituted.publicProfile.comparatorProfileDigest = signed8RootTreeAcceptedComparatorPublicDigest
	substituted.publicProfile.digest = digestSigned8RootTreeProfile(substituted.publicProfile)
	substituted.graph.publicDigest = substituted.publicProfile.digest
	if err = substituted.validate(); err == nil {
		t.Fatal("narrow audit-anchor profile substitution was accepted for the full-range instance")
	}
	evaluator, err := circuit.BindEvaluator(fixture.source)
	if err != nil {
		t.Fatal(err)
	}
	features, thresholds := [signed8RootTreeWords]int64{-128, -1, 0, 127}, [signed8RootTreeWords]int64{}
	featureCiphertext, thresholdCiphertext := fixture.encryptSigned(t, features), fixture.encryptSigned(t, thresholds)
	feature, err := circuit.BindFeature(featureCiphertext, fixture.params)
	if err != nil {
		t.Fatal(err)
	}
	threshold, err := circuit.BindOpaqueThreshold(thresholdCiphertext, fixture.params)
	if err != nil {
		t.Fatal(err)
	}
	publicResult, publicTrace, err := evaluator.EvaluatePublicNew(feature, thresholds)
	if err != nil {
		t.Fatal(err)
	}
	opaqueResult, opaqueTrace, err := evaluator.EvaluateOpaqueNew(feature, threshold)
	if err != nil {
		t.Fatal(err)
	}
	want := [signed8RootTreeWords]uint64{128, 127, 19, 157}
	if publicWords, opaqueWords := fixture.decryptWords(t, publicResult.Ciphertext()), fixture.decryptWords(t, opaqueResult.Ciphertext()); publicWords != want || opaqueWords != want {
		t.Fatalf("boundary selected leaves public=%v opaque=%v, want=%v", publicWords, opaqueWords, want)
	}
	assertSigned8RootTreeEncryptedEvidence(t, fixture, circuit, publicResult, publicTrace, Signed8PublicThresholdCTPT, features, thresholds)
	assertSigned8RootTreeEncryptedEvidence(t, fixture, circuit, opaqueResult, opaqueTrace, Signed8OpaqueThresholdCTCT, features, thresholds)

	// Change only the second encrypted threshold block.  The already-measured
	// opaque result is the independent base; only that block may switch child.
	isolatedThresholds := thresholds
	isolatedThresholds[1] = -2
	isolatedThresholdCiphertext := fixture.encryptSigned(t, isolatedThresholds)
	isolatedThreshold, err := circuit.BindOpaqueThreshold(isolatedThresholdCiphertext, fixture.params)
	if err != nil {
		t.Fatal(err)
	}
	isolatedOpaqueResult, _, err := evaluator.EvaluateOpaqueNew(feature, isolatedThreshold)
	if err != nil {
		t.Fatal(err)
	}
	if baseWords, isolatedWords := fixture.decryptWords(t, opaqueResult.Ciphertext()), fixture.decryptWords(t, isolatedOpaqueResult.Ciphertext()); baseWords != [signed8RootTreeWords]uint64{128, 127, 19, 157} ||
		isolatedWords != [signed8RootTreeWords]uint64{128, 128, 19, 157} {
		t.Fatalf("one-block opaque-threshold change leaked: base=%v isolated=%v", baseWords, isolatedWords)
	}

	baseFeatures, isolatedFeatures := [signed8RootTreeWords]int64{-1, -1, -1, -1}, [signed8RootTreeWords]int64{-1, 1, -1, -1}
	baseCiphertext, isolatedCiphertext := fixture.encryptSigned(t, baseFeatures), fixture.encryptSigned(t, isolatedFeatures)
	base, err := circuit.BindFeature(baseCiphertext, fixture.params)
	if err != nil {
		t.Fatal(err)
	}
	isolated, err := circuit.BindFeature(isolatedCiphertext, fixture.params)
	if err != nil {
		t.Fatal(err)
	}
	baseResult, _, err := evaluator.EvaluatePublicNew(base, thresholds)
	if err != nil {
		t.Fatal(err)
	}
	isolatedResult, _, err := evaluator.EvaluatePublicNew(isolated, thresholds)
	if err != nil {
		t.Fatal(err)
	}
	if baseWords, isolatedWords := fixture.decryptWords(t, baseResult.Ciphertext()), fixture.decryptWords(t, isolatedResult.Ciphertext()); baseWords != [signed8RootTreeWords]uint64{128, 127, 249, 42} || isolatedWords != [signed8RootTreeWords]uint64{128, 128, 249, 42} {
		t.Fatalf("one-block feature change leaked: base=%v isolated=%v", baseWords, isolatedWords)
	}
}

func assertSigned8RootTreeEncryptedEvidence(
	t *testing.T,
	fixture signed8ComparatorFixture,
	circuit *Signed8RootTreeCircuit,
	result Signed8RootTreeResult,
	trace Signed8RootTreeTrace,
	mode Signed8ComparatorOperandMode,
	features, thresholds [signed8RootTreeWords]int64,
) (canonicalReencodeDistinguished, nonWrapCanonicalAgreement bool, maxRootError float64) {
	t.Helper()
	profile := circuit.profileForMode(mode)
	if circuit.Ranges() == mustSigned8RootTreeNarrowRange(t) && circuit.Leaves() == signed8RootTreeCanonicalAuditLeaves() {
		wantProfileDigest := "217dee6f265ec8c53819552838d9c9d64ea56e43df185b936f97d360b1e17be3"
		if mode == Signed8OpaqueThresholdCTCT {
			wantProfileDigest = "09e8c10628c8a6820dbc439d31f9fa6f61d1e6d1ef607db7a8a8b977edeb5073"
		}
		if profile.Digest() != wantProfileDigest || result.ProfileDigest() != wantProfileDigest || trace.ProfileDigest() != wantProfileDigest {
			t.Fatalf("canonical T0 runtime profile witness=%s/%s/%s, want literal %s",
				profile.Digest(), result.ProfileDigest(), trace.ProfileDigest(), wantProfileDigest)
		}
	}
	if result.ProfileDigest() != profile.Digest() || result.RangeDigest() != profile.RangeDigest() ||
		result.ComparatorProfileDigest() != profile.ComparatorProfileDigest() || result.LeavesDigest() != profile.LeavesDigest() ||
		result.OperandMode() != mode || result.OutputEncoding() != Signed8RootTreeArithmeticRootSlots ||
		trace.ProfileDigest() != profile.Digest() || trace.RangeDigest() != profile.RangeDigest() ||
		trace.ComparatorProfileDigest() != profile.ComparatorProfileDigest() || trace.LeavesDigest() != profile.LeavesDigest() ||
		trace.OperandMode() != mode || trace.OutputEncoding() != Signed8RootTreeArithmeticRootSlots {
		t.Fatal("signed8 root-tree result or trace provenance changed")
	}
	if trace.OperationCounts() != profile.OperationCounts() ||
		profile.SetupCounts() != (Signed8RootTreeSetupCounts{LeftPlaintextEncodings: 1, CorrectedDeltaPlaintextEncodings: 1}) ||
		!trace.TimingMeasured() || trace.TotalWallTime() < trace.ComparatorWallTime()+trace.LeafSelectionWallTime() {
		t.Fatalf("signed8 root-tree operation/timing ledger changed: counts=%+v total=%s comparator=%s selection=%s",
			trace.OperationCounts(), trace.TotalWallTime(), trace.ComparatorWallTime(), trace.LeafSelectionWallTime())
	}
	serialized := trace.SerializedBytes()
	wantSerialized := independentlyMarshalSigned8RootTreeBoundaries(t, fixture.params, trace.States())
	if serialized != wantSerialized {
		t.Fatalf("signed8 root-tree serialization evidence=%+v, independently marshaled=%+v", serialized, wantSerialized)
	}
	states, wantStates := trace.States(), profile.States()
	if len(states) != signed8RootTreeStateCount || len(wantStates) != signed8RootTreeStateCount {
		t.Fatalf("signed8 root-tree states=%d profile=%d, want %d", len(states), len(wantStates), signed8RootTreeStateCount)
	}
	for index, state := range states {
		want := wantStates[index]
		if state.Stage != want.Stage() || state.Level != want.Level() || state.Degree != want.Degree() ||
			state.LogDimensions != want.LogDimensions() || !state.Scale.Equal(want.Scale()) {
			t.Fatalf("signed8 root-tree state[%d]=%+v, want %+v", index, state, want)
		}
	}
	assertSigned8ComparatorTrace(t, fixture, trace.ComparatorTrace(), mode)
	if !reflect.DeepEqual(trace.KeyPreflight(), trace.ComparatorTrace().KeyPreflight()) {
		t.Fatal("signed8 root-tree and comparator key evidence differ")
	}

	ciphertext := result.Ciphertext()
	decoded := make([]complex128, ciphertext.Slots())
	if err := fixture.integerEncoder.Decode(fixture.decryptor.DecryptNew(ciphertext), decoded); err != nil {
		t.Fatal(err)
	}
	for lane, pair := range circuit.Leaves() {
		branch := signed8GEZ256Oracle(features[lane], thresholds[lane])
		selected := pair.Left
		if branch == 1 {
			selected = pair.Right
		}
		leftRoots := z2n.Complex128(fixture.ringZ.ArithmeticRootSlots(uint64(uint8(pair.Left))))
		branchRoots := z2n.Complex128(fixture.ringZ.ArithmeticRootSlots(branch))
		delta := uint64(uint8(int16(pair.Right) - int16(pair.Left)))
		correctedDelta, err := fixture.ringZ.ToRootSlots(fixture.ringZ.BinaryEncode(delta))
		if err != nil {
			t.Fatal(err)
		}
		correctedRoots := z2n.Complex128(correctedDelta)
		canonicalRoots := z2n.Complex128(fixture.ringZ.ArithmeticRootSlots(uint64(uint8(selected))))
		unsignedSum := int(uint8(pair.Left)) + int(uint8(delta))
		for slot := 0; slot < signed8RootTreeWordSlots; slot++ {
			wantRoot := leftRoots[slot] + branchRoots[slot]*correctedRoots[slot]
			rootError := cmplxDistance(decoded[signed8RootTreeWordSlots*lane+slot], wantRoot)
			if rootError > maxRootError {
				maxRootError = rootError
			}
			if rootError > 5e-4 {
				t.Fatalf("mode=%s lane=%d slot=%d selected=%d root error=%g exceeds 5e-4", mode, lane, slot, selected, rootError)
			}
			canonicalDistance := cmplxDistance(wantRoot, canonicalRoots[slot])
			if branch == 1 && unsignedSum >= 256 && canonicalDistance > 1e-3 {
				canonicalReencodeDistinguished = true
			}
			if branch == 0 {
				if canonicalDistance > 1e-9 {
					t.Fatalf("zero-selector canonical control lane=%d slot=%d distance=%g", lane, slot, canonicalDistance)
				}
			}
			if branch == 1 && pair == (Signed8LeafPair{Left: 5, Right: 7}) {
				if canonicalDistance > 1e-9 {
					t.Fatalf("fixed non-wrap selected-right canonical control lane=%d slot=%d distance=%g", lane, slot, canonicalDistance)
				}
				nonWrapCanonicalAgreement = true
			}
		}
	}
	return canonicalReencodeDistinguished, nonWrapCanonicalAgreement, maxRootError
}

func mustSigned8RootTreeNarrowRange(t *testing.T) Signed8NoOverflowRange {
	t.Helper()
	ranges, err := NewSigned8NoOverflowRange(-8, 7, -8, 7)
	if err != nil {
		t.Fatal(err)
	}
	return ranges
}

func independentlyMarshalSigned8RootTreeBoundaries(
	t *testing.T,
	params ckks.Parameters,
	states []Signed8RootTreeCiphertextState,
) Signed8RootTreeSerializedBytes {
	t.Helper()
	if len(states) != signed8RootTreeStateCount {
		t.Fatalf("cannot independently marshal %d root-tree states", len(states))
	}
	marshal := func(state Signed8RootTreeCiphertextState) int {
		ciphertext := ckks.NewCiphertext(params, state.Degree, state.Level)
		ciphertext.LogDimensions = state.LogDimensions
		ciphertext.IsBatched = true
		ciphertext.IsNTT = true
		switch state.Stage {
		case Signed8RootTreeStageRawProduct:
			ciphertext.Scale = params.DefaultScale().Mul(rlwe.NewScale(params.Q()[signed8RootTreeBranchLevel]))
		default:
			ciphertext.Scale = params.DefaultScale()
		}
		payload, err := ciphertext.MarshalBinary()
		if err != nil {
			t.Fatalf("independently marshal root-tree %s: %v", state.Stage, err)
		}
		return len(payload)
	}
	return Signed8RootTreeSerializedBytes{
		ComparatorGE:    marshal(states[signed8RootTreeComparatorStateIndex]),
		RawProduct:      marshal(states[signed8RootTreeRawProductStateIndex]),
		RescaledProduct: marshal(states[signed8RootTreeRescaledStateIndex]),
		Output:          marshal(states[signed8RootTreeOutputStateIndex]),
	}
}

func assertSigned8RootTreeRuntimeAccessorsAreDefensive(
	t *testing.T,
	result Signed8RootTreeResult,
	trace Signed8RootTreeTrace,
) {
	t.Helper()
	firstCiphertext, sealedCiphertext := result.Ciphertext(), result.Ciphertext()
	if firstCiphertext == nil || sealedCiphertext == nil {
		t.Fatal("root-tree result accessor returned nil")
	}
	firstCiphertext.Value[0].Coeffs[0][0]++
	if result.Ciphertext().Equal(firstCiphertext) || !result.Ciphertext().Equal(sealedCiphertext) {
		t.Fatal("root-tree result ciphertext accessor aliases sealed output")
	}

	states := trace.States()
	if len(states) == 0 {
		t.Fatal("root-tree trace has no states")
	}
	wantFirstLevel := states[signed8RootTreeComparatorStateIndex].Level
	states[signed8RootTreeComparatorStateIndex].Level = -1
	if trace.States()[signed8RootTreeComparatorStateIndex].Level != wantFirstLevel {
		t.Fatal("root-tree state accessor aliases sealed trace")
	}

	nested := trace.ComparatorTrace()
	if len(nested.states) == 0 || len(nested.a2bTrace.states) == 0 || len(nested.signProvenance.states) == 0 {
		t.Fatal("root-tree nested comparator evidence is incomplete")
	}
	nested.states[0].Level = -1
	nested.a2bTrace.states[0].Level = -1
	nested.signProvenance.states[0].Level = -1
	nested.keyPreflight.GraphMismatch = "mutated"
	nested.keyPreflight.MissingGaloisElements = append(nested.keyPreflight.MissingGaloisElements, 1)
	freshNested := trace.ComparatorTrace()
	if freshNested.states[0].Level == -1 || freshNested.a2bTrace.states[0].Level == -1 ||
		freshNested.signProvenance.states[0].Level == -1 || freshNested.keyPreflight.GraphMismatch == "mutated" ||
		len(freshNested.keyPreflight.MissingGaloisElements) != 0 {
		t.Fatal("root-tree comparator-trace accessor aliases nested evidence")
	}

	preflight := trace.KeyPreflight()
	preflight.GraphMismatch = "mutated"
	preflight.UnexpectedGaloisElements = append(preflight.UnexpectedGaloisElements, 1)
	freshPreflight := trace.KeyPreflight()
	if freshPreflight.GraphMismatch == "mutated" || len(freshPreflight.UnexpectedGaloisElements) != 0 {
		t.Fatal("root-tree key-preflight accessor aliases sealed evidence")
	}
}
