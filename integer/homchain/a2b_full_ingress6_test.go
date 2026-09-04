package homchain

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/bootstrapping"
	ckksdft "github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/dft"
	ckkslintrans "github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/lintrans"
	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/mod1"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/ring"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
)

func TestA2BFullIngress6ConstructsOnlyTheFixedL6Sibling(t *testing.T) {
	params, err := GaoA2BKernelFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	ranges := NewA2BFullIngress6FullRingRangeCertificate()
	circuit, err := NewA2BFullIngress6Circuit(
		params,
		ckks.NewEncoder(params, 192),
		ckks.NewEncoder(params, 256),
		A2BFullIngress6StandaloneTestFixtureV1,
		ranges,
	)
	if err != nil {
		t.Fatal(err)
	}
	if circuit.Profile().InputLevel() != 6 || circuit.Profile().RangeDigest() != ranges.Digest() {
		t.Fatalf("fixed ingress6 profile changed: %+v", circuit.Profile())
	}
}

type a2bFullIngress6InternalFixture struct {
	params    ckks.Parameters
	circuit   *A2BFullIngress6Circuit
	source    *bootstrapping.Evaluator
	evaluator *A2BFullIngress6Evaluator
	input     A2BFullIngress6Input
	keygen    *rlwe.KeyGenerator
	secretKey *rlwe.SecretKey
}

func newA2BFullIngress6InternalFixture(t *testing.T) a2bFullIngress6InternalFixture {
	t.Helper()
	params, err := GaoA2BKernelFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	circuit, err := NewA2BFullIngress6Circuit(
		params,
		ckks.NewEncoder(params, 192),
		ckks.NewEncoder(params, 256),
		A2BFullIngress6StandaloneTestFixtureV1,
		NewA2BFullIngress6FullRingRangeCertificate(),
	)
	if err != nil {
		t.Fatal(err)
	}
	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	dft := circuit.suffix.refresh.profile.dft
	bootstrapParameters := bootstrapping.Parameters{
		ResidualParameters:      params,
		BootstrappingParameters: params,
		SlotsToCoeffsParameters: dft.SlotsToCoeffsLiteral(),
		CoeffsToSlotsParameters: dft.CoeffsToSlotsLiteral(),
		Mod1ParametersLiteral: mod1.ParametersLiteral{
			LevelQ: dft.CoeffsToSlotsLiteral().LevelQ - 3, LogScale: params.LogDefaultScale(),
			Mod1Type: mod1.SinContinuous, LogMessageRatio: 15, K: 1, Mod1Degree: 3,
		},
		CircuitOrder: bootstrapping.Custom,
	}
	evaluationKeys := &bootstrapping.EvaluationKeys{MemEvaluationKeySet: rlwe.NewMemEvaluationKeySet(
		keyGenerator.GenRelinearizationKeyNew(secretKey),
		keyGenerator.GenGaloisKeysNew(circuit.RequiredKeyProfile().All(), secretKey)...,
	)}
	source, err := bootstrapping.NewEvaluator(bootstrapParameters, evaluationKeys)
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := circuit.BindEvaluator(source)
	if err != nil {
		t.Fatal(err)
	}
	input, err := circuit.BindInput(newA2BFullIngress6TestCiphertext(params, 6, params.DefaultScale()), params)
	if err != nil {
		t.Fatal(err)
	}
	return a2bFullIngress6InternalFixture{
		params: params, circuit: circuit, source: source, evaluator: evaluator, input: input,
		keygen: keyGenerator, secretKey: secretKey,
	}
}

func requireA2BFullIngress6ZeroOperationFailure(
	t *testing.T,
	result A2BFullResult,
	trace A2BFullIngress6Trace,
	err error,
) {
	t.Helper()
	if err == nil || !reflect.DeepEqual(result, A2BFullResult{}) || len(trace.States()) != 0 ||
		trace.OperationCounts() != (A2BFullIngress6OperationCounts{}) ||
		trace.SerializedBytes().OnlineTotal() != 0 || len(trace.SerializedBytes().RetainedBoundaries()) != 0 ||
		len(trace.retainedCiphertexts) != 0 || len(trace.RuntimeGaloisElements()) != 0 || trace.RelinearizationKeyMatched() {
		t.Fatalf("ingress6 failure was not pre-HE and zero-result: result=%+v states=%d counts=%+v bytes=%+v err=%v",
			result, len(trace.States()), trace.OperationCounts(), trace.SerializedBytes(), err)
	}
}

func a2bFullIngress6TestCiphertextFingerprint(ciphertext *rlwe.Ciphertext) string {
	if ciphertext == nil {
		return "nil"
	}
	payload, err := ciphertext.MarshalBinary()
	if err != nil {
		return "marshal-error:" + err.Error()
	}
	return fmt.Sprintf("%p:%s", ciphertext, sha256Hex(payload))
}

func a2bFullIngress6TestPlaintextFingerprint(plaintext *rlwe.Plaintext) string {
	if plaintext == nil {
		return "nil"
	}
	payload, err := plaintext.MarshalBinary()
	if err != nil {
		return "marshal-error:" + err.Error()
	}
	return fmt.Sprintf("%p:%s", plaintext, sha256Hex(payload))
}

func a2bFullIngress6MutationFingerprint(
	fixture *a2bFullIngress6InternalFixture,
	input A2BFullIngress6Input,
) string {
	var canonical strings.Builder
	fmt.Fprintf(&canonical, "input=%s|path=%s|params=%s|producer=%s|range=%s|admission=%s|payload=%s|binding=%s",
		a2bFullIngress6TestCiphertextFingerprint(input.ciphertext), input.pathDigest, input.parameterDigest,
		input.producerSource, input.rangeDigest, input.admissionDigest, input.payloadDigest, input.bindingDigest)
	if fixture == nil {
		return digestString(canonical.String())
	}
	circuit, evaluator := fixture.circuit, fixture.evaluator
	fmt.Fprintf(&canonical, "|fixture=%p|circuit=%p|source=%p|evaluator=%p", fixture, circuit, fixture.source, evaluator)
	if circuit != nil {
		fmt.Fprintf(&canonical, "|profile=%+v|ranges=%+v|mask=%s|iter1-mask=%s|id-scale=%s|special=%d/%d",
			circuit.profile, circuit.ranges, a2bFullIngress6TestPlaintextFingerprint(circuit.lowMask),
			a2bFullIngress6TestPlaintextFingerprint(circuit.suffix.iter1Mask),
			a2bFullIngress6TestPlaintextFingerprint(circuit.suffix.idScale),
			a2bRefreshLinearIdentity(circuit.specialB0.Low), a2bRefreshLinearIdentity(circuit.specialB0.High))
		fmt.Fprintf(&canonical, "|circuit-graph=%p/%p/%d/%d/%p/%p/%v/%v/%v/%v/%v/%v/%s/%s/%s/%s/%s",
			circuit.graph.circuit, circuit.graph.suffix, circuit.graph.specialLow, circuit.graph.specialHigh,
			circuit.graph.mask, circuit.graph.maskSeal, circuit.graph.firstSTCFactors,
			circuit.graph.sharedCTSFactors, circuit.graph.secondSTCFactors,
			circuit.graph.firstSTCPayloadDigests, circuit.graph.sharedCTSPayloadDigests, circuit.graph.secondSTCPayloadDigests,
			circuit.graph.firstSTCPayloadDigest, circuit.graph.sharedCTSPayloadDigest, circuit.graph.secondSTCPayloadDigest,
			circuit.graph.profileDigest, circuit.graph.keyDigest)
		fmt.Fprintf(&canonical, "|circuit-mask-seal=%s", a2bFullIngress6TestPlaintextFingerprint(circuit.graph.maskSeal))
		firstDigests, firstGroup, firstErr := digestA2BFullIngress6EncodedFactorGroup("first-stc", circuit.firstSTC.Matrices)
		sharedDigests, sharedGroup, sharedErr := digestA2BFullIngress6EncodedFactorGroup("shared-cts", circuit.suffix.refresh.cts.Matrices)
		secondDigests, secondGroup, secondErr := digestA2BFullIngress6EncodedFactorGroup("second-stc", circuit.suffix.secondSTC.Matrices)
		fmt.Fprintf(&canonical, "|actual-payloads=%v/%s/%v;%v/%s/%v;%v/%s/%v",
			firstDigests, firstGroup, firstErr, sharedDigests, sharedGroup, sharedErr, secondDigests, secondGroup, secondErr)
		for index, factor := range circuit.firstSTC.Matrices {
			fmt.Fprintf(&canonical, "|first-stc-%d=%d", index, a2bRefreshLinearIdentity(factor))
		}
		for index, factor := range circuit.suffix.refresh.cts.Matrices {
			fmt.Fprintf(&canonical, "|cts-%d=%d", index, a2bRefreshLinearIdentity(factor))
		}
		for index, factor := range circuit.suffix.secondSTC.Matrices {
			fmt.Fprintf(&canonical, "|second-stc-%d=%d", index, a2bRefreshLinearIdentity(factor))
		}
	}
	if evaluator != nil {
		fmt.Fprintf(&canonical, "|eval-graph=%p/%p/%d/%d/%p/%p/%v/%v/%v/%v/%v/%v/%s/%s/%s/%s/%s|eval-suffix=%p",
			evaluator.graph.circuit, evaluator.graph.suffix, evaluator.graph.specialLow, evaluator.graph.specialHigh,
			evaluator.graph.mask, evaluator.graph.maskSeal, evaluator.graph.firstSTCFactors,
			evaluator.graph.sharedCTSFactors, evaluator.graph.secondSTCFactors,
			evaluator.graph.firstSTCPayloadDigests, evaluator.graph.sharedCTSPayloadDigests, evaluator.graph.secondSTCPayloadDigests,
			evaluator.graph.firstSTCPayloadDigest, evaluator.graph.sharedCTSPayloadDigest, evaluator.graph.secondSTCPayloadDigest,
			evaluator.graph.profileDigest, evaluator.graph.keyDigest, evaluator.suffix)
		fmt.Fprintf(&canonical, "|eval-mask-seal=%s", a2bFullIngress6TestPlaintextFingerprint(evaluator.graph.maskSeal))
		if evaluator.suffix != nil {
			fmt.Fprintf(&canonical, "|suffix-keyset=%p|suffix-relin=%p", evaluator.suffix.keySet, evaluator.suffix.relinearizationKey)
			elements := make([]uint64, 0, len(evaluator.suffix.galoisKeys))
			for element := range evaluator.suffix.galoisKeys {
				elements = append(elements, element)
			}
			sort.Slice(elements, func(i, j int) bool { return elements[i] < elements[j] })
			for _, element := range elements {
				fmt.Fprintf(&canonical, "|suffix-galois-%d=%p", element, evaluator.suffix.galoisKeys[element])
			}
		}
	}
	if fixture.source != nil && fixture.source.MemEvaluationKeySet != nil {
		keys := fixture.source.MemEvaluationKeySet
		fmt.Fprintf(&canonical, "|keyset=%p|relin=%p", keys, keys.RelinearizationKey)
		elements := append([]uint64(nil), keys.GetGaloisKeysList()...)
		sort.Slice(elements, func(i, j int) bool { return elements[i] < elements[j] })
		for _, element := range elements {
			fmt.Fprintf(&canonical, "|galois-%d=%p/%d", element, keys.GaloisKeys[element], keys.GaloisKeys[element].GaloisElement)
		}
	}
	return digestString(canonical.String())
}

func TestA2BFullIngress6CompletePreHEMutationMatrix(t *testing.T) {
	type mutation struct {
		name   string
		mutate func(*a2bFullIngress6InternalFixture, *A2BFullIngress6Input)
	}
	firstElement := func(fixture *a2bFullIngress6InternalFixture) uint64 {
		return fixture.circuit.RequiredKeyProfile().All()[0]
	}
	mutations := []mutation{
		{"nil-evaluator-result-seam", func(fixture *a2bFullIngress6InternalFixture, _ *A2BFullIngress6Input) { fixture.evaluator = nil }},
		{"zero-input-seam", func(_ *a2bFullIngress6InternalFixture, input *A2BFullIngress6Input) { *input = A2BFullIngress6Input{} }},
		{"nil-input-ciphertext", func(_ *a2bFullIngress6InternalFixture, input *A2BFullIngress6Input) { input.ciphertext = nil }},
		{"payload-coefficient", func(_ *a2bFullIngress6InternalFixture, input *A2BFullIngress6Input) {
			input.ciphertext.Value[0].Coeffs[0][0] ^= 1
		}},
		{"payload-digest", func(_ *a2bFullIngress6InternalFixture, input *A2BFullIngress6Input) { input.payloadDigest = "tampered" }},
		{"binding-certificate", func(_ *a2bFullIngress6InternalFixture, input *A2BFullIngress6Input) { input.bindingDigest = "tampered" }},
		{"path-certificate", func(_ *a2bFullIngress6InternalFixture, input *A2BFullIngress6Input) { input.pathDigest = "tampered" }},
		{"parameter-certificate", func(_ *a2bFullIngress6InternalFixture, input *A2BFullIngress6Input) {
			input.parameterDigest = "tampered"
		}},
		{"producer-certificate", func(_ *a2bFullIngress6InternalFixture, input *A2BFullIngress6Input) {
			input.producerSource = A2BFullIngress6Depth2PrefixL6V1
		}},
		{"range-certificate", func(_ *a2bFullIngress6InternalFixture, input *A2BFullIngress6Input) { input.rangeDigest = "tampered" }},
		{"admission-certificate", func(_ *a2bFullIngress6InternalFixture, input *A2BFullIngress6Input) {
			input.admissionDigest = "tampered"
		}},
		{"relinearization-deleted", func(fixture *a2bFullIngress6InternalFixture, _ *A2BFullIngress6Input) {
			fixture.source.MemEvaluationKeySet.RelinearizationKey = nil
		}},
		{"relinearization-replaced", func(fixture *a2bFullIngress6InternalFixture, _ *A2BFullIngress6Input) {
			foreign := ckks.NewKeyGenerator(fixture.params)
			fixture.source.MemEvaluationKeySet.RelinearizationKey = foreign.GenRelinearizationKeyNew(foreign.GenSecretKeyNew())
		}},
		{"galois-deleted", func(fixture *a2bFullIngress6InternalFixture, _ *A2BFullIngress6Input) {
			delete(fixture.source.MemEvaluationKeySet.GaloisKeys, firstElement(fixture))
		}},
		{"galois-wrong-element", func(fixture *a2bFullIngress6InternalFixture, _ *A2BFullIngress6Input) {
			elements := fixture.circuit.RequiredKeyProfile().All()
			fixture.source.MemEvaluationKeySet.GaloisKeys[elements[0]] = fixture.source.MemEvaluationKeySet.GaloisKeys[elements[1]]
		}},
		{"galois-same-element-pointer-replaced", func(fixture *a2bFullIngress6InternalFixture, _ *A2BFullIngress6Input) {
			element := firstElement(fixture)
			foreign := ckks.NewKeyGenerator(fixture.params)
			fixture.source.MemEvaluationKeySet.GaloisKeys[element] = foreign.GenGaloisKeyNew(element, foreign.GenSecretKeyNew())
		}},
		{"galois-extra", func(fixture *a2bFullIngress6InternalFixture, _ *A2BFullIngress6Input) {
			required := make(map[uint64]bool)
			for _, element := range fixture.circuit.RequiredKeyProfile().All() {
				required[element] = true
			}
			for rotation := 1; rotation < fixture.params.MaxSlots(); rotation++ {
				element := fixture.params.GaloisElement(rotation)
				if !required[element] {
					fixture.source.MemEvaluationKeySet.GaloisKeys[element] = fixture.keygen.GenGaloisKeyNew(element, fixture.secretKey)
					return
				}
			}
			panic("no extra Galois element fixture")
		}},
		{"evaluator-graph-profile-seal", func(fixture *a2bFullIngress6InternalFixture, _ *A2BFullIngress6Input) {
			fixture.evaluator.graph.profileDigest = "tampered"
		}},
		{"evaluator-graph-mask-seal", func(fixture *a2bFullIngress6InternalFixture, _ *A2BFullIngress6Input) {
			fixture.evaluator.graph.maskSeal.Scale = rlwe.NewScale(1)
		}},
		{"evaluator-graph-first-stc-seal", func(fixture *a2bFullIngress6InternalFixture, _ *A2BFullIngress6Input) {
			fixture.evaluator.graph.firstSTCFactors[0] = 0
		}},
		{"evaluator-graph-cts-seal", func(fixture *a2bFullIngress6InternalFixture, _ *A2BFullIngress6Input) {
			fixture.evaluator.graph.sharedCTSFactors[0] = 0
		}},
		{"evaluator-graph-second-stc-seal", func(fixture *a2bFullIngress6InternalFixture, _ *A2BFullIngress6Input) {
			fixture.evaluator.graph.secondSTCFactors[0] = 0
		}},
		{"evaluator-graph-first-stc-payload-seal", func(fixture *a2bFullIngress6InternalFixture, _ *A2BFullIngress6Input) {
			fixture.evaluator.graph.firstSTCPayloadDigests[0] = "tampered"
		}},
		{"evaluator-graph-shared-cts-payload-seal", func(fixture *a2bFullIngress6InternalFixture, _ *A2BFullIngress6Input) {
			fixture.evaluator.graph.sharedCTSPayloadDigests[0] = "tampered"
		}},
		{"evaluator-graph-second-stc-payload-seal", func(fixture *a2bFullIngress6InternalFixture, _ *A2BFullIngress6Input) {
			fixture.evaluator.graph.secondSTCPayloadDigests[0] = "tampered"
		}},
		{"evaluator-graph-first-stc-payload-group", func(fixture *a2bFullIngress6InternalFixture, _ *A2BFullIngress6Input) {
			fixture.evaluator.graph.firstSTCPayloadDigest = "tampered"
		}},
		{"evaluator-graph-shared-cts-payload-group", func(fixture *a2bFullIngress6InternalFixture, _ *A2BFullIngress6Input) {
			fixture.evaluator.graph.sharedCTSPayloadDigest = "tampered"
		}},
		{"evaluator-graph-second-stc-payload-group", func(fixture *a2bFullIngress6InternalFixture, _ *A2BFullIngress6Input) {
			fixture.evaluator.graph.secondSTCPayloadDigest = "tampered"
		}},
		{"circuit-graph-profile-cache", func(fixture *a2bFullIngress6InternalFixture, _ *A2BFullIngress6Input) {
			fixture.circuit.graph.profileDigest = "tampered"
		}},
		{"circuit-graph-mask-cache", func(fixture *a2bFullIngress6InternalFixture, _ *A2BFullIngress6Input) {
			fixture.circuit.graph.maskSeal.Scale = rlwe.NewScale(1)
		}},
		{"circuit-graph-first-stc-truncated", func(fixture *a2bFullIngress6InternalFixture, _ *A2BFullIngress6Input) {
			fixture.circuit.graph.firstSTCFactors = fixture.circuit.graph.firstSTCFactors[:1]
		}},
		{"circuit-graph-first-stc-appended", func(fixture *a2bFullIngress6InternalFixture, _ *A2BFullIngress6Input) {
			fixture.circuit.graph.firstSTCFactors = append(append([]uintptr(nil), fixture.circuit.graph.firstSTCFactors...), 1)
		}},
		{"circuit-graph-cts-truncated", func(fixture *a2bFullIngress6InternalFixture, _ *A2BFullIngress6Input) {
			fixture.circuit.graph.sharedCTSFactors = fixture.circuit.graph.sharedCTSFactors[:2]
		}},
		{"circuit-graph-cts-appended", func(fixture *a2bFullIngress6InternalFixture, _ *A2BFullIngress6Input) {
			fixture.circuit.graph.sharedCTSFactors = append(append([]uintptr(nil), fixture.circuit.graph.sharedCTSFactors...), 1)
		}},
		{"circuit-graph-second-stc-truncated", func(fixture *a2bFullIngress6InternalFixture, _ *A2BFullIngress6Input) {
			fixture.circuit.graph.secondSTCFactors = fixture.circuit.graph.secondSTCFactors[:1]
		}},
		{"circuit-graph-second-stc-appended", func(fixture *a2bFullIngress6InternalFixture, _ *A2BFullIngress6Input) {
			fixture.circuit.graph.secondSTCFactors = append(append([]uintptr(nil), fixture.circuit.graph.secondSTCFactors...), 1)
		}},
		{"circuit-graph-first-stc-payload-truncated", func(fixture *a2bFullIngress6InternalFixture, _ *A2BFullIngress6Input) {
			fixture.circuit.graph.firstSTCPayloadDigests = fixture.circuit.graph.firstSTCPayloadDigests[:1]
		}},
		{"circuit-graph-first-stc-payload-appended", func(fixture *a2bFullIngress6InternalFixture, _ *A2BFullIngress6Input) {
			fixture.circuit.graph.firstSTCPayloadDigests = append(append([]string(nil), fixture.circuit.graph.firstSTCPayloadDigests...), "tampered")
		}},
		{"circuit-graph-shared-cts-payload-truncated", func(fixture *a2bFullIngress6InternalFixture, _ *A2BFullIngress6Input) {
			fixture.circuit.graph.sharedCTSPayloadDigests = fixture.circuit.graph.sharedCTSPayloadDigests[:2]
		}},
		{"circuit-graph-shared-cts-payload-appended", func(fixture *a2bFullIngress6InternalFixture, _ *A2BFullIngress6Input) {
			fixture.circuit.graph.sharedCTSPayloadDigests = append(append([]string(nil), fixture.circuit.graph.sharedCTSPayloadDigests...), "tampered")
		}},
		{"circuit-graph-second-stc-payload-truncated", func(fixture *a2bFullIngress6InternalFixture, _ *A2BFullIngress6Input) {
			fixture.circuit.graph.secondSTCPayloadDigests = fixture.circuit.graph.secondSTCPayloadDigests[:1]
		}},
		{"circuit-graph-second-stc-payload-appended", func(fixture *a2bFullIngress6InternalFixture, _ *A2BFullIngress6Input) {
			fixture.circuit.graph.secondSTCPayloadDigests = append(append([]string(nil), fixture.circuit.graph.secondSTCPayloadDigests...), "tampered")
		}},
		{"circuit-profile", func(fixture *a2bFullIngress6InternalFixture, _ *A2BFullIngress6Input) {
			fixture.circuit.profile.digest = "tampered"
		}},
		{"circuit-profile-first-stc-payload", func(fixture *a2bFullIngress6InternalFixture, _ *A2BFullIngress6Input) {
			fixture.circuit.profile.firstSTCEncodedPayloadDigest = "tampered"
		}},
		{"circuit-mask-pointer", func(fixture *a2bFullIngress6InternalFixture, _ *A2BFullIngress6Input) {
			fixture.circuit.lowMask = fixture.circuit.lowMask.CopyNew()
		}},
		{"circuit-first-stc-factor", func(fixture *a2bFullIngress6InternalFixture, _ *A2BFullIngress6Input) {
			fixture.circuit.firstSTC.Matrices[0] = fixture.circuit.firstSTC.Matrices[1]
		}},
		{"circuit-cts-factor", func(fixture *a2bFullIngress6InternalFixture, _ *A2BFullIngress6Input) {
			fixture.circuit.suffix.refresh.cts.Matrices[0] = fixture.circuit.suffix.refresh.cts.Matrices[1]
		}},
		{"circuit-second-stc-factor", func(fixture *a2bFullIngress6InternalFixture, _ *A2BFullIngress6Input) {
			fixture.circuit.suffix.secondSTC.Matrices[0] = fixture.circuit.suffix.secondSTC.Matrices[1]
		}},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			fixture := newA2BFullIngress6InternalFixture(t)
			input := fixture.input
			test.mutate(&fixture, &input)
			before := a2bFullIngress6MutationFingerprint(&fixture, input)
			var result A2BFullResult
			var trace A2BFullIngress6Trace
			var err error
			if fixture.evaluator == nil {
				var evaluator *A2BFullIngress6Evaluator
				result, trace, err = evaluator.EvaluateNew(input)
			} else {
				result, trace, err = fixture.evaluator.EvaluateNew(input)
			}
			requireA2BFullIngress6ZeroOperationFailure(t, result, trace, err)
			after := a2bFullIngress6MutationFingerprint(&fixture, input)
			if before != after {
				t.Fatalf("pre-HE failure mutated input/graph/cache/key state: before=%s after=%s", before, after)
			}
		})
	}
}

func TestA2BFullIngress6EvaluatorGraphSealLengthsFailClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*a2bFullIngress6CircuitGraph)
	}{
		{"first-stc-truncated", func(graph *a2bFullIngress6CircuitGraph) { graph.firstSTCFactors = graph.firstSTCFactors[:1] }},
		{"first-stc-empty", func(graph *a2bFullIngress6CircuitGraph) { graph.firstSTCFactors = nil }},
		{"first-stc-appended", func(graph *a2bFullIngress6CircuitGraph) { graph.firstSTCFactors = append(graph.firstSTCFactors, 1) }},
		{"shared-cts-truncated", func(graph *a2bFullIngress6CircuitGraph) { graph.sharedCTSFactors = graph.sharedCTSFactors[:2] }},
		{"shared-cts-empty", func(graph *a2bFullIngress6CircuitGraph) { graph.sharedCTSFactors = nil }},
		{"shared-cts-appended", func(graph *a2bFullIngress6CircuitGraph) { graph.sharedCTSFactors = append(graph.sharedCTSFactors, 1) }},
		{"second-stc-truncated", func(graph *a2bFullIngress6CircuitGraph) { graph.secondSTCFactors = graph.secondSTCFactors[:1] }},
		{"second-stc-empty", func(graph *a2bFullIngress6CircuitGraph) { graph.secondSTCFactors = nil }},
		{"second-stc-appended", func(graph *a2bFullIngress6CircuitGraph) { graph.secondSTCFactors = append(graph.secondSTCFactors, 1) }},
		{"first-stc-payload-truncated", func(graph *a2bFullIngress6CircuitGraph) {
			graph.firstSTCPayloadDigests = graph.firstSTCPayloadDigests[:1]
		}},
		{"first-stc-payload-empty", func(graph *a2bFullIngress6CircuitGraph) { graph.firstSTCPayloadDigests = nil }},
		{"first-stc-payload-appended", func(graph *a2bFullIngress6CircuitGraph) {
			graph.firstSTCPayloadDigests = append(graph.firstSTCPayloadDigests, "tampered")
		}},
		{"shared-cts-payload-truncated", func(graph *a2bFullIngress6CircuitGraph) {
			graph.sharedCTSPayloadDigests = graph.sharedCTSPayloadDigests[:2]
		}},
		{"shared-cts-payload-empty", func(graph *a2bFullIngress6CircuitGraph) { graph.sharedCTSPayloadDigests = nil }},
		{"shared-cts-payload-appended", func(graph *a2bFullIngress6CircuitGraph) {
			graph.sharedCTSPayloadDigests = append(graph.sharedCTSPayloadDigests, "tampered")
		}},
		{"second-stc-payload-truncated", func(graph *a2bFullIngress6CircuitGraph) {
			graph.secondSTCPayloadDigests = graph.secondSTCPayloadDigests[:1]
		}},
		{"second-stc-payload-empty", func(graph *a2bFullIngress6CircuitGraph) { graph.secondSTCPayloadDigests = nil }},
		{"second-stc-payload-appended", func(graph *a2bFullIngress6CircuitGraph) {
			graph.secondSTCPayloadDigests = append(graph.secondSTCPayloadDigests, "tampered")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newA2BFullIngress6InternalFixture(t)
			test.mutate(&fixture.evaluator.graph)
			result, trace, err := fixture.evaluator.EvaluateNew(fixture.input)
			requireA2BFullIngress6ZeroOperationFailure(t, result, trace, err)
		})
	}
}

func mutateA2BFullIngress6EncodedDiagonalCoefficient(
	t *testing.T,
	factor *ckkslintrans.LinearTransformation,
) (diagonal int, mutated uint64, restore func()) {
	t.Helper()
	if factor == nil || len(factor.Vec) == 0 {
		t.Fatal("ingress6 encoded factor has no diagonal payload")
	}
	indexes := make([]int, 0, len(factor.Vec))
	for index := range factor.Vec {
		indexes = append(indexes, index)
	}
	sort.Ints(indexes)
	diagonal = indexes[0]
	encoded := factor.Vec[diagonal]
	if len(encoded.Q.Coeffs) == 0 || len(encoded.Q.Coeffs[0]) == 0 {
		t.Fatalf("ingress6 encoded factor diagonal %d has no Q coefficient payload", diagonal)
	}
	original := encoded.Q.Coeffs[0][0]
	encoded.Q.Coeffs[0][0] = original ^ 1
	mutated = encoded.Q.Coeffs[0][0]
	return diagonal, mutated, func() { encoded.Q.Coeffs[0][0] = original }
}

func requireA2BFullIngress6EncodedPayloadMutationFailsClosed(
	t *testing.T,
	fixture *a2bFullIngress6InternalFixture,
	matrix *ckksdft.Matrix,
	factorIndex int,
) {
	t.Helper()
	if matrix == nil || factorIndex < 0 || factorIndex >= len(matrix.Matrices) {
		t.Fatalf("invalid ingress6 encoded-factor fixture index %d", factorIndex)
	}
	literalBefore := cloneDFTLiteral(matrix.MatrixLiteral)
	profileBefore := fixture.circuit.Profile()
	slicePointerBefore := reflect.ValueOf(matrix.Matrices).Pointer()
	pointerBefore := a2bRefreshLinearIdentity(matrix.Matrices[factorIndex])
	diagonal, mutated, restore := mutateA2BFullIngress6EncodedDiagonalCoefficient(t, &matrix.Matrices[factorIndex])
	defer restore()
	if slicePointerAfter, pointerAfter := reflect.ValueOf(matrix.Matrices).Pointer(), a2bRefreshLinearIdentity(matrix.Matrices[factorIndex]); slicePointerAfter != slicePointerBefore || pointerAfter != pointerBefore {
		t.Fatalf("in-place encoded mutation changed matrix slice or factor map pointer: slice=%d/%d map=%d/%d",
			slicePointerBefore, slicePointerAfter, pointerBefore, pointerAfter)
	}
	if !a2bRefreshLiteralEqual(matrix.MatrixLiteral, literalBefore) ||
		!reflect.DeepEqual(fixture.circuit.Profile(), profileBefore) {
		t.Fatal("in-place encoded mutation changed MatrixLiteral or public profile")
	}

	input := fixture.input
	before := a2bFullIngress6MutationFingerprint(fixture, input)
	result, trace, err := fixture.evaluator.EvaluateNew(input)
	requireA2BFullIngress6ZeroOperationFailure(t, result, trace, err)
	encoded := matrix.Matrices[factorIndex].Vec[diagonal]
	if got := encoded.Q.Coeffs[0][0]; got != mutated {
		t.Fatalf("pre-HE failure rewrote mutated encoded coefficient: got=%d want=%d", got, mutated)
	}
	if slicePointerAfter, pointerAfter := reflect.ValueOf(matrix.Matrices).Pointer(), a2bRefreshLinearIdentity(matrix.Matrices[factorIndex]); slicePointerAfter != slicePointerBefore || pointerAfter != pointerBefore ||
		!a2bRefreshLiteralEqual(matrix.MatrixLiteral, literalBefore) ||
		!reflect.DeepEqual(fixture.circuit.Profile(), profileBefore) {
		t.Fatal("pre-HE failure changed factor pointer, MatrixLiteral, or public profile")
	}
	after := a2bFullIngress6MutationFingerprint(fixture, input)
	if before != after {
		t.Fatalf("pre-HE encoded-payload failure mutated input/graph/cache/key state: before=%s after=%s", before, after)
	}
}

func TestA2BFullIngress6FirstSTCEncodedPayloadMutationFailsClosed(t *testing.T) {
	for factorIndex := 0; factorIndex < 2; factorIndex++ {
		t.Run(fmt.Sprintf("factor-%d", factorIndex), func(t *testing.T) {
			fixture := newA2BFullIngress6InternalFixture(t)
			requireA2BFullIngress6EncodedPayloadMutationFailsClosed(t, &fixture, &fixture.circuit.firstSTC, factorIndex)
		})
	}
}

func TestA2BFullIngress6SharedCTSEncodedPayloadMutationFailsClosed(t *testing.T) {
	for factorIndex := 0; factorIndex < 3; factorIndex++ {
		t.Run(fmt.Sprintf("factor-%d", factorIndex), func(t *testing.T) {
			fixture := newA2BFullIngress6InternalFixture(t)
			requireA2BFullIngress6EncodedPayloadMutationFailsClosed(t, &fixture, &fixture.circuit.suffix.refresh.cts, factorIndex)
		})
	}
}

func TestA2BFullIngress6SecondSTCEncodedPayloadMutationFailsClosed(t *testing.T) {
	for factorIndex := 0; factorIndex < 2; factorIndex++ {
		t.Run(fmt.Sprintf("factor-%d", factorIndex), func(t *testing.T) {
			fixture := newA2BFullIngress6InternalFixture(t)
			requireA2BFullIngress6EncodedPayloadMutationFailsClosed(t, &fixture, &fixture.circuit.suffix.secondSTC, factorIndex)
		})
	}
}

func TestA2BFullIngress6AdmissionOwnsAndBindsTheExactL6Payload(t *testing.T) {
	params, err := GaoA2BKernelFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	ranges := NewA2BFullIngress6FullRingRangeCertificate()
	circuit, err := NewA2BFullIngress6Circuit(
		params,
		ckks.NewEncoder(params, 192),
		ckks.NewEncoder(params, 256),
		A2BFullIngress6StandaloneTestFixtureV1,
		ranges,
	)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := newA2BFullIngress6TestCiphertext(params, 6, params.DefaultScale())
	before := ciphertext.CopyNew()
	input, err := circuit.BindInput(ciphertext, params)
	if err != nil {
		t.Fatal(err)
	}
	if !ciphertext.Equal(before) || input.PayloadDigest() == "" ||
		input.RangeDigest() != ranges.Digest() ||
		input.AdmissionDigest() != circuit.Profile().AdmissionDigest() ||
		input.ParameterDigest() != circuit.Profile().ParameterDigest() {
		t.Fatalf("ingress6 admission evidence is incomplete: %+v", input)
	}
	ciphertext.Resize(ciphertext.Degree(), 0)
	if input.Level() != 6 {
		t.Fatal("ingress6 admission aliases the caller ciphertext")
	}

	invalid := []struct {
		name   string
		mutate func(*rlwe.Ciphertext)
	}{
		{"level5", func(ct *rlwe.Ciphertext) { ct.Resize(ct.Degree(), 5) }},
		{"level7", func(ct *rlwe.Ciphertext) { ct.Resize(ct.Degree(), 7) }},
		{"wrong-scale", func(ct *rlwe.Ciphertext) { ct.Scale = rlwe.NewScale(uint64(1) << 34) }},
		{"degree2", func(ct *rlwe.Ciphertext) { ct.Resize(2, ct.Level()) }},
		{"partial", func(ct *rlwe.Ciphertext) { ct.LogDimensions.Cols-- }},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			candidate := newA2BFullIngress6TestCiphertext(params, 6, params.DefaultScale())
			test.mutate(candidate)
			candidateBefore := candidate.CopyNew()
			if got, bindErr := circuit.BindInput(candidate, params); bindErr == nil || !reflect.DeepEqual(got, A2BFullIngress6Input{}) || !candidate.Equal(candidateBefore) {
				t.Fatalf("invalid ingress was admitted or mutated: input=%+v err=%v", got, bindErr)
			}
		})
	}

	foreign, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN: 5, LogQ: []int{50, 35, 35, 35, 35, 35, 34}, LogP: []int{50}, LogDefaultScale: 35,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, bindErr := circuit.BindInput(newA2BFullIngress6TestCiphertext(params, 6, params.DefaultScale()), foreign); bindErr == nil || !reflect.DeepEqual(got, A2BFullIngress6Input{}) {
		t.Fatalf("foreign declared origin was admitted: input=%+v err=%v", got, bindErr)
	}
}

func TestA2BFullIngress6RejectsOpenEndedProducerAndRangeTokens(t *testing.T) {
	params, err := GaoA2BKernelFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	refreshEncoder := ckks.NewEncoder(params, 192)
	kernelEncoder := ckks.NewEncoder(params, 256)
	if _, err = NewA2BFullIngress6Circuit(params, refreshEncoder, kernelEncoder, A2BFullIngress6Source("caller-string"), NewA2BFullIngress6FullRingRangeCertificate()); err == nil {
		t.Fatal("arbitrary producer string unlocked ingress6")
	}
	if _, err = NewA2BFullIngress6Circuit(params, refreshEncoder, kernelEncoder, A2BFullIngress6Depth2PrefixL6V1, A2BFullIngress6RangeCertificate{}); err == nil {
		t.Fatal("zero or caller-forged range certificate unlocked ingress6")
	}
}

func TestA2BFullIngress6BoundPayloadAndPrivateCertificateSelfCheck(t *testing.T) {
	params, err := GaoA2BKernelFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	circuit, err := NewA2BFullIngress6Circuit(
		params,
		ckks.NewEncoder(params, 192),
		ckks.NewEncoder(params, 256),
		A2BFullIngress6Depth2PrefixL6V1,
		NewA2BFullIngress6FullRingRangeCertificate(),
	)
	if err != nil {
		t.Fatal(err)
	}
	input, err := circuit.BindInput(newA2BFullIngress6TestCiphertext(params, 6, params.DefaultScale()), params)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*A2BFullIngress6Input)
	}{
		{"payload-level", func(candidate *A2BFullIngress6Input) { candidate.ciphertext.Resize(candidate.ciphertext.Degree(), 5) }},
		{"payload-scale", func(candidate *A2BFullIngress6Input) { candidate.ciphertext.Scale = rlwe.NewScale(uint64(1) << 34) }},
		{"payload-digest", func(candidate *A2BFullIngress6Input) { candidate.payloadDigest = "tampered" }},
		{"binding-digest", func(candidate *A2BFullIngress6Input) { candidate.bindingDigest = "tampered" }},
		{"producer", func(candidate *A2BFullIngress6Input) {
			candidate.producerSource = A2BFullIngress6StandaloneTestFixtureV1
		}},
		{"range", func(candidate *A2BFullIngress6Input) { candidate.rangeDigest = "tampered" }},
		{"admission", func(candidate *A2BFullIngress6Input) { candidate.admissionDigest = "tampered" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := input
			candidate.ciphertext = input.ciphertext.CopyNew()
			test.mutate(&candidate)
			if err := circuit.validateInput(candidate); err == nil {
				t.Fatal("post-bind payload or certificate tamper passed private validation")
			}
		})
	}
}

func TestA2BFullIngress6SourceHasNoOpenIngressOrForbiddenRefreshBridge(t *testing.T) {
	params, err := GaoA2BKernelFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	circuit, err := NewA2BFullIngress6Circuit(
		params,
		ckks.NewEncoder(params, 192),
		ckks.NewEncoder(params, 256),
		A2BFullIngress6StandaloneTestFixtureV1,
		NewA2BFullIngress6FullRingRangeCertificate(),
	)
	if err != nil {
		t.Fatal(err)
	}
	typeOfCircuit := reflect.TypeOf(circuit)
	methods := make([]string, typeOfCircuit.NumMethod())
	for index := range methods {
		methods[index] = typeOfCircuit.Method(index).Name
	}
	if want := []string{"BindEvaluator", "BindInput", "Profile", "RequiredKeyProfile"}; !reflect.DeepEqual(methods, want) {
		t.Fatalf("ingress6 public surface=%v, want fixed sibling surface %v", methods, want)
	}
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate ingress6 source")
	}
	payload, err := os.ReadFile(filepath.Join(filepath.Dir(currentFile), "a2b_full_ingress6.go"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(payload)
	for _, forbidden := range []string{
		"AtIngress", ".SetScale(", "DecryptNew(", "EncryptNew(",
		"DropLevel(scaledDown", "DropLevel(current", "trace.operationCounts = e.circuit.profile.operationCounts",
		"marshalA2BFullIngress6StateTemplate", "appendA2BFullIngress6Iter1RefreshStates",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("ingress6 source contains forbidden open ingress, relabel, legacy conversion, or copied ledger %q", forbidden)
		}
	}
	for _, witness := range []string{
		"ScaleDown(current.CopyNew())", "ModUp(scaledDown)",
		"SubNew(highAligned, id0Over16)", "SubNew(lowAligned, id0)",
		"refreshIter1(iter1Masked", "ScaleDown(stc.CopyNew())",
		"measureA2BFullIngress6RuntimeSerializedBytes", "lowMSB: msb0", "highMSB: msb1",
	} {
		if !strings.Contains(source, witness) {
			t.Fatalf("ingress6 source omits fixed physical-graph witness %q", witness)
		}
	}
}

func newA2BFullIngress6TestCiphertext(params ckks.Parameters, level int, scale rlwe.Scale) *rlwe.Ciphertext {
	ciphertext := ckks.NewCiphertext(params, 1, level)
	ciphertext.Scale = scale
	ciphertext.LogDimensions = ring.Dimensions{Rows: 0, Cols: params.LogMaxSlots()}
	ciphertext.IsBatched = true
	ciphertext.IsNTT = true
	return ciphertext
}

func TestA2BFullIngress6ProfileSealsTheMeasuredPrefixAndAcceptedSuffix(t *testing.T) {
	params, err := GaoA2BKernelFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	ranges := NewA2BFullIngress6FullRingRangeCertificate()
	circuit, err := NewA2BFullIngress6Circuit(
		params,
		ckks.NewEncoder(params, 192),
		ckks.NewEncoder(params, 256),
		A2BFullIngress6StandaloneTestFixtureV1,
		ranges,
	)
	if err != nil {
		t.Fatal(err)
	}
	profile := circuit.Profile()
	if profile.Fidelity() != A2BFullFunctionalLattigoAdaptationNotSecureNotSourceSecure ||
		profile.Schedule() != A2BFullIngress6SerialLowThenHigh ||
		profile.InputLevel() != 6 || profile.OutputLevel() != 5 ||
		!profile.InputScale().EqualScale(params.DefaultScale()) ||
		!reflect.DeepEqual(profile.FirstSTCFactorOutputLevels(), []int{3, 2}) ||
		profile.Source() != A2BFullIngress6StandaloneTestFixtureV1 ||
		profile.RangeDigest() != ranges.Digest() || profile.ParameterDigest() == "" ||
		profile.AdmissionDigest() == "" || profile.Digest() == "" {
		t.Fatalf("fixed ingress6 profile is incomplete: %+v", profile)
	}
	if profile.TrustedOriginAssumption() != A2BFullIngress6TrustedDeclaredOrigin ||
		profile.SuffixProfileDigest() == "" || profile.KeyProfileDigest() == "" ||
		profile.FirstSTCExecutionMatrixDigest() == "" ||
		profile.SharedCTSExecutionMatrixDigest() == "" ||
		profile.FirstSTCEncodedPayloadDigest() == "" ||
		profile.SharedCTSEncodedPayloadDigest() == "" ||
		profile.SecondSTCEncodedPayloadDigest() == "" ||
		profile.LevelLedger() != "input6->special5->mask4->first-stc-factor3/2->sd0->mu20->cts17->kernel5->id0/16-4->high5-drop4-sub->iter1-mask3->stc1->sd0->mu20->cts17->kernel5->low5/high5" {
		t.Fatalf("fixed ingress6 graph ledger is incomplete: %+v", profile)
	}
	baseline, err := NewA2BFullCircuit(params, ckks.NewEncoder(params, 192), ckks.NewEncoder(params, 256))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := circuit.RequiredKeyProfile().All(), baseline.RequiredKeyProfile().All(); !reflect.DeepEqual(got, want) {
		t.Fatalf("ingress6 keys=%v, suffix=%v", got, want)
	}

	wantStages := []A2BFullIngress6Stage{
		A2BFullIngress6StageInput,
		A2BFullIngress6StageSpecialLow, A2BFullIngress6StageSpecialHigh,
		A2BFullIngress6StageIter0Mask,
		A2BFullIngress6StageIter0STCFactor0, A2BFullIngress6StageIter0STCFactor1,
		A2BFullIngress6StageIter0ScaleDown, A2BFullIngress6StageIter0ModUp, A2BFullIngress6StageIter0CTS,
		A2BFullIngress6StageIter0ID, A2BFullIngress6StageIter0MSB,
		A2BFullIngress6StageID0Over16,
		A2BFullIngress6StageHighAligned, A2BFullIngress6StageHighUpdated,
		A2BFullIngress6StageLowAligned, A2BFullIngress6StageLowSelfRemoved,
		A2BFullIngress6StageIter1Mask,
		A2BFullIngress6StageIter1STC, A2BFullIngress6StageIter1ScaleDown,
		A2BFullIngress6StageIter1ModUp, A2BFullIngress6StageIter1CTS,
		A2BFullIngress6StageIter1ID, A2BFullIngress6StageIter1MSB,
		A2BFullIngress6StageID1Aligned, A2BFullIngress6StageHighSelfRemoved,
	}
	wantLevels := []int{6, 5, 5, 4, 3, 2, 0, 20, 17, 5, 5, 4, 4, 4, 5, 5, 3, 1, 0, 20, 17, 5, 5, 4, 4}
	states := profile.ExpectedStates()
	if len(states) != len(wantStages) {
		t.Fatalf("ingress6 ordered states=%d, want %d", len(states), len(wantStages))
	}
	for index, state := range states {
		if state.Stage != wantStages[index] || state.Level != wantLevels[index] || state.Degree != 1 ||
			state.LogDimensions != params.LogMaxDimensions() || !state.Scale.EqualScale(params.DefaultScale()) {
			t.Fatalf("ingress6 ordered state %d=%+v, want stage=%q level=%d/S35/degree1/full", index, state, wantStages[index], wantLevels[index])
		}
	}
	states[0].Stage = A2BFullIngress6StageAdmission
	if profile.ExpectedStates()[0].Stage != A2BFullIngress6StageInput {
		t.Fatal("ingress6 expected-state projection aliases the sealed profile")
	}
	serialized := profile.ExpectedSerializedBytes()
	boundaries := serialized.RetainedBoundaries()
	if !serialized.Complete() || serialized.OnlineInputBytes() == 0 || serialized.OnlineLowOutputBytes() == 0 ||
		serialized.OnlineHighOutputBytes() == 0 || len(boundaries) != len(wantStages) {
		t.Fatalf("ingress6 serialized-byte profile is incomplete: online=%d/%d/%d boundaries=%v",
			serialized.OnlineInputBytes(), serialized.OnlineLowOutputBytes(), serialized.OnlineHighOutputBytes(), boundaries)
	}
	for index, boundary := range boundaries {
		if boundary.Stage != wantStages[index] || boundary.Bytes <= 0 {
			t.Fatalf("ingress6 serialized boundary %d=%+v, want stage=%q and positive bytes", index, boundary, wantStages[index])
		}
	}
	boundaries[0].Bytes = 0
	if profile.ExpectedSerializedBytes().RetainedBoundaries()[0].Bytes == 0 {
		t.Fatal("ingress6 serialized-byte projection aliases the sealed profile")
	}
	t.Logf("ingress6 encoded payload digests: first-stc=%s shared-cts=%s second-stc=%s",
		profile.FirstSTCEncodedPayloadDigest(), profile.SharedCTSEncodedPayloadDigest(), profile.SecondSTCEncodedPayloadDigest())
	for name, values := range map[string][2]string{
		"profile":            {profile.Digest(), "3cc7441efb87258f5a545c81d29c3e11b74f5a433cd8527f4a5632d8c070d7dc"},
		"admission":          {profile.AdmissionDigest(), "3155f62fa1a3db5162cab1f1438a87f80f1618584751512ff8453a4967de6ced"},
		"range":              {profile.RangeDigest(), "ff371b8f67cad287fdf0b7bc58dae84886072e56049d6da920455f0fd3045512"},
		"key-graph":          {profile.KeyProfileDigest(), "798b57c477bbe8a8ea001e0ad784a44e95d70ec29143d3c3460ecdcf11f5f6a0"},
		"first-stc-encoded":  {profile.FirstSTCEncodedPayloadDigest(), "9d7cf0b9096d183da30eae6bbaec0a19f33e3f5e3eda3614de43333fef38d9c9"},
		"shared-cts-encoded": {profile.SharedCTSEncodedPayloadDigest(), "3d796c83d500bfbe90f23c3130347e8c830e45d5ea8250cebbc7787ca3c14a41"},
		"second-stc-encoded": {profile.SecondSTCEncodedPayloadDigest(), "d20c0c5aeb1fb3392a43356e3d2c263593a116b2cb014269480f5881d1606e43"},
	} {
		if values[0] != values[1] {
			t.Fatalf("ingress6 frozen %s digest=%s, want %s", name, values[0], values[1])
		}
	}
	if got, want := circuit.RequiredKeyProfile().All(), []uint64{5, 17, 25, 33, 41, 49, 63}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ingress6 frozen exact key graph=%v, want %v", got, want)
	}
	t.Logf("ingress6 digests: profile=%s admission=%s range=%s keys=%s elements=%v special=%s first-stc=%s",
		profile.Digest(), profile.AdmissionDigest(), profile.RangeDigest(), profile.KeyProfileDigest(),
		circuit.RequiredKeyProfile().All(), profile.SpecialB0CompiledDigest(), profile.FirstSTCExecutionMatrixDigest())
}
