package homchain

import (
	"math"
	"math/cmplx"
	"reflect"
	"testing"
	"time"

	"github.com/nc26676027/LCPDTE/integer/treeplan"
	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/bootstrapping"
	ckksdft "github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/dft"
	ckkslintrans "github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/lintrans"
	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/mod1"
	ckkspolynomial "github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/polynomial"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
)

func TestSigned8Depth2ChildSelectorDecodeEncryptedSelectedChildren(t *testing.T) {
	tests := []struct {
		name string
		mode Signed8ComparatorOperandMode
	}{
		{name: "public-threshold", mode: Signed8PublicThresholdCTPT},
		{name: "opaque-threshold", mode: Signed8OpaqueThresholdCTCT},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testSigned8Depth2ChildSelectorDecodeEncryptedSelectedChildren(t, test.mode)
		})
	}
}

func testSigned8Depth2ChildSelectorDecodeEncryptedSelectedChildren(
	t *testing.T,
	mode Signed8ComparatorOperandMode,
) {
	t.Helper()
	fixture := newSigned8Depth2ChildSelectorDecodeIntegrationFixture(t, mode)
	childResult, _, err := fixture.childEvaluator.EvaluateNew(fixture.childInput)
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := NewSigned8Depth2ChildSelectorDecodeCircuit(fixture.child)
	if err != nil {
		t.Fatal(err)
	}
	input, err := decoder.BindChildResult(fixture.childInput, childResult)
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := decoder.BindEvaluator(fixture.source)
	if err != nil {
		t.Fatal(err)
	}
	result, trace, err := evaluator.EvaluateNew(input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = evaluator.preflight(); err != nil {
		t.Fatalf("runtime identity snapshots changed after accepted decoder scratch use: %v", err)
	}
	if err = decoder.validateResult(result); err != nil {
		t.Fatalf("sealed decoder result did not validate: %v", err)
	}
	if err = decoder.validateTrace(input, result, trace); err != nil {
		t.Fatalf("sealed decoder trace did not validate: %v", err)
	}
	if result.ProfileDigest() != decoder.Profile().Digest() ||
		result.ChildInputBindingDigest() != input.ChildInputBindingDigest() ||
		result.ChildResultProvenanceDigest() != childResult.ProvenanceDigest() ||
		result.OperandsProvenanceDigest() != fixture.childInput.OperandsProvenanceDigest() ||
		result.ProducerProfileDigest() != input.ProducerProfileDigest() ||
		result.OperandMode() != mode ||
		result.Path() != SelectorReraiseDecodePeriodicPath || result.Digest() == "" ||
		trace.Digest() == "" || trace.ResultProvenanceDigest() != result.Digest() {
		t.Fatalf("decoder result/trace provenance is incomplete: result=%+v trace=%+v", result, trace)
	}
	if trace.OperationCounts() != decoder.Profile().OperationCounts() ||
		trace.AttemptedOperationLowerBound() != trace.OperationCounts() || len(trace.States()) != 19 ||
		trace.LogicalPeakLiveCiphertexts() != 8 || trace.SerializedBytes().ModuleTotal() != 57404 ||
		trace.SerializedBytes().RetainedTraceTotal() != 49408 ||
		trace.SerializedBytes() != decoder.Profile().ExpectedSerializedBytes() {
		t.Fatalf("decoder runtime ledger changed: counts=%+v states=%d bytes=%+v peak=%d",
			trace.OperationCounts(), len(trace.States()), trace.SerializedBytes(), trace.LogicalPeakLiveCiphertexts())
	}

	want := [4]float64{1, 0, 1, 1}
	decoded := make([]complex128, result.Ciphertext().Slots())
	if err = fixture.integerEncoder.Decode(fixture.decryptor.DecryptNew(result.Ciphertext()), decoded); err != nil {
		t.Fatal(err)
	}
	for word, wantValue := range want {
		for slot := 0; slot < selectorReraiseDecodeHalfWidth; slot++ {
			value := decoded[word*selectorReraiseDecodeHalfWidth+slot]
			errorComplex := cmplx.Abs(value - complex(wantValue, 0))
			if math.Abs(real(value)-wantValue) > 2e-3 || math.Abs(imag(value)) > 2e-3 ||
				errorComplex >= 1.0/256.0 {
				t.Fatalf("word=%d slot=%d decoded=%v want=%.0f |error|=%g", word, slot, value, wantValue, errorComplex)
			}
		}
	}

	resultCopy := result.Ciphertext()
	resultCopy.Value[0].Coeffs[0][0] ^= 1
	states := trace.States()
	states[0].Level = 99
	checkpoint := trace.NormalVLow()
	checkpoint.Value[0].Coeffs[0][0] ^= 1
	if err = decoder.validateResult(result); err != nil ||
		decoder.validateTrace(input, result, trace) != nil || trace.States()[0].Level != 4 ||
		trace.NormalVLow().Equal(checkpoint) {
		t.Fatal("decoder result or trace accessor aliases sealed evidence")
	}
	tamperedAttemptLowerBound := cloneSigned8Depth2ChildSelectorDecodeTrace(trace)
	tamperedAttemptLowerBound.attemptedOperationLowerBound.LinearTransformations++
	tamperedAttemptLowerBound.traceDigest = digestSigned8Depth2ChildSelectorDecodeTrace(tamperedAttemptLowerBound)
	if err = decoder.validateTrace(input, result, tamperedAttemptLowerBound); err == nil {
		t.Fatal("self-consistently resealed successful trace with a changed attempted-operation lower bound was admitted")
	}

	foreignResult := cloneSigned8Depth2ChildSelectorDecodeResult(result)
	if mode == Signed8PublicThresholdCTPT {
		foreignResult.producerProfileDigest = decoder.profile.producerOpaqueDigest
		foreignResult.operandMode = Signed8OpaqueThresholdCTCT
	} else {
		foreignResult.producerProfileDigest = decoder.profile.producerPublicDigest
		foreignResult.operandMode = Signed8PublicThresholdCTPT
	}
	foreignResult.inputProvenanceDigest = digestString("foreign-self-consistent-decoder-input")
	foreignResult.childInputBindingDigest = digestString("foreign-self-consistent-child-input")
	foreignResult.childResultProvenanceDigest = digestString("foreign-self-consistent-child-result")
	foreignResult.operandsProvenanceDigest = digestString("foreign-self-consistent-operands")
	foreignResult.provenanceDigest = digestSigned8Depth2ChildSelectorDecodeResult(foreignResult)
	if err = decoder.validateResult(foreignResult); err != nil {
		t.Fatalf("self-consistent foreign result fixture should validate independently: %v", err)
	}
	foreignTrace := cloneSigned8Depth2ChildSelectorDecodeTrace(trace)
	foreignTrace.producerProfileDigest = foreignResult.producerProfileDigest
	foreignTrace.operandMode = foreignResult.operandMode
	foreignTrace.inputProvenanceDigest = foreignResult.inputProvenanceDigest
	foreignTrace.childInputBindingDigest = foreignResult.childInputBindingDigest
	foreignTrace.childResultProvenanceDigest = foreignResult.childResultProvenanceDigest
	foreignTrace.operandsProvenanceDigest = foreignResult.operandsProvenanceDigest
	foreignTrace.resultProvenanceDigest = foreignResult.provenanceDigest
	foreignTrace.traceDigest = digestSigned8Depth2ChildSelectorDecodeTrace(foreignTrace)
	if err = decoder.validateTrace(input, foreignResult, foreignTrace); err == nil {
		t.Fatal("two independently self-sealed foreign result/trace halves were admitted with the supplied input")
	}
}

func TestSigned8Depth2ChildSelectorDecodeRuntimeGraphAndKeyMutationMatrix(t *testing.T) {
	decoder, evaluator := newSigned8Depth2ChildSelectorDecodeBoundEvaluator(t)
	foreignBase, err := decoder.base.BindEvaluator(evaluator.source)
	if err != nil {
		t.Fatal(err)
	}
	keyGenerator := ckks.NewKeyGenerator(decoder.params)
	foreignSecret := keyGenerator.GenSecretKeyNew()
	foreignRelinearization := keyGenerator.GenRelinearizationKeyNew(foreignSecret)
	firstElement := decoder.keyProfile.all[0]
	foreignGalois := keyGenerator.GenGaloisKeyNew(firstElement, foreignSecret)
	type mutation struct {
		name   string
		mutate func(*Signed8Depth2ChildSelectorDecodeEvaluator) func()
	}
	noRestore := func() {}
	mutations := []mutation{
		{"nil-source", func(value *Signed8Depth2ChildSelectorDecodeEvaluator) func() { value.source = nil; return noRestore }},
		{"self-consistent-foreign-base", func(value *Signed8Depth2ChildSelectorDecodeEvaluator) func() {
			value.base = foreignBase
			return noRestore
		}},
		{"same-key-pointer-new-keyset", func(value *Signed8Depth2ChildSelectorDecodeEvaluator) func() {
			keys := make([]*rlwe.GaloisKey, 0, len(value.galoisKeys))
			for _, element := range decoder.keyProfile.all {
				keys = append(keys, value.galoisKeys[element])
			}
			value.keySet = rlwe.NewMemEvaluationKeySet(value.relinearizationKey, keys...)
			return noRestore
		}},
		{"foreign-relinearization", func(value *Signed8Depth2ChildSelectorDecodeEvaluator) func() {
			value.relinearizationKey = foreignRelinearization
			return noRestore
		}},
		{"new-galois-cache-map", func(value *Signed8Depth2ChildSelectorDecodeEvaluator) func() {
			clone := make(map[uint64]*rlwe.GaloisKey, len(value.galoisKeys))
			for element, key := range value.galoisKeys {
				clone[element] = key
			}
			value.galoisKeys = clone
			return noRestore
		}},
		{"foreign-galois-key", func(value *Signed8Depth2ChildSelectorDecodeEvaluator) func() {
			clone := make(map[uint64]*rlwe.GaloisKey, len(value.galoisKeys))
			for element, key := range value.galoisKeys {
				clone[element] = key
			}
			clone[firstElement] = foreignGalois
			value.galoisKeys = clone
			return noRestore
		}},
		{"source-evaluation-keys-wrapper", func(value *Signed8Depth2ChildSelectorDecodeEvaluator) func() {
			before := value.source.EvaluationKeys
			value.source.EvaluationKeys = &bootstrapping.EvaluationKeys{MemEvaluationKeySet: before.MemEvaluationKeySet}
			return func() { value.source.EvaluationKeys = before }
		}},
		{"source-encoder-object", func(value *Signed8Depth2ChildSelectorDecodeEvaluator) func() {
			before := value.source.Evaluator.Encoder
			clone := *before
			value.source.Evaluator.Encoder = &clone
			return func() { value.source.Evaluator.Encoder = before }
		}},
		{"base-linear-object", func(value *Signed8Depth2ChildSelectorDecodeEvaluator) func() {
			before := value.base.linear
			clone := *before
			value.base.linear = &clone
			return func() { value.base.linear = before }
		}},
		{"kernel-polynomial-object", func(value *Signed8Depth2ChildSelectorDecodeEvaluator) func() {
			before := value.base.kernel.polynomial
			clone := *before
			value.base.kernel.polynomial = &clone
			return func() { value.base.kernel.polynomial = before }
		}},
		{"kernel-encoder-object", func(value *Signed8Depth2ChildSelectorDecodeEvaluator) func() {
			before := value.base.kernel.operationalEncoder
			clone := *before
			value.base.kernel.operationalEncoder = &clone
			return func() { value.base.kernel.operationalEncoder = before }
		}},
		{"source-ckks-snapshot", func(value *Signed8Depth2ChildSelectorDecodeEvaluator) func() {
			value.graph.sourceCKKS = ckks.EvaluatorRuntimeIdentity{}
			return noRestore
		}},
		{"source-dft-snapshot", func(value *Signed8Depth2ChildSelectorDecodeEvaluator) func() {
			value.graph.sourceDFT = ckksdft.EvaluatorRuntimeIdentity{}
			return noRestore
		}},
		{"linear-snapshot", func(value *Signed8Depth2ChildSelectorDecodeEvaluator) func() {
			value.graph.linear = ckkslintrans.EvaluatorRuntimeIdentity{}
			return noRestore
		}},
		{"polynomial-snapshot", func(value *Signed8Depth2ChildSelectorDecodeEvaluator) func() {
			value.graph.kernelPolynomial = ckkspolynomial.EvaluatorRuntimeIdentity{}
			return noRestore
		}},
		{"profile-digest", func(value *Signed8Depth2ChildSelectorDecodeEvaluator) func() {
			value.graph.profileDigest = "tampered"
			return noRestore
		}},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			changed := *evaluator
			restore := test.mutate(&changed)
			defer restore()
			if _, err := changed.preflight(); err == nil {
				t.Fatal("mutated runtime graph or key identity passed preflight")
			}
		})
	}
	if _, err := evaluator.preflight(); err != nil {
		t.Fatalf("accepted runtime graph changed after rejected mutations: %v", err)
	}
	if got := len(mutations); got != 16 {
		t.Fatalf("runtime graph/key cases=%d, want 16", got)
	}
}

func TestSigned8Depth2ChildSelectorDecodeBootstrapMetadataMutationMatrixFailsBeforeWork(t *testing.T) {
	decoder, evaluator := newSigned8Depth2ChildSelectorDecodeBoundEvaluator(t)
	childInput, childResult := newSigned8Depth2ChildDecodeAdmissionPair(
		t, decoder.child, Signed8PublicThresholdCTPT, 29,
	)
	input, err := decoder.BindChildResult(childInput, childResult)
	if err != nil {
		t.Fatal(err)
	}
	type mutation struct {
		name   string
		mutate func(*bootstrapping.Evaluator) func()
	}
	mutations := []mutation{
		{"residual-parameters", func(source *bootstrapping.Evaluator) func() {
			before := source.ResidualParameters
			source.ResidualParameters = ckks.Parameters{}
			return func() { source.ResidualParameters = before }
		}},
		{"bootstrapping-parameters", func(source *bootstrapping.Evaluator) func() {
			before := source.BootstrappingParameters
			source.BootstrappingParameters = ckks.Parameters{}
			return func() { source.BootstrappingParameters = before }
		}},
		{"slots-to-coeffs-log-slots", func(source *bootstrapping.Evaluator) func() {
			before := source.SlotsToCoeffsParameters.LogSlots
			source.SlotsToCoeffsParameters.LogSlots++
			return func() { source.SlotsToCoeffsParameters.LogSlots = before }
		}},
		{"coeffs-to-slots-log-slots", func(source *bootstrapping.Evaluator) func() {
			before := source.CoeffsToSlotsParameters.LogSlots
			source.CoeffsToSlotsParameters.LogSlots++
			return func() { source.CoeffsToSlotsParameters.LogSlots = before }
		}},
		{"mod1-literal-message-ratio", func(source *bootstrapping.Evaluator) func() {
			before := source.Mod1ParametersLiteral.LogMessageRatio
			source.Mod1ParametersLiteral.LogMessageRatio++
			return func() { source.Mod1ParametersLiteral.LogMessageRatio = before }
		}},
		{"circuit-order", func(source *bootstrapping.Evaluator) func() {
			before := source.CircuitOrder
			source.CircuitOrder++
			return func() { source.CircuitOrder = before }
		}},
		{"ephemeral-secret-weight", func(source *bootstrapping.Evaluator) func() {
			before := source.EphemeralSecretWeight
			source.EphemeralSecretWeight++
			return func() { source.EphemeralSecretWeight = before }
		}},
		{"mod1-execution-message-ratio", func(source *bootstrapping.Evaluator) func() {
			before := source.Mod1Parameters.LogMessageRatio
			source.Mod1Parameters.LogMessageRatio++
			return func() { source.Mod1Parameters.LogMessageRatio = before }
		}},
		{"mod1-execution-default-scale", func(source *bootstrapping.Evaluator) func() {
			before := source.Mod1Parameters.LogDefaultScale
			source.Mod1Parameters.LogDefaultScale++
			return func() { source.Mod1Parameters.LogDefaultScale = before }
		}},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			restore := test.mutate(evaluator.source)
			defer restore()
			if _, preflightErr := evaluator.preflight(); preflightErr == nil {
				t.Fatal("mutated bootstrapping execution metadata passed preflight")
			}
			result, trace, evalErr := evaluator.EvaluateNew(input)
			if evalErr == nil || !reflect.DeepEqual(result, Signed8Depth2ChildSelectorDecodeResult{}) ||
				!reflect.DeepEqual(trace, Signed8Depth2ChildSelectorDecodeTrace{}) {
				t.Fatalf("pre-HE metadata failure exposed work: result=%+v trace=%+v err=%v", result, trace, evalErr)
			}
		})
	}
	if got := len(mutations); got != 9 {
		t.Fatalf("bootstrap metadata cases=%d, want 9", got)
	}
	if _, err = evaluator.preflight(); err != nil {
		t.Fatalf("accepted metadata graph changed after rejected mutations: %v", err)
	}
}

func TestSigned8Depth2ChildSelectorDecodeRealNormalVPartialFailureFinalizer(t *testing.T) {
	decoder, evaluator := newSigned8Depth2ChildSelectorDecodeBoundEvaluator(t)
	childInput, childResult := newSigned8Depth2ChildDecodeAdmissionPair(
		t, decoder.child, Signed8PublicThresholdCTPT, 31,
	)
	input, err := decoder.BindChildResult(childInput, childResult)
	if err != nil {
		t.Fatal(err)
	}
	preflight, err := evaluator.preflight()
	if err != nil {
		t.Fatal(err)
	}
	helper := SelectorReraiseDecodeTrace{}
	if err = appendSelectorReraiseDecodeState(
		&helper, SelectorStageInput, SelectorReraiseDecodeWhole, input.branch,
	); err != nil {
		t.Fatal(err)
	}
	helper.logicalPeakLive = 2
	vHalves, err := evaluator.base.evaluateNormalV(input.branch, &helper)
	if err != nil {
		t.Fatal(err)
	}
	helper.normalVLow, helper.normalVHigh = vHalves[0].CopyNew(), vHalves[1].CopyNew()
	helper.logicalPeakLive = 6
	attemptedLowerBound := attemptedSigned8Depth2ChildSelectorDecodeLowerBound(
		helper.operationCounts, Signed8Depth2ChildSelectorStageSTCFactor0,
	)
	result, trace, err := finalizeSigned8Depth2ChildSelectorDecodeFailure(
		decoder, input, helper, preflight, Signed8Depth2ChildSelectorStageSTCFactor0,
		attemptedLowerBound, time.Millisecond,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result, Signed8Depth2ChildSelectorDecodeResult{}) ||
		trace.FailureStage() != Signed8Depth2ChildSelectorStageSTCFactor0 ||
		len(trace.States()) != 5 || trace.OperationCounts().LinearTransformations != 2 ||
		trace.AttemptedOperationLowerBound().ScalarMultiplicationsPlusMinusI != 1 ||
		trace.SerializedBytes().ModuleTotal() != 7770 || trace.Digest() == "" {
		t.Fatalf("normal-V partial finalization lost evidence: result=%+v trace=%+v", result, trace)
	}
	if err = decoder.validateFailureTrace(input, trace); err != nil {
		t.Fatalf("normal-V partial trace did not validate: %v", err)
	}
	sealed := trace.NormalVLow()
	helper.normalVLow.Value[0].Coeffs[0][0] ^= 1
	if trace.NormalVLow().Equal(helper.normalVLow) {
		t.Fatal("partial finalizer retained helper checkpoint alias")
	}
	sealed.Value[0].Coeffs[0][0] ^= 1
	if trace.NormalVLow().Equal(sealed) {
		t.Fatal("partial normal-V accessor aliases sealed trace")
	}
}

func newSigned8Depth2ChildSelectorDecodeBoundEvaluator(
	t *testing.T,
) (*Signed8Depth2ChildSelectorDecodeCircuit, *Signed8Depth2ChildSelectorDecodeEvaluator) {
	t.Helper()
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
	prefix, err := NewSigned8Depth2SourcePrefixCircuit(selector, signed8Depth2ChildSelectorDecodeTestTree())
	if err != nil {
		t.Fatal(err)
	}
	child, err := NewSigned8Depth2ChildComparatorCircuit(prefix)
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := NewSigned8Depth2ChildSelectorDecodeCircuit(child)
	if err != nil {
		t.Fatal(err)
	}
	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	evaluationKeys := &bootstrapping.EvaluationKeys{MemEvaluationKeySet: rlwe.NewMemEvaluationKeySet(
		keyGenerator.GenRelinearizationKeyNew(secretKey),
		keyGenerator.GenGaloisKeysNew(decoder.RequiredKeyProfile().All(), secretKey)...,
	)}
	dft := producer.a2b.refresh.Profile().DFT()
	source, err := bootstrapping.NewEvaluator(bootstrapping.Parameters{
		ResidualParameters: params, BootstrappingParameters: params,
		SlotsToCoeffsParameters: dft.SlotsToCoeffsLiteral(),
		CoeffsToSlotsParameters: dft.CoeffsToSlotsLiteral(),
		Mod1ParametersLiteral: mod1.ParametersLiteral{
			LevelQ: dft.CoeffsToSlotsLiteral().LevelQ - 3, LogScale: params.LogDefaultScale(),
			Mod1Type: mod1.SinContinuous, LogMessageRatio: 15, K: 1, Mod1Degree: 3,
		},
		CircuitOrder: bootstrapping.Custom,
	}, evaluationKeys)
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := decoder.BindEvaluator(source)
	if err != nil {
		t.Fatal(err)
	}
	return decoder, evaluator
}

type signed8Depth2ChildSelectorDecodeIntegrationFixture struct {
	params         ckks.Parameters
	refreshEncoder *ckks.Encoder
	integerEncoder *ckks.Encoder
	producer       *Signed8ComparatorCircuit
	source         *bootstrapping.Evaluator
	producerEval   *Signed8ComparatorEvaluator
	encryptor      *rlwe.Encryptor
	decryptor      *rlwe.Decryptor
	child          *Signed8Depth2ChildComparatorCircuit
	childInput     Signed8Depth2ChildComparatorInput
	childEvaluator *Signed8Depth2ChildComparatorEvaluator
}

func newSigned8Depth2ChildSelectorDecodeIntegrationFixture(
	t *testing.T,
	mode Signed8ComparatorOperandMode,
) signed8Depth2ChildSelectorDecodeIntegrationFixture {
	t.Helper()
	params, err := GaoA2BKernelFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	refreshEncoder := ckks.NewEncoder(params, signed8RefreshEncoderPrecision)
	integerEncoder := ckks.NewEncoder(params, signed8IntegerEncoderPrecision)
	ranges, err := NewSigned8NoOverflowRange(-8, 7, -8, 7)
	if err != nil {
		t.Fatal(err)
	}
	producer, err := NewSigned8ComparatorCircuit(params, refreshEncoder, integerEncoder, ranges)
	if err != nil {
		t.Fatal(err)
	}
	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	keys := &bootstrapping.EvaluationKeys{MemEvaluationKeySet: rlwe.NewMemEvaluationKeySet(
		keyGenerator.GenRelinearizationKeyNew(secretKey),
		keyGenerator.GenGaloisKeysNew(producer.a2b.RequiredKeyProfile().All(), secretKey)...,
	)}
	dft := producer.a2b.refresh.Profile().DFT()
	source, err := bootstrapping.NewEvaluator(bootstrapping.Parameters{
		ResidualParameters: params, BootstrappingParameters: params,
		SlotsToCoeffsParameters: dft.SlotsToCoeffsLiteral(),
		CoeffsToSlotsParameters: dft.CoeffsToSlotsLiteral(),
		Mod1ParametersLiteral: mod1.ParametersLiteral{
			LevelQ: dft.CoeffsToSlotsLiteral().LevelQ - 3, LogScale: params.LogDefaultScale(),
			Mod1Type: mod1.SinContinuous, LogMessageRatio: 15, K: 1, Mod1Degree: 3,
		},
		CircuitOrder: bootstrapping.Custom,
	}, keys)
	if err != nil {
		t.Fatal(err)
	}
	producerEvaluator, err := producer.BindEvaluator(source)
	if err != nil {
		t.Fatal(err)
	}
	encryptor := ckks.NewEncryptor(params, secretKey)
	decryptor := ckks.NewDecryptor(params, secretKey)
	encryptSigned := func(words [4]int64) *rlwe.Ciphertext {
		var residues [4]uint64
		for index, value := range words {
			residues[index] = uint64(value) & 0xff
		}
		plaintext, encodeErr := newSigned8WordPlaintext(
			params, refreshEncoder, signed8RefreshEncoderPrecision, signed8InputLevel, residues,
		)
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		ciphertext, encryptErr := encryptor.EncryptNew(plaintext)
		if encryptErr != nil {
			t.Fatal(encryptErr)
		}
		return ciphertext
	}
	selector, err := NewSelectorReraiseDecodeCircuit(producer)
	if err != nil {
		t.Fatal(err)
	}
	prefix, err := NewSigned8Depth2SourcePrefixCircuit(selector, signed8Depth2ChildSelectorDecodeTestTree())
	if err != nil {
		t.Fatal(err)
	}
	selectorEvaluator, err := selector.BindEvaluator(source)
	if err != nil {
		t.Fatal(err)
	}
	prefixEvaluator, err := prefix.BindEvaluator(source)
	if err != nil {
		t.Fatal(err)
	}
	rootFeature, err := producer.BindFeature(encryptSigned([4]int64{-1, 1, -2, 2}), params)
	if err != nil {
		t.Fatal(err)
	}
	var rootResult Signed8ComparatorResult
	switch mode {
	case Signed8PublicThresholdCTPT:
		rootResult, _, err = producerEvaluator.CompareGEPublicNew(rootFeature, [4]int64{})
	case Signed8OpaqueThresholdCTCT:
		rootThreshold, bindErr := producer.BindOpaqueThreshold(encryptSigned([4]int64{}), params)
		if bindErr != nil {
			t.Fatal(bindErr)
		}
		rootResult, _, err = producerEvaluator.CompareGEOpaqueNew(rootFeature, rootThreshold)
	default:
		t.Fatalf("unsupported integration mode %q", mode)
	}
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
	conditionInput, err := prefix.BindSelectorResult(selectorResult)
	if err != nil {
		t.Fatal(err)
	}
	left, err := producer.BindFeature(encryptSigned([4]int64{-3, -2, -1, 0}), params)
	if err != nil {
		t.Fatal(err)
	}
	right, err := producer.BindFeature(encryptSigned([4]int64{1, 2, 3, 4}), params)
	if err != nil {
		t.Fatal(err)
	}
	operands, _, err := prefixEvaluator.EvaluateNew(conditionInput, [2]Signed8FeatureInput{left, right})
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
	childEvaluator, err := child.BindEvaluator(source)
	if err != nil {
		t.Fatal(err)
	}
	return signed8Depth2ChildSelectorDecodeIntegrationFixture{
		params: params, refreshEncoder: refreshEncoder, integerEncoder: integerEncoder,
		producer: producer, source: source, producerEval: producerEvaluator,
		encryptor: encryptor, decryptor: decryptor, child: child,
		childInput: childInput, childEvaluator: childEvaluator,
	}
}

func signed8Depth2ChildSelectorDecodeTestTree() treeplan.BinaryTree[int8, float64] {
	return treeplan.BinaryTree[int8, float64]{
		Depth: 2,
		Splits: []treeplan.BinarySplit[int8]{
			{Feature: 0, Threshold: 0}, {Feature: 1, Threshold: -4}, {Feature: 2, Threshold: 3},
		},
		Leaves: []float64{-1.25, 2.5, -3.75, 5},
	}
}
