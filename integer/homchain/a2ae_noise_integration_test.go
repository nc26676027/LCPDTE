package homchain_test

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/nc26676027/LCPDTE/integer/homchain"
	"github.com/nc26676027/LCPDTE/integer/z2n"
	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/bootstrapping"
	ckksdft "github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/dft"
	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/mod1"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/ring"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
	"github.com/nc26676027/LCPDTE/lattigo/utils/bignum"
)

func TestA2AENoiseFixedCircuitProfile(t *testing.T) {
	params, err := homchain.A2AENoiseFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := params.LogN(), 5; got != want {
		t.Fatalf("LogN: got %d, want %d", got, want)
	}
	if got, want := params.MaxLevel(), 16; got != want {
		t.Fatalf("MaxLevel: got %d, want %d", got, want)
	}
	if got, want := params.MaxSlots(), 16; got != want {
		t.Fatalf("slots: got %d, want %d", got, want)
	}

	encoder := ckks.NewEncoder(params, z2n.DefaultPrecision)
	circuit, err := homchain.NewA2AENoiseCircuit(params, encoder, homchain.A2AENoiseOptions{
		MaxAbsLog2ScaleDownError: 1e-6,
	})
	if err != nil {
		t.Fatal(err)
	}
	profile := circuit.Profile()
	if got, want := profile.Fidelity(), homchain.A2AENoiseLattigoAdaptation; got != want {
		t.Fatalf("fidelity: got %q, want %q", got, want)
	}
	if got, want := profile.Maturity(), homchain.A2AENoiseFunctionalNotSecure; got != want {
		t.Fatalf("maturity: got %q, want %q", got, want)
	}
	if got, want := profile.TransformNames(), []homchain.TransformName{
		homchain.V0FusedT, homchain.V1FusedT,
		homchain.U0FusedTInv, homchain.U1FusedTInv,
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("transform family: got %v, want %v", got, want)
	}
	if got, want := profile.LogicalDepth(), 16; got != want {
		t.Fatalf("logical depth: got %d, want %d", got, want)
	}
	if got, want := profile.PostModUpPhysicalDepth(), 13; got != want {
		t.Fatalf("post-ModUp physical depth: got %d, want %d", got, want)
	}
	if profile.WordBits() != z2n.Word8 || profile.Words() != 4 || profile.Slots() != 16 || profile.EncoderPrecision() != z2n.DefaultPrecision {
		t.Fatalf("fixed packing profile mismatch: n=%d words=%d slots=%d precision=%d",
			profile.WordBits(), profile.Words(), profile.Slots(), profile.EncoderPrecision())
	}
	dftProfile := profile.DFT()
	if dftProfile.EncoderPrecision() != z2n.DefaultPrecision || dftProfile.GeneratorPrecision() != z2n.DefaultPrecision ||
		dftProfile.SlotsToCoeffsMatrixDigest() == "" || dftProfile.CoeffsToSlotsMatrixDigest() == "" {
		t.Fatalf("DFT numerical provenance is incomplete: %+v", dftProfile)
	}
	stcLiteral, ctsLiteral := dftProfile.SlotsToCoeffsLiteral(), dftProfile.CoeffsToSlotsLiteral()
	one := new(big.Float).SetPrec(z2n.DefaultPrecision).SetInt64(1)
	oneSixteenth := new(big.Float).SetPrec(z2n.DefaultPrecision).SetMantExp(new(big.Float).SetPrec(z2n.DefaultPrecision).SetInt64(1), -4)
	if stcLiteral.Type != ckksdft.HomomorphicDecode || stcLiteral.Format != ckksdft.SplitRealAndImag ||
		stcLiteral.LevelQ != 15 || !reflect.DeepEqual(stcLiteral.Levels, []int{1, 1}) || stcLiteral.Scaling.Cmp(one) != 0 ||
		ctsLiteral.Type != ckksdft.HomomorphicEncode || ctsLiteral.Format != ckksdft.SplitRealAndImag ||
		ctsLiteral.LevelQ != 16 || !reflect.DeepEqual(ctsLiteral.Levels, []int{1, 1, 1}) || ctsLiteral.Scaling.Cmp(oneSixteenth) != 0 {
		t.Fatalf("sealed STC/CTS schedule mismatch: stc=%+v cts=%+v", stcLiteral, ctsLiteral)
	}
	if profile.FusedT().LevelQ() != 16 || profile.FusedTInverse().LevelQ() != 4 ||
		!profile.FusedT().MatrixScale().EqualScale(rlwe.NewScale(params.Q()[16])) {
		t.Fatalf("fused transform levels/scales mismatch: V=%+v U=%+v", profile.FusedT(), profile.FusedTInverse())
	}
	finalSineScale, err := profile.SineScaleSchedule()[4].Scale()
	if err != nil {
		t.Fatal(err)
	}
	expectedUScale := rlwe.NewScale(params.Q()[4]).Mul(params.DefaultScale()).Div(finalSineScale)
	if !profile.FusedTInverse().MatrixScale().EqualScale(expectedUScale) {
		t.Fatalf("fused U scale does not naturally align L4 to exact Delta: got=%s want=%s",
			profile.FusedTInverse().MatrixScale().ValueHex(), expectedUScale.Value.Text('x', -1))
	}
	if profile.Digest() == "" || profile.TransformSourceDigest() == "" || profile.DFT().Digest() == "" {
		t.Fatal("profile provenance digest is incomplete")
	}
	if got, want := profile.Digest(), "6173b79dfcfcc993748793d10fb853e8f4692313ef94fc12958719f726280c18"; got != want {
		t.Fatalf("frozen A2A-e profile digest: got %q, want %q", got, want)
	}
	if got, want := profile.TransformSourceDigest(), "238898a468ace45c1c524c90d113bb5b3c916757dcdc53232c4a38964026c1fb"; got != want {
		t.Fatalf("frozen fused-transform source digest: got %q, want %q", got, want)
	}
	if got, want := dftProfile.SlotsToCoeffsMatrixDigest(), "3b4394a6c84929ea5116601b55c14c27b9598d2c56972f1150b394d88c2a735b"; got != want {
		t.Fatalf("frozen STC matrix digest: got %q, want %q", got, want)
	}
	if got, want := dftProfile.CoeffsToSlotsMatrixDigest(), "24641e4398b624bc35b3bdc7609c61a86d796514b671a5283f38fb4a4edcd4e0"; got != want {
		t.Fatalf("frozen CTS matrix digest: got %q, want %q", got, want)
	}
	keys := circuit.RequiredKeyProfile()
	if got, want := keys.All(), []uint64{5, 17, 25, 33, 41, 49, 63}; !reflect.DeepEqual(got, want) {
		t.Fatalf("exact Galois union: got %v, want %v", got, want)
	}
	if !keys.RelinearizationRequired() || keys.Digest() == "" {
		t.Fatal("A2A-e key profile omits relinearization or digest")
	}

	// Circuit construction calibrates only deterministic Lattigo scale
	// metadata. Fresh ephemeral calibration keys must therefore yield an
	// identical sealed schedule and profile digest, and no key may be retained
	// by the circuit object.
	secondCircuit, err := homchain.NewA2AENoiseCircuit(params, ckks.NewEncoder(params, z2n.DefaultPrecision), homchain.A2AENoiseOptions{
		MaxAbsLog2ScaleDownError: 1e-6,
	})
	if err != nil {
		t.Fatal(err)
	}
	firstSchedule, secondSchedule := profile.SineScaleSchedule(), secondCircuit.Profile().SineScaleSchedule()
	if len(firstSchedule) != 5 || !reflect.DeepEqual(firstSchedule, secondSchedule) || profile.Digest() != secondCircuit.Profile().Digest() {
		t.Fatalf("scale calibration is not deterministic: first=%v second=%v digests=%s/%s",
			firstSchedule, secondSchedule, profile.Digest(), secondCircuit.Profile().Digest())
	}
	circuitType := reflect.TypeOf(circuit).Elem()
	for i := 0; i < circuitType.NumField(); i++ {
		fieldType := circuitType.Field(i).Type.String()
		if strings.Contains(fieldType, "SecretKey") || strings.Contains(fieldType, "RelinearizationKey") || strings.Contains(fieldType, "EvaluationKey") {
			t.Fatalf("construction-time calibration key leaked into circuit field %s %s", circuitType.Field(i).Name, fieldType)
		}
	}
	if got := secondCircuit.RequiredKeyProfile().All(); !reflect.DeepEqual(got, keys.All()) {
		t.Fatalf("construction-time calibration changed the runtime key claim: %v vs %v", got, keys.All())
	}
	scaleHex := make([]string, len(firstSchedule))
	for i := range firstSchedule {
		scaleHex[i] = firstSchedule[i].ValueHex()
	}
	t.Logf("A2A-e sealed profile=%s transform=%s STC=%s CTS=%s sine-scales=%v U-scale=%s keys=%v",
		profile.Digest(), profile.TransformSourceDigest(), dftProfile.SlotsToCoeffsMatrixDigest(),
		dftProfile.CoeffsToSlotsMatrixDigest(), scaleHex, profile.FusedTInverse().MatrixScale().ValueHex(), keys.All())
}

func TestA2AENoiseExactScaleMetadataRejectsNumericOnlySentinels(t *testing.T) {
	params, err := homchain.A2AENoiseFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	canonical := params.DefaultScale()
	canonicalSnapshot, err := homchain.NewExactScaleSnapshot(canonical)
	if err != nil {
		t.Fatal(err)
	}

	higherPrecisionValue := new(big.Float).
		SetPrec(canonical.Value.Prec() + 64).
		SetMode(canonical.Value.Mode()).
		Set(&canonical.Value)
	differentRoundingValue := new(big.Float).
		SetPrec(canonical.Value.Prec()).
		SetMode(big.ToZero).
		Set(&canonical.Value)
	variants := map[string]rlwe.Scale{
		"precision": {Value: *higherPrecisionValue},
		"rounding":  {Value: *differentRoundingValue},
		"modulus":   rlwe.NewScaleModT(canonical, 257),
	}
	for name, variant := range variants {
		if !canonical.Equal(variant) {
			t.Fatalf("%s sentinel does not exercise rlwe.Scale numeric equality", name)
		}
		if canonicalSnapshot.EqualScale(variant) {
			t.Fatalf("%s sentinel passed exact scale metadata equality", name)
		}
	}
}

func TestA2AENoiseRejectsMissingKeysBeforeEvaluation(t *testing.T) {
	params, err := homchain.A2AENoiseFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	encoder := ckks.NewEncoder(params, z2n.DefaultPrecision)
	circuit, err := homchain.NewA2AENoiseCircuit(params, encoder, homchain.A2AENoiseOptions{MaxAbsLog2ScaleDownError: 1e-6})
	if err != nil {
		t.Fatal(err)
	}
	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	for _, missing := range circuit.RequiredKeyProfile().All() {
		missing := missing
		t.Run("galois-"+new(big.Int).SetUint64(missing).String(), func(t *testing.T) {
			source := a2aeNoiseBootstrapEvaluator(t, circuit, params, keyGenerator, secretKey, nil, true)
			delete(source.MemEvaluationKeySet.GaloisKeys, missing)
			if _, err = circuit.BindEvaluator(source); err == nil || !strings.Contains(err.Error(), "key preflight failed") {
				t.Fatalf("missing Galois key %d was accepted: %v", missing, err)
			}
		})
	}
	t.Run("relinearization", func(t *testing.T) {
		source := a2aeNoiseBootstrapEvaluator(t, circuit, params, keyGenerator, secretKey, nil, true)
		source.MemEvaluationKeySet.RelinearizationKey = nil
		if _, err = circuit.BindEvaluator(source); err == nil || !strings.Contains(err.Error(), "key preflight failed") {
			t.Fatalf("missing relinearization key was accepted: %v", err)
		}
	})
}

func TestA2AENoiseRejectsForeignGraphsCertificatesAndInputStates(t *testing.T) {
	params, err := homchain.A2AENoiseFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	encoder := ckks.NewEncoder(params, z2n.DefaultPrecision)
	circuit, err := homchain.NewA2AENoiseCircuit(params, encoder, homchain.A2AENoiseOptions{MaxAbsLog2ScaleDownError: 1e-6})
	if err != nil {
		t.Fatal(err)
	}
	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	source := a2aeNoiseBootstrapEvaluator(t, circuit, params, keyGenerator, secretKey, nil, true)
	evaluator, err := circuit.BindEvaluator(source)
	if err != nil {
		t.Fatal(err)
	}
	certificate := newA2AENoiseTestCertificate(t, circuit.Profile(), params.DefaultScale())
	validInput := newA2AENoiseMetadataCiphertext(params, 1, 16)
	perturbation := certificate.MaxAbsPerturbation()
	perturbation.SetInt64(99)
	if certificate.MaxAbsPerturbation().Cmp(big.NewRat(1, 256)) != 0 {
		t.Fatal("certificate perturbation accessor aliases the admission")
	}

	t.Run("foreign-profile-certificate", func(t *testing.T) {
		foreignCircuit, constructErr := homchain.NewA2AENoiseCircuit(params, encoder, homchain.A2AENoiseOptions{MaxAbsLog2ScaleDownError: 2e-6})
		if constructErr != nil {
			t.Fatal(constructErr)
		}
		foreign := newA2AENoiseTestCertificate(t, foreignCircuit.Profile(), params.DefaultScale())
		before := validInput.CopyNew()
		if _, _, evalErr := evaluator.EvalArithToArithNoise(validInput, foreign); evalErr == nil || !strings.Contains(evalErr.Error(), "foreign") {
			t.Fatalf("foreign certificate was accepted: %v", evalErr)
		}
		if !validInput.Equal(before) {
			t.Fatal("certificate rejection mutated the input")
		}
	})

	tests := []struct {
		name   string
		mutate func(*rlwe.Ciphertext)
	}{
		{"wrong-level", func(ct *rlwe.Ciphertext) { ct.Resize(1, 15) }},
		{"wrong-scale", func(ct *rlwe.Ciphertext) { ct.Scale = rlwe.NewScale(math.Exp2(34)) }},
		{"wrong-dimensions", func(ct *rlwe.Ciphertext) { ct.LogDimensions = ring.Dimensions{Rows: 0, Cols: 3} }},
		{"not-batched", func(ct *rlwe.Ciphertext) { ct.IsBatched = false }},
		{"not-ntt", func(ct *rlwe.Ciphertext) { ct.IsNTT = false }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			input := validInput.CopyNew()
			test.mutate(input)
			before := input.CopyNew()
			if _, _, evalErr := evaluator.EvalArithToArithNoise(input, certificate); evalErr == nil {
				t.Fatalf("%s input was accepted", test.name)
			}
			if !input.Equal(before) {
				t.Fatalf("%s rejection mutated the input", test.name)
			}
		})
	}
	t.Run("wrong-degree", func(t *testing.T) {
		input := newA2AENoiseMetadataCiphertext(params, 2, 16)
		before := input.CopyNew()
		if _, _, evalErr := evaluator.EvalArithToArithNoise(input, certificate); evalErr == nil {
			t.Fatal("degree-2 input was accepted")
		}
		if !input.Equal(before) {
			t.Fatal("degree rejection mutated the input")
		}
	})

	t.Run("wrong-evaluator-parameters", func(t *testing.T) {
		wrongParams, paramsErr := homchain.GaoSineKernelFunctionalParameters()
		if paramsErr != nil {
			t.Fatal(paramsErr)
		}
		foreignSource := *source
		foreignSource.Evaluator = ckks.NewEvaluator(wrongParams, source.MemEvaluationKeySet)
		if _, bindErr := circuit.BindEvaluator(&foreignSource); bindErr == nil || !strings.Contains(bindErr.Error(), "parameters differ") {
			t.Fatalf("foreign evaluator parameters were accepted: %v", bindErr)
		}
	})

	t.Run("post-bind-key-removal", func(t *testing.T) {
		galoisElement := circuit.RequiredKeyProfile().All()[0]
		key := source.MemEvaluationKeySet.GaloisKeys[galoisElement]
		delete(source.MemEvaluationKeySet.GaloisKeys, galoisElement)
		defer func() { source.MemEvaluationKeySet.GaloisKeys[galoisElement] = key }()
		input := validInput.CopyNew()
		before := input.CopyNew()
		if _, trace, evalErr := evaluator.EvalArithToArithNoise(input, certificate); evalErr == nil || !reflect.DeepEqual(trace.KeyPreflight().MissingGaloisElements, []uint64{galoisElement}) {
			t.Fatalf("post-bind key removal was accepted: err=%v preflight=%+v", evalErr, trace.KeyPreflight())
		} else if trace.FailureStage() != homchain.A2AENoiseStageKeyPreflight || trace.OperationCounts() != (homchain.A2AENoiseOperationCounts{}) || len(trace.States()) != 0 {
			t.Fatalf("post-bind key removal has non-fail-closed trace: stage=%q counts=%+v states=%v", trace.FailureStage(), trace.OperationCounts(), trace.States())
		}
		if !input.Equal(before) {
			t.Fatal("key rejection mutated the input")
		}
	})

	t.Run("post-bind-relinearization-replacement", func(t *testing.T) {
		original := source.MemEvaluationKeySet.RelinearizationKey
		source.MemEvaluationKeySet.RelinearizationKey = keyGenerator.GenRelinearizationKeyNew(secretKey)
		defer func() { source.MemEvaluationKeySet.RelinearizationKey = original }()
		input := validInput.CopyNew()
		before := input.CopyNew()
		if _, trace, evalErr := evaluator.EvalArithToArithNoise(input, certificate); evalErr == nil || trace.KeyPreflight().GraphMismatch == "" {
			t.Fatalf("post-bind relin replacement was accepted: err=%v preflight=%+v", evalErr, trace.KeyPreflight())
		} else if trace.FailureStage() != homchain.A2AENoiseStageKeyPreflight || trace.OperationCounts() != (homchain.A2AENoiseOperationCounts{}) || len(trace.States()) != 0 {
			t.Fatalf("post-bind relin replacement has non-fail-closed trace: stage=%q counts=%+v states=%v", trace.FailureStage(), trace.OperationCounts(), trace.States())
		}
		if !input.Equal(before) {
			t.Fatal("relinearization-key rejection mutated the input")
		}
	})

	t.Run("post-bind-evaluator-swap", func(t *testing.T) {
		source.Evaluator = source.Evaluator.ShallowCopy()
		input := validInput.CopyNew()
		before := input.CopyNew()
		if _, trace, evalErr := evaluator.EvalArithToArithNoise(input, certificate); evalErr == nil || trace.KeyPreflight().GraphMismatch == "" {
			t.Fatalf("post-bind source evaluator swap was accepted: err=%v trace=%+v", evalErr, trace.KeyPreflight())
		} else if trace.FailureStage() != homchain.A2AENoiseStageKeyPreflight || trace.OperationCounts() != (homchain.A2AENoiseOperationCounts{}) || len(trace.States()) != 0 {
			t.Fatalf("post-bind evaluator swap has non-fail-closed trace: stage=%q counts=%+v states=%v", trace.FailureStage(), trace.OperationCounts(), trace.States())
		}
		if !input.Equal(before) {
			t.Fatal("graph rejection mutated the input")
		}
	})

	method, ok := reflect.TypeOf(evaluator).MethodByName("EvalArithToArithNoise")
	if !ok || method.Type.NumIn() != 3 || method.Type.In(2) != reflect.TypeOf(homchain.A2AENoiseInputCertificate{}) ||
		method.Type.In(2) == reflect.TypeOf(homchain.A2AIAdmissionCertificate{}) ||
		method.Type.In(2) == reflect.TypeOf(homchain.GaoSineKernelInputCertificate{}) {
		t.Fatalf("A2A-e admission is not strongly isolated: %v", method.Type)
	}
}

func TestA2AENoiseRejectsInvalidParametersAndAdmissions(t *testing.T) {
	params, err := homchain.A2AENoiseFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	encoder := ckks.NewEncoder(params, z2n.DefaultPrecision)
	if _, err = homchain.NewA2AENoiseCircuit(params, nil, homchain.A2AENoiseOptions{MaxAbsLog2ScaleDownError: 1e-6}); err == nil {
		t.Fatal("nil encoder was accepted")
	}
	if _, err = homchain.NewA2AENoiseCircuit(params, ckks.NewEncoder(params, 53), homchain.A2AENoiseOptions{MaxAbsLog2ScaleDownError: 1e-6}); err == nil {
		t.Fatal("53-bit encoder was accepted")
	}
	wrongParams, err := homchain.GaoSineKernelFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = homchain.NewA2AENoiseCircuit(wrongParams, ckks.NewEncoder(wrongParams, z2n.DefaultPrecision), homchain.A2AENoiseOptions{MaxAbsLog2ScaleDownError: 1e-6}); err == nil {
		t.Fatal("foreign CKKS parameters were accepted")
	}
	reorderedLiteral := params.ParametersLiteral()
	reorderedLiteral.Q = append([]uint64(nil), reorderedLiteral.Q...)
	reorderedLiteral.Q[0], reorderedLiteral.Q[1] = reorderedLiteral.Q[1], reorderedLiteral.Q[0]
	reorderedParams, err := ckks.NewParametersFromLiteral(reorderedLiteral)
	if err != nil {
		t.Fatal(err)
	}
	if reorderedParams.Equal(&params) {
		t.Fatal("same-bit reordered-Q negative unexpectedly equals the canonical chain")
	}
	if _, err = homchain.NewA2AENoiseCircuit(reorderedParams, ckks.NewEncoder(reorderedParams, z2n.DefaultPrecision), homchain.A2AENoiseOptions{MaxAbsLog2ScaleDownError: 1e-6}); err == nil || !strings.Contains(err.Error(), "exact canonical modulus chain") {
		t.Fatalf("same-bit reordered Q chain was accepted: %v", err)
	}
	for _, bound := range []float64{0, -1, math.NaN(), math.Inf(1)} {
		if _, err = homchain.NewA2AENoiseCircuit(params, encoder, homchain.A2AENoiseOptions{MaxAbsLog2ScaleDownError: bound}); err == nil {
			t.Fatalf("invalid ScaleDown error bound %g was accepted", bound)
		}
	}
	circuit, err := homchain.NewA2AENoiseCircuit(params, encoder, homchain.A2AENoiseOptions{MaxAbsLog2ScaleDownError: 1e-6})
	if err != nil {
		t.Fatal(err)
	}
	artifact := "inline-functional-not-secure:a2ae-invalid-admission-controls"
	digest := sha256.Sum256([]byte(artifact))
	digestText := hex.EncodeToString(digest[:])
	for _, test := range []struct {
		name         string
		scale        rlwe.Scale
		lift         int64
		perturbation *big.Rat
		artifact     string
		digest       string
	}{
		{"integer-lift-overflow", params.DefaultScale(), 16, big.NewRat(0, 1), artifact, digestText},
		{"periodic-domain-overflow", params.DefaultScale(), 15, big.NewRat(2, 1), artifact, digestText},
		{"negative-perturbation", params.DefaultScale(), 0, big.NewRat(-1, 2), artifact, digestText},
		{"modular-scale", rlwe.NewScaleModT(params.DefaultScale(), 257), 0, big.NewRat(0, 1), artifact, digestText},
		{"empty-artifact", params.DefaultScale(), 0, big.NewRat(0, 1), "", digestText},
		{"wrong-evidence-digest", params.DefaultScale(), 0, big.NewRat(0, 1), artifact, strings.Repeat("0", 64)},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			if _, certificateErr := homchain.NewA2AENoiseInputCertificate(
				circuit.Profile(), test.scale, test.lift, test.perturbation, test.artifact, test.digest,
			); certificateErr == nil {
				t.Fatalf("invalid admission %s was accepted", test.name)
			}
		})
	}
}

func TestFunctionalNotSecureA2AENoiseNoCrossWordCrosstalk(t *testing.T) {
	params, err := homchain.A2AENoiseFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	ringZ, err := z2n.New(z2n.Word8)
	if err != nil {
		t.Fatal(err)
	}
	encoder := ckks.NewEncoder(params, z2n.DefaultPrecision)
	circuit, err := homchain.NewA2AENoiseCircuit(params, encoder, homchain.A2AENoiseOptions{MaxAbsLog2ScaleDownError: 1e-6})
	if err != nil {
		t.Fatal(err)
	}
	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	source := a2aeNoiseBootstrapEvaluator(t, circuit, params, keyGenerator, secretKey, nil, true)
	evaluator, err := circuit.BindEvaluator(source)
	if err != nil {
		t.Fatal(err)
	}
	certificate := newA2AENoiseTestCertificate(t, circuit.Profile(), params.DefaultScale())
	words := [4]uint64{0x00, 0x01, 0x80, 0xa5}
	baseline, bases := encryptA2AENoiseWordSentinel(t, params, ringZ, encoder, secretKey, words, -1)
	sentinel, _ := encryptA2AENoiseWordSentinel(t, params, ringZ, encoder, secretKey, words, 0)
	baselineOutput, baselineTrace, err := evaluator.EvalArithToArithNoise(baseline, certificate)
	if err != nil {
		t.Fatal(err)
	}
	sentinelOutput, sentinelTrace, err := evaluator.EvalArithToArithNoise(sentinel, certificate)
	if err != nil {
		t.Fatal(err)
	}
	decryptor := ckks.NewDecryptor(params, secretKey)
	affectedPhaseDifference := 0.0
	for _, pair := range [][2]*rlwe.Ciphertext{
		{baselineTrace.CoeffsToSlotsLow(), sentinelTrace.CoeffsToSlotsLow()},
		{baselineTrace.CoeffsToSlotsHigh(), sentinelTrace.CoeffsToSlotsHigh()},
	} {
		baselineValues := decodeA2AENoise(t, encoder, decryptor, pair[0])
		sentinelValues := decodeA2AENoise(t, encoder, decryptor, pair[1])
		for word := 0; word < 4; word++ {
			for slot := 0; slot < 4; slot++ {
				difference := sentinelValues[4*word+slot] - baselineValues[4*word+slot]
				phaseDifference := 16 * real(difference)
				phaseDistanceToInteger := math.Abs(phaseDifference - math.Round(phaseDifference))
				if word == 0 {
					affectedPhaseDifference = math.Max(affectedPhaseDifference, phaseDistanceToInteger)
				} else if phaseDistanceToInteger > 3e-4 || math.Abs(16*imag(difference)) > 3e-4 {
					t.Fatalf("sentinel word 0 crossed into CTS periodic phase of word %d slot %d: 16*delta=%v distance-to-Z=%.3g",
						word, slot, 16*difference, phaseDistanceToInteger)
				}
			}
		}
	}
	if affectedPhaseDifference < 1e-4 {
		t.Fatalf("word-0 sentinel did not activate either CTS periodic phase: max distance-to-Z %.3g", affectedPhaseDifference)
	}
	baselinePolynomials := decodeA2AENoisePolynomialBlocks(t, ringZ, encoder, decryptor, baselineOutput)
	sentinelPolynomials := decodeA2AENoisePolynomialBlocks(t, ringZ, encoder, decryptor, sentinelOutput)
	for word := 1; word < 4; word++ {
		for coefficient := 0; coefficient < 8; coefficient++ {
			baselineValue, _ := baselinePolynomials[word].Coefficients()[coefficient].Float64()
			sentinelValue, _ := sentinelPolynomials[word].Coefficients()[coefficient].Float64()
			baseValue, _ := bases[word].Coefficients()[coefficient].Float64()
			if math.Abs(baselineValue-sentinelValue) > 3e-4 || math.Abs(sentinelValue-baseValue) > 3e-4 {
				t.Fatalf("sentinel word 0 crossed into output word %d coefficient %d: baseline=%.9g sentinel=%.9g base=%.9g",
					word, coefficient, baselineValue, sentinelValue, baseValue)
			}
		}
		if residue, decodeErr := ringZ.DecodeArithmetic(sentinelPolynomials[word]); decodeErr != nil || residue != words[word] {
			t.Fatalf("unaffected word %d residue: got %#x want %#x err=%v", word, residue, words[word], decodeErr)
		}
	}
}

func TestA2AENoiseSourceGraphHasSingleGuardedScaleDown(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	sourcePath := filepath.Join(filepath.Dir(filename), "a2ae_noise.go")
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	body := string(source)
	if got := strings.Count(body, "e.bootstrap.ScaleDown("); got != 1 {
		t.Fatalf("A2A-e production has %d ScaleDown call sites, want exactly one", got)
	}
	if got := strings.Count(body, ".DropLevel("); got != 1 {
		t.Fatalf("A2A-e production has %d DropLevel call sites, want exactly one", got)
	}
	if strings.Contains(body, ".SetScale(") {
		t.Fatal("A2A-e production retags ciphertext scale metadata")
	}
	if strings.Contains(body, "scaledDown, scaledDown.Scale") {
		t.Fatal("A2A-e ScaleDown snapshots its actual scale as the expected scale")
	}
	if strings.Contains(body, ".Mul(*errScale).Equal(scaledDown.Scale)") {
		t.Fatal("A2A-e ScaleDown relies on numeric-only rlwe.Scale.Equal")
	}
	if got := strings.Count(body, "newDFTMatrixFromLiteralAtPrecision("); got != 2 || strings.Contains(body, "ckksdft.NewMatrixFromLiteral(") {
		t.Fatalf("A2A-e production DFT constructor path is not exclusively supplied-encoder precision: high-precision calls=%d", got)
	}
	for _, forbidden := range []string{"specifications.VPair()", "specifications.VSpecialB0Pair()", "specifications.UPair()"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("A2A-e production contains forbidden transform source %q", forbidden)
		}
	}
}

func TestA2AENoiseFixedPolynomialControlsRejectWrongC0AndDoubleAngleCount(t *testing.T) {
	profile, err := homchain.NewGaoSineKernelProfile()
	if err != nil {
		t.Fatal(err)
	}
	x := new(big.Float).SetPrec(z2n.DefaultPrecision).SetFloat64(0.173)
	oracle, err := homchain.EvaluateGaoSineKernelOracle(profile, x)
	if err != nil {
		t.Fatal(err)
	}
	correct := evaluateA2AENoiseTestPolynomial(profile.LattigoCoefficientValues(), profile.RecurrenceValues(), x, 3)
	wrongC0 := evaluateA2AENoiseTestPolynomial(profile.SourceCoefficientValues(), profile.RecurrenceValues(), x, 3)
	wrongRounds := evaluateA2AENoiseTestPolynomial(profile.LattigoCoefficientValues(), profile.RecurrenceValues(), x, 2)
	want, _ := oracle.FixedKernel().Float64()
	correctValue, _ := correct.Float64()
	wrongC0Value, _ := wrongC0.Float64()
	wrongRoundsValue, _ := wrongRounds.Float64()
	if math.Abs(correctValue-want) > 1e-15 {
		t.Fatalf("independent fixed oracle mismatch: got %.18g want %.18g", correctValue, want)
	}
	if math.Abs(wrongC0Value-want) < 1e-6 {
		t.Fatalf("unhalved c0 was not source-distinguishing: got %.18g want %.18g", wrongC0Value, want)
	}
	if math.Abs(wrongRoundsValue-want) < 1e-6 {
		t.Fatalf("two double-angle rounds were not source-distinguishing: got %.18g want %.18g", wrongRoundsValue, want)
	}
}

func TestFunctionalNotSecureA2AENoiseEndToEndPeriodicLiftOracle(t *testing.T) {
	params, err := homchain.A2AENoiseFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	ringZ, err := z2n.New(z2n.Word8)
	if err != nil {
		t.Fatal(err)
	}
	encoder := ckks.NewEncoder(params, z2n.DefaultPrecision)
	circuit, err := homchain.NewA2AENoiseCircuit(params, encoder, homchain.A2AENoiseOptions{MaxAbsLog2ScaleDownError: 1e-6})
	if err != nil {
		t.Fatal(err)
	}
	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	source := a2aeNoiseBootstrapEvaluator(t, circuit, params, keyGenerator, secretKey, nil, true)
	evaluator, err := circuit.BindEvaluator(source)
	if err != nil {
		t.Fatal(err)
	}

	artifact := "inline-functional-not-secure:a2ae-periodic-domain-max-lift-15-max-u-1-over-256"
	artifactDigest := sha256.Sum256([]byte(artifact))
	certificate, err := homchain.NewA2AENoiseInputCertificate(
		circuit.Profile(), params.DefaultScale(), 15, big.NewRat(1, 256),
		artifact, hex.EncodeToString(artifactDigest[:]),
	)
	if err != nil {
		t.Fatal(err)
	}
	if certificate.DomainInternallyVerified() || certificate.VerificationStatus() != homchain.A2AENoiseDomainExternalUnverified {
		t.Fatal("periodic integer-lift domain was promoted to an internal proof")
	}

	words := [4]uint64{0x00, 0x01, 0x80, 0xa5}
	pattern := [8]int64{1, -1, 2, -2, 3, -3, 4, -4}
	inputSlots := make([]*bignum.Complex, 0, params.MaxSlots())
	bases := make([]z2n.Polynomial, len(words))
	inputs := make([]z2n.Polynomial, len(words))
	expectedOutputs := make([]z2n.Polynomial, len(words))
	expectedRecovered := make([]z2n.Polynomial, len(words))
	uValues := make([][]*big.Float, len(words))
	integerLifts := make(map[int64]struct{})
	sineProfile, err := homchain.NewGaoSineKernelProfile()
	if err != nil {
		t.Fatal(err)
	}
	for wordIndex, word := range words {
		base, err := ringZ.CanonicalizeArithmetic(ringZ.ArithmeticEncode(word))
		if err != nil {
			t.Fatal(err)
		}
		bases[wordIndex] = base
		uCoefficients := make([]*big.Float, len(pattern))
		for coefficient, value := range pattern {
			numerator := big.NewInt(int64(wordIndex+1) * value)
			uCoefficients[coefficient] = new(big.Float).SetPrec(z2n.DefaultPrecision).SetRat(new(big.Rat).SetFrac(numerator, big.NewInt(4096)))
		}
		uValues[wordIndex] = uCoefficients
		uPolynomial, err := ringZ.NewPolynomial(uCoefficients)
		if err != nil {
			t.Fatal(err)
		}
		errorPolynomial, err := ringZ.Mul(uPolynomial, ringZ.TauInverse())
		if err != nil {
			t.Fatal(err)
		}
		noisy, err := ringZ.Add(base, errorPolynomial)
		if err != nil {
			t.Fatal(err)
		}
		inputs[wordIndex] = noisy
		block, err := ringZ.ToRootSlots(noisy)
		if err != nil {
			t.Fatal(err)
		}
		inputSlots = append(inputSlots, block...)

		timesTauBase, err := ringZ.MulTau(base)
		if err != nil {
			t.Fatal(err)
		}
		baseLifts := timesTauBase.Coefficients()
		recoveredNumerators := make([]*big.Float, len(pattern))
		for coefficient := range recoveredNumerators {
			liftFloat, _ := baseLifts[coefficient].Float64()
			lift := int64(math.Round(liftFloat))
			if math.Abs(liftFloat-float64(lift)) > 1e-30 {
				t.Fatalf("word %d coefficient %d base lift %.18g is not integral", wordIndex, coefficient, liftFloat)
			}
			integerLifts[lift] = struct{}{}
			x := new(big.Float).SetPrec(z2n.DefaultPrecision).Add(
				new(big.Float).SetPrec(z2n.DefaultPrecision).SetInt64(lift), uCoefficients[coefficient],
			)
			x.Quo(x, new(big.Float).SetPrec(z2n.DefaultPrecision).SetInt64(16))
			oracle, err := homchain.EvaluateGaoSineKernelOracle(sineProfile, x)
			if err != nil {
				t.Fatalf("word %d coefficient %d periodic oracle: %v", wordIndex, coefficient, err)
			}
			recoveredNumerators[coefficient] = oracle.FixedKernel()
		}
		recoveredNumeratorPolynomial, err := ringZ.NewPolynomial(recoveredNumerators)
		if err != nil {
			t.Fatal(err)
		}
		expectedRecovered[wordIndex], err = ringZ.Mul(recoveredNumeratorPolynomial, ringZ.TauInverse())
		if err != nil {
			t.Fatal(err)
		}
		expectedOutputs[wordIndex], err = ringZ.Sub(noisy, expectedRecovered[wordIndex])
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(integerLifts) < 2 {
		t.Fatalf("periodicity fixture exercised only one integer lift: %v", integerLifts)
	}

	plaintext := ckks.NewPlaintext(params, params.MaxLevel())
	plaintext.LogDimensions = circuit.Profile().FusedT().LogDimensions()
	plaintext.Scale = params.DefaultScale()
	if err = encoder.Encode(inputSlots, plaintext); err != nil {
		t.Fatal(err)
	}
	input, err := ckks.NewEncryptor(params, secretKey).EncryptNew(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	inputBefore := input.CopyNew()
	output, trace, err := evaluator.EvalArithToArithNoise(input, certificate)
	if err != nil {
		t.Fatal(err)
	}
	if !input.Equal(inputBefore) {
		t.Fatal("EvalArithToArithNoise mutated its input")
	}
	if output.Level() != 3 || !output.Scale.Equal(params.DefaultScale()) {
		t.Fatalf("output level/scale: L%d S=%s", output.Level(), output.Scale.Value.Text('x', -1))
	}
	if trace.Fidelity() != homchain.A2AENoiseLattigoAdaptation || trace.Maturity() != homchain.A2AENoiseFunctionalNotSecure ||
		trace.ProfileDigest() != circuit.Profile().Digest() || trace.CertificateDigest() != certificate.Digest() || trace.FailureStage() != "" {
		t.Fatalf("trace binding/fidelity failed: %+v", trace)
	}
	if trace.PeriodicDomain() == "" {
		t.Fatal("trace omitted the x=(I+u)/16 periodic-domain semantics")
	}
	preflight := trace.KeyPreflight()
	if !preflight.Checked || !preflight.GraphChecked || !preflight.GraphMatched || !preflight.DenseNoSwitchMatched ||
		!preflight.RelinearizationPresent || !preflight.RelinearizationMatched || len(preflight.MissingGaloisElements) != 0 {
		t.Fatalf("key/graph preflight is incomplete: %+v", preflight)
	}
	counts := trace.OperationCounts()
	if counts != (homchain.A2AENoiseOperationCounts{
		FusedTZToC: 1, SlotsToCoeffsFactors: 2, ScaleDown: 1, ModUp: 1, CoeffsToSlotsFactors: 3,
		SinePolynomialPerHalf: 1, DoubleAnglesPerHalf: 3, FusedTInverseCToZ: 1,
		OriginalDropLevel: 1, FinalInputMinusRecovered: 1,
	}) {
		t.Fatalf("operation identity/counts: %+v", counts)
	}
	assertA2AENoiseTraceLedger(t, params, trace)

	decryptor := ckks.NewDecryptor(params, secretKey)
	assertA2AENoiseLiveSineSchedule(t, circuit.Profile(), trace)
	assertA2AENoiseDetachedAccessors(t, circuit, trace)
	assertA2AENoiseWrongTransformControls(t, circuit, params, ringZ, encoder, source, decryptor, input, trace)
	assertA2AENoiseWrongCTSNormalization(t, params, encoder, source, decryptor, trace)
	ctsLow := decodeA2AENoise(t, encoder, decryptor, trace.CoeffsToSlotsLow())
	ctsHigh := decodeA2AENoise(t, encoder, decryptor, trace.CoeffsToSlotsHigh())
	maxIntegerDistance, maxAbsLift := 0.0, 0.0
	for wordIndex := range words {
		for halfSlot := 0; halfSlot < 4; halfSlot++ {
			for half, values := range []struct {
				name string
				got  []complex128
				off  int
			}{{"low", ctsLow, 0}, {"high", ctsHigh, 4}} {
				_ = half
				index := 4*wordIndex + halfSlot
				u, _ := uValues[wordIndex][values.off+halfSlot].Float64()
				lift := math.Round(16*real(values.got[index]) - u)
				distance := math.Abs(16*real(values.got[index]) - u - lift)
				maxIntegerDistance = math.Max(maxIntegerDistance, distance)
				maxAbsLift = math.Max(maxAbsLift, math.Abs(lift))
				if math.Abs(imag(values.got[index])) > 8e-4 || distance > 8e-3 || math.Abs(lift) >= 16 {
					t.Fatalf("word %d %s[%d]: x=%v u=%.12g distance-to-Z=%.3g |I|=%.3g", wordIndex, values.name, halfSlot, values.got[index], u, distance, math.Abs(lift))
				}
			}
		}
	}

	recovered := decodeA2AENoisePolynomialBlocks(t, ringZ, encoder, decryptor, trace.RecoveredError())
	gotOutputs := decodeA2AENoisePolynomialBlocks(t, ringZ, encoder, decryptor, output)
	if difference := maxA2AENoiseCiphertextDifference(t, encoder, decryptor, trace.RecoveredError(), output); difference < 1e-2 {
		t.Fatalf("returned recovered error instead of input-minus-recovered output: max difference %.3g", difference)
	}
	maxRecoveredError, maxOutputError := 0.0, 0.0
	maxInputNoise, maxOutputNoise := 0.0, 0.0
	maxRecoveredLow, maxRecoveredHigh := 0.0, 0.0
	for wordIndex, word := range words {
		if residue, err := ringZ.DecodeArithmetic(gotOutputs[wordIndex]); err != nil || residue != word {
			t.Fatalf("word %d residue: got %#x, want %#x, err=%v", wordIndex, residue, word, err)
		}
		for coefficient := 0; coefficient < 8; coefficient++ {
			gotRecovered, _ := recovered[wordIndex].Coefficients()[coefficient].Float64()
			wantRecovered, _ := expectedRecovered[wordIndex].Coefficients()[coefficient].Float64()
			maxRecoveredError = math.Max(maxRecoveredError, math.Abs(gotRecovered-wantRecovered))
			if coefficient < 4 {
				maxRecoveredLow = math.Max(maxRecoveredLow, math.Abs(gotRecovered))
			} else {
				maxRecoveredHigh = math.Max(maxRecoveredHigh, math.Abs(gotRecovered))
			}
			gotOutput, _ := gotOutputs[wordIndex].Coefficients()[coefficient].Float64()
			wantOutput, _ := expectedOutputs[wordIndex].Coefficients()[coefficient].Float64()
			maxOutputError = math.Max(maxOutputError, math.Abs(gotOutput-wantOutput))
			baseValue, _ := bases[wordIndex].Coefficients()[coefficient].Float64()
			inputValue, _ := inputs[wordIndex].Coefficients()[coefficient].Float64()
			maxInputNoise = math.Max(maxInputNoise, math.Abs(inputValue-baseValue))
			maxOutputNoise = math.Max(maxOutputNoise, math.Abs(gotOutput-baseValue))
		}
	}
	if maxRecoveredError > 3e-4 || maxOutputError > 3e-4 {
		t.Fatalf("fixed-polynomial oracle errors: recovered=%.3g output=%.3g", maxRecoveredError, maxOutputError)
	}
	if maxRecoveredLow < 1e-5 || maxRecoveredHigh < 1e-5 {
		t.Fatalf("both sine halves did not participate: max recovered low=%.3g high=%.3g", maxRecoveredLow, maxRecoveredHigh)
	}
	if !(maxOutputNoise < maxInputNoise/100) {
		t.Fatalf("noise was not materially reduced: input=%.3g output=%.3g", maxInputNoise, maxOutputNoise)
	}
	t.Logf("A2A-e periodic lift: max distance-to-Z=%.3g max |I|=%.1f; recovered oracle=%.3g output oracle=%.3g; noise %.3g -> %.3g; profile=%s",
		maxIntegerDistance, maxAbsLift, maxRecoveredError, maxOutputError, maxInputNoise, maxOutputNoise, circuit.Profile().Digest())
}

func a2aeNoiseBootstrapEvaluator(
	t *testing.T,
	circuit *homchain.A2AENoiseCircuit,
	params ckks.Parameters,
	keyGenerator *rlwe.KeyGenerator,
	secretKey *rlwe.SecretKey,
	omit *uint64,
	withRelinearization bool,
) *bootstrapping.Evaluator {
	t.Helper()
	galois := circuit.RequiredKeyProfile().All()
	if omit != nil {
		filtered := make([]uint64, 0, len(galois)-1)
		for _, element := range galois {
			if element != *omit {
				filtered = append(filtered, element)
			}
		}
		galois = filtered
	}
	dft := circuit.Profile().DFT()
	parameters := bootstrapping.Parameters{
		ResidualParameters: params, BootstrappingParameters: params,
		SlotsToCoeffsParameters: dft.SlotsToCoeffsLiteral(), CoeffsToSlotsParameters: dft.CoeffsToSlotsLiteral(),
		Mod1ParametersLiteral: mod1.ParametersLiteral{
			LevelQ: dft.CoeffsToSlotsLiteral().LevelQ - 3, LogScale: params.LogDefaultScale(),
			Mod1Type: mod1.SinContinuous, LogMessageRatio: 0, K: 1, Mod1Degree: 3,
		},
		CircuitOrder: bootstrapping.Custom,
	}
	var relin *rlwe.RelinearizationKey
	if withRelinearization {
		relin = keyGenerator.GenRelinearizationKeyNew(secretKey)
	}
	keys := &bootstrapping.EvaluationKeys{MemEvaluationKeySet: rlwe.NewMemEvaluationKeySet(
		relin, keyGenerator.GenGaloisKeysNew(galois, secretKey)...,
	)}
	evaluator, err := bootstrapping.NewEvaluator(parameters, keys)
	if err != nil {
		t.Fatal(err)
	}
	return evaluator
}

func assertA2AENoiseTraceLedger(t *testing.T, params ckks.Parameters, trace homchain.A2AENoiseTrace) {
	t.Helper()
	expected := []struct {
		lane  homchain.A2AENoiseLane
		stage homchain.A2AENoiseStage
		level int
	}{
		{homchain.A2AENoiseWhole, homchain.A2AENoiseStageInput, 16},
		{homchain.A2AENoiseLow, homchain.A2AENoiseStageFusedTZToC, 15},
		{homchain.A2AENoiseHigh, homchain.A2AENoiseStageFusedTZToC, 15},
		{homchain.A2AENoiseWhole, homchain.A2AENoiseStageSlotsToCoeffs, 13},
		{homchain.A2AENoiseWhole, homchain.A2AENoiseStageScaleDown, 0},
		{homchain.A2AENoiseWhole, homchain.A2AENoiseStageModUp, 16},
		{homchain.A2AENoiseLow, homchain.A2AENoiseStageCoeffsToSlots, 13},
		{homchain.A2AENoiseHigh, homchain.A2AENoiseStageCoeffsToSlots, 13},
		{homchain.A2AENoiseLow, homchain.A2AENoiseStageSinePolynomial, 7},
		{homchain.A2AENoiseLow, homchain.A2AENoiseStageDoubleAngle0, 6},
		{homchain.A2AENoiseLow, homchain.A2AENoiseStageDoubleAngle1, 5},
		{homchain.A2AENoiseLow, homchain.A2AENoiseStageDoubleAngle2, 4},
		{homchain.A2AENoiseHigh, homchain.A2AENoiseStageSinePolynomial, 7},
		{homchain.A2AENoiseHigh, homchain.A2AENoiseStageDoubleAngle0, 6},
		{homchain.A2AENoiseHigh, homchain.A2AENoiseStageDoubleAngle1, 5},
		{homchain.A2AENoiseHigh, homchain.A2AENoiseStageDoubleAngle2, 4},
		{homchain.A2AENoiseWhole, homchain.A2AENoiseStageRecoveredError, 3},
		{homchain.A2AENoiseWhole, homchain.A2AENoiseStageOriginalDropLevel, 3},
		{homchain.A2AENoiseWhole, homchain.A2AENoiseStageOutputSubtract, 3},
	}
	if got := len(trace.States()); got != len(expected) {
		t.Fatalf("trace states: got %d, want %d", got, len(expected))
	}
	for _, item := range expected {
		state, ok := trace.State(item.lane, item.stage)
		if !ok || state.Level != item.level || state.Degree != 1 || !state.ScaleExact {
			t.Fatalf("state %s/%s: got %+v ok=%t, want level=%d exact", item.lane, item.stage, state, ok, item.level)
		}
	}
	scaledDown, _ := trace.State(homchain.A2AENoiseWhole, homchain.A2AENoiseStageScaleDown)
	raised, _ := trace.State(homchain.A2AENoiseWhole, homchain.A2AENoiseStageModUp)
	ctsLow, _ := trace.State(homchain.A2AENoiseLow, homchain.A2AENoiseStageCoeffsToSlots)
	if !scaledDown.Scale.Equal(raised.Scale) || !raised.Scale.Equal(ctsLow.Scale) || !ctsLow.Scale.EqualScale(params.DefaultScale()) {
		t.Fatal("ScaleDown/ModUp/CTS did not naturally preserve exact Delta")
	}
	errScaleSnapshot, errLog2 := trace.ScaleDownError()
	if math.IsNaN(errLog2) || math.IsInf(errLog2, 0) || math.Abs(errLog2) > 1e-6 {
		t.Fatalf("ScaleDown log2 error: %g", errLog2)
	}
	errScale, err := errScaleSnapshot.Scale()
	if err != nil {
		t.Fatal(err)
	}
	expectedScaleDown, err := homchain.NewExactScaleSnapshot(rlwe.NewScale(params.Q()[0]).Mul(errScale))
	if err != nil {
		t.Fatal(err)
	}
	if !scaledDown.ExpectedScale.Equal(expectedScaleDown) || !scaledDown.Scale.Equal(expectedScaleDown) || !scaledDown.ScaleExact {
		t.Fatalf("ScaleDown exact raw-scale witness is not independently q0*errScale: got=%+v want=%+v", scaledDown, expectedScaleDown)
	}
}

func assertA2AENoiseLiveSineSchedule(t *testing.T, profile homchain.A2AENoiseProfile, trace homchain.A2AENoiseTrace) {
	t.Helper()
	schedule := profile.SineScaleSchedule()
	if len(schedule) != 5 {
		t.Fatalf("sealed sine scale schedule has %d states, want 5", len(schedule))
	}
	stages := []homchain.A2AENoiseStage{
		homchain.A2AENoiseStageSinePolynomial,
		homchain.A2AENoiseStageDoubleAngle0,
		homchain.A2AENoiseStageDoubleAngle1,
		homchain.A2AENoiseStageDoubleAngle2,
	}
	for _, lane := range []homchain.A2AENoiseLane{homchain.A2AENoiseLow, homchain.A2AENoiseHigh} {
		for i, stage := range stages {
			state, ok := trace.State(lane, stage)
			if !ok || !state.Scale.Equal(schedule[i+1]) || !state.ExpectedScale.Equal(schedule[i+1]) || !state.ScaleExact {
				t.Fatalf("live %s/%s scale does not exact-match calibrated schedule[%d]: %+v", lane, stage, i+1, state)
			}
		}
	}
}

func assertA2AENoiseDetachedAccessors(t *testing.T, circuit *homchain.A2AENoiseCircuit, trace homchain.A2AENoiseTrace) {
	t.Helper()
	profile := circuit.Profile()
	names := profile.TransformNames()
	names[0] = homchain.V0Normal
	if circuit.Profile().TransformNames()[0] != homchain.V0FusedT {
		t.Fatal("profile transform-name accessor aliases sealed state")
	}
	rotations := profile.FusedT().RotationIndexes()
	if len(rotations) != 0 {
		rotations[0]++
		if reflect.DeepEqual(rotations, circuit.Profile().FusedT().RotationIndexes()) {
			t.Fatal("profile rotation accessor aliases sealed state")
		}
	}
	schedule := profile.SineScaleSchedule()
	schedule[0] = homchain.ExactScaleSnapshot{}
	if circuit.Profile().SineScaleSchedule()[0] == (homchain.ExactScaleSnapshot{}) {
		t.Fatal("profile sine schedule accessor aliases sealed state")
	}
	ctsLiteral := profile.DFT().CoeffsToSlotsLiteral()
	ctsLiteral.Levels[0] = 99
	ctsLiteral.Scaling.SetInt64(99)
	freshCTS := circuit.Profile().DFT().CoeffsToSlotsLiteral()
	if freshCTS.Levels[0] == 99 || freshCTS.Scaling.Cmp(new(big.Float).SetPrec(z2n.DefaultPrecision).SetInt64(99)) == 0 {
		t.Fatal("DFT literal accessor aliases sealed matrix metadata")
	}
	keys := circuit.RequiredKeyProfile().All()
	keys[0] = 0
	if circuit.RequiredKeyProfile().All()[0] == 0 {
		t.Fatal("key-profile accessor aliases sealed state")
	}
	states := trace.States()
	states[0].Level = -1
	if trace.States()[0].Level == -1 {
		t.Fatal("trace state accessor aliases evidence")
	}
	preflight := trace.KeyPreflight()
	preflight.MissingGaloisElements = append(preflight.MissingGaloisElements, 1)
	if len(trace.KeyPreflight().MissingGaloisElements) != 0 {
		t.Fatal("trace preflight accessor aliases evidence")
	}
	cts := trace.CoeffsToSlotsLow()
	cts.Scale = rlwe.NewScale(1)
	if trace.CoeffsToSlotsLow().Scale.Equal(rlwe.NewScale(1)) {
		t.Fatal("trace ciphertext accessor aliases evidence")
	}
}

func assertA2AENoiseWrongTransformControls(
	t *testing.T,
	circuit *homchain.A2AENoiseCircuit,
	params ckks.Parameters,
	ringZ *z2n.Ring,
	encoder *ckks.Encoder,
	source *bootstrapping.Evaluator,
	decryptor *rlwe.Decryptor,
	input *rlwe.Ciphertext,
	trace homchain.A2AENoiseTrace,
) {
	t.Helper()
	specifications, err := homchain.NewSpecificationsFromRing(ringZ, 4)
	if err != nil {
		t.Fatal(err)
	}
	vOptions := homchain.CompileOptions{
		LevelQ: params.MaxLevel(), LevelP: params.MaxLevelP(),
		Scale: rlwe.NewScale(params.Q()[params.MaxLevel()]), LogBabyStepGiantStepRatio: 0,
	}
	normalV, err := homchain.CompilePair(params, encoder, specifications.VPair(), vOptions)
	if err != nil {
		t.Fatal(err)
	}
	specialV, err := homchain.CompilePair(params, encoder, specifications.VSpecialB0Pair(), vOptions)
	if err != nil {
		t.Fatal(err)
	}
	triangle := homchain.NewEvaluator(source.Evaluator)
	normalHalves, err := triangle.ZToCNew(input.CopyNew(), normalV)
	if err != nil {
		t.Fatal(err)
	}
	specialHalves, err := triangle.ZToCNew(input.CopyNew(), specialV)
	if err != nil {
		t.Fatal(err)
	}
	fusedHalves := homchain.CiphertextPair{trace.FusedTLow(), trace.FusedTHigh()}
	if difference := maxA2AENoisePairDifference(t, encoder, decryptor, normalHalves, fusedHalves); difference < 1e-3 {
		t.Fatalf("normal V is not source-distinguished from fused-t V: max difference %.3g", difference)
	}
	if difference := maxA2AENoisePairDifference(t, encoder, decryptor, specialHalves, fusedHalves); difference < 1e-3 {
		t.Fatalf("special-b0 V is not source-distinguished from fused-t V: max difference %.3g", difference)
	}

	uScale, err := circuit.Profile().FusedTInverse().MatrixScale().Scale()
	if err != nil {
		t.Fatal(err)
	}
	uOptions := homchain.CompileOptions{
		LevelQ: 4, LevelP: params.MaxLevelP(), Scale: uScale, LogBabyStepGiantStepRatio: 0,
	}
	normalU, err := homchain.CompilePair(params, encoder, specifications.UPair(), uOptions)
	if err != nil {
		t.Fatal(err)
	}
	fusedU, err := homchain.CompilePair(params, encoder, specifications.UFusedTInvPair(), uOptions)
	if err != nil {
		t.Fatal(err)
	}
	sine := homchain.CiphertextPair{trace.SineLow(), trace.SineHigh()}
	normalRecovered, err := triangle.CToZNew(sine, normalU)
	if err != nil {
		t.Fatal(err)
	}
	swappedRecovered, err := triangle.CToZNew(homchain.CiphertextPair{trace.SineHigh(), trace.SineLow()}, fusedU)
	if err != nil {
		t.Fatal(err)
	}
	correctRecovered := trace.RecoveredError()
	if difference := maxA2AENoiseCiphertextDifference(t, encoder, decryptor, normalRecovered, correctRecovered); difference < 1e-3 {
		t.Fatalf("normal U is not source-distinguished from fused-t-inverse U: max difference %.3g", difference)
	}
	if difference := maxA2AENoiseCiphertextDifference(t, encoder, decryptor, swappedRecovered, correctRecovered); difference < 1e-3 {
		t.Fatalf("swapped low/high halves are not source-distinguished: max difference %.3g", difference)
	}
}

func assertA2AENoiseWrongCTSNormalization(
	t *testing.T,
	params ckks.Parameters,
	encoder *ckks.Encoder,
	source *bootstrapping.Evaluator,
	decryptor *rlwe.Decryptor,
	trace homchain.A2AENoiseTrace,
) {
	t.Helper()
	wrongLiteral := trace.DFT().CoeffsToSlotsLiteral()
	wrongLiteral.Scaling = new(big.Float).SetPrec(z2n.DefaultPrecision).SetInt64(1)
	wrongMatrix, err := ckksdft.NewMatrixFromLiteral(params, wrongLiteral, encoder)
	if err != nil {
		t.Fatal(err)
	}
	wrongLow, wrongHigh, err := source.DFTEvaluator.CoeffsToSlotsNew(trace.RaisedCoefficients(), wrongMatrix)
	if err != nil {
		t.Fatal(err)
	}
	wrong := homchain.CiphertextPair{wrongLow, wrongHigh}
	correct := homchain.CiphertextPair{trace.CoeffsToSlotsLow(), trace.CoeffsToSlotsHigh()}
	if difference := maxA2AENoisePairDifference(t, encoder, decryptor, wrong, correct); difference < 1e-2 {
		t.Fatalf("CTS Scaling=1 is not source-distinguished from sealed Scaling=1/16: max difference %.3g", difference)
	}
}

func maxA2AENoisePairDifference(
	t *testing.T,
	encoder *ckks.Encoder,
	decryptor *rlwe.Decryptor,
	left, right homchain.CiphertextPair,
) float64 {
	t.Helper()
	maximum := 0.0
	for half := 0; half < 2; half++ {
		leftValues := decodeA2AENoise(t, encoder, decryptor, left[half])
		rightValues := decodeA2AENoise(t, encoder, decryptor, right[half])
		for i := range leftValues {
			maximum = math.Max(maximum, math.Hypot(real(leftValues[i]-rightValues[i]), imag(leftValues[i]-rightValues[i])))
		}
	}
	return maximum
}

func maxA2AENoiseCiphertextDifference(
	t *testing.T,
	encoder *ckks.Encoder,
	decryptor *rlwe.Decryptor,
	left, right *rlwe.Ciphertext,
) float64 {
	t.Helper()
	leftValues := decodeA2AENoise(t, encoder, decryptor, left)
	rightValues := decodeA2AENoise(t, encoder, decryptor, right)
	maximum := 0.0
	for i := range leftValues {
		maximum = math.Max(maximum, math.Hypot(real(leftValues[i]-rightValues[i]), imag(leftValues[i]-rightValues[i])))
	}
	return maximum
}

func decodeA2AENoise(t *testing.T, encoder *ckks.Encoder, decryptor *rlwe.Decryptor, ciphertext *rlwe.Ciphertext) []complex128 {
	t.Helper()
	if ciphertext == nil {
		t.Fatal("nil A2A-e evidence ciphertext")
	}
	values := make([]complex128, ciphertext.Slots())
	if err := encoder.Decode(decryptor.DecryptNew(ciphertext), values); err != nil {
		t.Fatal(err)
	}
	return values
}

func decodeA2AENoisePolynomialBlocks(t *testing.T, ringZ *z2n.Ring, encoder *ckks.Encoder, decryptor *rlwe.Decryptor, ciphertext *rlwe.Ciphertext) []z2n.Polynomial {
	t.Helper()
	values := decodeA2AENoise(t, encoder, decryptor, ciphertext)
	result := make([]z2n.Polynomial, 4)
	for word := 0; word < 4; word++ {
		block := make([]*bignum.Complex, 4)
		for slot := range block {
			block[slot] = bignum.ToComplex(values[4*word+slot], z2n.DefaultPrecision)
		}
		polynomial, err := ringZ.FromRootSlots(block)
		if err != nil {
			t.Fatal(err)
		}
		result[word] = polynomial
	}
	return result
}

func newA2AENoiseTestCertificate(t *testing.T, profile homchain.A2AENoiseProfile, scale rlwe.Scale) homchain.A2AENoiseInputCertificate {
	t.Helper()
	artifact := "inline-functional-not-secure:a2ae-test-domain"
	digest := sha256.Sum256([]byte(artifact))
	certificate, err := homchain.NewA2AENoiseInputCertificate(
		profile, scale, 15, big.NewRat(1, 256), artifact, hex.EncodeToString(digest[:]),
	)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func newA2AENoiseMetadataCiphertext(params ckks.Parameters, degree, level int) *rlwe.Ciphertext {
	ciphertext := ckks.NewCiphertext(params, degree, level)
	ciphertext.LogDimensions = ring.Dimensions{Rows: 0, Cols: 4}
	ciphertext.Scale = params.DefaultScale()
	ciphertext.IsBatched = true
	ciphertext.IsNTT = true
	return ciphertext
}

func encryptA2AENoiseWordSentinel(
	t *testing.T,
	params ckks.Parameters,
	ringZ *z2n.Ring,
	encoder *ckks.Encoder,
	secretKey *rlwe.SecretKey,
	words [4]uint64,
	perturbedWord int,
) (*rlwe.Ciphertext, []z2n.Polynomial) {
	t.Helper()
	pattern := [8]int64{1, -1, 2, -2, 3, -3, 4, -4}
	slots := make([]*bignum.Complex, 0, params.MaxSlots())
	bases := make([]z2n.Polynomial, len(words))
	for wordIndex, word := range words {
		base, err := ringZ.CanonicalizeArithmetic(ringZ.ArithmeticEncode(word))
		if err != nil {
			t.Fatal(err)
		}
		bases[wordIndex] = base
		value := base
		if wordIndex == perturbedWord {
			coefficients := make([]*big.Float, len(pattern))
			for i, coefficient := range pattern {
				coefficients[i] = new(big.Float).SetPrec(z2n.DefaultPrecision).SetRat(big.NewRat(coefficient, 4096))
			}
			u, polynomialErr := ringZ.NewPolynomial(coefficients)
			if polynomialErr != nil {
				t.Fatal(polynomialErr)
			}
			errorPolynomial, polynomialErr := ringZ.Mul(u, ringZ.TauInverse())
			if polynomialErr != nil {
				t.Fatal(polynomialErr)
			}
			value, polynomialErr = ringZ.Add(base, errorPolynomial)
			if polynomialErr != nil {
				t.Fatal(polynomialErr)
			}
		}
		block, err := ringZ.ToRootSlots(value)
		if err != nil {
			t.Fatal(err)
		}
		slots = append(slots, block...)
	}
	plaintext := ckks.NewPlaintext(params, params.MaxLevel())
	plaintext.LogDimensions = ring.Dimensions{Rows: 0, Cols: 4}
	plaintext.Scale = params.DefaultScale()
	if err := encoder.Encode(slots, plaintext); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := ckks.NewEncryptor(params, secretKey).EncryptNew(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	return ciphertext, bases
}

func evaluateA2AENoiseTestPolynomial(coefficients, recurrence []*big.Float, x *big.Float, rounds int) *big.Float {
	precision := x.Prec()
	bNext := new(big.Float).SetPrec(precision)
	bNextNext := new(big.Float).SetPrec(precision)
	twoX := new(big.Float).SetPrec(precision).Add(x, x)
	for i := len(coefficients) - 1; i >= 1; i-- {
		current := new(big.Float).SetPrec(precision).Mul(twoX, bNext)
		current.Sub(current, bNextNext)
		current.Add(current, coefficients[i])
		bNextNext, bNext = bNext, current
	}
	result := new(big.Float).SetPrec(precision).Mul(x, bNext)
	result.Sub(result, bNextNext)
	result.Add(result, coefficients[0])
	for i := 0; i < rounds; i++ {
		result.Mul(result, result)
		result.Add(result, result)
		result.Add(result, recurrence[i])
	}
	return result
}
