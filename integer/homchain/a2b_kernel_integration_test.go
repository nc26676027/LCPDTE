package homchain

import (
	"math"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

func TestGaoA2BKernelEvaluatesAllCodePointsWithOneSharedLUTBasis(t *testing.T) {
	params, err := GaoA2BKernelFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	encoder := ckks.NewEncoder(params, 256)
	circuit, err := NewGaoA2BKernelCircuit(params, encoder)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := circuit.Profile().Digest(), "44471389349992ceda095f2b4bd09a992af7235f6dfabbf0703aa9fe3986519e"; got != want {
		t.Fatalf("Gao A2B kernel v3 profile digest: got %s, want %s", got, want)
	}

	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	relinearizationKey := keyGenerator.GenRelinearizationKeyNew(secretKey)
	conjugationKey := keyGenerator.GenGaloisKeyNew(params.GaloisElementForComplexConjugation(), secretKey)
	evaluator := ckks.NewEvaluator(params, rlwe.NewMemEvaluationKeySet(relinearizationKey, conjugationKey))
	callerPrecision := evaluator.Encoder.Prec()
	if callerPrecision > 53 {
		t.Fatalf("caller evaluator precision=%d, want default <=53", callerPrecision)
	}
	bound, err := circuit.BindEvaluator(evaluator)
	if err != nil {
		t.Fatal(err)
	}

	values := make([]complex128, params.MaxSlots())
	for point := range values {
		values[point] = complex(float64(point)/256, 0)
	}
	plaintext := ckks.NewPlaintext(params, circuit.Profile().InputLevel())
	plaintext.LogDimensions = params.LogMaxDimensions()
	plaintext.Scale = params.DefaultScale()
	if err = encoder.Encode(values, plaintext); err != nil {
		t.Fatal(err)
	}
	input, err := ckks.NewEncryptor(params, secretKey).EncryptNew(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	inputBefore := input.CopyNew()
	result, err := bound.EvaluateNew(input)
	if err != nil {
		t.Fatal(err)
	}
	if !input.Equal(inputBefore) {
		t.Fatal("Gao A2B kernel mutated its input")
	}
	if evaluator.Encoder.Prec() != callerPrecision || bound.OperationalEncoderPrecision() != 256 {
		t.Fatalf("encoder isolation failed: caller=%d (started %d), operational=%d",
			evaluator.Encoder.Prec(), callerPrecision, bound.OperationalEncoderPrecision())
	}

	identity := result.IdentityCiphertext()
	msb := result.MSBCiphertext()
	if identity == nil || msb == nil {
		t.Fatal("Gao A2B kernel returned a nil named output")
	}
	identityValues := make([]complex128, params.MaxSlots())
	msbValues := make([]complex128, params.MaxSlots())
	exponentialValues := make([]complex128, params.MaxSlots())
	rootValues := make([]complex128, params.MaxSlots())
	decryptor := ckks.NewDecryptor(params, secretKey)
	if err = encoder.Decode(decryptor.DecryptNew(identity), identityValues); err != nil {
		t.Fatal(err)
	}
	if err = encoder.Decode(decryptor.DecryptNew(msb), msbValues); err != nil {
		t.Fatal(err)
	}
	if err = encoder.Decode(decryptor.DecryptNew(result.ExponentialBaseCiphertext()), exponentialValues); err != nil {
		t.Fatal(err)
	}
	if err = encoder.Decode(decryptor.DecryptNew(result.RootOfUnityCiphertext()), rootValues); err != nil {
		t.Fatal(err)
	}
	exponentialProfile, err := NewGaoA2BExpProfile()
	if err != nil {
		t.Fatal(err)
	}
	var maxIdentityError, maxMSBError, maxExponentialError, maxRootError float64
	for point := range values {
		wantIdentity := 0.0
		if point != 0 {
			wantIdentity = float64(point-16) / 16
		}
		wantMSB := 0.0
		if 1 <= point && point <= 8 {
			wantMSB = 1
		}
		identityError := math.Abs(real(identityValues[point]) - wantIdentity)
		if identityError > maxIdentityError {
			maxIdentityError = identityError
		}
		if identityError >= math.Ldexp(1, -12) {
			t.Fatalf("identity slot point=%d: got %.12g, want %.12g, error %.3g", point, real(identityValues[point]), wantIdentity, identityError)
		}
		msbError := math.Abs(real(msbValues[point]) - wantMSB)
		if msbError > maxMSBError {
			maxMSBError = msbError
		}
		if msbError >= math.Ldexp(1, -12) {
			t.Fatalf("MSB slot point=%d: got %.12g, want %.12g, error %.3g", point, real(msbValues[point]), wantMSB, msbError)
		}
		y := new(big.Float).SetPrec(256).Quo(
			new(big.Float).SetPrec(256).SetInt64(int64(point)),
			new(big.Float).SetPrec(256).SetInt64(256),
		)
		oracle, oracleErr := EvaluateGaoA2BExpOracle(exponentialProfile, y)
		if oracleErr != nil {
			t.Fatal(oracleErr)
		}
		baseWant := complexFromA2BKernelBig(oracle.BasePolynomial())
		rootWant := complexFromA2BKernelBig(oracle.FinalPolynomial())
		if approximationError := cmplxDistanceA2BKernel(exponentialValues[point], baseWant); approximationError > maxExponentialError {
			maxExponentialError = approximationError
		}
		if approximationError := cmplxDistanceA2BKernel(rootValues[point], rootWant); approximationError > maxRootError {
			maxRootError = approximationError
		}
	}
	if maxExponentialError >= math.Ldexp(1, -18) || maxRootError >= math.Ldexp(1, -16) {
		t.Fatalf("encrypted exponential checkpoints exceed gates: base=%.3g root=%.3g", maxExponentialError, maxRootError)
	}

	counts := result.Provenance().OperationCounts()
	if counts.ExpPolynomialEvaluations != 1 || counts.ComplexSquarings != 2 ||
		counts.MultiPolynomialEvaluations != 1 || counts.SharedPowerBases != 1 ||
		counts.GenericLUTEvaluations != 0 || counts.Conjugations != 2 || counts.RealRecoveries != 2 {
		t.Fatalf("unexpected Gao A2B kernel operation path: %+v", counts)
	}
	states := result.Provenance().States()
	wantStages := []GaoA2BKernelStage{
		GaoA2BKernelStageInput, GaoA2BKernelStageExponential, GaoA2BKernelStageSquare0,
		GaoA2BKernelStageRootOfUnity, GaoA2BKernelStageIdentityLUT, GaoA2BKernelStageMSBLUT,
		GaoA2BKernelStageIdentityOutput, GaoA2BKernelStageMSBOutput,
	}
	wantLevels := []int{17, 11, 10, 9, 5, 5, 5, 5}
	if len(states) != len(wantStages) {
		t.Fatalf("ciphertext states=%d, want %d", len(states), len(wantStages))
	}
	for index := range states {
		if states[index].Stage != wantStages[index] || states[index].Level != wantLevels[index] ||
			states[index].Degree != 1 || !states[index].ScaleExact {
			t.Fatalf("state %d mismatch: %+v", index, states[index])
		}
	}
	const measuredOutputScaleHex = "0x1p+35"
	if states[6].Scale.ValueHex() != measuredOutputScaleHex || states[7].Scale.ValueHex() != measuredOutputScaleHex ||
		!states[6].Scale.Equal(circuit.Profile().BooleanOutputScale()) ||
		!states[7].Scale.Equal(circuit.Profile().BooleanOutputScale()) ||
		circuit.Profile().BooleanOutputLevel() != 5 {
		t.Fatalf("sealed exact-default output state drifted: ID=%s MSB=%s profile=L%d/%s want=L5/%s",
			states[6].Scale.ValueHex(), states[7].Scale.ValueHex(), circuit.Profile().BooleanOutputLevel(),
			circuit.Profile().BooleanOutputScale().ValueHex(), measuredOutputScaleHex)
	}

	// Measure the source-scheduled residual factor ID*(1/16). Encoding the
	// dyadic at the current Q limb and rescaling consumes exactly one level and
	// preserves the ID output scale without metadata retagging.
	residualPlaintext := ckks.NewPlaintext(params, identity.Level())
	residualPlaintext.LogDimensions = params.LogMaxDimensions()
	residualPlaintext.Scale = rlwe.NewScale(params.Q()[identity.Level()])
	residualFactor := make([]*big.Float, params.MaxSlots())
	for index := range residualFactor {
		residualFactor[index] = new(big.Float).SetPrec(256).Quo(
			new(big.Float).SetPrec(256).SetInt64(1),
			new(big.Float).SetPrec(256).SetInt64(16),
		)
	}
	if err = encoder.Encode(residualFactor, residualPlaintext); err != nil {
		t.Fatal(err)
	}
	residualIdentity, err := bound.ckks.MulNew(identity, residualPlaintext)
	if err != nil {
		t.Fatal(err)
	}
	if err = bound.ckks.Rescale(residualIdentity, residualIdentity); err != nil {
		t.Fatal(err)
	}
	if residualIdentity.Level() != 4 || !residualIdentity.Scale.Equal(identity.Scale) {
		t.Fatalf("ID*(1/16) state level=%d scale=%v, want level=4 scale=%v",
			residualIdentity.Level(), residualIdentity.Scale, identity.Scale)
	}
	residualScale, err := NewExactScaleSnapshot(residualIdentity.Scale)
	if err != nil {
		t.Fatal(err)
	}
	if residualScale.ValueHex() != measuredOutputScaleHex || !residualScale.Equal(circuit.Profile().BooleanOutputScale()) {
		t.Fatalf("ID*(1/16) scale=%s, want sealed exact-default %s", residualScale.ValueHex(), measuredOutputScaleHex)
	}
	t.Logf("Gao A2B encrypted max errors: exp=%.3g root=%.3g ID=%.3g MSB=%.3g", maxExponentialError, maxRootError, maxIdentityError, maxMSBError)
	t.Logf("Gao A2B measured output: ID level=%d scale=%s; MSB level=%d scale=%s; ID*(1/16) level=%d scale=%s",
		identity.Level(), states[6].Scale.ValueHex(), msb.Level(), states[7].Scale.ValueHex(),
		residualIdentity.Level(), residualIdentity.Scale.Value.Text('x', -1))
}

func TestGaoA2BKernelIsInvariantUnderIntegerLiftsOfTheNormalizedInput(t *testing.T) {
	params, err := GaoA2BKernelFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	encoder := ckks.NewEncoder(params, 256)
	circuit, err := NewGaoA2BKernelCircuit(params, encoder)
	if err != nil {
		t.Fatal(err)
	}
	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	keySet := rlwe.NewMemEvaluationKeySet(
		keyGenerator.GenRelinearizationKeyNew(secretKey),
		keyGenerator.GenGaloisKeyNew(params.GaloisElementForComplexConjugation(), secretKey),
	)
	bound, err := circuit.BindEvaluator(ckks.NewEvaluator(params, keySet))
	if err != nil {
		t.Fatal(err)
	}
	encryptor := ckks.NewEncryptor(params, secretKey)
	decryptor := ckks.NewDecryptor(params, secretKey)
	var maxIdentityError, maxMSBError float64
	for _, integerLift := range []int{-15, -7, 0, 7, 15} {
		values := make([]complex128, params.MaxSlots())
		for point := range values {
			// y=(J+p/16)/16. The two complex squares cancel integer J
			// and leave the LUT root exp(+2*pi*i*p/16).
			values[point] = complex(float64(integerLift)/16+float64(point)/256, 0)
		}
		plaintext := ckks.NewPlaintext(params, circuit.Profile().InputLevel())
		plaintext.LogDimensions = params.LogMaxDimensions()
		plaintext.Scale = params.DefaultScale()
		if err = encoder.Encode(values, plaintext); err != nil {
			t.Fatal(err)
		}
		input, encryptionErr := encryptor.EncryptNew(plaintext)
		if encryptionErr != nil {
			t.Fatal(encryptionErr)
		}
		result, evaluationErr := bound.EvaluateNew(input)
		if evaluationErr != nil {
			t.Fatalf("integer lift J=%d: %v", integerLift, evaluationErr)
		}
		identityValues := make([]complex128, params.MaxSlots())
		msbValues := make([]complex128, params.MaxSlots())
		if err = encoder.Decode(decryptor.DecryptNew(result.IdentityCiphertext()), identityValues); err != nil {
			t.Fatal(err)
		}
		if err = encoder.Decode(decryptor.DecryptNew(result.MSBCiphertext()), msbValues); err != nil {
			t.Fatal(err)
		}
		for point := range values {
			wantIdentity := 0.0
			if point != 0 {
				wantIdentity = float64(point-16) / 16
			}
			wantMSB := 0.0
			if point >= 1 && point <= 8 {
				wantMSB = 1
			}
			identityError := math.Abs(real(identityValues[point]) - wantIdentity)
			msbError := math.Abs(real(msbValues[point]) - wantMSB)
			maxIdentityError = math.Max(maxIdentityError, identityError)
			maxMSBError = math.Max(maxMSBError, msbError)
			if identityError >= math.Ldexp(1, -11) || msbError >= math.Ldexp(1, -11) {
				t.Fatalf("lift J=%d point=%d: ID error=%.3g MSB error=%.3g", integerLift, point, identityError, msbError)
			}
		}
	}
	t.Logf("Gao A2B integer-lift invariance J={-15,-7,0,7,15}: max ID error=%.3g max MSB error=%.3g",
		maxIdentityError, maxMSBError)
}

func TestGaoA2BKernelRejectsInvalidKeysGraphProfileAndInputBeforeMutation(t *testing.T) {
	params, err := GaoA2BKernelFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	encoder := ckks.NewEncoder(params, 256)
	circuit, err := NewGaoA2BKernelCircuit(params, encoder)
	if err != nil {
		t.Fatal(err)
	}
	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	relinearizationKey := keyGenerator.GenRelinearizationKeyNew(secretKey)
	conjugationKey := keyGenerator.GenGaloisKeyNew(params.GaloisElementForComplexConjugation(), secretKey)
	if _, err = circuit.BindEvaluator(ckks.NewEvaluator(params, rlwe.NewMemEvaluationKeySet(nil, conjugationKey))); err == nil {
		t.Fatal("bind accepted a missing relinearization key")
	}
	if _, err = circuit.BindEvaluator(ckks.NewEvaluator(params, rlwe.NewMemEvaluationKeySet(relinearizationKey))); err == nil {
		t.Fatal("bind accepted a missing conjugation key")
	}
	if _, err = NewGaoA2BKernelCircuit(params, ckks.NewEncoder(params)); err == nil {
		t.Fatal("constructor accepted the caller's default <=53-bit encoder")
	}
	wrongParams, parameterErr := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN: 5, LogQ: []int{50, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35},
		LogP: []int{50}, LogDefaultScale: 34,
	})
	if parameterErr != nil {
		t.Fatal(parameterErr)
	}
	if _, err = NewGaoA2BKernelCircuit(wrongParams, ckks.NewEncoder(wrongParams, 256)); err == nil {
		t.Fatal("constructor accepted a parameter profile with the wrong default scale")
	}
	reorderedQ := append([]uint64(nil), params.Q()...)
	reorderedQ[1], reorderedQ[2] = reorderedQ[2], reorderedQ[1]
	reorderedParams, parameterErr := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN: 5, Q: reorderedQ, P: append([]uint64(nil), params.P()...), LogDefaultScale: 35,
	})
	if parameterErr != nil {
		t.Fatal(parameterErr)
	}
	if params.Equal(&reorderedParams) {
		t.Fatal("same-bit reordered-Q negative unexpectedly equals the canonical kernel parameters")
	}
	if _, err = NewGaoA2BKernelCircuit(reorderedParams, ckks.NewEncoder(reorderedParams, 256)); err == nil {
		t.Fatal("constructor accepted a same-bit reordered Q chain")
	}

	keySet := rlwe.NewMemEvaluationKeySet(relinearizationKey, conjugationKey)
	sourceEvaluator := ckks.NewEvaluator(params, keySet)
	bound, err := circuit.BindEvaluator(sourceEvaluator)
	if err != nil {
		t.Fatal(err)
	}
	values := make([]complex128, params.MaxSlots())
	for point := range values {
		values[point] = complex(float64(point)/256, 0)
	}
	plaintext := ckks.NewPlaintext(params, circuit.Profile().InputLevel())
	plaintext.LogDimensions = params.LogMaxDimensions()
	plaintext.Scale = params.DefaultScale()
	if err = encoder.Encode(values, plaintext); err != nil {
		t.Fatal(err)
	}
	input, err := ckks.NewEncryptor(params, secretKey).EncryptNew(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	assertPreflightRejects := func(name string, candidate *rlwe.Ciphertext) {
		t.Helper()
		before := candidate.CopyNew()
		if _, evaluationErr := bound.EvaluateNew(candidate); evaluationErr == nil {
			t.Fatalf("%s: evaluation unexpectedly succeeded", name)
		}
		if !candidate.Equal(before) {
			t.Fatalf("%s: failed preflight mutated the ciphertext", name)
		}
	}

	badLevel := input.CopyNew()
	badLevel.Resize(1, 16)
	assertPreflightRejects("wrong input level", badLevel)
	badScale := input.CopyNew()
	badScale.Scale = badScale.Scale.Mul(rlwe.NewScale(2))
	assertPreflightRejects("wrong input scale", badScale)
	badDimensions := input.CopyNew()
	badDimensions.LogDimensions.Cols--
	assertPreflightRejects("partial slot dimensions", badDimensions)

	originalRelinearization := keySet.RelinearizationKey
	keySet.RelinearizationKey = nil
	assertPreflightRejects("post-bind deleted relinearization key", input)
	keySet.RelinearizationKey = originalRelinearization
	keySet.RelinearizationKey = keyGenerator.GenRelinearizationKeyNew(keyGenerator.GenSecretKeyNew())
	assertPreflightRejects("post-bind swapped relinearization key", input)
	keySet.RelinearizationKey = originalRelinearization

	conjugationElement := params.GaloisElementForComplexConjugation()
	originalConjugation := keySet.GaloisKeys[conjugationElement]
	keySet.GaloisKeys[conjugationElement] = nil
	assertPreflightRejects("post-bind deleted conjugation key", input)
	keySet.GaloisKeys[conjugationElement] = originalConjugation
	keySet.GaloisKeys[conjugationElement] = keyGenerator.GenGaloisKeyNew(conjugationElement, keyGenerator.GenSecretKeyNew())
	assertPreflightRejects("post-bind swapped conjugation key", input)
	keySet.GaloisKeys[conjugationElement] = originalConjugation

	originalSourceKeySet := sourceEvaluator.EvaluationKeySet
	sourceEvaluator.EvaluationKeySet = rlwe.NewMemEvaluationKeySet(originalRelinearization, originalConjugation)
	assertPreflightRejects("post-bind source key-set replacement", input)
	sourceEvaluator.EvaluationKeySet = originalSourceKeySet

	originalCoefficient := new(big.Float).SetPrec(256).Set(circuit.exponentialOperand.Value[0].Coeffs[0].Real())
	circuit.exponentialOperand.Value[0].Coeffs[0].Real().Add(
		circuit.exponentialOperand.Value[0].Coeffs[0].Real(), new(big.Float).SetPrec(256).SetInt64(1),
	)
	assertPreflightRejects("post-bind sealed exponential coefficient mutation", input)
	circuit.exponentialOperand.Value[0].Coeffs[0].Real().Set(originalCoefficient)
	originalIdentityCoefficient := new(big.Float).SetPrec(256).Set(circuit.identityOperand.Value[0].Coeffs[0].Real())
	circuit.identityOperand.Value[0].Coeffs[0].Real().Add(
		circuit.identityOperand.Value[0].Coeffs[0].Real(), new(big.Float).SetPrec(256).SetInt64(1),
	)
	assertPreflightRejects("post-bind sealed identity coefficient mutation", input)
	circuit.identityOperand.Value[0].Coeffs[0].Real().Set(originalIdentityCoefficient)

	originalMSBCoefficient := new(big.Float).SetPrec(256).Set(circuit.msbOperand.Value[0].Coeffs[0].Real())
	circuit.msbOperand.Value[0].Coeffs[0].Real().Add(
		circuit.msbOperand.Value[0].Coeffs[0].Real(), new(big.Float).SetPrec(256).SetInt64(1),
	)
	assertPreflightRejects("post-bind sealed MSB coefficient mutation", input)
	circuit.msbOperand.Value[0].Coeffs[0].Real().Set(originalMSBCoefficient)

	originalIdentityMappingSlot := circuit.identityOperand.Mapping[0][0]
	circuit.identityOperand.Mapping[0][0] = 1
	assertPreflightRejects("post-bind sealed identity mapping mutation", input)
	circuit.identityOperand.Mapping[0][0] = originalIdentityMappingSlot

	originalProfileDigest := circuit.profile.digest
	circuit.profile.digest = strings.Repeat("0", 64)
	assertPreflightRejects("post-bind profile digest mutation", input)
	circuit.profile.digest = originalProfileDigest

	result, err := bound.EvaluateNew(input)
	if err != nil {
		t.Fatalf("restored graph did not recover: %v", err)
	}
	if got, want := result.Provenance().OperandGraphDigest(), circuit.Profile().OperandGraphDigest(); got != want {
		t.Fatalf("result operand graph digest: got %s, want %s", got, want)
	}
	firstOutput := result.IdentityCiphertext()
	firstOutput.Scale = rlwe.NewScale(3)
	if result.IdentityCiphertext().Scale.Equal(firstOutput.Scale) {
		t.Fatal("named output accessor leaked mutable result metadata")
	}
	profileCopy := circuit.Profile()
	profileCopy.digest = strings.Repeat("f", 64)
	profileCopy.keyProfile.rotationIndexes = append(profileCopy.keyProfile.rotationIndexes, 1)
	if circuit.Profile().Digest() != originalProfileDigest || len(circuit.Profile().KeyProfile().RequiredRotationIndexes()) != 0 {
		t.Fatal("profile accessor leaked mutable profile state")
	}
}

func TestGaoA2BKernelPackedComplexDispatchUsesPrivate256BitEncoder(t *testing.T) {
	params, err := GaoA2BKernelFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := NewGaoA2BExpProfile()
	if err != nil {
		t.Fatal(err)
	}
	defaultEvaluator := ckks.NewEvaluator(params, nil)
	if defaultEvaluator.Encoder.Prec() > 53 {
		t.Fatalf("rounding sentinel requires default <=53-bit encoder, got %d", defaultEvaluator.Encoder.Prec())
	}
	operationalEvaluator := defaultEvaluator.ShallowCopy()
	operationalEvaluator.Encoder = ckks.NewEncoder(params, 256)
	var exact *bignum.Complex
	largestScalarRounding := new(big.Float).SetPrec(256)
	for _, candidate := range profile.LattigoCoefficientValues() {
		if candidate.Real().Sign() != 0 || candidate.Imag().Sign() == 0 {
			continue
		}
		rounded := &bignum.Complex{
			new(big.Float).SetPrec(256),
			new(big.Float).SetPrec(256).Set(new(big.Float).SetPrec(53).Set(candidate.Imag())),
		}
		rounding := distanceA2BKernelBigComplex(candidate, rounded, 256)
		if rounding.Cmp(largestScalarRounding) > 0 {
			largestScalarRounding.Set(rounding)
			exact = candidate
		}
	}
	if exact == nil || largestScalarRounding.Cmp(powerOfTwoA2BKernel(-56, 256)) <= 0 {
		t.Fatalf("no imaginary Gao coefficient exposes the scalar53 rounding sentinel: max=%s", largestScalarRounding.Text('e', 8))
	}
	if exact.Real().Sign() != 0 || exact.Imag().Sign() == 0 {
		t.Fatal("rounding sentinel did not select a genuinely imaginary Gao coefficient")
	}
	packed := make([]*bignum.Complex, params.MaxSlots())
	for index := range packed {
		packed[index] = cloneA2BExpComplex(exact)
	}
	highScaleValue := new(big.Float).SetPrec(256).SetInt(new(big.Int).Lsh(big.NewInt(1), 200))
	zero := ckks.NewCiphertext(params, 1, params.MaxLevel())
	zero.Scale = rlwe.NewScale(highScaleValue)
	scalarOutput := zero.CopyNew()
	if err = operationalEvaluator.Add(scalarOutput, exact, scalarOutput); err != nil {
		t.Fatal(err)
	}
	packedOutput := zero.CopyNew()
	if err = operationalEvaluator.Add(packedOutput, packed, packedOutput); err != nil {
		t.Fatal(err)
	}
	if scalarOutput.Equal(packedOutput) {
		t.Fatal("complex scalar53 and full-slot vector256 Add branches were not distinguishable")
	}
	secretKey := ckks.NewKeyGenerator(params).GenSecretKeyNew()
	decryptor := ckks.NewDecryptor(params, secretKey)
	scalarValues := make([]*bignum.Complex, params.MaxSlots())
	packedValues := make([]*bignum.Complex, params.MaxSlots())
	if err = operationalEvaluator.Decode(decryptor.DecryptNew(scalarOutput), scalarValues); err != nil {
		t.Fatal(err)
	}
	if err = operationalEvaluator.Decode(decryptor.DecryptNew(packedOutput), packedValues); err != nil {
		t.Fatal(err)
	}
	scalarError := distanceA2BKernelBigComplex(scalarValues[0], exact, 256)
	packedError := distanceA2BKernelBigComplex(packedValues[0], exact, 256)
	if packedError.Cmp(powerOfTwoA2BKernel(-128, 256)) >= 0 ||
		scalarError.Cmp(powerOfTwoA2BKernel(-56, 256)) <= 0 {
		t.Fatalf("complex Add rounding sentinel: scalar53=%s packed256=%s",
			scalarError.Text('e', 8), packedError.Text('e', 8))
	}

	one := ckks.NewCiphertext(params, 1, params.MaxLevel())
	one.Scale = rlwe.NewScale(1)
	if err = operationalEvaluator.Add(one, 1, one); err != nil {
		t.Fatal(err)
	}
	scalarMultiplyOutput := ckks.NewCiphertext(params, 1, params.MaxLevel())
	scalarMultiplyOutput.Scale = rlwe.NewScale(highScaleValue)
	if err = operationalEvaluator.MulThenAdd(one, exact, scalarMultiplyOutput); err != nil {
		t.Fatal(err)
	}
	packedMultiplyOutput := ckks.NewCiphertext(params, 1, params.MaxLevel())
	packedMultiplyOutput.Scale = rlwe.NewScale(highScaleValue)
	if err = operationalEvaluator.MulThenAdd(one, packed, packedMultiplyOutput); err != nil {
		t.Fatal(err)
	}
	if scalarMultiplyOutput.Equal(packedMultiplyOutput) {
		t.Fatal("complex scalar53 and full-slot vector256 MulThenAdd branches were not distinguishable")
	}
	if err = operationalEvaluator.Decode(decryptor.DecryptNew(scalarMultiplyOutput), scalarValues); err != nil {
		t.Fatal(err)
	}
	if err = operationalEvaluator.Decode(decryptor.DecryptNew(packedMultiplyOutput), packedValues); err != nil {
		t.Fatal(err)
	}
	scalarMultiplyError := distanceA2BKernelBigComplex(scalarValues[0], exact, 256)
	packedMultiplyError := distanceA2BKernelBigComplex(packedValues[0], exact, 256)
	if packedMultiplyError.Cmp(powerOfTwoA2BKernel(-128, 256)) >= 0 ||
		scalarMultiplyError.Cmp(powerOfTwoA2BKernel(-56, 256)) <= 0 {
		t.Fatalf("complex MulThenAdd rounding sentinel: scalar53=%s packed256=%s",
			scalarMultiplyError.Text('e', 8), packedMultiplyError.Text('e', 8))
	}
	if defaultEvaluator.Encoder.Prec() > 53 || operationalEvaluator.Encoder.Prec() != 256 {
		t.Fatal("rounding sentinel evaluator precision changed")
	}
	t.Logf("Gao A2B complex dispatch sentinel: Add scalar53=%s packed256=%s; MulThenAdd scalar53=%s packed256=%s",
		scalarError.Text('e', 8), packedError.Text('e', 8), scalarMultiplyError.Text('e', 8), packedMultiplyError.Text('e', 8))
}

func TestGaoA2BKernelNormalizationAndSourceAlternativesAreDistinguishable(t *testing.T) {
	profile, err := NewGaoA2BExpProfile()
	if err != nil {
		t.Fatal(err)
	}
	const precision = uint(256)
	one := &bignum.Complex{
		new(big.Float).SetPrec(precision).SetInt64(1),
		new(big.Float).SetPrec(precision),
	}
	maxCollapsedDistance := new(big.Float).SetPrec(precision)
	for point := 0; point < 16; point++ {
		unnormalized := new(big.Float).SetPrec(precision).Quo(
			new(big.Float).SetPrec(precision).SetInt64(int64(point)),
			new(big.Float).SetPrec(precision).SetInt64(16),
		)
		oracle, oracleErr := EvaluateGaoA2BExpOracle(profile, unnormalized)
		if oracleErr != nil {
			t.Fatal(oracleErr)
		}
		collapsedDistance := distanceA2BKernelBigComplex(oracle.FinalPolynomial(), one, precision)
		if collapsedDistance.Cmp(maxCollapsedDistance) > 0 {
			maxCollapsedDistance.Set(collapsedDistance)
		}
	}
	if maxCollapsedDistance.Cmp(powerOfTwoA2BKernel(-20, precision)) >= 0 {
		t.Fatalf("unnormalized y=p/16 did not collapse all integer points near z=1: max=%s",
			maxCollapsedDistance.Text('e', 8))
	}

	point := int64(8)
	normalized := new(big.Float).SetPrec(precision).Quo(
		new(big.Float).SetPrec(precision).SetInt64(point),
		new(big.Float).SetPrec(precision).SetInt64(256),
	)
	oracle, err := EvaluateGaoA2BExpOracle(profile, normalized)
	if err != nil {
		t.Fatal(err)
	}
	oneSquare := squareA2BExpComplex(oracle.BasePolynomial(), precision)
	if distanceA2BKernelBigComplex(oneSquare, oracle.FinalTargetValue(), precision).Cmp(
		new(big.Float).SetPrec(precision).SetFloat64(1),
	) <= 0 {
		t.Fatal("one complex square was not source-distinguishable from the mandated two-square root")
	}

	targetPoint := int64(5)
	targetY := new(big.Float).SetPrec(precision).Quo(
		new(big.Float).SetPrec(precision).SetInt64(targetPoint),
		new(big.Float).SetPrec(precision).SetInt64(256),
	)
	targetOracle, err := EvaluateGaoA2BExpOracle(profile, targetY)
	if err != nil {
		t.Fatal(err)
	}
	missingFreeTermDivision := profile.SourceCoefficientValues()
	doubleFreeTermDivision := profile.LattigoCoefficientValues()
	two := new(big.Float).SetPrec(precision).SetInt64(2)
	doubleFreeTermDivision[0].Real().Quo(doubleFreeTermDivision[0].Real(), two)
	doubleFreeTermDivision[0].Imag().Quo(doubleFreeTermDivision[0].Imag(), two)
	for name, coefficients := range map[string][]*bignum.Complex{
		"missing-c0-over-2": missingFreeTermDivision,
		"double-c0-over-2":  doubleFreeTermDivision,
	} {
		candidate := clenshawA2BExpComplex(coefficients, targetY, precision)
		candidate = squareA2BExpComplex(candidate, precision)
		candidate = squareA2BExpComplex(candidate, precision)
		if distanceA2BKernelBigComplex(candidate, targetOracle.FinalTargetValue(), precision).Cmp(
			new(big.Float).SetPrec(precision).SetFloat64(0.01),
		) <= 0 {
			t.Fatalf("%s was not distinguished from the frozen c0/2-once convention", name)
		}
	}

	gaoMSB := func(point int) float64 {
		if point >= 1 && point <= 8 {
			return 1
		}
		return 0
	}
	if gaoMSB(1) != 1 || gaoMSB(9) != 0 {
		t.Fatal("kernel test fixture no longer represents Gao's periodic MSB semantics")
	}
	conventionalSignBit := func(point int) float64 {
		if point >= 8 {
			return 1
		}
		return 0
	}
	if conventionalSignBit(1) == gaoMSB(1) || conventionalSignBit(9) == gaoMSB(9) {
		t.Fatal("conventional sign bit was not distinguishable from Gao's MSB LUT")
	}
	t.Logf("Gao A2B omitted-normalization negative y=p/16: all 16 roots collapse near 1, max distance=%s",
		maxCollapsedDistance.Text('e', 8))
}

func TestGaoA2BKernelSourceHasOneSharedLUTCallAndNoLevelOrScaleRetag(t *testing.T) {
	_, testFilename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate kernel integration test source")
	}
	productionFilename := strings.TrimSuffix(testFilename, "_integration_test.go") + ".go"
	sourceBytes, err := os.ReadFile(productionFilename)
	if err != nil {
		t.Fatal(err)
	}
	source := string(sourceBytes)
	if count := strings.Count(source, "e.polynomial.EvaluateMultiPoly("); count != 1 {
		t.Fatalf("production EvaluateMultiPoly calls=%d, want exactly one", count)
	}
	if count := strings.Count(source, "e.polynomial.Evaluate("); count != 1 {
		t.Fatalf("production generic polynomial Evaluate calls=%d, want only exp46", count)
	}
	if count := strings.Count(source, "MulRelinNew(root, root)"); count != 1 {
		t.Fatalf("sealed two-round square loop has %d concrete MulRelin call sites, want one loop body", count)
	}
	for _, forbidden := range []string{"DropLevel", "SetScale", "normalizationOperand"} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("production source contains forbidden level/scale/extra-normalization seam %q", forbidden)
		}
	}
	if !strings.Contains(source, "[]interface{}{identityOperand, msbOperand}") ||
		!strings.Contains(source, "[2]GaoA2BLUTKind{GaoA2BLUTIdentity, GaoA2BLUTMSB}") {
		t.Fatal("production source does not bind the named ID-then-MSB shared-call order")
	}
	vendorFilename := filepath.Join(filepath.Dir(testFilename), "..", "..", "vendor", "github.com", "tuneinsight", "lattigo", "v6", "circuits", "common", "polynomial", "polynomial_evaluator.go")
	vendorBytes, err := os.ReadFile(vendorFilename)
	if err != nil {
		t.Fatal(err)
	}
	vendorSource := string(vendorBytes)
	multiStart := strings.Index(vendorSource, "func (eval Evaluator[T]) EvaluateMultiPoly")
	if multiStart < 0 {
		t.Fatal("vendored patched Lattigo EvaluateMultiPoly implementation is missing")
	}
	multiEndOffset := strings.Index(vendorSource[multiStart:], "// BabyStep")
	if multiEndOffset < 0 {
		t.Fatal("cannot isolate vendored EvaluateMultiPoly implementation")
	}
	multiBody := vendorSource[multiStart : multiStart+multiEndOffset]
	if count := strings.Count(multiBody, "powerbasis = NewPowerBasis("); count != 1 {
		t.Fatalf("vendored EvaluateMultiPoly creates %d power bases, want exactly one shared basis", count)
	}
	if strings.Index(multiBody, "powerbasis = NewPowerBasis(") > strings.LastIndex(multiBody, "for i := 0; i < len(p_list); i++ {") {
		t.Fatal("vendored EvaluateMultiPoly constructs its power basis inside the per-polynomial evaluation loop")
	}
	params, err := GaoA2BKernelFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	circuit, err := NewGaoA2BKernelCircuit(params, ckks.NewEncoder(params, 256))
	if err != nil {
		t.Fatal(err)
	}
	profile := circuit.Profile()
	if profile.Claim() != GaoA2BKernelFunctionalLattigoOptimizedAdaptationNotSecureNotFullA2B ||
		profile.InputNormalization() != "refreshed-normalized-y=(J+p/16)/16;kernel-grid-J=0-gives-y=p/256" ||
		len(profile.KeyProfile().RequiredRotationIndexes()) != 0 ||
		!profile.KeyProfile().RequiresRelinearization() || !profile.KeyProfile().RequiresConjugation() ||
		profile.OperandPlan().OutputOrder() != [2]GaoA2BLUTKind{GaoA2BLUTIdentity, GaoA2BLUTMSB} ||
		profile.OperandPlan().ExponentialMappedSlots() != 16 ||
		profile.OperandPlan().LUTMappedSlots() != [2]int{16, 16} {
		t.Fatalf("sealed profile/path mismatch: %+v", profile)
	}
}

func TestGaoA2BKernelExactScaleGateRejectsRecordedDrift(t *testing.T) {
	target, err := NewExactScaleSnapshot(rlwe.NewScale(1 << 35))
	if err != nil {
		t.Fatal(err)
	}
	drifted, err := NewExactScaleSnapshot(rlwe.NewScale((1 << 35) + 1))
	if err != nil {
		t.Fatal(err)
	}
	state := GaoA2BKernelCiphertextState{
		Stage: GaoA2BKernelStageExponential, Scale: drifted, TargetScale: target, ScaleExact: false,
	}
	if err = requireA2BKernelExactScale(state); err == nil {
		t.Fatal("recorded intermediate scale drift was accepted")
	}
	state.Scale = target
	state.ScaleExact = true
	if err = requireA2BKernelExactScale(state); err != nil {
		t.Fatalf("exact intermediate scale was rejected: %v", err)
	}
}

func distanceA2BKernelBigComplex(left, right *bignum.Complex, precision uint) *big.Float {
	realDifference := new(big.Float).SetPrec(precision).Sub(left.Real(), right.Real())
	imaginaryDifference := new(big.Float).SetPrec(precision).Sub(left.Imag(), right.Imag())
	realDifference.Mul(realDifference, realDifference)
	imaginaryDifference.Mul(imaginaryDifference, imaginaryDifference)
	return new(big.Float).SetPrec(precision).Sqrt(
		new(big.Float).SetPrec(precision).Add(realDifference, imaginaryDifference),
	)
}

func powerOfTwoA2BKernel(exponent int, precision uint) *big.Float {
	return new(big.Float).SetPrec(precision).SetMantExp(new(big.Float).SetPrec(precision).SetInt64(1), exponent)
}

func complexFromA2BKernelBig(value *bignum.Complex) complex128 {
	realValue, _ := value.Real().Float64()
	imaginaryValue, _ := value.Imag().Float64()
	return complex(realValue, imaginaryValue)
}

func cmplxDistanceA2BKernel(left, right complex128) float64 {
	realDifference := real(left) - real(right)
	imaginaryDifference := imag(left) - imag(right)
	return math.Hypot(realDifference, imaginaryDifference)
}
