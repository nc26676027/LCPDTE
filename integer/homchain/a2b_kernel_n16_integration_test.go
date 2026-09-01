package homchain

import (
	"math"
	"testing"

	"dt_go/integer/securityparams"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func TestGaoA2BKernelN16L11EvaluatesAllResiduesOnSparseSlots(t *testing.T) {
	params, err := securityparams.GaoCompatibleN16Parameters()
	if err != nil {
		t.Fatal(err)
	}
	encoder := ckks.NewEncoder(params, 256)
	circuit, err := NewGaoA2BKernelN16L11Circuit(params, encoder)
	if err != nil {
		t.Fatal(err)
	}
	profile := circuit.Profile()
	if profile.Claim() != GaoA2BKernelN16L11KernelOnlyUnverified ||
		profile.InputLevel() != 17 || profile.BooleanOutputLevel() != 5 ||
		profile.Slots() != 1<<11 || profile.LogDimensions() != (ring.Dimensions{Rows: 0, Cols: 11}) ||
		profile.OperationalEncoderPrecision() != 256 ||
		!profile.InputScale().EqualScale(params.DefaultScale()) ||
		!profile.BooleanOutputScale().EqualScale(params.DefaultScale()) {
		t.Fatalf("unexpected N16/L11 Gao kernel profile: %+v", profile)
	}
	if profile.ExponentialDegree() != 46 || profile.SquaringRounds() != 2 ||
		profile.LUTDegrees() != [2]int{15, 15} ||
		profile.OperandPlan().ExponentialMappedSlots() != 1<<11 ||
		profile.OperandPlan().LUTMappedSlots() != [2]int{1 << 11, 1 << 11} {
		t.Fatalf("unexpected N16/L11 Gao kernel polynomial graph: %+v", profile)
	}

	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	relinearizationKey := keyGenerator.GenRelinearizationKeyNew(secretKey)
	conjugationKey := keyGenerator.GenGaloisKeyNew(params.GaloisElementForComplexConjugation(), secretKey)
	keySet := rlwe.NewMemEvaluationKeySet(relinearizationKey, conjugationKey)
	bound, err := circuit.BindEvaluator(ckks.NewEvaluator(params, keySet))
	if err != nil {
		t.Fatal(err)
	}
	if got := bound.OperationalEncoderPrecision(); got != 256 {
		t.Fatalf("operational encoder precision=%d, want 256", got)
	}
	if got := bound.SparseCoefficientSlots(); got != 1<<11 {
		t.Fatalf("sparse coefficient getter slots=%d, want %d", got, 1<<11)
	}

	values := make([]complex128, 1<<11)
	for index := range values {
		residue := index & 15
		values[index] = complex(float64(residue)/256, 0)
	}
	plaintext := ckks.NewPlaintext(params, profile.InputLevel())
	plaintext.LogDimensions = profile.LogDimensions()
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
		t.Fatal("N16/L11 Gao kernel mutated its input")
	}

	decryptor := ckks.NewDecryptor(params, secretKey)
	identity := make([]complex128, 1<<11)
	msb := make([]complex128, 1<<11)
	if err = encoder.Decode(decryptor.DecryptNew(result.IDCiphertext()), identity); err != nil {
		t.Fatal(err)
	}
	if err = encoder.Decode(decryptor.DecryptNew(result.MSBCiphertext()), msb); err != nil {
		t.Fatal(err)
	}
	var maxIdentityError, maxMSBError, maxImaginary float64
	for index := range values {
		residue := index & 15
		wantIdentity := 0.0
		if residue != 0 {
			wantIdentity = float64(residue-16) / 16
		}
		wantMSB := 0.0
		if residue >= 1 && residue <= 8 {
			wantMSB = 1
		}
		identityError := math.Abs(real(identity[index]) - wantIdentity)
		msbError := math.Abs(real(msb[index]) - wantMSB)
		imaginary := math.Max(math.Abs(imag(identity[index])), math.Abs(imag(msb[index])))
		maxIdentityError = math.Max(maxIdentityError, identityError)
		maxMSBError = math.Max(maxMSBError, msbError)
		maxImaginary = math.Max(maxImaginary, imaginary)
		if identityError >= math.Ldexp(1, -11) || msbError >= math.Ldexp(1, -11) || imaginary >= math.Ldexp(1, -20) {
			t.Fatalf("slot=%d residue=%d: ID=%v want=%g MSB=%v want=%g", index, residue, identity[index], wantIdentity, msb[index], wantMSB)
		}
	}

	provenance := result.Provenance()
	counts := provenance.OperationCounts()
	if counts != (GaoA2BKernelOperationCounts{
		ExpPolynomialEvaluations: 1, ComplexSquarings: 2,
		MultiPolynomialEvaluations: 1, SharedPowerBases: 1,
		GenericLUTEvaluations: 0, Conjugations: 2, RealRecoveries: 2,
	}) {
		t.Fatalf("unexpected N16/L11 Gao kernel operation counts: %+v", counts)
	}
	wantStages := []GaoA2BKernelStage{
		GaoA2BKernelStageInput, GaoA2BKernelStageExponential, GaoA2BKernelStageSquare0,
		GaoA2BKernelStageRootOfUnity, GaoA2BKernelStageIdentityLUT, GaoA2BKernelStageMSBLUT,
		GaoA2BKernelStageIdentityOutput, GaoA2BKernelStageMSBOutput,
	}
	wantLevels := []int{17, 11, 10, 9, 5, 5, 5, 5}
	states := provenance.States()
	if len(states) != len(wantStages) {
		t.Fatalf("N16/L11 Gao kernel states=%d, want %d", len(states), len(wantStages))
	}
	for index := range states {
		if states[index].Stage != wantStages[index] || states[index].Level != wantLevels[index] ||
			states[index].Degree != 1 || !states[index].ScaleExact {
			t.Fatalf("N16/L11 Gao kernel state %d mismatch: %+v", index, states[index])
		}
	}
	if provenance.ProfileDigest() != profile.Digest() ||
		provenance.OperationalEncoderPrecision() != 256 ||
		provenance.OperandPlan().ExponentialMappedSlots() != 1<<11 {
		t.Fatalf("N16/L11 Gao kernel provenance drifted: %+v", provenance)
	}
	t.Logf("N16/L11 Gao A2B kernel maxima: ID=%.12g MSB=%.12g imaginary=%.12g", maxIdentityError, maxMSBError, maxImaginary)
}

func TestGaoA2BKernelN16L11RejectsWrongSparseShapeAndKeys(t *testing.T) {
	params, err := securityparams.GaoCompatibleN16Parameters()
	if err != nil {
		t.Fatal(err)
	}
	circuit, err := NewGaoA2BKernelN16L11Circuit(params, ckks.NewEncoder(params, 256))
	if err != nil {
		t.Fatal(err)
	}
	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	relinearizationKey := keyGenerator.GenRelinearizationKeyNew(secretKey)
	conjugationKey := keyGenerator.GenGaloisKeyNew(params.GaloisElementForComplexConjugation(), secretKey)
	if _, err = circuit.BindEvaluator(ckks.NewEvaluator(params, rlwe.NewMemEvaluationKeySet(relinearizationKey))); err == nil {
		t.Fatal("N16/L11 Gao kernel accepted a missing conjugation key")
	}
	if _, err = circuit.BindEvaluator(ckks.NewEvaluator(params, rlwe.NewMemEvaluationKeySet(nil, conjugationKey))); err == nil {
		t.Fatal("N16/L11 Gao kernel accepted a missing relinearization key")
	}
	bound, err := circuit.BindEvaluator(ckks.NewEvaluator(params, rlwe.NewMemEvaluationKeySet(relinearizationKey, conjugationKey)))
	if err != nil {
		t.Fatal(err)
	}
	plaintext := ckks.NewPlaintext(params, 17)
	plaintext.LogDimensions = ring.Dimensions{Rows: 0, Cols: 12}
	plaintext.Scale = params.DefaultScale()
	values := make([]complex128, 1<<12)
	if err = ckks.NewEncoder(params, 256).Encode(values, plaintext); err != nil {
		t.Fatal(err)
	}
	input, err := ckks.NewEncryptor(params, secretKey).EncryptNew(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	before := input.CopyNew()
	if _, err = bound.EvaluateNew(input); err == nil {
		t.Fatal("N16/L11 Gao kernel accepted LogSlots=12 input")
	}
	if !input.Equal(before) {
		t.Fatal("failed N16/L11 Gao kernel preflight mutated its input")
	}
}
