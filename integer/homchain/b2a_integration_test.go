package homchain_test

import (
	"math"
	"math/big"
	"reflect"
	"testing"

	"github.com/nc26676027/LCPDTE/integer/homchain"
	"github.com/nc26676027/LCPDTE/integer/z2n"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

func TestB2AFullWord8ProfileAndSmokeVector(t *testing.T) {
	params := b2aFunctionalParameters(t)
	encoder := ckks.NewEncoder(params, z2n.DefaultPrecision)
	circuit, err := homchain.NewB2AFullCircuit(params, encoder)
	if err != nil {
		t.Fatal(err)
	}

	profile := circuit.Profile()
	if got, want := profile.Fidelity(), homchain.B2ALattigoAdaptation; got != want {
		t.Fatalf("fidelity: got %q, want %q", got, want)
	}
	if got, want := profile.WordBits(), z2n.Word8; got != want {
		t.Fatalf("word bits: got %d, want %d", got, want)
	}
	if got, want := profile.Words(), 2; got != want {
		t.Fatalf("words: got %d, want %d", got, want)
	}
	if got, want := profile.Slots(), 8; got != want {
		t.Fatalf("slots: got %d, want %d", got, want)
	}
	if got, want := profile.LogDimensions(), (ring.Dimensions{Rows: 0, Cols: 3}); got != want {
		t.Fatalf("dimensions: got %+v, want %+v", got, want)
	}
	if got, want := profile.LevelQ(), 1; got != want {
		t.Fatalf("LevelQ: got %d, want %d", got, want)
	}
	if got, want := profile.LevelP(), 0; got != want {
		t.Fatalf("LevelP: got %d, want %d", got, want)
	}
	if got, want := profile.EncoderPrecision(), z2n.DefaultPrecision; got != want {
		t.Fatalf("encoder precision: got %d, want %d", got, want)
	}
	if !profile.InputScale().EqualScale(params.DefaultScale()) || profile.InputScale().HasMod() {
		t.Fatal("profile does not bind the exact non-modular default input scale")
	}
	if profile.RequiresRelinearization() || profile.RequiresConjugation() {
		t.Fatal("standalone B2A profile requested a relinearization or conjugation key")
	}
	if got, want := profile.RequiredRotationIndexes(), []int{1, 2, 4, 6}; !reflect.DeepEqual(got, want) {
		t.Fatalf("rotations: got %v, want %v", got, want)
	}
	if got, want := profile.RequiredGaloisElements(), []uint64{5, 9, 17, 25}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Galois elements: got %v, want %v", got, want)
	}
	if got, want := profile.Digest(), "783ca9bc757fe908bddea34d35d70791b04668f93cee52d13189dd02c68f8f8b"; got != want {
		t.Fatalf("profile digest: got %q, want %q", got, want)
	}
	matrixScaleSnapshot := profile.MatrixScale()
	matrixScale, err := matrixScaleSnapshot.Scale()
	if err != nil {
		t.Fatal(err)
	}
	if want := rlwe.NewScale(params.Q()[1]); !matrixScaleSnapshot.EqualScale(want) {
		t.Fatalf("matrix scale: got %s, want q1=%d", matrixScale.Value.Text('g', -1), params.Q()[1])
	}

	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	galoisKeys := keyGenerator.GenGaloisKeysNew(profile.RequiredGaloisElements(), secretKey)
	// A nil relinearization key is intentional: B2A uses only ct-pt products.
	evaluationKeySet := rlwe.NewMemEvaluationKeySet(nil, galoisKeys...)
	bound, err := circuit.BindEvaluator(ckks.NewEvaluator(params, evaluationKeySet))
	if err != nil {
		t.Fatal(err)
	}

	lowValues := []complex128{0, 0, 0, 0, 1, 0, 1, 0}
	highValues := []complex128{1, 0, 0, 0, 0, 1, 0, 1}
	lowCiphertext := b2aEncrypt(t, params, encoder, secretKey, lowValues)
	highCiphertext := b2aEncrypt(t, params, encoder, secretKey, highValues)
	lowBefore := lowCiphertext.CopyNew()
	highBefore := highCiphertext.CopyNew()

	low, err := circuit.BindLow(lowCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	high, err := circuit.BindHigh(highCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	input, err := circuit.BindInput(low, high)
	if err != nil {
		t.Fatal(err)
	}
	result, err := bound.EvaluateNew(input)
	if err != nil {
		t.Fatal(err)
	}
	if !lowCiphertext.Equal(lowBefore) || !highCiphertext.Equal(highBefore) {
		t.Fatal("B2A mutated a Boolean input half")
	}

	output := result.Ciphertext()
	if output == nil {
		t.Fatal("nil B2A output")
	}
	if got, want := output.Level(), 0; got != want {
		t.Fatalf("output level: got %d, want %d", got, want)
	}
	if got, want := output.Degree(), 1; got != want {
		t.Fatalf("output degree: got %d, want %d", got, want)
	}
	defaultScale := params.DefaultScale()
	outputScaleSnapshot, err := homchain.NewExactScaleSnapshot(output.Scale)
	if err != nil {
		t.Fatal(err)
	}
	if !outputScaleSnapshot.EqualScale(defaultScale) {
		t.Fatalf("output scale: got %s, want exact input scale %s", output.Scale.Value.Text('x', -1), defaultScale.Value.Text('x', -1))
	}

	provenance := result.Provenance()
	if got, want := provenance.Fidelity(), homchain.B2ALattigoAdaptation; got != want {
		t.Fatalf("result fidelity: got %q, want %q", got, want)
	}
	if got, want := provenance.ProfileDigest(), profile.Digest(); got != want {
		t.Fatalf("result digest: got %q, want %q", got, want)
	}
	wantStages := []homchain.B2AStage{
		homchain.B2AStageInputLow,
		homchain.B2AStageInputHigh,
		homchain.B2AStageFusedLow,
		homchain.B2AStageFusedHigh,
		homchain.B2AStageRecombined,
		homchain.B2AStageRescaled,
	}
	states := provenance.States()
	if len(states) != len(wantStages) {
		t.Fatalf("state count: got %d, want %d", len(states), len(wantStages))
	}
	preRescaleScale := params.DefaultScale().Mul(matrixScale)
	for i, wantStage := range wantStages {
		if states[i].Stage != wantStage {
			t.Fatalf("state %d stage: got %q, want %q", i, states[i].Stage, wantStage)
		}
		wantLevel := 1
		wantScale := params.DefaultScale()
		if i >= 2 && i <= 4 {
			wantScale = preRescaleScale
		}
		if wantStage == homchain.B2AStageRescaled {
			wantLevel = 0
		}
		if states[i].Level != wantLevel || !states[i].Scale.EqualScale(wantScale) {
			t.Fatalf("state %q: got level=%d scale=%s", wantStage, states[i].Level, states[i].ScaleString())
		}
	}

	decoded := b2aDecrypt(t, params, encoder, secretKey, output)
	ringZ, err := z2n.New(z2n.Word8)
	if err != nil {
		t.Fatal(err)
	}
	wantWords := []uint64{0x10, 0xa5}
	wantNumerators := [][]int64{
		{16, 0, 0, 0, -128, -64, -32, -16},
		{37, -64, -160, -80, -40, -148, -74, -165},
	}
	for wordIndex, word := range wantWords {
		base := wordIndex * 4
		wantSlots := ringZ.ArithmeticRootSlots(word)
		block := make([]*bignum.Complex, 4)
		for slot := range block {
			b2aAssertApproxComplex(t, decoded[base+slot], wantSlots[slot].Complex128(), 5e-4)
			block[slot] = bignum.ToComplex(decoded[base+slot], z2n.DefaultPrecision)
		}
		polynomial, err := ringZ.FromRootSlots(block)
		if err != nil {
			t.Fatal(err)
		}
		coefficients := polynomial.Coefficients()
		for coefficient, numerator := range wantNumerators[wordIndex] {
			got, _ := coefficients[coefficient].Float64()
			want := float64(numerator) / 256
			if math.Abs(got-want) > 5e-4 {
				t.Fatalf("word %#02x coefficient %d: got %.9g, want %.9g", word, coefficient, got, want)
			}
		}
		if got, err := ringZ.DecodeArithmetic(polynomial); err != nil || got != word {
			t.Fatalf("word %d residue: got %#02x, err=%v", wordIndex, got, err)
		}
	}
}

func TestB2AFullRejectsContractMismatchesAndEveryMissingKey(t *testing.T) {
	params := b2aFunctionalParameters(t)
	encoder := ckks.NewEncoder(params, z2n.DefaultPrecision)
	circuit, err := homchain.NewB2AFullCircuit(params, encoder)
	if err != nil {
		t.Fatal(err)
	}
	profile := circuit.Profile()
	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	valid := b2aEncrypt(t, params, encoder, secretKey, make([]complex128, params.MaxSlots()))

	if _, err = circuit.BindLow(nil); err == nil {
		t.Fatal("BindLow(nil) succeeded")
	}
	if _, err = circuit.BindHigh(nil); err == nil {
		t.Fatal("BindHigh(nil) succeeded")
	}
	badDegree := valid.CopyNew()
	badDegree.Resize(2, badDegree.Level())
	if _, err = circuit.BindLow(badDegree); err == nil {
		t.Fatal("degree-2 Boolean half was accepted")
	}
	badLevel := valid.CopyNew()
	badLevel.Resize(badLevel.Degree(), 0)
	if _, err = circuit.BindLow(badLevel); err == nil {
		t.Fatal("level-0 Boolean half was accepted")
	}
	badDimensions := valid.CopyNew()
	badDimensions.LogDimensions = ring.Dimensions{Rows: 0, Cols: 2}
	if _, err = circuit.BindLow(badDimensions); err == nil {
		t.Fatal("partially packed Boolean half was accepted")
	}
	badBatching := valid.CopyNew()
	badBatching.IsBatched = false
	if _, err = circuit.BindLow(badBatching); err == nil {
		t.Fatal("non-batched Boolean half was accepted")
	}

	highScaleMismatch := valid.CopyNew()
	highScaleMismatch.Scale = highScaleMismatch.Scale.Mul(rlwe.NewScale(2))
	if _, err = circuit.BindHigh(highScaleMismatch); err == nil {
		t.Fatal("non-profile Boolean scale was accepted")
	}

	sharedModularScale := valid.CopyNew()
	sharedModularScale.Scale.Mod = big.NewInt(257)
	if _, err = circuit.BindLow(sharedModularScale); err == nil {
		t.Fatal("Boolean half with a shared modular scale was accepted")
	}

	sharedPrecisionMismatch := valid.CopyNew()
	sharedPrecisionMismatch.Scale.Value = *new(big.Float).
		SetPrec(sharedPrecisionMismatch.Scale.Value.Prec() + 1).
		Set(&sharedPrecisionMismatch.Scale.Value)
	if _, err = circuit.BindLow(sharedPrecisionMismatch); err == nil {
		t.Fatal("Boolean half with a non-profile scale precision was accepted")
	}

	sharedRoundingMismatch := valid.CopyNew()
	sharedRoundingMismatch.Scale.Value.SetMode(big.ToZero)
	if _, err = circuit.BindLow(sharedRoundingMismatch); err == nil {
		t.Fatal("Boolean half with a non-profile scale rounding mode was accepted")
	}

	if _, err = circuit.BindEvaluator(ckks.NewEvaluator(params, nil)); err == nil {
		t.Fatal("nil evaluation-key set was accepted")
	}
	required := profile.RequiredGaloisElements()
	for missingIndex, missing := range required {
		present := append([]uint64(nil), required[:missingIndex]...)
		present = append(present, required[missingIndex+1:]...)
		keys := keyGenerator.GenGaloisKeysNew(present, secretKey)
		if _, err = circuit.BindEvaluator(ckks.NewEvaluator(params, rlwe.NewMemEvaluationKeySet(nil, keys...))); err == nil {
			t.Fatalf("preflight accepted key set missing Galois element %d", missing)
		}
	}

	allKeys := keyGenerator.GenGaloisKeysNew(required, secretKey)
	bound, err := circuit.BindEvaluator(ckks.NewEvaluator(params, rlwe.NewMemEvaluationKeySet(nil, allKeys...)))
	if err != nil {
		t.Fatal(err)
	}
	validHigh := valid.CopyNew()
	boundLow, err := circuit.BindLow(valid)
	if err != nil {
		t.Fatal(err)
	}
	boundHigh, err := circuit.BindHigh(validHigh)
	if err != nil {
		t.Fatal(err)
	}
	boundInput, err := circuit.BindInput(boundLow, boundHigh)
	if err != nil {
		t.Fatal(err)
	}
	validHigh.Scale = validHigh.Scale.Mul(rlwe.NewScale(2))
	if _, err = bound.EvaluateNew(boundInput); err == nil {
		t.Fatal("post-bind exact-scale mutation was accepted")
	}
}

func TestB2AFullRejectsParametersOutsideTheFixedVerticalSlice(t *testing.T) {
	validParameters := b2aFunctionalParameters(t)
	mismatchedEncoderParameters, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN: 4, LogQ: []int{40, 31}, LogP: []int{40}, LogDefaultScale: 30,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = homchain.NewB2AFullCircuit(validParameters, ckks.NewEncoder(mismatchedEncoderParameters, z2n.DefaultPrecision)); err == nil {
		t.Fatal("encoder with mismatched parameters was accepted")
	}
	if _, err = homchain.NewB2AFullCircuit(validParameters, ckks.NewEncoder(validParameters, 192)); err == nil {
		t.Fatal("encoder with non-profile precision was accepted")
	}

	testCases := []struct {
		name    string
		literal ckks.ParametersLiteral
	}{
		{name: "not-LogN4", literal: ckks.ParametersLiteral{LogN: 5, LogQ: []int{40, 30}, LogP: []int{40}, LogDefaultScale: 30}},
		{name: "three-Q-primes", literal: ckks.ParametersLiteral{LogN: 4, LogQ: []int{40, 30, 30}, LogP: []int{40}, LogDefaultScale: 30}},
		{name: "wrong-Q-profile", literal: ckks.ParametersLiteral{LogN: 4, LogQ: []int{39, 30}, LogP: []int{40}, LogDefaultScale: 30}},
		{name: "wrong-P-profile", literal: ckks.ParametersLiteral{LogN: 4, LogQ: []int{40, 30}, LogP: []int{39}, LogDefaultScale: 30}},
		{name: "wrong-default-scale", literal: ckks.ParametersLiteral{LogN: 4, LogQ: []int{40, 30}, LogP: []int{40}, LogDefaultScale: 29}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			params, err := ckks.NewParametersFromLiteral(testCase.literal)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = homchain.NewB2AFullCircuit(params, ckks.NewEncoder(params, z2n.DefaultPrecision)); err == nil {
				t.Fatal("out-of-profile parameters were accepted")
			}
		})
	}
}

func TestB2AFullFusedSemanticsDifferFromNormalUAndPreserveHalfOrder(t *testing.T) {
	params := b2aFunctionalParameters(t)
	encoder := ckks.NewEncoder(params, z2n.DefaultPrecision)
	circuit, err := homchain.NewB2AFullCircuit(params, encoder)
	if err != nil {
		t.Fatal(err)
	}
	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	galoisKeys := keyGenerator.GenGaloisKeysNew(circuit.Profile().RequiredGaloisElements(), secretKey)
	ckksEvaluator := ckks.NewEvaluator(params, rlwe.NewMemEvaluationKeySet(nil, galoisKeys...))
	bound, err := circuit.BindEvaluator(ckksEvaluator)
	if err != nil {
		t.Fatal(err)
	}

	lowValues := []complex128{0, 0, 0, 0, 1, 0, 1, 0}
	highValues := []complex128{1, 0, 0, 0, 0, 1, 0, 1}
	lowCiphertext := b2aEncrypt(t, params, encoder, secretKey, lowValues)
	highCiphertext := b2aEncrypt(t, params, encoder, secretKey, highValues)
	fusedOutput := b2aEvaluate(t, circuit, bound, lowCiphertext, highCiphertext)

	ringZ, err := z2n.New(z2n.Word8)
	if err != nil {
		t.Fatal(err)
	}
	specifications, err := homchain.NewSpecificationsFromRing(ringZ, 2)
	if err != nil {
		t.Fatal(err)
	}
	normalPair, err := homchain.CompilePair(params, encoder, specifications.UPair(), homchain.CompileOptions{
		LevelQ: 1, LevelP: 0, Scale: rlwe.NewScale(params.Q()[1]), LogBabyStepGiantStepRatio: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := normalPair.GaloisElements(params), circuit.Profile().RequiredGaloisElements(); !reflect.DeepEqual(got, want) {
		t.Fatalf("normal/fused key schedule differs: normal=%v fused=%v", got, want)
	}
	normalOutput, err := homchain.NewEvaluator(ckksEvaluator).CToZNew(homchain.CiphertextPair{lowCiphertext, highCiphertext}, normalPair)
	if err != nil {
		t.Fatal(err)
	}

	fusedDecoded := b2aDecrypt(t, params, encoder, secretKey, fusedOutput)
	normalDecoded := b2aDecrypt(t, params, encoder, secretKey, normalOutput)
	fusedPolynomial := b2aRecoverPolynomial(t, ringZ, fusedDecoded[:4])
	normalPolynomial := b2aRecoverPolynomial(t, ringZ, normalDecoded[:4])
	normalCoefficients := normalPolynomial.Coefficients()
	wantBinary := ringZ.BinaryEncode(0x10).Coefficients()
	for i := range normalCoefficients {
		got, _ := normalCoefficients[i].Float64()
		want, _ := wantBinary[i].Float64()
		if math.Abs(got-want) > 5e-4 {
			t.Fatalf("normal U coefficient %d: got %.9g, want binary coefficient %.9g", i, got, want)
		}
	}
	fusedCoefficientZero, _ := fusedPolynomial.Coefficients()[0].Float64()
	if math.Abs(fusedCoefficientZero-1.0/16.0) > 5e-4 {
		t.Fatalf("fused coefficient zero: got %.9g, want 1/16", fusedCoefficientZero)
	}
	if normalCoefficientFour, _ := normalCoefficients[4].Float64(); math.Abs(normalCoefficientFour-fusedPolynomialCoefficient(t, fusedPolynomial, 4)) < 1 {
		t.Fatalf("normal U unexpectedly approximates fused arithmetic semantics: normal coeff4=%.9g", normalCoefficientFour)
	}
	canonical, err := ringZ.CanonicalizeArithmetic(ringZ.ArithmeticEncode(0x10))
	if err != nil {
		t.Fatal(err)
	}
	canonicalCoefficientZero, _ := canonical.Coefficients()[0].Float64()
	if math.Abs(fusedCoefficientZero-canonicalCoefficientZero) < 0.9 {
		t.Fatalf("raw B2A output was confused with A2A-I canonical output: raw=%.9g canonical=%.9g", fusedCoefficientZero, canonicalCoefficientZero)
	}

	swapped := b2aEvaluate(t, circuit, bound, highCiphertext, lowCiphertext)
	b2aAssertResidues(t, ringZ, b2aDecrypt(t, params, encoder, secretKey, swapped), []uint64{0x01, 0x5a})

	reversedLow := b2aReverseWordBlocks(lowValues, 4)
	reversedHigh := b2aReverseWordBlocks(highValues, 4)
	reversed := b2aEvaluate(
		t, circuit, bound,
		b2aEncrypt(t, params, encoder, secretKey, reversedLow),
		b2aEncrypt(t, params, encoder, secretKey, reversedHigh),
	)
	b2aAssertResidues(t, ringZ, b2aDecrypt(t, params, encoder, secretKey, reversed), []uint64{0x80, 0x5a})
}

func TestB2AFullExhaustiveWord8ResiduesAndErrorMargins(t *testing.T) {
	params := b2aFunctionalParameters(t)
	encoder := ckks.NewEncoder(params, z2n.DefaultPrecision)
	circuit, err := homchain.NewB2AFullCircuit(params, encoder)
	if err != nil {
		t.Fatal(err)
	}
	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	galoisKeys := keyGenerator.GenGaloisKeysNew(circuit.Profile().RequiredGaloisElements(), secretKey)
	bound, err := circuit.BindEvaluator(ckks.NewEvaluator(params, rlwe.NewMemEvaluationKeySet(nil, galoisKeys...)))
	if err != nil {
		t.Fatal(err)
	}
	ringZ, err := z2n.New(z2n.Word8)
	if err != nil {
		t.Fatal(err)
	}

	maxSlotError := 0.0
	maxCoefficientError := 0.0
	maxBitError := 0.0
	minRoundingMargin := 0.5
	for first := uint64(0); first < 256; first += 2 {
		words := []uint64{first, first + 1}
		lowValues := make([]complex128, 8)
		highValues := make([]complex128, 8)
		for wordIndex, word := range words {
			halves, err := z2n.A2BBooleanHalvesOracle(word, z2n.Word8)
			if err != nil {
				t.Fatal(err)
			}
			for bit := 0; bit < 4; bit++ {
				lowValues[wordIndex*4+bit] = complex(float64(halves.Low[bit]), 0)
				highValues[wordIndex*4+bit] = complex(float64(halves.High[bit]), 0)
			}
		}
		output := b2aEvaluate(
			t, circuit, bound,
			b2aEncrypt(t, params, encoder, secretKey, lowValues),
			b2aEncrypt(t, params, encoder, secretKey, highValues),
		)
		decoded := b2aDecrypt(t, params, encoder, secretKey, output)
		for wordIndex, word := range words {
			base := wordIndex * 4
			wantSlots := ringZ.ArithmeticRootSlots(word)
			for slot := 0; slot < 4; slot++ {
				errorMagnitude := math.Abs(real(decoded[base+slot]-wantSlots[slot].Complex128())) + math.Abs(imag(decoded[base+slot]-wantSlots[slot].Complex128()))
				maxSlotError = math.Max(maxSlotError, errorMagnitude)
			}
			polynomial := b2aRecoverPolynomial(t, ringZ, decoded[base:base+4])
			wantCoefficients := ringZ.ArithmeticEncode(word).Coefficients()
			gotCoefficients := polynomial.Coefficients()
			for i := range gotCoefficients {
				got, _ := gotCoefficients[i].Float64()
				want, _ := wantCoefficients[i].Float64()
				maxCoefficientError = math.Max(maxCoefficientError, math.Abs(got-want))
			}
			timesTau, err := ringZ.MulTau(polynomial)
			if err != nil {
				t.Fatal(err)
			}
			for bit, coefficient := range timesTau.Coefficients() {
				got, _ := coefficient.Float64()
				want := float64(word >> uint(bit) & 1)
				errorMagnitude := math.Abs(got - want)
				maxBitError = math.Max(maxBitError, errorMagnitude)
				minRoundingMargin = math.Min(minRoundingMargin, 0.5-errorMagnitude)
			}
			if got, err := ringZ.DecodeArithmetic(polynomial); err != nil || got != word {
				t.Fatalf("word %#02x residue: got %#02x, err=%v", word, got, err)
			}
		}
	}

	t.Logf("B2A exhaustive n=8: max-slot-error=%.3g max-coefficient-error=%.3g max-bit-error=%.3g min-rounding-margin=%.6f",
		maxSlotError, maxCoefficientError, maxBitError, minRoundingMargin)
	if maxSlotError > 5e-4 {
		t.Fatalf("max root-slot error %.3g exceeds 5e-4", maxSlotError)
	}
	if maxCoefficientError > 5e-4 {
		t.Fatalf("max coefficient error %.3g exceeds 5e-4", maxCoefficientError)
	}
	if maxBitError > 1e-3 || minRoundingMargin < 0.499 {
		t.Fatalf("bit recovery margin too small: max error %.3g, min margin %.6f", maxBitError, minRoundingMargin)
	}
}

func b2aFunctionalParameters(t *testing.T) ckks.Parameters {
	t.Helper()
	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            4,
		LogQ:            []int{40, 30},
		LogP:            []int{40},
		LogDefaultScale: 30,
	})
	if err != nil {
		t.Fatal(err)
	}
	return params
}

func b2aEncrypt(t *testing.T, params ckks.Parameters, encoder *ckks.Encoder, secretKey *rlwe.SecretKey, values []complex128) *rlwe.Ciphertext {
	t.Helper()
	plaintext := ckks.NewPlaintext(params, params.MaxLevel())
	plaintext.LogDimensions = ring.Dimensions{Rows: 0, Cols: 3}
	if err := encoder.Encode(values, plaintext); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := ckks.NewEncryptor(params, secretKey).EncryptNew(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	return ciphertext
}

func b2aDecrypt(t *testing.T, params ckks.Parameters, encoder *ckks.Encoder, secretKey *rlwe.SecretKey, ciphertext *rlwe.Ciphertext) []complex128 {
	t.Helper()
	values := make([]complex128, ciphertext.Slots())
	if err := encoder.Decode(ckks.NewDecryptor(params, secretKey).DecryptNew(ciphertext), values); err != nil {
		t.Fatal(err)
	}
	return values
}

func b2aEvaluate(t *testing.T, circuit *homchain.B2AFullCircuit, evaluator *homchain.B2AFullEvaluator, lowCiphertext, highCiphertext *rlwe.Ciphertext) *rlwe.Ciphertext {
	t.Helper()
	low, err := circuit.BindLow(lowCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	high, err := circuit.BindHigh(highCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	input, err := circuit.BindInput(low, high)
	if err != nil {
		t.Fatal(err)
	}
	result, err := evaluator.EvaluateNew(input)
	if err != nil {
		t.Fatal(err)
	}
	return result.Ciphertext()
}

func b2aRecoverPolynomial(t *testing.T, ringZ *z2n.Ring, slots []complex128) z2n.Polynomial {
	t.Helper()
	highPrecision := make([]*bignum.Complex, len(slots))
	for i := range slots {
		highPrecision[i] = bignum.ToComplex(slots[i], z2n.DefaultPrecision)
	}
	polynomial, err := ringZ.FromRootSlots(highPrecision)
	if err != nil {
		t.Fatal(err)
	}
	return polynomial
}

func fusedPolynomialCoefficient(t *testing.T, polynomial z2n.Polynomial, index int) float64 {
	t.Helper()
	coefficients := polynomial.Coefficients()
	if index < 0 || index >= len(coefficients) {
		t.Fatalf("coefficient index %d outside [0,%d)", index, len(coefficients))
	}
	value, _ := coefficients[index].Float64()
	return value
}

func b2aAssertResidues(t *testing.T, ringZ *z2n.Ring, slots []complex128, want []uint64) {
	t.Helper()
	if len(slots) != len(want)*4 {
		t.Fatalf("slot count: got %d, want %d", len(slots), len(want)*4)
	}
	for i, word := range want {
		polynomial := b2aRecoverPolynomial(t, ringZ, slots[i*4:(i+1)*4])
		got, err := ringZ.DecodeArithmetic(polynomial)
		if err != nil || got != word {
			t.Fatalf("word %d residue: got %#02x, want %#02x, err=%v", i, got, word, err)
		}
	}
}

func b2aReverseWordBlocks(values []complex128, width int) []complex128 {
	result := append([]complex128(nil), values...)
	for base := 0; base < len(result); base += width {
		for left, right := base, base+width-1; left < right; left, right = left+1, right-1 {
			result[left], result[right] = result[right], result[left]
		}
	}
	return result
}

func b2aAssertApproxComplex(t *testing.T, got, want complex128, tolerance float64) {
	t.Helper()
	if errorMagnitude := math.Abs(real(got-want)) + math.Abs(imag(got-want)); errorMagnitude > tolerance {
		t.Fatalf("got %.12g%+.12gi, want %.12g%+.12gi, L1 error %.3g > %.3g",
			real(got), imag(got), real(want), imag(want), errorMagnitude, tolerance)
	}
}
