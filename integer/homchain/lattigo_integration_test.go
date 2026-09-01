package homchain_test

import (
	"math"
	"reflect"
	"sort"
	"testing"

	"dt_go/integer/homchain"
	"dt_go/integer/z2n"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

func TestFunctionalNotSecureLattigoFourWordZToCThenCToZ(t *testing.T) {
	context := newFunctionalContext(t, 4, false)
	want := packedRootSlots(context.ringZ, 0, 1, 173, 255)
	ciphertext := context.encrypt(t, want)

	coefficientHalves, err := context.evaluator.ZToCNew(ciphertext, context.vPair)
	if err != nil {
		t.Fatal(err)
	}
	reconstructed, err := context.evaluator.CToZNew(coefficientHalves, context.uPair)
	if err != nil {
		t.Fatal(err)
	}
	assertCiphertextSlotsClose(t, context, reconstructed, want, 3e-4)
}

func TestFunctionalNotSecureEncryptedOneHotWordHasNoCrossTalk(t *testing.T) {
	context := newFunctionalContext(t, 4, false)
	input := packedRootSlots(context.ringZ, 0, 0, 173, 0)
	coefficientHalves, err := context.evaluator.ZToCNew(context.encrypt(t, input), context.vPair)
	if err != nil {
		t.Fatal(err)
	}

	low := context.decrypt(t, coefficientHalves[0])
	high := context.decrypt(t, coefficientHalves[1])
	halfWidth := len(context.ringZ.Roots())
	for word := 0; word < 4; word++ {
		if word == 2 {
			continue
		}
		for column := 0; column < halfWidth; column++ {
			assertApproxComplex(t, low[word*halfWidth+column], 0, 2e-5)
			assertApproxComplex(t, high[word*halfWidth+column], 0, 2e-5)
		}
	}

	coefficients := context.ringZ.ArithmeticEncode(173).Coefficients()
	for column := 0; column < halfWidth; column++ {
		wantLow, _ := coefficients[column].Float64()
		wantHigh, _ := coefficients[column+halfWidth].Float64()
		assertApproxComplex(t, low[2*halfWidth+column], complex(wantLow, 0), 2e-5)
		assertApproxComplex(t, high[2*halfWidth+column], complex(wantHigh, 0), 2e-5)
	}
}

func TestFunctionalNotSecureEncryptedFusedTAndTInverseRoundTrip(t *testing.T) {
	context := newFunctionalContext(t, 4, true)
	want := packedRootSlots(context.ringZ, 3, 17, 129, 254)
	coefficientHalves, err := context.evaluator.ZToCNew(context.encrypt(t, want), context.vPair)
	if err != nil {
		t.Fatal(err)
	}
	reconstructed, err := context.evaluator.CToZNew(coefficientHalves, context.uPair)
	if err != nil {
		t.Fatal(err)
	}
	assertCiphertextSlotsClose(t, context, reconstructed, want, 4e-4)
}

func TestFunctionalNotSecureEncryptedSpecialB0Convention(t *testing.T) {
	context := newFunctionalContext(t, 4, false)
	specialV, err := homchain.CompilePair(context.params, context.encoder, context.specs.VSpecialB0Pair(), context.compileOptions)
	if err != nil {
		t.Fatal(err)
	}

	// The normal and special pairs have the same diagonal indexes, so the
	// context's exact key set is sufficient for both evaluations.
	input := packedRootSlots(context.ringZ, 1, 7, 31, 173)
	ciphertext := context.encrypt(t, input)
	normal, err := context.evaluator.ZToCNew(ciphertext, context.vPair)
	if err != nil {
		t.Fatal(err)
	}
	special, err := context.evaluator.ZToCNew(ciphertext, specialV)
	if err != nil {
		t.Fatal(err)
	}
	normalLow := context.decrypt(t, normal[0])
	specialLow := context.decrypt(t, special[0])
	normalHigh := context.decrypt(t, normal[1])
	specialHigh := context.decrypt(t, special[1])

	halfWidth := len(context.ringZ.Roots())
	for word := 0; word < 4; word++ {
		base := word * halfWidth
		assertApproxComplex(t, specialLow[base], 2*normalLow[base+1], 4e-5)
		for column := 1; column < halfWidth; column++ {
			assertApproxComplex(t, specialLow[base+column], normalLow[base+column], 4e-5)
		}
		for column := 0; column < halfWidth; column++ {
			assertApproxComplex(t, specialHigh[base+column], normalHigh[base+column], 4e-5)
		}
	}
}

func TestFullSlotBlockDiagonalLayoutMatchesRepeatedRowOracle(t *testing.T) {
	ringZ, err := z2n.New(z2n.Word8)
	if err != nil {
		t.Fatal(err)
	}
	specs, err := homchain.NewSpecificationsFromRing(ringZ, 4)
	if err != nil {
		t.Fatal(err)
	}
	full, err := specs.V0.FullSlot()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := full.LogDimensions().Rows, 0; got != want {
		t.Fatalf("full-slot log rows: got %d, want %d", got, want)
	}
	if got, want := full.LogDimensions().Cols, 4; got != want {
		t.Fatalf("full-slot log columns: got %d, want %d", got, want)
	}
	diagonals := full.Diagonals()
	indexes := diagonals.DiagonalsIndexList()
	sort.Ints(indexes)
	if want := []int{0, 1, 2, 3, 13, 14, 15}; !reflect.DeepEqual(indexes, want) {
		t.Fatalf("full-slot diagonal indexes: got %v, want %v", indexes, want)
	}

	input := packedRootSlots(ringZ, 1, 7, 31, 173)
	want, err := specs.V0.EvaluatePlaintext(input)
	if err != nil {
		t.Fatal(err)
	}
	got, err := full.EvaluatePlaintext(input)
	if err != nil {
		t.Fatal(err)
	}
	for i := range want {
		assertComplexClose(t, got[i], want[i], 1e-70)
	}
	zero := bignum.ToComplex(0, z2n.DefaultPrecision)
	for word := 0; word < 4; word++ {
		base := word * 4
		// +1 cannot read the next block from the last slot.
		assertComplexClose(t, diagonals[1][base+3], zero, 0)
		// -1 (normalized to 15) cannot read the previous block from the first slot.
		assertComplexClose(t, diagonals[15][base], zero, 0)
	}
}

func TestCompactPublicParametersMatchCompileFullSlotProvenance(t *testing.T) {
	params := functionalParameters(t)
	ringZ, err := z2n.New(z2n.Word8)
	if err != nil {
		t.Fatal(err)
	}
	specs, err := homchain.NewSpecificationsFromRing(ringZ, 4)
	if err != nil {
		t.Fatal(err)
	}
	options := functionalCompileOptions(params)
	encoder := ckks.NewEncoder(params, z2n.DefaultPrecision)
	baseline, err := homchain.Compile(params, encoder, specs.V0, options)
	if err != nil {
		t.Fatal(err)
	}
	baselineGalois, err := specs.V0.GaloisElements(params, options.LogBabyStepGiantStepRatio)
	if err != nil {
		t.Fatal(err)
	}

	// Mutating accessor results must not alter Parameters, GaloisElements, or
	// the plaintext polynomials subsequently emitted by Compile.
	exposedMatrix := specs.V0.Matrix()
	exposedMatrix[0][0].Real().SetInt64(999)
	exposedDiagonals := specs.V0.Diagonals()
	exposedDiagonals[0][0].Real().SetInt64(999)
	delete(exposedDiagonals, 1)

	publicParameters, err := specs.V0.Parameters(options)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := homchain.Compile(params, encoder, specs.V0, options)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := publicParameters.LogDimensions, compiled.LogDimensions; got != want {
		t.Fatalf("public/compiled dimensions differ: got %+v, want %+v", got, want)
	}
	if publicParameters.LogDimensions.Rows != 0 || publicParameters.LogDimensions.Cols != 4 {
		t.Fatalf("compact Parameters returned non-encodable dimensions: %+v", publicParameters.LogDimensions)
	}
	gotIndexes := append([]int(nil), publicParameters.DiagonalsIndexList...)
	wantIndexes := make([]int, 0, len(compiled.Vec))
	for index := range compiled.Vec {
		wantIndexes = append(wantIndexes, index)
	}
	sort.Ints(gotIndexes)
	sort.Ints(wantIndexes)
	if !reflect.DeepEqual(gotIndexes, wantIndexes) {
		t.Fatalf("public/compiled diagonal provenance differs: got %v, want %v", gotIndexes, wantIndexes)
	}
	if len(baseline.Vec) != len(compiled.Vec) {
		t.Fatalf("compiled diagonal count changed after accessor mutation: got %d, want %d", len(compiled.Vec), len(baseline.Vec))
	}
	for index, wantPolynomial := range baseline.Vec {
		gotPolynomial, ok := compiled.Vec[index]
		if !ok || !wantPolynomial.Equal(&gotPolynomial) {
			t.Fatalf("compiled plaintext diagonal %d changed after accessor mutation", index)
		}
	}
	gotGalois, err := specs.V0.GaloisElements(params, options.LogBabyStepGiantStepRatio)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotGalois, baselineGalois) {
		t.Fatalf("Galois provenance changed after accessor mutation: got %v, want %v", gotGalois, baselineGalois)
	}
}

func TestGaloisElementsReportsInvalidTransformSpec(t *testing.T) {
	params := functionalParameters(t)
	var invalid homchain.TransformSpec
	if got, err := invalid.GaloisElements(params, 0); err == nil {
		t.Fatalf("invalid transform returned keys %v without an error", got)
	}
}

func TestNaiveGaloisElementsExactlyMatchFullSlotRotations(t *testing.T) {
	params := functionalParameters(t)
	ringZ, err := z2n.New(z2n.Word8)
	if err != nil {
		t.Fatal(err)
	}
	specs, err := homchain.NewSpecificationsFromRing(ringZ, 4)
	if err != nil {
		t.Fatal(err)
	}
	encoder := ckks.NewEncoder(params, z2n.DefaultPrecision)
	options := functionalCompileOptions(params)
	options.LogBabyStepGiantStepRatio = -1
	pair, err := homchain.CompilePair(params, encoder, specs.VPair(), options)
	if err != nil {
		t.Fatal(err)
	}

	got := pair.GaloisElements(params)
	want := params.GaloisElements([]int{1, 2, 3, 13, 14, 15})
	sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Galois elements: got %v, want %v", got, want)
	}
}

func TestBSGSGaloisElementsExactlyMatchReportedRotationIndexes(t *testing.T) {
	params := functionalParameters(t)
	ringZ, err := z2n.New(z2n.Word8)
	if err != nil {
		t.Fatal(err)
	}
	specs, err := homchain.NewSpecificationsFromRing(ringZ, 4)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := homchain.CompilePair(
		params,
		ckks.NewEncoder(params, z2n.DefaultPrecision),
		specs.VPair(),
		functionalCompileOptions(params),
	)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := pair.RotationIndexes(), []int{1, 2, 12, 14}; !reflect.DeepEqual(got, want) {
		t.Fatalf("BSGS rotations: got %v, want %v", got, want)
	}
	wantGalois := params.GaloisElements(pair.RotationIndexes())
	sort.Slice(wantGalois, func(i, j int) bool { return wantGalois[i] < wantGalois[j] })
	if got := pair.GaloisElements(params); !reflect.DeepEqual(got, wantGalois) {
		t.Fatalf("BSGS Galois elements: got %v, want %v", got, wantGalois)
	}
}

type functionalContext struct {
	params         ckks.Parameters
	ringZ          *z2n.Ring
	specs          homchain.Specifications
	encoder        *ckks.Encoder
	compileOptions homchain.CompileOptions
	vPair          homchain.CompiledPair
	uPair          homchain.CompiledPair
	evaluator      *homchain.Evaluator
	secretKey      *rlwe.SecretKey
}

func newFunctionalContext(t *testing.T, words int, fused bool) functionalContext {
	t.Helper()
	params := functionalParameters(t)
	ringZ, err := z2n.New(z2n.Word8)
	if err != nil {
		t.Fatal(err)
	}
	specs, err := homchain.NewSpecificationsFromRing(ringZ, words)
	if err != nil {
		t.Fatal(err)
	}
	encoder := ckks.NewEncoder(params, z2n.DefaultPrecision)
	options := functionalCompileOptions(params)
	vSpec := specs.VPair()
	uSpec := specs.UPair()
	if fused {
		vSpec = specs.VFusedTPair()
		uSpec = specs.UFusedTInvPair()
	}
	vPair, err := homchain.CompilePair(params, encoder, vSpec, options)
	if err != nil {
		t.Fatal(err)
	}
	uPair, err := homchain.CompilePair(params, encoder, uSpec, options)
	if err != nil {
		t.Fatal(err)
	}
	if vPair.Low.LogDimensions.Rows != 0 || vPair.Low.LogDimensions.Cols != 4 {
		t.Fatalf("compiled dimensions: got %+v, want {Rows:0 Cols:4}", vPair.Low.LogDimensions)
	}

	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	galoisElements := homchain.GaloisElementsForRoundTrip(params, vPair, uPair)
	galoisKeys := keyGenerator.GenGaloisKeysNew(galoisElements, secretKey)
	ckksEvaluator := ckks.NewEvaluator(params, rlwe.NewMemEvaluationKeySet(nil, galoisKeys...))
	return functionalContext{
		params: params, ringZ: ringZ, specs: specs, encoder: encoder, compileOptions: options,
		vPair: vPair, uPair: uPair, evaluator: homchain.NewEvaluator(ckksEvaluator), secretKey: secretKey,
	}
}

func functionalParameters(t *testing.T) ckks.Parameters {
	t.Helper()
	// FUNCTIONAL-NOT-SECURE: LogN=8 is intentionally tiny. These tests check
	// Lattigo transform wiring and approximate correctness, not HE security.
	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            8,
		LogQ:            []int{40, 30, 30},
		LogP:            []int{40},
		LogDefaultScale: 30,
	})
	if err != nil {
		t.Fatal(err)
	}
	return params
}

func functionalCompileOptions(params ckks.Parameters) homchain.CompileOptions {
	return homchain.CompileOptions{
		LevelQ: params.MaxLevel(), LevelP: params.MaxLevelP(), Scale: params.DefaultScale(),
		LogBabyStepGiantStepRatio: 0,
	}
}

func (c functionalContext) encrypt(t *testing.T, values []*bignum.Complex) *rlwe.Ciphertext {
	t.Helper()
	plaintext := ckks.NewPlaintext(c.params, c.params.MaxLevel())
	plaintext.LogDimensions = c.vPair.Low.LogDimensions
	if err := c.encoder.Encode(values, plaintext); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := ckks.NewEncryptor(c.params, c.secretKey).EncryptNew(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	return ciphertext
}

func (c functionalContext) decrypt(t *testing.T, ciphertext *rlwe.Ciphertext) []complex128 {
	t.Helper()
	values := make([]complex128, ciphertext.Slots())
	if err := c.encoder.Decode(ckks.NewDecryptor(c.params, c.secretKey).DecryptNew(ciphertext), values); err != nil {
		t.Fatal(err)
	}
	return values
}

func assertCiphertextSlotsClose(t *testing.T, context functionalContext, ciphertext *rlwe.Ciphertext, want []*bignum.Complex, tolerance float64) {
	t.Helper()
	got := context.decrypt(t, ciphertext)
	if len(got) != len(want) {
		t.Fatalf("decoded slots: got %d, want %d", len(got), len(want))
	}
	for i := range want {
		assertApproxComplex(t, got[i], want[i].Complex128(), tolerance)
	}
}

func assertApproxComplex(t *testing.T, got, want complex128, tolerance float64) {
	t.Helper()
	if errorMagnitude := math.Abs(real(got-want)) + math.Abs(imag(got-want)); errorMagnitude > tolerance {
		t.Fatalf("got %.12g%+.12gi, want %.12g%+.12gi, L1 error %.3g > %.3g",
			real(got), imag(got), real(want), imag(want), errorMagnitude, tolerance)
	}
}
