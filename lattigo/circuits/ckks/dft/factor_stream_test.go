package dft

import (
	"errors"
	"reflect"
	"testing"

	ltcommon "github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/lintrans"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/ring"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
)

type memoryFactorSource struct {
	literal MatrixLiteral
	factors []ltcommon.LinearTransformation
}

type validatedMemoryFactorSource struct {
	literal        MatrixLiteral
	factors        []ValidatedFactor
	legacyReads    int
	validatedReads int
}

func (s *validatedMemoryFactorSource) Literal() MatrixLiteral { return s.literal }
func (s *validatedMemoryFactorSource) FactorCount() int       { return len(s.factors) }
func (s *validatedMemoryFactorSource) ReadFactor(int) (ltcommon.LinearTransformation, error) {
	s.legacyReads++
	return ltcommon.LinearTransformation{}, errors.New("legacy factor path called")
}
func (s *validatedMemoryFactorSource) ReadValidatedFactor(index int) (ValidatedFactor, error) {
	s.validatedReads++
	if index < 0 || index >= len(s.factors) {
		return ValidatedFactor{}, errors.New("factor index out of range")
	}
	return s.factors[index], nil
}

func (s memoryFactorSource) Literal() MatrixLiteral { return s.literal }
func (s memoryFactorSource) FactorCount() int       { return len(s.factors) }
func (s memoryFactorSource) ReadFactor(index int) (ltcommon.LinearTransformation, error) {
	if index < 0 || index >= len(s.factors) {
		return ltcommon.LinearTransformation{}, errors.New("factor index out of range")
	}
	return s.factors[index], nil
}

func TestForEachEncodedMatrixFactorMatchesWholeMatrix(t *testing.T) {
	params := explicitPrecisionTestParameters(t)
	literal := explicitPrecisionTestLiteral()
	encoder := ckks.NewEncoder(params)

	want, err := NewMatrixFromLiteralWithGeneratorPrecisionStreaming(params, literal, encoder, encoder.Prec())
	if err != nil {
		t.Fatal(err)
	}

	got := make([]ltcommon.LinearTransformation, 0, literal.Depth(false))
	err = ForEachEncodedMatrixFactor(params, literal, encoder, encoder.Prec(), func(index, count int, factor ltcommon.LinearTransformation) error {
		if index != len(got) || count != literal.Depth(false) {
			t.Fatalf("callback index/count=%d/%d, want %d/%d", index, count, len(got), literal.Depth(false))
		}
		if err := ValidateMatrixFactor(params, literal, index, factor); err != nil {
			t.Fatalf("validate factor %d: %v", index, err)
		}
		got = append(got, factor)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want.Matrices) {
		t.Fatal("factor-at-a-time encoding differs from whole streaming construction")
	}
}

func TestForEachEncodedMatrixFactorStopsAtCallbackError(t *testing.T) {
	params := explicitPrecisionTestParameters(t)
	literal := explicitPrecisionTestLiteral()
	encoder := ckks.NewEncoder(params)
	sentinel := errors.New("stop")
	calls := 0

	err := ForEachEncodedMatrixFactor(params, literal, encoder, encoder.Prec(), func(_, _ int, _ ltcommon.LinearTransformation) error {
		calls++
		return sentinel
	})
	if !errors.Is(err, sentinel) || calls != 1 {
		t.Fatalf("err=%v calls=%d, want sentinel/1", err, calls)
	}
}

func TestValidateMatrixFactorRejectsWrongIndexAndMetadata(t *testing.T) {
	params := explicitPrecisionTestParameters(t)
	literal := explicitPrecisionTestLiteral()
	encoder := ckks.NewEncoder(params)
	whole, err := NewMatrixFromLiteralWithGeneratorPrecisionStreaming(params, literal, encoder, encoder.Prec())
	if err != nil {
		t.Fatal(err)
	}

	if err := ValidateMatrixFactor(params, literal, -1, whole.Matrices[0]); err == nil {
		t.Fatal("negative factor index was accepted")
	}
	broken := whole.Matrices[0]
	broken.MetaData = &rlwe.MetaData{}
	if err := ValidateMatrixFactor(params, literal, 0, broken); err == nil {
		t.Fatal("invalid factor metadata was accepted")
	}
}

func TestValidatedFactorRejectsWrongIdentity(t *testing.T) {
	params := explicitPrecisionTestParameters(t)
	literal := explicitPrecisionTestLiteral()
	matrix, err := NewMatrixFromLiteralWithGeneratorPrecisionStreaming(params, literal, ckks.NewEncoder(params), 53)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewValidatedFactor(params, literal, -1, matrix.Matrices[0]); err == nil {
		t.Fatal("negative validated-factor index was accepted")
	}
	broken := matrix.Matrices[0]
	broken.MetaData = &rlwe.MetaData{}
	if _, err := NewValidatedFactor(params, literal, 0, broken); err == nil {
		t.Fatal("invalid transformation was sealed as validated")
	}
}

func TestFactorSourceDenseCoeffsToSlotsMatchesResidentMatrix(t *testing.T) {
	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN: 4, LogQ: []int{60, 60, 60, 60, 60}, LogP: []int{60}, LogDefaultScale: 43,
	})
	if err != nil {
		t.Fatal(err)
	}
	literal := MatrixLiteral{
		Type: HomomorphicEncode, LogSlots: 3, LevelQ: 3, LevelP: 0,
		Levels: []int{1, 1, 1}, Format: SplitRealAndImag, LogBSGSRatio: 2,
	}
	encoder := ckks.NewEncoder(params)
	matrix, err := NewMatrixFromLiteralWithGeneratorPrecisionStreaming(params, literal, encoder, encoder.Prec())
	if err != nil {
		t.Fatal(err)
	}
	validated := make([]ValidatedFactor, len(matrix.Matrices))
	for index, factor := range matrix.Matrices {
		validated[index], err = NewValidatedFactor(params, literal, index, factor)
		if err != nil {
			t.Fatal(err)
		}
	}
	source := &validatedMemoryFactorSource{literal: literal, factors: validated}

	keyGenerator := rlwe.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	galEls := append(literal.GaloisElements(params), params.GaloisElementForComplexConjugation())
	keySet := rlwe.NewMemEvaluationKeySet(nil, keyGenerator.GenGaloisKeysNew(galEls, secretKey)...)
	heEvaluator := ckks.NewEvaluator(params, keySet)
	evaluator := NewEvaluator(params, heEvaluator)
	plaintext := ckks.NewPlaintext(params, literal.LevelQ)
	plaintext.LogDimensions = ring.Dimensions{Rows: 0, Cols: literal.LogSlots}
	plaintext.Scale = params.DefaultScale()
	values := []complex128{1 + 2i, 3 - 4i, 5 + 6i, 7 - 8i, 9 + 10i, 11 - 12i, 13 + 14i, 15 - 16i}
	if err = encoder.Encode(values, plaintext); err != nil {
		t.Fatal(err)
	}
	input, err := ckks.NewEncryptor(params, secretKey).EncryptNew(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	wantReal, wantImag, err := evaluator.CoeffsToSlotsNew(input.CopyNew(), matrix)
	if err != nil {
		t.Fatal(err)
	}
	gotReal, gotImag, err := evaluator.CoeffsToSlotsFromFactorsNew(input.CopyNew(), source)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotReal, wantReal) || !reflect.DeepEqual(gotImag, wantImag) {
		t.Fatal("factor-source dense CoeffsToSlots differs from resident-matrix evaluation")
	}
	realOnlySource := &validatedMemoryFactorSource{literal: literal, factors: validated}
	gotRealOnly, err := evaluator.CoeffsToSlotsRealFromFactorsNew(input.CopyNew(), realOnlySource)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotRealOnly, wantReal) {
		t.Fatal("factor-source real-only CoeffsToSlots differs from resident-matrix real output")
	}
	if source.legacyReads != 0 || source.validatedReads != len(matrix.Matrices) {
		t.Fatalf("legacy/validated reads=%d/%d, want 0/%d", source.legacyReads, source.validatedReads, len(matrix.Matrices))
	}
}

func TestFactorSourceDenseSlotsToCoeffsMatchesResidentMatrix(t *testing.T) {
	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN: 4, LogQ: []int{60, 60, 60, 60, 60}, LogP: []int{60}, LogDefaultScale: 43,
	})
	if err != nil {
		t.Fatal(err)
	}
	literal := MatrixLiteral{
		Type: HomomorphicDecode, LogSlots: 3, LevelQ: 3, LevelP: 0,
		Levels: []int{1, 1, 1}, Format: SplitRealAndImag, LogBSGSRatio: 2,
	}
	encoder := ckks.NewEncoder(params)
	matrix, err := NewMatrixFromLiteralWithGeneratorPrecisionStreaming(params, literal, encoder, encoder.Prec())
	if err != nil {
		t.Fatal(err)
	}
	source := memoryFactorSource{literal: literal, factors: matrix.Matrices}
	keyGenerator := rlwe.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	keySet := rlwe.NewMemEvaluationKeySet(nil, keyGenerator.GenGaloisKeysNew(literal.GaloisElements(params), secretKey)...)
	evaluator := NewEvaluator(params, ckks.NewEvaluator(params, keySet))

	encrypt := func(values []float64) *rlwe.Ciphertext {
		plaintext := ckks.NewPlaintext(params, literal.LevelQ)
		plaintext.LogDimensions = ring.Dimensions{Rows: 0, Cols: literal.LogSlots}
		plaintext.Scale = params.DefaultScale()
		if err := encoder.Encode(values, plaintext); err != nil {
			t.Fatal(err)
		}
		ciphertext, err := ckks.NewEncryptor(params, secretKey).EncryptNew(plaintext)
		if err != nil {
			t.Fatal(err)
		}
		return ciphertext
	}
	realInput := encrypt([]float64{1, 2, 3, 4, 5, 6, 7, 8})
	imagInput := encrypt([]float64{8, 7, 6, 5, 4, 3, 2, 1})
	want, err := evaluator.SlotsToCoeffsNew(realInput.CopyNew(), imagInput.CopyNew(), matrix)
	if err != nil {
		t.Fatal(err)
	}
	got, err := evaluator.SlotsToCoeffsFromFactorsNew(realInput.CopyNew(), imagInput.CopyNew(), source)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("factor-source dense SlotsToCoeffs differs from resident-matrix evaluation")
	}
}
