package secureeval

import (
	"math"
	"testing"

	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/ring"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
)

// The production constructor and evaluator are intentionally exercised here
// only at their validation boundary. A successful construction allocates the
// complete N=65536 DFT/key graph and belongs in the opt-in end-to-end gate.
func TestGaoFullPackedA2BEvaluatorRejectsEmptySetupAndInput(t *testing.T) {
	if evaluator, err := newGaoFullPackedA2BEvaluator(nil); err == nil || evaluator != nil {
		t.Fatalf("nil secret key: evaluator=%v err=%v", evaluator, err)
	}

	var evaluator *gaoFullPackedA2BEvaluator
	low, high, online, err := evaluator.EvaluateNew(nil)
	if err == nil || low != nil || high != nil || online != 0 {
		t.Fatalf("nil evaluator/input: low=%v high=%v online=%v err=%v", low, high, online, err)
	}
}

func TestAdjustGaoFullPackedToLevelMatchesOpenFHELevelDirection(t *testing.T) {
	parameters, err := newGaoN16FullPackedTransportParameters()
	if err != nil {
		t.Fatal(err)
	}
	params := parameters.BootstrappingParameters
	evaluator := ckks.NewEvaluator(params, nil)
	for _, test := range []struct {
		name        string
		sourceLevel int
		targetLevel int
	}{
		{name: "full input to Z2C", sourceLevel: 20, targetLevel: 4},
		{name: "LUT to retained core", sourceLevel: 5, targetLevel: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := ckks.NewCiphertext(params, 1, test.sourceLevel)
			input.Scale = params.DefaultScale()
			input.LogDimensions = ring.Dimensions{Rows: 0, Cols: gaoFullPackedLogSlots}
			before := input.CopyNew()
			got, err := adjustGaoFullPackedToLevel(evaluator, input, test.targetLevel, params.DefaultScale())
			if err != nil {
				t.Fatal(err)
			}
			if got == input || got.Level() != test.targetLevel || got.Degree() != 1 ||
				got.LogDimensions != input.LogDimensions || !got.Scale.Equal(params.DefaultScale()) {
				t.Fatalf("adjusted state: level=%d degree=%d dimensions=%+v scale=%v",
					got.Level(), got.Degree(), got.LogDimensions, got.Scale)
			}
			if !input.Equal(before) {
				t.Fatal("level adjustment mutated the reusable input")
			}
		})
	}

	if got, err := adjustGaoFullPackedToLevel(evaluator, nil, 4, rlwe.NewScale(1)); err == nil || got != nil {
		t.Fatalf("nil adjustment input: got=%v err=%v", got, err)
	}
}

func TestAdjustGaoFullPackedToLevelPreservesEncryptedValues(t *testing.T) {
	parameters, err := newGaoN16FullPackedTransportParameters()
	if err != nil {
		t.Fatal(err)
	}
	params := parameters.BootstrappingParameters
	secretKey := ckks.NewKeyGenerator(params).GenSecretKeyNew()
	encoder := ckks.NewEncoder(params)
	encryptor := ckks.NewEncryptor(params, secretKey)
	decryptor := ckks.NewDecryptor(params, secretKey)
	evaluator := ckks.NewEvaluator(params, nil)
	values := make([]complex128, gaoFullPackedSlots)
	for index := range values {
		values[index] = complex(float64((index%31)-15)/64, 0)
	}

	for _, test := range []struct {
		name        string
		sourceLevel int
		targetLevel int
	}{
		{name: "full input to Z2C", sourceLevel: 20, targetLevel: 4},
		{name: "LUT to retained core", sourceLevel: 5, targetLevel: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			plaintext := ckks.NewPlaintext(params, test.sourceLevel)
			plaintext.LogDimensions = ring.Dimensions{Rows: 0, Cols: gaoFullPackedLogSlots}
			plaintext.Scale = params.DefaultScale()
			if err := encoder.Encode(values, plaintext); err != nil {
				t.Fatal(err)
			}
			input, err := encryptor.EncryptNew(plaintext)
			if err != nil {
				t.Fatal(err)
			}
			adjusted, err := adjustGaoFullPackedToLevel(evaluator, input, test.targetLevel, params.DefaultScale())
			if err != nil {
				t.Fatal(err)
			}
			decoded := make([]complex128, len(values))
			if err := encoder.Decode(decryptor.DecryptNew(adjusted), decoded); err != nil {
				t.Fatal(err)
			}
			for index := range values {
				if delta := math.Abs(real(decoded[index]) - real(values[index])); delta > 1e-6 {
					t.Fatalf("slot %d changed by %.3g: got %.12g want %.12g", index, delta, real(decoded[index]), real(values[index]))
				}
				if imaginary := math.Abs(imag(decoded[index])); imaginary > 1e-6 {
					t.Fatalf("slot %d imaginary residual %.3g", index, imaginary)
				}
			}
		})
	}
}

func TestAdjustGaoFullPackedScaledToLevelFusesOneSixteenth(t *testing.T) {
	parameters, err := newGaoN16FullPackedTransportParameters()
	if err != nil {
		t.Fatal(err)
	}
	params := parameters.BootstrappingParameters
	secretKey := ckks.NewKeyGenerator(params).GenSecretKeyNew()
	encoder := ckks.NewEncoder(params)
	values := make([]complex128, gaoFullPackedSlots)
	for index := range values {
		values[index] = complex(float64((index%31)-15)/64, 0)
	}
	plaintext := ckks.NewPlaintext(params, 5)
	plaintext.LogDimensions = ring.Dimensions{Rows: 0, Cols: gaoFullPackedLogSlots}
	plaintext.Scale = params.DefaultScale()
	if err = encoder.Encode(values, plaintext); err != nil {
		t.Fatal(err)
	}
	input, err := ckks.NewEncryptor(params, secretKey).EncryptNew(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	adjusted, err := adjustGaoFullPackedScaledToLevel(
		ckks.NewEvaluator(params, nil), input, 3, params.DefaultScale(), 1, 16,
	)
	if err != nil {
		t.Fatal(err)
	}
	decoded := make([]complex128, len(values))
	if err = encoder.Decode(ckks.NewDecryptor(params, secretKey).DecryptNew(adjusted), decoded); err != nil {
		t.Fatal(err)
	}
	for index := range values {
		want := real(values[index]) / 16
		if delta := math.Abs(real(decoded[index]) - want); delta > 1e-6 {
			t.Fatalf("slot %d changed by %.3g: got %.12g want %.12g", index, delta, real(decoded[index]), want)
		}
	}
}
