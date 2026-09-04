// Modified by the LCPDTE project for local module integration and, where applicable,
// runtime instrumentation. See lattigo/NOTICE for attribution and modification details.

package ckks

import (
	"math/big"
	"testing"

	"github.com/nc26676027/LCPDTE/lattigo/utils/bignum"
)

func runtimeIdentityTestParameters(t *testing.T) Parameters {
	t.Helper()
	params, err := NewParametersFromLiteral(ParametersLiteral{
		LogN:            4,
		LogQ:            []int{30, 30, 30},
		LogP:            []int{30, 30},
		LogDefaultScale: 25,
	})
	if err != nil {
		t.Fatal(err)
	}
	return params
}

func TestEncoderRuntimeIdentitySnapshot(t *testing.T) {
	params := runtimeIdentityTestParameters(t)
	encoder := NewEncoder(params)
	before, err := encoder.RuntimeIdentitySnapshot()
	if err != nil {
		t.Fatal(err)
	}

	plaintext := NewPlaintext(params, params.MaxLevel())
	if err := encoder.Encode([]float64{1, 2, 3, 4}, plaintext); err != nil {
		t.Fatal(err)
	}
	afterEncode, err := encoder.RuntimeIdentitySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !before.Equal(afterEncode) {
		t.Fatal("normal Encode scratch mutation changed the runtime identity")
	}

	coefficientPlaintext := NewPlaintext(params, params.MaxLevel())
	coefficientPlaintext.IsBatched = false
	if err := encoder.Encode([]float64{1, 2, 3, 4}, coefficientPlaintext); err != nil {
		t.Fatal(err)
	}
	beforeDecode, err := encoder.RuntimeIdentitySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	decoded := make([]float64, params.N())
	if err := encoder.Decode(coefficientPlaintext, decoded); err != nil {
		t.Fatal(err)
	}
	afterDecode, err := encoder.RuntimeIdentitySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !beforeDecode.Equal(afterDecode) {
		t.Fatal("normal Decode scratch mutation changed the runtime identity")
	}

	encoder.bigintCoeffs = make([]*big.Int, len(encoder.bigintCoeffs))
	afterScratchReplacement, err := encoder.RuntimeIdentitySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if before.Equal(afterScratchReplacement) {
		t.Fatal("private Encoder scratch replacement was not detected")
	}

	var nilEncoder *Encoder
	if _, err := nilEncoder.RuntimeIdentitySnapshot(); err == nil {
		t.Fatal("nil Encoder did not fail closed")
	}
}

func TestEncoderRuntimeIdentitySnapshotHighPrecisionEncode(t *testing.T) {
	params := runtimeIdentityTestParameters(t)
	encoder := NewEncoder(params, 256)
	before, err := encoder.RuntimeIdentitySnapshot()
	if err != nil {
		t.Fatal(err)
	}

	values := make([]*bignum.Complex, params.MaxSlots())
	for i := range values {
		values[i] = &bignum.Complex{
			new(big.Float).SetPrec(256).SetInt64(int64(i + 1)),
			new(big.Float).SetPrec(256),
		}
	}
	plaintext := NewPlaintext(params, params.MaxLevel())
	if err := encoder.Encode(values, plaintext); err != nil {
		t.Fatal(err)
	}
	afterEncode, err := encoder.RuntimeIdentitySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !before.Equal(afterEncode) {
		t.Fatal("normal high-precision Encode scratch permutation changed the runtime identity")
	}

	scratch := encoder.buffCmplx.([]*bignum.Complex)
	scratch[0] = &bignum.Complex{
		new(big.Float).SetPrec(256),
		new(big.Float).SetPrec(256),
	}
	afterElementReplacement, err := encoder.RuntimeIdentitySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if afterEncode.Equal(afterElementReplacement) {
		t.Fatal("high-precision scratch element replacement was not detected")
	}

	immutableEncoder := NewEncoder(params, 256)
	beforeRootMutation, err := immutableEncoder.RuntimeIdentitySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	root := immutableEncoder.roots.([]*bignum.Complex)[0][0]
	root.Add(root, new(big.Float).SetPrec(256).SetInt64(1))
	afterRootMutation, err := immutableEncoder.RuntimeIdentitySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if beforeRootMutation.Equal(afterRootMutation) {
		t.Fatal("high-precision immutable root value mutation was not detected")
	}
}

func TestEvaluatorRuntimeIdentitySnapshot(t *testing.T) {
	params := runtimeIdentityTestParameters(t)
	eval := NewEvaluator(params, nil)
	before, err := eval.RuntimeIdentitySnapshot()
	if err != nil {
		t.Fatal(err)
	}

	input := NewCiphertext(params, 1, params.MaxLevel())
	output := NewCiphertext(params, 1, params.MaxLevel())
	if err := eval.Add(input, []float64{1, 2, 3, 4}, output); err != nil {
		t.Fatal(err)
	}
	afterOperation, err := eval.RuntimeIdentitySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !before.Equal(afterOperation) {
		t.Fatal("normal evaluator operation changed the runtime identity")
	}

	foreign := NewEvaluator(params, nil)
	*eval = *foreign
	afterReplacement, err := eval.RuntimeIdentitySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if before.Equal(afterReplacement) {
		t.Fatal("same-parameter whole-value replacement was not detected")
	}

	var nilEval *Evaluator
	if _, err := nilEval.RuntimeIdentitySnapshot(); err == nil {
		t.Fatal("nil Evaluator did not fail closed")
	}
}
