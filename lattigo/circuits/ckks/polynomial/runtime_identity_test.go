package polynomial

import (
	"testing"

	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
	"github.com/nc26676027/LCPDTE/lattigo/utils/bignum"
)

func runtimeIdentityTestParameters(t *testing.T) ckks.Parameters {
	t.Helper()
	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
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

func TestEvaluatorRuntimeIdentitySnapshot(t *testing.T) {
	params := runtimeIdentityTestParameters(t)
	target := ckks.NewEvaluator(params, nil)
	eval := NewEvaluator(params, target)
	before, err := eval.RuntimeIdentitySnapshot()
	if err != nil {
		t.Fatal(err)
	}

	getter := eval.CoefficientGetter.(CoefficientGetter)
	getter.values[0] = bignum.ToComplex(1, params.EncodingPrecision())
	afterScratchWrite, err := eval.RuntimeIdentitySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !before.Equal(afterScratchWrite) {
		t.Fatal("CoefficientGetter scratch content changed the runtime identity")
	}

	eval.CoefficientGetter = CoefficientGetter{values: make([]*bignum.Complex, params.MaxSlots())}
	afterGetterReplacement, err := eval.RuntimeIdentitySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if before.Equal(afterGetterReplacement) {
		t.Fatal("CoefficientGetter private backing replacement was not detected")
	}

	foreign := NewEvaluator(params, ckks.NewEvaluator(params, nil))
	*eval = *foreign
	afterWholeReplacement, err := eval.RuntimeIdentitySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if before.Equal(afterWholeReplacement) {
		t.Fatal("same-parameter whole-value replacement was not detected")
	}

	var nilEval *Evaluator
	if _, err := nilEval.RuntimeIdentitySnapshot(); err == nil {
		t.Fatal("nil polynomial Evaluator did not fail closed")
	}
}

func TestEvaluatorRuntimeIdentitySnapshotHighPrecisionEvaluation(t *testing.T) {
	params := runtimeIdentityTestParameters(t)
	target := ckks.NewEvaluator(params, nil)
	target.Encoder = ckks.NewEncoder(params, 256)
	eval := NewEvaluator(params, target)
	before, err := eval.RuntimeIdentitySnapshot()
	if err != nil {
		t.Fatal(err)
	}

	input := ckks.NewCiphertext(params, 1, params.MaxLevel())
	poly := bignum.NewPolynomial(bignum.Monomial, []float64{1, 2}, nil)
	if _, err := eval.Evaluate(input, poly, params.DefaultScale()); err != nil {
		t.Fatal(err)
	}
	after, err := eval.RuntimeIdentitySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !before.Equal(after) {
		t.Fatal("normal high-precision polynomial evaluation changed the runtime identity")
	}
}
