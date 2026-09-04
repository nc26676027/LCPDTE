package lintrans

import (
	"testing"

	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
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
	eval := NewEvaluator(target)
	before, err := eval.RuntimeIdentitySnapshot()
	if err != nil {
		t.Fatal(err)
	}

	foreignTarget := ckks.NewEvaluator(params, nil)
	*eval = *NewEvaluator(foreignTarget)
	afterReplacement, err := eval.RuntimeIdentitySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if before.Equal(afterReplacement) {
		t.Fatal("embedded common evaluator target replacement was not detected")
	}

	var nilEval *Evaluator
	if _, err := nilEval.RuntimeIdentitySnapshot(); err == nil {
		t.Fatal("nil linear-transformation Evaluator did not fail closed")
	}
}
