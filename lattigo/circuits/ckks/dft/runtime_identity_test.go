package dft

import (
	"testing"

	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
)

func runtimeIdentityTestParameters(t *testing.T, logScale int) ckks.Parameters {
	t.Helper()
	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            4,
		LogQ:            []int{30, 30, 30},
		LogP:            []int{30, 30},
		LogDefaultScale: logScale,
	})
	if err != nil {
		t.Fatal(err)
	}
	return params
}

func TestEvaluatorRuntimeIdentitySnapshot(t *testing.T) {
	params := runtimeIdentityTestParameters(t, 25)
	target := ckks.NewEvaluator(params, nil)
	eval := NewEvaluator(params, target)
	before, err := eval.RuntimeIdentitySnapshot()
	if err != nil {
		t.Fatal(err)
	}

	eval.parameters = runtimeIdentityTestParameters(t, 24)
	afterPrivateDrift, err := eval.RuntimeIdentitySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if before.Equal(afterPrivateDrift) {
		t.Fatal("private DFT parameters drift was not detected")
	}
	if before.ParametersDigest() == afterPrivateDrift.ParametersDigest() {
		t.Fatal("private DFT parameters digest did not change")
	}

	eval = NewEvaluator(params, target)
	before, err = eval.RuntimeIdentitySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	foreign := NewEvaluator(params, ckks.NewEvaluator(params, nil))
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
		t.Fatal("nil DFT Evaluator did not fail closed")
	}
}
