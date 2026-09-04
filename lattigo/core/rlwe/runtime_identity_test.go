package rlwe

import (
	"testing"

	"github.com/nc26676027/LCPDTE/lattigo/ring"
	"github.com/nc26676027/LCPDTE/lattigo/ring/ringqp"
)

func runtimeIdentityTestParameters(t *testing.T) Parameters {
	t.Helper()
	params, err := NewParametersFromLiteral(ParametersLiteral{
		LogN:    4,
		LogQ:    []int{30, 30, 30},
		LogP:    []int{30, 30},
		NTTFlag: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return params
}

func TestEvaluatorRuntimeIdentitySnapshot(t *testing.T) {
	params := runtimeIdentityTestParameters(t)
	keyGenerator := NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	galEl := params.GaloisElement(1)
	keySet := NewMemEvaluationKeySet(nil, keyGenerator.GenGaloisKeyNew(galEl, secretKey))
	eval := NewEvaluator(params, keySet)
	before, err := eval.RuntimeIdentitySnapshot()
	if err != nil {
		t.Fatal(err)
	}

	input := NewCiphertext(params, 1, params.MaxLevel())
	output := NewCiphertext(params, 1, params.MaxLevel())
	if err := eval.Automorphism(input, galEl, output); err != nil {
		t.Fatal(err)
	}
	afterOperation, err := eval.RuntimeIdentitySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !before.Equal(afterOperation) {
		t.Fatal("normal evaluator operation changed the runtime identity")
	}

	foreign := NewEvaluator(params, keySet)
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

func TestEvaluatorBuffersRuntimeIdentityIncludesOuterBackings(t *testing.T) {
	params := runtimeIdentityTestParameters(t)
	buffers := NewEvaluatorBuffers(params)
	before, err := buffers.RuntimeIdentitySnapshot()
	if err != nil {
		t.Fatal(err)
	}

	buffers.BuffCt.Value = append([]ring.Poly(nil), buffers.BuffCt.Value...)
	afterCiphertextOuterReplacement, err := buffers.RuntimeIdentitySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if before.Equal(afterCiphertextOuterReplacement) {
		t.Fatal("BuffCt.Value outer backing replacement was not detected")
	}

	before, err = buffers.RuntimeIdentitySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	buffers.BuffDecompQP = append([]ringqp.Poly(nil), buffers.BuffDecompQP...)
	afterDecompOuterReplacement, err := buffers.RuntimeIdentitySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if before.Equal(afterDecompOuterReplacement) {
		t.Fatal("BuffDecompQP outer backing replacement was not detected")
	}

	var nilBuffers *EvaluatorBuffers
	if _, err := nilBuffers.RuntimeIdentitySnapshot(); err == nil {
		t.Fatal("nil EvaluatorBuffers did not fail closed")
	}
}
