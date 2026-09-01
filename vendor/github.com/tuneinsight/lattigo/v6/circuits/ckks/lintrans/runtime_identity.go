package lintrans

import (
	"fmt"
	"reflect"

	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// EvaluatorRuntimeIdentity is a value-only snapshot of the CKKS linear-
// transformation evaluator's embedded common evaluator binding.
type EvaluatorRuntimeIdentity struct {
	owner           uintptr
	commonEvaluator uintptr
	dynamicType     string
	target          uintptr
	ckks            ckks.EvaluatorRuntimeIdentity
}

// RuntimeIdentitySnapshot returns a fail-closed snapshot of the embedded
// common evaluator and its concrete CKKS target. Custom target implementations
// are rejected because their private runtime graph cannot be inspected here.
func (eval *Evaluator) RuntimeIdentitySnapshot() (EvaluatorRuntimeIdentity, error) {
	if eval == nil {
		return EvaluatorRuntimeIdentity{}, fmt.Errorf("CKKS linear-transformation Evaluator is nil")
	}
	target, ok := eval.Evaluator.Evaluator.(*ckks.Evaluator)
	if !ok || target == nil {
		return EvaluatorRuntimeIdentity{}, fmt.Errorf("linear-transformation evaluator target must be a non-nil *ckks.Evaluator, got %T", eval.Evaluator.Evaluator)
	}
	ckksIdentity, err := target.RuntimeIdentitySnapshot()
	if err != nil {
		return EvaluatorRuntimeIdentity{}, fmt.Errorf("invalid CKKS evaluator target: %w", err)
	}
	return EvaluatorRuntimeIdentity{
		owner:           reflect.ValueOf(eval).Pointer(),
		commonEvaluator: reflect.ValueOf(&eval.Evaluator).Pointer(),
		dynamicType:     reflect.TypeOf(target).String(),
		target:          reflect.ValueOf(target).Pointer(),
		ckks:            ckksIdentity,
	}, nil
}

// Equal reports whether two snapshots describe the same common-evaluator
// binding and concrete CKKS evaluator object graph.
func (identity EvaluatorRuntimeIdentity) Equal(other EvaluatorRuntimeIdentity) bool {
	return reflect.DeepEqual(identity, other)
}
