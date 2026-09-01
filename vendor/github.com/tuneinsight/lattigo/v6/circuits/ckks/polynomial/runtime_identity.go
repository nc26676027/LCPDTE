package polynomial

import (
	"crypto/sha256"
	"fmt"
	"reflect"

	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

type sliceRuntimeIdentity struct {
	data uintptr
	len  int
	cap  int
}

func runtimeSliceIdentity[T any](values []T) sliceRuntimeIdentity {
	return sliceRuntimeIdentity{data: reflect.ValueOf(values).Pointer(), len: len(values), cap: cap(values)}
}

type coefficientGetterRuntimeIdentity struct {
	dynamicType string
	target      uintptr
	values      sliceRuntimeIdentity
}

func snapshotCoefficientGetter(value any, expectedLength int) (coefficientGetterRuntimeIdentity, error) {
	var getter CoefficientGetter
	identity := coefficientGetterRuntimeIdentity{}
	switch value := value.(type) {
	case CoefficientGetter:
		getter = value
		identity.dynamicType = "polynomial.CoefficientGetter"
	case *CoefficientGetter:
		if value == nil {
			return coefficientGetterRuntimeIdentity{}, fmt.Errorf("CoefficientGetter contains a typed nil *CoefficientGetter")
		}
		getter = *value
		identity.dynamicType = "*polynomial.CoefficientGetter"
		identity.target = reflect.ValueOf(value).Pointer()
	default:
		return coefficientGetterRuntimeIdentity{}, fmt.Errorf("CoefficientGetter must be polynomial.CoefficientGetter or *polynomial.CoefficientGetter, got %T", value)
	}
	if len(getter.values) != expectedLength {
		return coefficientGetterRuntimeIdentity{}, fmt.Errorf("CoefficientGetter values length is %d, want %d", len(getter.values), expectedLength)
	}
	identity.values = runtimeSliceIdentity(getter.values)
	return identity, nil
}

// EvaluatorRuntimeIdentity is a value-only snapshot of a CKKS polynomial
// evaluator's parameters, common evaluator target and CoefficientGetter backing.
type EvaluatorRuntimeIdentity struct {
	owner             uintptr
	parametersDigest  [sha256.Size]byte
	ringQ             uintptr
	ringP             uintptr
	commonEvaluator   uintptr
	targetDynamicType string
	target            uintptr
	ckks              ckks.EvaluatorRuntimeIdentity
	coefficientGetter coefficientGetterRuntimeIdentity
}

// RuntimeIdentitySnapshot returns a fail-closed, value-only snapshot of the
// polynomial evaluator's actual runtime dependencies. Scratch coefficient
// values are excluded while the private values-slice backing is retained as an
// opaque identity descriptor.
func (eval *Evaluator) RuntimeIdentitySnapshot() (EvaluatorRuntimeIdentity, error) {
	if eval == nil {
		return EvaluatorRuntimeIdentity{}, fmt.Errorf("CKKS polynomial Evaluator is nil")
	}
	parameters, err := eval.Parameters.MarshalBinary()
	if err != nil {
		return EvaluatorRuntimeIdentity{}, fmt.Errorf("cannot marshal CKKS polynomial parameters: %w", err)
	}
	target, ok := eval.Evaluator.Evaluator.(*ckks.Evaluator)
	if !ok || target == nil {
		return EvaluatorRuntimeIdentity{}, fmt.Errorf("polynomial evaluator target must be a non-nil *ckks.Evaluator, got %T", eval.Evaluator.Evaluator)
	}
	ckksIdentity, err := target.RuntimeIdentitySnapshot()
	if err != nil {
		return EvaluatorRuntimeIdentity{}, fmt.Errorf("invalid CKKS evaluator target: %w", err)
	}
	getter, err := snapshotCoefficientGetter(eval.Evaluator.CoefficientGetter, eval.Parameters.MaxSlots())
	if err != nil {
		return EvaluatorRuntimeIdentity{}, err
	}
	if eval.Parameters.RingQ() == nil {
		return EvaluatorRuntimeIdentity{}, fmt.Errorf("polynomial parameters RingQ is nil")
	}
	identity := EvaluatorRuntimeIdentity{
		owner:             reflect.ValueOf(eval).Pointer(),
		parametersDigest:  sha256.Sum256(parameters),
		ringQ:             reflect.ValueOf(eval.Parameters.RingQ()).Pointer(),
		commonEvaluator:   reflect.ValueOf(&eval.Evaluator).Pointer(),
		targetDynamicType: reflect.TypeOf(target).String(),
		target:            reflect.ValueOf(target).Pointer(),
		ckks:              ckksIdentity,
		coefficientGetter: getter,
	}
	if ringP := eval.Parameters.RingP(); ringP != nil {
		identity.ringP = reflect.ValueOf(ringP).Pointer()
	}
	return identity, nil
}

// Equal reports whether two snapshots describe the same polynomial evaluator
// binding, immutable parameters and private CoefficientGetter backing topology.
func (identity EvaluatorRuntimeIdentity) Equal(other EvaluatorRuntimeIdentity) bool {
	return reflect.DeepEqual(identity, other)
}
