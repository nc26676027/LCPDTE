package dft

import (
	"crypto/sha256"
	"fmt"
	"reflect"

	ckkslintrans "github.com/tuneinsight/lattigo/v6/circuits/ckks/lintrans"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// EvaluatorRuntimeIdentity is a value-only snapshot of a DFT evaluator's
// private CKKS parameters and both public evaluator targets.
type EvaluatorRuntimeIdentity struct {
	owner            uintptr
	parametersDigest [sha256.Size]byte
	ringQ            uintptr
	ringP            uintptr
	ckks             ckks.EvaluatorRuntimeIdentity
	linearTransform  ckkslintrans.EvaluatorRuntimeIdentity
}

// ParametersDigest returns a defensive value copy of the digest of the DFT
// evaluator's private CKKS parameters.
func (identity EvaluatorRuntimeIdentity) ParametersDigest() [sha256.Size]byte {
	return identity.parametersDigest
}

// RuntimeIdentitySnapshot returns a fail-closed, value-only snapshot of the
// DFT evaluator. The private parameters are marshaled and hashed, so numeric or
// structural drift is visible without returning the private value itself.
func (eval *Evaluator) RuntimeIdentitySnapshot() (EvaluatorRuntimeIdentity, error) {
	if eval == nil {
		return EvaluatorRuntimeIdentity{}, fmt.Errorf("DFT Evaluator is nil")
	}
	parameters, err := eval.parameters.MarshalBinary()
	if err != nil {
		return EvaluatorRuntimeIdentity{}, fmt.Errorf("cannot marshal private DFT parameters: %w", err)
	}
	if eval.parameters.RingQ() == nil {
		return EvaluatorRuntimeIdentity{}, fmt.Errorf("private DFT parameters RingQ is nil")
	}
	ckksIdentity, err := eval.Evaluator.RuntimeIdentitySnapshot()
	if err != nil {
		return EvaluatorRuntimeIdentity{}, fmt.Errorf("invalid DFT CKKS evaluator: %w", err)
	}
	linearTransform, err := eval.LTEvaluator.RuntimeIdentitySnapshot()
	if err != nil {
		return EvaluatorRuntimeIdentity{}, fmt.Errorf("invalid DFT linear-transformation evaluator: %w", err)
	}
	identity := EvaluatorRuntimeIdentity{
		owner:            reflect.ValueOf(eval).Pointer(),
		parametersDigest: sha256.Sum256(parameters),
		ringQ:            reflect.ValueOf(eval.parameters.RingQ()).Pointer(),
		ckks:             ckksIdentity,
		linearTransform:  linearTransform,
	}
	if ringP := eval.parameters.RingP(); ringP != nil {
		identity.ringP = reflect.ValueOf(ringP).Pointer()
	}
	return identity, nil
}

// Equal reports whether two snapshots describe the same private DFT
// configuration and evaluator object graph.
func (identity EvaluatorRuntimeIdentity) Equal(other EvaluatorRuntimeIdentity) bool {
	return reflect.DeepEqual(identity, other)
}
