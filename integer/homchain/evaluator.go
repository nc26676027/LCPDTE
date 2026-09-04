package homchain

import (
	"fmt"

	ckkslintrans "github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/lintrans"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
)

// CiphertextPair contains the recovered low/high real coefficient halves.
type CiphertextPair [2]*rlwe.Ciphertext

// Evaluator evaluates only Gao--Zheng's linear Z-To-C/C-To-Z foundation. It
// performs the CKKS rescale following each linear transform, but it does not
// claim or implement integer truncation, modulus raising, or bootstrapping.
type Evaluator struct {
	ckks   *ckks.Evaluator
	linear *ckkslintrans.Evaluator
}

func NewEvaluator(evaluator *ckks.Evaluator) *Evaluator {
	if evaluator == nil {
		return &Evaluator{}
	}
	return &Evaluator{ckks: evaluator, linear: ckkslintrans.NewEvaluator(evaluator)}
}

// ZToCNew applies V0 and V1 with one EvaluateManyNew call. Lattigo shares the
// ciphertext decomposition and, for BSGS transforms, the baby-step hoisted
// pre-rotations between both halves. Each half is then projected to 2*Re(.)
// and rescaled once.
func (e *Evaluator) ZToCNew(input *rlwe.Ciphertext, v CompiledPair) (CiphertextPair, error) {
	if e == nil || e.ckks == nil || e.linear == nil {
		return CiphertextPair{}, fmt.Errorf("homchain: nil evaluator")
	}
	if input == nil {
		return CiphertextPair{}, fmt.Errorf("homchain: nil Z-To-C input")
	}
	outputs, err := e.linear.EvaluateManyNew(input, []ckkslintrans.LinearTransformation{v.Low, v.High})
	if err != nil {
		return CiphertextPair{}, fmt.Errorf("homchain: evaluate V halves: %w", err)
	}
	var result CiphertextPair
	for i, output := range outputs {
		conjugate, err := e.ckks.ConjugateNew(output)
		if err != nil {
			return CiphertextPair{}, fmt.Errorf("homchain: conjugate V half %d: %w", i, err)
		}
		if err = e.ckks.Add(output, conjugate, output); err != nil {
			return CiphertextPair{}, fmt.Errorf("homchain: project V half %d to real: %w", i, err)
		}
		if err = e.ckks.Rescale(output, output); err != nil {
			return CiphertextPair{}, fmt.Errorf("homchain: rescale V half %d: %w", i, err)
		}
		result[i] = output
	}
	return result, nil
}

// CToZNew applies U0/U1 to different coefficient-half ciphertexts, adds the
// results, and performs one CKKS rescale. No bootstrap is performed.
func (e *Evaluator) CToZNew(input CiphertextPair, u CompiledPair) (*rlwe.Ciphertext, error) {
	if e == nil || e.ckks == nil || e.linear == nil {
		return nil, fmt.Errorf("homchain: nil evaluator")
	}
	if input[0] == nil || input[1] == nil {
		return nil, fmt.Errorf("homchain: nil C-To-Z input half")
	}
	low, err := e.linear.EvaluateNew(input[0], u.Low)
	if err != nil {
		return nil, fmt.Errorf("homchain: evaluate U0: %w", err)
	}
	high, err := e.linear.EvaluateNew(input[1], u.High)
	if err != nil {
		return nil, fmt.Errorf("homchain: evaluate U1: %w", err)
	}
	if err = e.ckks.Add(low, high, low); err != nil {
		return nil, fmt.Errorf("homchain: recombine U halves: %w", err)
	}
	if err = e.ckks.Rescale(low, low); err != nil {
		return nil, fmt.Errorf("homchain: rescale U recombination: %w", err)
	}
	return low, nil
}
