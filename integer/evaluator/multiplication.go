package evaluator

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// MultShort implements Gao--Zheng Definition 15. lhs carries
// tau^{-1}[m]_tau (Arithmetic), rhs carries [m']_tau (Short), and exactly one
// CKKS rescale converts their pointwise product back to Arithmetic mode.
func (c *Codec) MultShort(lhs, rhs *Value) (*Value, error) {
	if err := c.validateMultiplicationPair(lhs, rhs, Arithmetic, Short); err != nil {
		return nil, err
	}
	if err := c.requireMultiplicationResources(lhs.Metadata.Level, 1); err != nil {
		return nil, err
	}

	product, err := c.evaluator.MulRelinNew(lhs.Ciphertext, rhs.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("integer/evaluator: MultShort multiply/relinearize: %w", err)
	}
	if err := c.evaluator.Rescale(product, product); err != nil {
		return nil, fmt.Errorf("integer/evaluator: MultShort rescale: %w", err)
	}
	return c.finishMultiplicationResult(product, lhs.Metadata.WordCount, "MultShort")
}

// MultFull implements Gao--Zheng Definition 14. It first multiplies and
// relinearizes two Arithmetic ciphertexts and rescales once. It then
// multiplies by the repeated high-precision root-slot vector of tau=X-2 and
// rescales a second time. The result again carries tau^{-1}[mm']_tau.
func (c *Codec) MultFull(lhs, rhs *Value) (*Value, error) {
	if err := c.validateMultiplicationPair(lhs, rhs, Arithmetic, Arithmetic); err != nil {
		return nil, err
	}
	if err := c.requireMultiplicationResources(lhs.Metadata.Level, 2); err != nil {
		return nil, err
	}

	product, err := c.evaluator.MulRelinNew(lhs.Ciphertext, rhs.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("integer/evaluator: MultFull multiply/relinearize: %w", err)
	}
	if err := c.evaluator.Rescale(product, product); err != nil {
		return nil, fmt.Errorf("integer/evaluator: MultFull first rescale: %w", err)
	}

	tauPlaintext, err := c.encodeRepeatedTau(product)
	if err != nil {
		return nil, err
	}
	product, err = c.evaluator.MulNew(product, tauPlaintext)
	if err != nil {
		return nil, fmt.Errorf("integer/evaluator: MultFull multiply by tau: %w", err)
	}
	if err := c.evaluator.Rescale(product, product); err != nil {
		return nil, fmt.Errorf("integer/evaluator: MultFull second rescale: %w", err)
	}
	return c.finishMultiplicationResult(product, lhs.Metadata.WordCount, "MultFull")
}

func (c *Codec) validateMultiplicationPair(lhs, rhs *Value, lhsMode, rhsMode Mode) error {
	if err := c.Validate(lhs); err != nil {
		return fmt.Errorf("integer/evaluator: left operand: %w", err)
	}
	if err := c.Validate(rhs); err != nil {
		return fmt.Errorf("integer/evaluator: right operand: %w", err)
	}
	if lhs.Metadata.Parameters.Mode != lhsMode || rhs.Metadata.Parameters.Mode != rhsMode {
		return fmt.Errorf("integer/evaluator: operand modes are (%d,%d), want (%d,%d)", lhs.Metadata.Parameters.Mode, rhs.Metadata.Parameters.Mode, lhsMode, rhsMode)
	}
	if lhs.Metadata.WordCount != rhs.Metadata.WordCount || lhs.Metadata.SlotsUsed != rhs.Metadata.SlotsUsed {
		return fmt.Errorf("integer/evaluator: operand packing differs")
	}
	if lhs.Metadata.Level != rhs.Metadata.Level {
		return fmt.Errorf("integer/evaluator: operand levels differ: %d and %d", lhs.Metadata.Level, rhs.Metadata.Level)
	}
	if !lhs.Metadata.Scale.Equal(rhs.Metadata.Scale) {
		return fmt.Errorf("integer/evaluator: operand scales differ")
	}
	return nil
}

func (c *Codec) requireMultiplicationResources(level, rescales int) error {
	if c.parameters.CKKS.LevelsConsumedPerRescaling() != 1 {
		return fmt.Errorf("integer/evaluator: Gao multiplication requires one modulus level per rescale, parameters consume %d", c.parameters.CKKS.LevelsConsumedPerRescaling())
	}
	if level < rescales {
		return fmt.Errorf("integer/evaluator: multiplication needs %d levels, operand has level %d", rescales, level)
	}
	if c.evaluationKeys == nil {
		return fmt.Errorf("integer/evaluator: relinearization key is unavailable")
	}
	relinearizationKey, err := c.evaluationKeys.GetRelinearizationKey()
	if err != nil {
		return fmt.Errorf("integer/evaluator: load relinearization key: %w", err)
	}
	if relinearizationKey == nil {
		return fmt.Errorf("integer/evaluator: relinearization key is nil")
	}
	return nil
}

func (c *Codec) encodeRepeatedTau(value *rlwe.Ciphertext) (*rlwe.Plaintext, error) {
	tauSlots, err := c.ring.ToRootSlots(c.ring.Tau())
	if err != nil {
		return nil, fmt.Errorf("integer/evaluator: evaluate tau at roots: %w", err)
	}
	slots := c.zeroSlots()
	blockSize := c.parameters.SlotsPerWord()
	for wordIndex := 0; wordIndex < c.parameters.WordCapacity(); wordIndex++ {
		copy(slots[wordIndex*blockSize:(wordIndex+1)*blockSize], tauSlots)
	}

	plaintext := ckks.NewPlaintext(c.parameters.CKKS, value.Level())
	plaintext.Scale = value.Scale
	if err := c.encoder.Encode(slots, plaintext); err != nil {
		return nil, fmt.Errorf("integer/evaluator: encode repeated tau root slots: %w", err)
	}
	return plaintext, nil
}

func (c *Codec) finishMultiplicationResult(ciphertext *rlwe.Ciphertext, wordCount int, operation string) (*Value, error) {
	value := c.newValueWithMode(ciphertext, wordCount, Arithmetic)
	if err := c.Validate(value); err != nil {
		return nil, fmt.Errorf("integer/evaluator: %s result failed validation: %w", operation, err)
	}
	return value, nil
}
