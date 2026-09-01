package evaluator

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// Add returns a fresh ciphertext containing lhs+rhs modulo 2^n per word.
func (c *Codec) Add(lhs, rhs *Value) (*Value, error) {
	if err := c.validateBinaryOperands(lhs, rhs); err != nil {
		return nil, err
	}
	ciphertext, err := c.evaluator.AddNew(lhs.Ciphertext, rhs.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("integer/evaluator: homomorphic add: %w", err)
	}
	return c.finishLinearResult(ciphertext, lhs.Metadata.WordCount)
}

// Sub returns a fresh ciphertext containing lhs-rhs modulo 2^n per word.
func (c *Codec) Sub(lhs, rhs *Value) (*Value, error) {
	if err := c.validateBinaryOperands(lhs, rhs); err != nil {
		return nil, err
	}
	ciphertext, err := c.evaluator.SubNew(lhs.Ciphertext, rhs.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("integer/evaluator: homomorphic subtract: %w", err)
	}
	return c.finishLinearResult(ciphertext, lhs.Metadata.WordCount)
}

// Negate returns a fresh ciphertext containing -value modulo 2^n per word.
func (c *Codec) Negate(value *Value) (*Value, error) {
	if err := c.validateArithmetic(value); err != nil {
		return nil, err
	}
	ciphertext := value.Ciphertext.CopyNew()
	ringQ := c.parameters.CKKS.RingQ().AtLevel(ciphertext.Level())
	for i := range ciphertext.Value {
		ringQ.Neg(ciphertext.Value[i], ciphertext.Value[i])
	}
	return c.finishLinearResult(ciphertext, value.Metadata.WordCount)
}

// AddPublic adds one public word to each encrypted word position. The public
// vector must exactly match the encrypted word count; no implicit broadcast or
// truncation is performed.
func (c *Codec) AddPublic(value *Value, words []uint64) (*Value, error) {
	if err := c.validateArithmetic(value); err != nil {
		return nil, err
	}
	plaintext, err := c.encodePublic(value, words)
	if err != nil {
		return nil, err
	}
	ciphertext, err := c.evaluator.AddNew(value.Ciphertext, plaintext)
	if err != nil {
		return nil, fmt.Errorf("integer/evaluator: homomorphic public add: %w", err)
	}
	return c.finishLinearResult(ciphertext, value.Metadata.WordCount)
}

// SubPublic subtracts one public word from each encrypted word position.
func (c *Codec) SubPublic(value *Value, words []uint64) (*Value, error) {
	if err := c.validateArithmetic(value); err != nil {
		return nil, err
	}
	plaintext, err := c.encodePublic(value, words)
	if err != nil {
		return nil, err
	}
	ciphertext, err := c.evaluator.SubNew(value.Ciphertext, plaintext)
	if err != nil {
		return nil, fmt.Errorf("integer/evaluator: homomorphic public subtract: %w", err)
	}
	return c.finishLinearResult(ciphertext, value.Metadata.WordCount)
}

func (c *Codec) validateBinaryOperands(lhs, rhs *Value) error {
	if err := c.validateArithmetic(lhs); err != nil {
		return fmt.Errorf("integer/evaluator: left operand: %w", err)
	}
	if err := c.validateArithmetic(rhs); err != nil {
		return fmt.Errorf("integer/evaluator: right operand: %w", err)
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

func (c *Codec) validateArithmetic(value *Value) error {
	if err := c.Validate(value); err != nil {
		return err
	}
	if value.Metadata.Parameters.Mode != Arithmetic {
		return fmt.Errorf("integer/evaluator: operand mode %d is not Arithmetic", value.Metadata.Parameters.Mode)
	}
	return nil
}

func (c *Codec) encodePublic(value *Value, words []uint64) (*rlwe.Plaintext, error) {
	if len(words) != value.Metadata.WordCount {
		return nil, fmt.Errorf("integer/evaluator: got %d public words, want %d", len(words), value.Metadata.WordCount)
	}
	for i, word := range words {
		if err := c.validateRawWord(word); err != nil {
			return nil, fmt.Errorf("integer/evaluator: public word %d: %w", i, err)
		}
	}
	slots := c.zeroSlots()
	blockSize := value.Metadata.SlotsPerWord
	for wordIndex, word := range words {
		block := c.ring.ArithmeticRootSlots(word)
		copy(slots[wordIndex*blockSize:(wordIndex+1)*blockSize], block)
	}
	plaintext := ckks.NewPlaintext(c.parameters.CKKS, value.Metadata.Level)
	*plaintext.MetaData = *value.Ciphertext.MetaData
	if err := c.encoder.Encode(slots, plaintext); err != nil {
		return nil, fmt.Errorf("integer/evaluator: encode public root slots: %w", err)
	}
	return plaintext, nil
}

func (c *Codec) finishLinearResult(ciphertext *rlwe.Ciphertext, wordCount int) (*Value, error) {
	value := c.newValue(ciphertext, wordCount)
	if err := c.Validate(value); err != nil {
		return nil, fmt.Errorf("integer/evaluator: linear result failed validation: %w", err)
	}
	return value, nil
}
