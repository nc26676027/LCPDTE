package ckksint

import (
	inteval "github.com/nc26676027/LCPDTE/integer/evaluator"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// The byte prevents Go from coalescing pointers to zero-sized allocation
// tokens, which would make independently keyed contexts appear identical.
type contextToken struct{ marker byte }

// Value is a packed arithmetic ciphertext in Z/(2^n). Its ciphertext and
// metadata are owned by the library and cannot be mutated through this type.
type Value struct {
	inner *inteval.Value
	owner *contextToken
}

// ShortValue is a packed Gao--Zheng short/binary operand. It is accepted only
// by MulShort and diagnostic decryption, preventing representation mix-ups.
type ShortValue struct {
	inner *inteval.Value
	owner *contextToken
}

// WordCount returns the number of packed modular words.
func (v *Value) WordCount() int {
	if v == nil || v.inner == nil {
		return 0
	}
	return v.inner.Metadata.WordCount
}

// Level returns the current CKKS modulus level, or -1 for a nil value.
func (v *Value) Level() int {
	if v == nil || v.inner == nil || v.inner.Ciphertext == nil {
		return -1
	}
	return v.inner.Ciphertext.Level()
}

// LattigoCiphertext returns a detached copy for explicit interoperability.
// Mutating the copy cannot change the library-owned value.
func (v *Value) LattigoCiphertext() *rlwe.Ciphertext {
	if v == nil || v.inner == nil || v.inner.Ciphertext == nil {
		return nil
	}
	return v.inner.Ciphertext.CopyNew()
}

// WordCount returns the number of packed short operands.
func (v *ShortValue) WordCount() int {
	if v == nil || v.inner == nil {
		return 0
	}
	return v.inner.Metadata.WordCount
}

// Level returns the current CKKS modulus level, or -1 for a nil value.
func (v *ShortValue) Level() int {
	if v == nil || v.inner == nil || v.inner.Ciphertext == nil {
		return -1
	}
	return v.inner.Ciphertext.Level()
}

// LattigoCiphertext returns a detached copy for explicit interoperability.
func (v *ShortValue) LattigoCiphertext() *rlwe.Ciphertext {
	if v == nil || v.inner == nil || v.inner.Ciphertext == nil {
		return nil
	}
	return v.inner.Ciphertext.CopyNew()
}
