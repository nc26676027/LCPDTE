// Package z2n implements the plaintext mathematics of the Gao--Zheng
// triangle representation of Z/(2^n). Its ring is
//
//	R_n = R[X]/(X^n-X+2),  tau = X-2,
//
// for n in {8, 16, 32, 64}. The package deliberately keeps ciphertext and
// CKKS concerns out of this layer so that encoding semantics can be audited
// and tested independently.
package z2n

import "fmt"

// WordBits is the exponent n in Z/(2^n) and the degree of X^n-X+2.
type WordBits uint

const (
	Word8  WordBits = 8
	Word16 WordBits = 16
	Word32 WordBits = 32
	Word64 WordBits = 64
)

const (
	// DefaultPrecision is used for all big.Float and bignum.Complex
	// calculations. It exceeds the 128-bit fixed-point precision of the
	// published root table, leaving guard bits for matrix products.
	DefaultPrecision uint = 256
	rootFractionBits uint = 128

	rootSourceCommit = "08f1eb87434e7be072cba889270a8400bbffc08e"
	rootSourcePath   = "src/core/include/math/z-constants.h"
)

// Metadata records the mathematical convention and provenance needed to
// reproduce a Ring. Root constants are exposed separately by RootConstants.
type Metadata struct {
	WordBits          WordBits
	PrecisionBits     uint
	PolynomialModulus string
	Tau               string
	RootCount         int
	RootFractionBits  uint
	RootSource        string
	RootSourceCommit  string
}

// Ring owns the precision and immutable transform data for one word size.
type Ring struct {
	bits      WordBits
	prec      uint
	transform *linearTransform
}

// New constructs a Ring at DefaultPrecision.
func New(bits WordBits) (*Ring, error) {
	return NewWithPrecision(bits, DefaultPrecision)
}

// NewWithPrecision constructs a Ring with at least 128 bits of precision.
func NewWithPrecision(bits WordBits, precision uint) (*Ring, error) {
	if !bits.supported() {
		return nil, fmt.Errorf("z2n: unsupported word size %d (want 8, 16, 32, or 64)", bits)
	}
	if precision < rootFractionBits {
		return nil, fmt.Errorf("z2n: precision %d is below the 128-bit root table", precision)
	}
	ring := &Ring{bits: bits, prec: precision}
	transform, err := ring.buildLinearTransform()
	if err != nil {
		return nil, err
	}
	ring.transform = transform
	return ring, nil
}

func (bits WordBits) supported() bool {
	switch bits {
	case Word8, Word16, Word32, Word64:
		return true
	default:
		return false
	}
}

// Metadata returns a value copy of the Ring's conventions and provenance.
func (r *Ring) Metadata() Metadata {
	return Metadata{
		WordBits:          r.bits,
		PrecisionBits:     r.prec,
		PolynomialModulus: "X^n-X+2",
		Tau:               "X-2",
		RootCount:         int(r.bits) / 2,
		RootFractionBits:  rootFractionBits,
		RootSource:        rootSourcePath,
		RootSourceCommit:  rootSourceCommit,
	}
}
