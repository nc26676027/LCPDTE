package ckksint

import (
	"math/big"

	inteval "github.com/nc26676027/LCPDTE/integer/evaluator"
	"github.com/nc26676027/LCPDTE/integer/z2n"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// WordBits is the width of each modular integer word.
type WordBits = z2n.WordBits

const (
	Word8  = z2n.Word8
	Word16 = z2n.Word16
	Word32 = z2n.Word32
	Word64 = z2n.Word64
)

// Signedness controls input bounds and signed decoding. Arithmetic always
// wraps modulo 2^WordBits.
type Signedness = inteval.Signedness

const (
	Unsigned       = inteval.Unsigned
	TwosComplement = inteval.TwosComplement
)

// SecurityBoundary states who is responsible for validating the complete
// cryptographic parameter tuple.
type SecurityBoundary = inteval.SecurityBoundary

const (
	// DemoOnly marks fast functional parameters that carry no security claim.
	DemoOnly = inteval.DemoOnly
	// ExternallyValidated means the caller validated the complete tuple outside
	// this package. It is a declaration, not an attestation by ckksint.
	ExternallyValidated = inteval.ExternallyValidated
)

// Bounds is the inclusive application domain for one word. Decimal strings
// preserve the full unsigned 64-bit range without pointer aliasing.
type Bounds struct {
	MinInclusive string
	MaxInclusive string
}

// NewBounds creates an inclusive word interval.
func NewBounds(minimum, maximum *big.Int) (Bounds, error) {
	bounds, err := inteval.NewBounds(minimum, maximum)
	return boundsFromEvaluator(bounds), err
}

// FullBounds returns the entire domain for a word width and signedness.
func FullBounds(bits WordBits, signedness Signedness) (Bounds, error) {
	bounds, err := inteval.FullBounds(bits, signedness)
	return boundsFromEvaluator(bounds), err
}

// Parameters fixes the CKKS container and the packed modular-integer
// interpretation. Mode is intentionally absent: a Context always uses the
// arithmetic representation and exposes short operands through ShortValue.
type Parameters struct {
	CKKS             ckks.Parameters
	WordBits         WordBits
	Signedness       Signedness
	Bounds           Bounds
	InitialLevel     int
	EncoderPrecision uint
	SecurityBoundary SecurityBoundary
}

// Validate checks that every semantic and CKKS field is explicit and
// internally consistent.
func (p Parameters) Validate() error { return p.evaluator().Validate() }

// SlotsPerWord returns the number of complex CKKS slots used by each word.
func (p Parameters) SlotsPerWord() int { return p.evaluator().SlotsPerWord() }

// WordCapacity returns the maximum packed word count.
func (p Parameters) WordCapacity() int { return p.evaluator().WordCapacity() }

// KeyMaterial supplies the client and evaluator keys for a Context. The
// encryption or secret key may be omitted for server-only contexts; methods
// that need an absent key return an error.
type KeyMaterial struct {
	EncryptionKey  rlwe.EncryptionKey
	SecretKey      *rlwe.SecretKey
	EvaluationKeys rlwe.EvaluationKeySet
}

// DemoParameters selects the word semantics for NewDemo. The CKKS tuple is
// fixed by the library and always marked DemoOnly.
type DemoParameters struct {
	WordBits   WordBits
	Signedness Signedness
}

func (p Parameters) evaluator() inteval.Parameters {
	return inteval.Parameters{
		CKKS:             p.CKKS,
		WordBits:         p.WordBits,
		Mode:             inteval.Arithmetic,
		Signedness:       p.Signedness,
		Bounds:           inteval.Bounds(p.Bounds),
		InitialLevel:     p.InitialLevel,
		EncoderPrecision: p.EncoderPrecision,
		SecurityBoundary: p.SecurityBoundary,
	}
}

func parametersFromEvaluator(p inteval.Parameters) Parameters {
	return Parameters{
		CKKS:             p.CKKS,
		WordBits:         p.WordBits,
		Signedness:       p.Signedness,
		Bounds:           boundsFromEvaluator(p.Bounds),
		InitialLevel:     p.InitialLevel,
		EncoderPrecision: p.EncoderPrecision,
		SecurityBoundary: p.SecurityBoundary,
	}
}

func boundsFromEvaluator(bounds inteval.Bounds) Bounds {
	return Bounds{MinInclusive: bounds.MinInclusive, MaxInclusive: bounds.MaxInclusive}
}
