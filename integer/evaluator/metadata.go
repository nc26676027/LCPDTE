// Package evaluator binds the high-precision z2n triangle representation to
// encrypted CKKS slots. It implements Gao--Zheng arithmetic and short
// representations; it does not claim refreshing, bootstrapping, or A2B
// support.
package evaluator

import (
	"fmt"
	"math/big"

	"github.com/nc26676027/LCPDTE/integer/z2n"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
)

// Mode identifies the semantic representation carried by a Value.
type Mode uint8

const (
	// Arithmetic is Gao--Zheng's tau^{-1}[m]_tau representation.
	Arithmetic Mode = iota + 1
	// Short is Gao--Zheng's binary [m]_tau representation (Definitions 14--15).
	// It is intended as the right operand of MultShort, not as an arithmetic
	// value for Add, Sub, or Negate.
	Short
)

// Binary is an explanatory alias for Short: both names mean [m]_tau.
const Binary = Short

// Signedness records how a residue should be interpreted for bound checks.
// Homomorphic arithmetic itself always wraps modulo 2^n.
type Signedness uint8

const (
	Unsigned Signedness = iota + 1
	TwosComplement
)

// SecurityBoundary makes the status of a parameter set explicit. This package
// validates structure, not an RLWE security estimate.
type SecurityBoundary uint8

const (
	// DemoOnly marks fast functional-test parameters that make no security claim.
	DemoOnly SecurityBoundary = iota + 1
	// ExternallyValidated means the caller separately validated the complete
	// parameter tuple. The package does not perform or attest that validation.
	ExternallyValidated
)

// Bounds is an immutable-by-value decimal interval. Strings avoid both uint64
// overflow at n=64 and pointer aliasing through big.Int fields.
type Bounds struct {
	MinInclusive string
	MaxInclusive string
}

// NewBounds constructs a decimal interval from caller-owned integers.
func NewBounds(minimum, maximum *big.Int) (Bounds, error) {
	if minimum == nil || maximum == nil {
		return Bounds{}, fmt.Errorf("integer/evaluator: bounds endpoints cannot be nil")
	}
	if minimum.Cmp(maximum) > 0 {
		return Bounds{}, fmt.Errorf("integer/evaluator: minimum %s exceeds maximum %s", minimum, maximum)
	}
	return Bounds{MinInclusive: minimum.String(), MaxInclusive: maximum.String()}, nil
}

// FullBounds returns the complete representable domain for one word.
func FullBounds(bits z2n.WordBits, signedness Signedness) (Bounds, error) {
	if !supportedWordBits(bits) {
		return Bounds{}, fmt.Errorf("integer/evaluator: unsupported word size %d", bits)
	}
	n := uint(bits)
	switch signedness {
	case Unsigned:
		maximum := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), n), big.NewInt(1))
		return NewBounds(big.NewInt(0), maximum)
	case TwosComplement:
		half := new(big.Int).Lsh(big.NewInt(1), n-1)
		minimum := new(big.Int).Neg(new(big.Int).Set(half))
		maximum := new(big.Int).Sub(new(big.Int).Set(half), big.NewInt(1))
		return NewBounds(minimum, maximum)
	default:
		return Bounds{}, fmt.Errorf("integer/evaluator: unsupported signedness %d", signedness)
	}
}

// Parameters fixes both the CKKS container and the integer semantics.
type Parameters struct {
	CKKS             ckks.Parameters
	WordBits         z2n.WordBits
	Mode             Mode
	Signedness       Signedness
	Bounds           Bounds
	InitialLevel     int
	EncoderPrecision uint
	SecurityBoundary SecurityBoundary
}

// Validate rejects every unspecified or internally inconsistent field.
func (p Parameters) Validate() error {
	if p.Mode != Arithmetic && p.Mode != Short {
		return fmt.Errorf("integer/evaluator: mode must be Arithmetic or Short, got %d", p.Mode)
	}
	if p.Signedness != Unsigned && p.Signedness != TwosComplement {
		return fmt.Errorf("integer/evaluator: signedness is unspecified or unsupported: %d", p.Signedness)
	}
	if !supportedWordBits(p.WordBits) {
		return fmt.Errorf("integer/evaluator: unsupported word size %d", p.WordBits)
	}
	if p.CKKS.QCount() == 0 || p.CKKS.N() == 0 {
		return fmt.Errorf("integer/evaluator: CKKS parameters are empty")
	}
	if p.InitialLevel < 0 || p.InitialLevel > p.CKKS.MaxLevel() {
		return fmt.Errorf("integer/evaluator: initial level %d outside [0,%d]", p.InitialLevel, p.CKKS.MaxLevel())
	}
	if p.EncoderPrecision < 128 {
		return fmt.Errorf("integer/evaluator: encoder precision %d is below 128 bits", p.EncoderPrecision)
	}
	if p.SecurityBoundary != DemoOnly && p.SecurityBoundary != ExternallyValidated {
		return fmt.Errorf("integer/evaluator: security boundary is unspecified or unsupported: %d", p.SecurityBoundary)
	}
	if err := p.Bounds.validate(p.WordBits, p.Signedness); err != nil {
		return err
	}
	if p.WordCapacity() == 0 {
		return fmt.Errorf("integer/evaluator: CKKS slot count %d cannot hold one %d-bit word", p.CKKS.MaxSlots(), p.WordBits)
	}
	return nil
}

// SlotsPerWord is n/2 because one arithmetic word uses one root from each
// complex-conjugate pair of X^n-X+2.
func (p Parameters) SlotsPerWord() int {
	if !supportedWordBits(p.WordBits) {
		return 0
	}
	return int(p.WordBits) / 2
}

// WordCapacity returns floor(MaxSlots/(n/2)).
func (p Parameters) WordCapacity() int {
	if slots := p.SlotsPerWord(); slots != 0 {
		return p.CKKS.MaxSlots() / slots
	}
	return 0
}

func (p Parameters) equal(other Parameters) bool {
	return p.CKKS.Equal(&other.CKKS) &&
		p.WordBits == other.WordBits &&
		p.Mode == other.Mode &&
		p.Signedness == other.Signedness &&
		p.Bounds == other.Bounds &&
		p.InitialLevel == other.InitialLevel &&
		p.EncoderPrecision == other.EncoderPrecision &&
		p.SecurityBoundary == other.SecurityBoundary
}

func (p Parameters) equalExceptMode(other Parameters) bool {
	p.Mode = other.Mode
	return p.equal(other)
}

func (b Bounds) validate(bits z2n.WordBits, signedness Signedness) error {
	minimum, maximum, err := b.endpoints()
	if err != nil {
		return err
	}
	if minimum.Cmp(maximum) > 0 {
		return fmt.Errorf("integer/evaluator: minimum %s exceeds maximum %s", minimum, maximum)
	}
	domain, err := FullBounds(bits, signedness)
	if err != nil {
		return err
	}
	domainMinimum, domainMaximum, _ := domain.endpoints()
	if minimum.Cmp(domainMinimum) < 0 || maximum.Cmp(domainMaximum) > 0 {
		return fmt.Errorf("integer/evaluator: bounds [%s,%s] exceed %d-bit domain [%s,%s]", minimum, maximum, bits, domainMinimum, domainMaximum)
	}
	return nil
}

func (b Bounds) endpoints() (minimum, maximum *big.Int, err error) {
	if b.MinInclusive == "" || b.MaxInclusive == "" {
		return nil, nil, fmt.Errorf("integer/evaluator: bounds are unspecified")
	}
	minimum, ok := new(big.Int).SetString(b.MinInclusive, 10)
	if !ok {
		return nil, nil, fmt.Errorf("integer/evaluator: invalid minimum bound %q", b.MinInclusive)
	}
	maximum, ok = new(big.Int).SetString(b.MaxInclusive, 10)
	if !ok {
		return nil, nil, fmt.Errorf("integer/evaluator: invalid maximum bound %q", b.MaxInclusive)
	}
	return minimum, maximum, nil
}

func (b Bounds) containsRaw(word uint64, bits z2n.WordBits, signedness Signedness) bool {
	minimum, maximum, err := b.endpoints()
	if err != nil {
		return false
	}
	value := new(big.Int).SetUint64(word)
	if signedness == TwosComplement && word&(uint64(1)<<(uint(bits)-1)) != 0 {
		value.Sub(value, new(big.Int).Lsh(big.NewInt(1), uint(bits)))
	}
	return value.Cmp(minimum) >= 0 && value.Cmp(maximum) <= 0
}

func supportedWordBits(bits z2n.WordBits) bool {
	switch bits {
	case z2n.Word8, z2n.Word16, z2n.Word32, z2n.Word64:
		return true
	default:
		return false
	}
}
