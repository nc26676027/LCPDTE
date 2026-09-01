package treeeval

import (
	"fmt"
	"math"
)

// PlainValue is a non-cryptographic test value whose provenance behaves like a
// public scalar/ciphertext union. Scalar remains as a convenience view for the
// existing real-valued fixtures; Exact is authoritative for integer values.
type PlainValue struct {
	Scalar     float64      `json:"scalar"`
	Exact      PublicScalar `json:"exact"`
	Provenance ValueKind    `json:"provenance"`
}

func plainValue(value PublicScalar, provenance ValueKind) PlainValue {
	legacy := value.Real
	if unsigned, ok := value.UnsignedValue(); ok {
		legacy = float64(unsigned)
	}
	if signed, ok := value.SignedValue(); ok {
		legacy = float64(signed)
	}
	return PlainValue{Scalar: legacy, Exact: value, Provenance: provenance}
}

func Public(value float64) PlainValue {
	return PlainValue{Scalar: value, Exact: PublicScalar{Kind: ScalarReal, Real: value}, Provenance: ValuePublic}
}

func Opaque(value float64) PlainValue {
	return PlainValue{Scalar: value, Exact: PublicScalar{Kind: ScalarReal, Real: value}, Provenance: ValueOpaque}
}

func PublicUnsigned(value uint64, width int) (PlainValue, error) {
	scalar, err := UnsignedScalar(value, width)
	if err != nil {
		return PlainValue{}, err
	}
	return plainValue(scalar, ValuePublic), nil
}

func OpaqueUnsigned(value uint64, width int) (PlainValue, error) {
	scalar, err := UnsignedScalar(value, width)
	if err != nil {
		return PlainValue{}, err
	}
	return plainValue(scalar, ValueOpaque), nil
}

func PublicSigned(value int64, width int) (PlainValue, error) {
	scalar, err := SignedScalar(value, width)
	if err != nil {
		return PlainValue{}, err
	}
	return plainValue(scalar, ValuePublic), nil
}

func OpaqueSigned(value int64, width int) (PlainValue, error) {
	scalar, err := SignedScalar(value, width)
	if err != nil {
		return PlainValue{}, err
	}
	return plainValue(scalar, ValueOpaque), nil
}

func (v PlainValue) UnsignedValue() (uint64, bool) { return v.Exact.UnsignedValue() }
func (v PlainValue) SignedValue() (int64, bool)    { return v.Exact.SignedValue() }

// PlainBackend is an independent arithmetic oracle and provenance checker.
type PlainBackend struct{}

func (PlainBackend) PublicConstant(value PublicScalar) (PlainValue, error) {
	if err := value.Validate(); err != nil {
		return PlainValue{}, err
	}
	return plainValue(value, ValuePublic), nil
}

func (PlainBackend) Kind(value PlainValue) ValueKind {
	if err := validatePlain(value); err != nil {
		return ValueInvalid
	}
	return value.Provenance
}

func validatePlain(values ...PlainValue) error {
	for _, value := range values {
		if value.Provenance != ValuePublic && value.Provenance != ValueOpaque {
			return fmt.Errorf("invalid provenance %s", value.Provenance)
		}
		if err := value.Exact.Validate(); err != nil {
			return fmt.Errorf("invalid exact scalar: %w", err)
		}
		if value.Exact.Kind == ScalarReal && math.Float64bits(value.Scalar) != math.Float64bits(value.Exact.Real) {
			return fmt.Errorf("real scalar view diverges from exact payload")
		}
	}
	return nil
}

func resultProvenance(left, right PlainValue) ValueKind {
	if left.Provenance == ValueOpaque || right.Provenance == ValueOpaque {
		return ValueOpaque
	}
	return ValuePublic
}

func plainRealResult(value float64, left, right PlainValue) (PlainValue, error) {
	scalar, err := RealScalar(value)
	if err != nil {
		return PlainValue{}, err
	}
	return plainValue(scalar, resultProvenance(left, right)), nil
}

func plainIntegerResult(kind ScalarKind, width int, bits uint64, left, right PlainValue) (PlainValue, error) {
	scalar := PublicScalar{Kind: kind, Bits: bits & bitMask(width), BitWidth: width}
	if err := scalar.Validate(); err != nil {
		return PlainValue{}, err
	}
	return plainValue(scalar, resultProvenance(left, right)), nil
}

func matchingIntegers(left, right PublicScalar) bool {
	return left.Kind != ScalarReal && left.Kind == right.Kind && left.BitWidth == right.BitWidth
}

func integerAndBinaryReal(left, right PublicScalar) (integer PublicScalar, bit uint64, ok bool) {
	switch {
	case left.Kind != ScalarReal && right.Kind == ScalarReal && (right.Real == 0 || right.Real == 1):
		return left, uint64(right.Real), true
	case right.Kind != ScalarReal && left.Kind == ScalarReal && (left.Real == 0 || left.Real == 1):
		return right, uint64(left.Real), true
	default:
		return PublicScalar{}, 0, false
	}
}

func (PlainBackend) Add(left, right PlainValue) (PlainValue, error) {
	if err := validatePlain(left, right); err != nil {
		return PlainValue{}, err
	}
	if left.Exact.Kind == ScalarReal && right.Exact.Kind == ScalarReal {
		return plainRealResult(left.Exact.Real+right.Exact.Real, left, right)
	}
	if matchingIntegers(left.Exact, right.Exact) {
		return plainIntegerResult(left.Exact.Kind, left.Exact.BitWidth, left.Exact.Bits+right.Exact.Bits, left, right)
	}
	if integer, bit, ok := integerAndBinaryReal(left.Exact, right.Exact); ok && bit == 0 {
		return plainIntegerResult(integer.Kind, integer.BitWidth, integer.Bits, left, right)
	}
	return PlainValue{}, fmt.Errorf("addition requires matching numeric domains")
}

func (PlainBackend) Sub(left, right PlainValue) (PlainValue, error) {
	if err := validatePlain(left, right); err != nil {
		return PlainValue{}, err
	}
	if left.Exact.Kind == ScalarReal && right.Exact.Kind == ScalarReal {
		return plainRealResult(left.Exact.Real-right.Exact.Real, left, right)
	}
	if matchingIntegers(left.Exact, right.Exact) {
		return plainIntegerResult(left.Exact.Kind, left.Exact.BitWidth, left.Exact.Bits-right.Exact.Bits, left, right)
	}
	return PlainValue{}, fmt.Errorf("subtraction requires matching numeric domains")
}

func (PlainBackend) Mul(left, right PlainValue) (PlainValue, error) {
	if err := validatePlain(left, right); err != nil {
		return PlainValue{}, err
	}
	if left.Exact.Kind == ScalarReal && right.Exact.Kind == ScalarReal {
		return plainRealResult(left.Exact.Real*right.Exact.Real, left, right)
	}
	if matchingIntegers(left.Exact, right.Exact) {
		return plainIntegerResult(left.Exact.Kind, left.Exact.BitWidth, left.Exact.Bits*right.Exact.Bits, left, right)
	}
	if integer, bit, ok := integerAndBinaryReal(left.Exact, right.Exact); ok {
		return plainIntegerResult(integer.Kind, integer.BitWidth, integer.Bits*bit, left, right)
	}
	return PlainValue{}, fmt.Errorf("multiplication requires matching numeric domains or a binary real selector")
}

func (PlainBackend) CompareGE(left, right PlainValue, policy ComparisonPolicy) (PlainValue, error) {
	if err := validatePlain(left, right); err != nil {
		return PlainValue{}, err
	}
	if err := policy.Validate(); err != nil {
		return PlainValue{}, fmt.Errorf("invalid comparison policy: %w", err)
	}
	if err := policy.validateOperand(left.Exact, true); err != nil {
		return PlainValue{}, fmt.Errorf("left operand: %w", err)
	}
	if err := policy.validateOperand(right.Exact, false); err != nil {
		return PlainValue{}, fmt.Errorf("right operand: %w", err)
	}
	ge := false
	switch policy.Kind {
	case ScalarReal:
		ge = left.Exact.Real >= right.Exact.Real
	case ScalarUnsigned:
		ge = left.Exact.Bits >= right.Exact.Bits
	case ScalarSigned:
		leftValue, _ := left.Exact.SignedValue()
		rightValue, _ := right.Exact.SignedValue()
		ge = leftValue >= rightValue
	}
	bit := 0.0
	if ge {
		bit = 1
	}
	return plainRealResult(bit, left, right)
}
