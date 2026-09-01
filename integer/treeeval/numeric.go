package treeeval

import (
	"fmt"
	"math"
	"math/big"
	"reflect"
)

// ScalarKind preserves an integer constant's exact bit pattern instead of
// routing every server-public value through float64.
type ScalarKind string

const (
	ScalarReal     ScalarKind = "real"
	ScalarUnsigned ScalarKind = "unsigned_integer"
	ScalarSigned   ScalarKind = "twos_complement_signed_integer"
)

// PublicScalar is the backend-neutral representation of a server-public
// constant. Integer Bits are the canonical low BitWidth bits.
type PublicScalar struct {
	Kind     ScalarKind `json:"kind"`
	Real     float64    `json:"real,omitempty"`
	Bits     uint64     `json:"bits,omitempty"`
	BitWidth int        `json:"bit_width,omitempty"`
}

func bitMask(width int) uint64 {
	if width == 64 {
		return math.MaxUint64
	}
	return (uint64(1) << width) - 1
}

func RealScalar(value float64) (PublicScalar, error) {
	scalar := PublicScalar{Kind: ScalarReal, Real: value}
	if err := scalar.Validate(); err != nil {
		return PublicScalar{}, err
	}
	return scalar, nil
}

func UnsignedScalar(value uint64, width int) (PublicScalar, error) {
	if width < 1 || width > 64 {
		return PublicScalar{}, fmt.Errorf("bit width must be in [1,64]: %d", width)
	}
	if value > bitMask(width) {
		return PublicScalar{}, fmt.Errorf("unsigned value %d does not fit %d bits", value, width)
	}
	return PublicScalar{Kind: ScalarUnsigned, Bits: value, BitWidth: width}, nil
}

func SignedScalar(value int64, width int) (PublicScalar, error) {
	if width < 1 || width > 64 {
		return PublicScalar{}, fmt.Errorf("bit width must be in [1,64]: %d", width)
	}
	if width < 64 {
		min := -(int64(1) << (width - 1))
		max := (int64(1) << (width - 1)) - 1
		if value < min || value > max {
			return PublicScalar{}, fmt.Errorf("signed value %d does not fit %d bits", value, width)
		}
	}
	return PublicScalar{Kind: ScalarSigned, Bits: uint64(value) & bitMask(width), BitWidth: width}, nil
}

func (s PublicScalar) Validate() error {
	switch s.Kind {
	case ScalarReal:
		if math.IsNaN(s.Real) || math.IsInf(s.Real, 0) {
			return fmt.Errorf("real scalar is non-finite")
		}
		if s.BitWidth != 0 || s.Bits != 0 {
			return fmt.Errorf("real scalar carries integer metadata")
		}
	case ScalarUnsigned, ScalarSigned:
		if s.BitWidth < 1 || s.BitWidth > 64 {
			return fmt.Errorf("integer bit width must be in [1,64]: %d", s.BitWidth)
		}
		if s.Bits&^bitMask(s.BitWidth) != 0 {
			return fmt.Errorf("integer bits 0x%x exceed width %d", s.Bits, s.BitWidth)
		}
		if s.Real != 0 {
			return fmt.Errorf("integer scalar carries a real payload")
		}
	default:
		return fmt.Errorf("unknown scalar kind %q", s.Kind)
	}
	return nil
}

func (s PublicScalar) UnsignedValue() (uint64, bool) {
	if s.Kind != ScalarUnsigned || s.Validate() != nil {
		return 0, false
	}
	return s.Bits, true
}

func (s PublicScalar) SignedValue() (int64, bool) {
	if s.Kind != ScalarSigned || s.Validate() != nil {
		return 0, false
	}
	if s.BitWidth == 64 {
		return int64(s.Bits), true
	}
	mask := bitMask(s.BitWidth)
	bits := s.Bits & mask
	if bits&(uint64(1)<<(s.BitWidth-1)) != 0 {
		bits |= ^mask
	}
	return int64(bits), true
}

func publicScalarFromOrdered[N interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 |
		~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr |
		~float32 | ~float64
}](value N) (PublicScalar, error) {
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Float32, reflect.Float64:
		return RealScalar(v.Float())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return SignedScalar(v.Int(), v.Type().Bits())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return UnsignedScalar(v.Uint(), v.Type().Bits())
	default:
		return PublicScalar{}, fmt.Errorf("unsupported scalar type %T", value)
	}
}

// ComparatorVariant identifies the physical comparison family the backend is
// expected to instantiate.
type ComparatorVariant string

const (
	ComparatorReal             ComparatorVariant = "real_order"
	ComparatorUnsignedBorrow   ComparatorVariant = "unsigned_borrow"
	ComparatorUnsignedWidened  ComparatorVariant = "unsigned_widened"
	ComparatorSignedNoOverflow ComparatorVariant = "signed_no_overflow"
	ComparatorSignedCorrected  ComparatorVariant = "signed_corrected"
)

// OverflowContract states why the comparator is valid on the declared ranges.
type OverflowContract string

const (
	OverflowRealOrder               OverflowContract = "real_order"
	OverflowBorrowExact             OverflowContract = "borrow_bit_exact"
	OverflowWidenedExact            OverflowContract = "logical_widening_exact"
	OverflowSignedDifferenceInRange OverflowContract = "signed_difference_proved_in_range"
	OverflowSignCorrectedExact      OverflowContract = "sign_corrected_exact"
)

// IntegerRange is an inclusive, exact range. Both endpoints have the policy's
// signedness and width.
type IntegerRange struct {
	Min PublicScalar `json:"min"`
	Max PublicScalar `json:"max"`
}

// ComparisonPolicy is mandatory at every comparator call. LeftRange describes
// encrypted query features and RightRange describes selected/public thresholds.
type ComparisonPolicy struct {
	Kind       ScalarKind        `json:"kind"`
	BitWidth   int               `json:"bit_width,omitempty"`
	Comparator ComparatorVariant `json:"comparator"`
	Overflow   OverflowContract  `json:"overflow_contract"`
	LeftRange  IntegerRange      `json:"left_range,omitempty"`
	RightRange IntegerRange      `json:"right_range,omitempty"`
}

func RealComparisonPolicy() ComparisonPolicy {
	return ComparisonPolicy{Kind: ScalarReal, Comparator: ComparatorReal, Overflow: OverflowRealOrder}
}

func NewUnsignedComparisonPolicy(width int, leftMin, leftMax, rightMin, rightMax uint64, comparator ComparatorVariant, overflow OverflowContract) (ComparisonPolicy, error) {
	lmin, err := UnsignedScalar(leftMin, width)
	if err != nil {
		return ComparisonPolicy{}, err
	}
	lmax, err := UnsignedScalar(leftMax, width)
	if err != nil {
		return ComparisonPolicy{}, err
	}
	rmin, err := UnsignedScalar(rightMin, width)
	if err != nil {
		return ComparisonPolicy{}, err
	}
	rmax, err := UnsignedScalar(rightMax, width)
	if err != nil {
		return ComparisonPolicy{}, err
	}
	policy := ComparisonPolicy{
		Kind: ScalarUnsigned, BitWidth: width, Comparator: comparator, Overflow: overflow,
		LeftRange: IntegerRange{Min: lmin, Max: lmax}, RightRange: IntegerRange{Min: rmin, Max: rmax},
	}
	if err := policy.Validate(); err != nil {
		return ComparisonPolicy{}, err
	}
	return policy, nil
}

func NewSignedComparisonPolicy(width int, leftMin, leftMax, rightMin, rightMax int64, comparator ComparatorVariant, overflow OverflowContract) (ComparisonPolicy, error) {
	lmin, err := SignedScalar(leftMin, width)
	if err != nil {
		return ComparisonPolicy{}, err
	}
	lmax, err := SignedScalar(leftMax, width)
	if err != nil {
		return ComparisonPolicy{}, err
	}
	rmin, err := SignedScalar(rightMin, width)
	if err != nil {
		return ComparisonPolicy{}, err
	}
	rmax, err := SignedScalar(rightMax, width)
	if err != nil {
		return ComparisonPolicy{}, err
	}
	policy := ComparisonPolicy{
		Kind: ScalarSigned, BitWidth: width, Comparator: comparator, Overflow: overflow,
		LeftRange: IntegerRange{Min: lmin, Max: lmax}, RightRange: IntegerRange{Min: rmin, Max: rmax},
	}
	if err := policy.Validate(); err != nil {
		return ComparisonPolicy{}, err
	}
	return policy, nil
}

func scalarBigInt(s PublicScalar) *big.Int {
	if value, ok := s.UnsignedValue(); ok {
		return new(big.Int).SetUint64(value)
	}
	value, _ := s.SignedValue()
	return big.NewInt(value)
}

func (r IntegerRange) validate(kind ScalarKind, width int) error {
	for name, bound := range map[string]PublicScalar{"min": r.Min, "max": r.Max} {
		if err := bound.Validate(); err != nil {
			return fmt.Errorf("%s bound: %w", name, err)
		}
		if bound.Kind != kind || bound.BitWidth != width {
			return fmt.Errorf("%s bound has kind/width %s/%d, want %s/%d", name, bound.Kind, bound.BitWidth, kind, width)
		}
	}
	if scalarBigInt(r.Min).Cmp(scalarBigInt(r.Max)) > 0 {
		return fmt.Errorf("range minimum exceeds maximum")
	}
	return nil
}

func (r IntegerRange) contains(value PublicScalar) bool {
	if value.Kind != r.Min.Kind || value.BitWidth != r.Min.BitWidth || value.Validate() != nil {
		return false
	}
	v := scalarBigInt(value)
	return v.Cmp(scalarBigInt(r.Min)) >= 0 && v.Cmp(scalarBigInt(r.Max)) <= 0
}

func (p ComparisonPolicy) Validate() error {
	if p.Kind == ScalarReal {
		if p.BitWidth != 0 || p.Comparator != ComparatorReal || p.Overflow != OverflowRealOrder {
			return fmt.Errorf("real comparison policy has inconsistent integer/comparator metadata")
		}
		return nil
	}
	if p.Kind != ScalarUnsigned && p.Kind != ScalarSigned {
		return fmt.Errorf("unknown comparison kind %q", p.Kind)
	}
	if p.BitWidth < 1 || p.BitWidth > 64 {
		return fmt.Errorf("integer comparison bit width must be in [1,64]: %d", p.BitWidth)
	}
	if err := p.LeftRange.validate(p.Kind, p.BitWidth); err != nil {
		return fmt.Errorf("left range: %w", err)
	}
	if err := p.RightRange.validate(p.Kind, p.BitWidth); err != nil {
		return fmt.Errorf("right range: %w", err)
	}
	switch p.Comparator {
	case ComparatorUnsignedBorrow:
		if p.Kind != ScalarUnsigned || p.Overflow != OverflowBorrowExact {
			return fmt.Errorf("unsigned-borrow comparator requires unsigned borrow-exact policy")
		}
	case ComparatorUnsignedWidened:
		if p.Kind != ScalarUnsigned || p.Overflow != OverflowWidenedExact {
			return fmt.Errorf("unsigned-widened comparator requires unsigned widened-exact policy")
		}
	case ComparatorSignedNoOverflow:
		if p.Kind != ScalarSigned || p.Overflow != OverflowSignedDifferenceInRange {
			return fmt.Errorf("signed-no-overflow comparator requires a signed difference-in-range proof")
		}
		minDifference := new(big.Int).Sub(scalarBigInt(p.LeftRange.Min), scalarBigInt(p.RightRange.Max))
		maxDifference := new(big.Int).Sub(scalarBigInt(p.LeftRange.Max), scalarBigInt(p.RightRange.Min))
		limit := new(big.Int).Lsh(big.NewInt(1), uint(p.BitWidth-1))
		minAllowed := new(big.Int).Neg(new(big.Int).Set(limit))
		maxAllowed := new(big.Int).Sub(new(big.Int).Set(limit), big.NewInt(1))
		if minDifference.Cmp(minAllowed) < 0 || maxDifference.Cmp(maxAllowed) > 0 {
			return fmt.Errorf("declared ranges do not prove signed subtraction free of overflow")
		}
	case ComparatorSignedCorrected:
		if p.Kind != ScalarSigned || p.Overflow != OverflowSignCorrectedExact {
			return fmt.Errorf("signed-corrected comparator requires signed sign-corrected policy")
		}
	default:
		return fmt.Errorf("unknown comparator variant %q", p.Comparator)
	}
	return nil
}

func (p ComparisonPolicy) validateOperand(value PublicScalar, left bool) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if value.Kind != p.Kind {
		return fmt.Errorf("operand kind %s does not match policy kind %s", value.Kind, p.Kind)
	}
	if p.Kind == ScalarReal {
		return value.Validate()
	}
	if value.BitWidth != p.BitWidth {
		return fmt.Errorf("operand width %d does not match policy width %d", value.BitWidth, p.BitWidth)
	}
	rangeToUse := p.RightRange
	if left {
		rangeToUse = p.LeftRange
	}
	if !rangeToUse.contains(value) {
		return fmt.Errorf("operand is outside its declared comparison range")
	}
	return nil
}
