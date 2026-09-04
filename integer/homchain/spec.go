package homchain

import (
	"fmt"
	"math/bits"

	ckkslintrans "github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/lintrans"
	"github.com/nc26676027/LCPDTE/lattigo/ring"
	"github.com/nc26676027/LCPDTE/lattigo/utils/bignum"
)

// TransformName identifies one Gao--Zheng matrix variant.
type TransformName string

// TransformLayout distinguishes the compact semantic row oracle from the
// single-row CKKS layout that Lattigo can encode.
type TransformLayout string

const (
	// RepeatedRowLayout evaluates the same h-by-h matrix independently on
	// 2^LogDimensions.Rows rows. It is the compact semantic representation.
	RepeatedRowLayout TransformLayout = "repeated-row"
	// FullSlotBlockDiagonalLayout embeds every word block in one L-by-L
	// block-diagonal matrix, where L=words*h. This is the CKKS layout.
	FullSlotBlockDiagonalLayout TransformLayout = "full-slot-block-diagonal"
)

const (
	U0Normal    TransformName = "U0"
	U1Normal    TransformName = "U1"
	V0Normal    TransformName = "V0"
	V1Normal    TransformName = "V1"
	V0SpecialB0 TransformName = "V0-special-b0"
	U0FusedTInv TransformName = "U0-fused-tInv"
	U1FusedTInv TransformName = "U1-fused-tInv"
	V0FusedT    TransformName = "V0-fused-t"
	V1FusedT    TransformName = "V1-fused-t"
)

// TransformSpec owns an auditable square matrix and its diagonal
// representation. Its state is immutable outside this package: accessors
// return values or deep copies, so the matrix and diagonals cannot diverge.
type TransformSpec struct {
	name          TransformName
	layout        TransformLayout
	logDimensions ring.Dimensions
	diagonals     ckkslintrans.Diagonals[*bignum.Complex]
	matrix        Matrix
	precision     uint
	wordCount     int
	halfWidth     int
}

// Name identifies the Gao--Zheng matrix variant.
func (s TransformSpec) Name() TransformName { return s.name }

// Layout reports whether the spec uses the compact semantic layout or the
// flattened CKKS layout.
func (s TransformSpec) Layout() TransformLayout { return s.layout }

// LogDimensions returns a value copy of the transform dimensions.
func (s TransformSpec) LogDimensions() ring.Dimensions { return s.logDimensions }

// Diagonals returns a deep copy of the high-precision diagonal representation.
func (s TransformSpec) Diagonals() ckkslintrans.Diagonals[*bignum.Complex] {
	return cloneDiagonals(s.diagonals)
}

// Matrix returns a deep copy of the square source matrix.
func (s TransformSpec) Matrix() Matrix { return cloneMatrix(s.matrix) }

// Words returns the number of independently repeated word rows.
func (s TransformSpec) Words() int {
	if s.wordCount != 0 {
		return s.wordCount
	}
	return 1 << s.logDimensions.Rows
}

// HalfWidth returns n/2, the square transform dimension.
func (s TransformSpec) HalfWidth() int {
	if s.halfWidth != 0 {
		return s.halfWidth
	}
	return 1 << s.logDimensions.Cols
}

// PairSpec groups the two halves of one rectangular transform.
type PairSpec struct {
	Low  TransformSpec
	High TransformSpec
}

// Specifications contains normal, special-b0, and fused-t/tInv variants.
type Specifications struct {
	U0 TransformSpec
	U1 TransformSpec
	V0 TransformSpec
	V1 TransformSpec

	V0SpecialB0 TransformSpec
	U0FusedTInv TransformSpec
	U1FusedTInv TransformSpec
	V0FusedT    TransformSpec
	V1FusedT    TransformSpec
}

func (s Specifications) UPair() PairSpec { return PairSpec{Low: s.U0, High: s.U1} }
func (s Specifications) VPair() PairSpec { return PairSpec{Low: s.V0, High: s.V1} }
func (s Specifications) VSpecialB0Pair() PairSpec {
	return PairSpec{Low: s.V0SpecialB0, High: s.V1}
}
func (s Specifications) UFusedTInvPair() PairSpec {
	return PairSpec{Low: s.U0FusedTInv, High: s.U1FusedTInv}
}
func (s Specifications) VFusedTPair() PairSpec {
	return PairSpec{Low: s.V0FusedT, High: s.V1FusedT}
}

// NewSpecifications builds every transform variant from injected matrices and
// root-slot representations of tau and tau^{-1}.
func NewSpecifications(matrices MatrixSet, words int, tSlots, tInvSlots []*bignum.Complex) (Specifications, error) {
	if !isPowerOfTwo(words) {
		return Specifications{}, fmt.Errorf("homchain: word count %d is not a positive power of two", words)
	}
	h := len(matrices.U0)
	for name, matrix := range map[string]Matrix{
		"U0": matrices.U0, "U1": matrices.U1, "V0": matrices.V0, "V1": matrices.V1,
	} {
		if err := validateMatrix(matrix, h, h, name); err != nil {
			return Specifications{}, err
		}
	}

	v0B0, err := specialB0(matrices.V0)
	if err != nil {
		return Specifications{}, err
	}
	u0TInv, err := scaleRows(matrices.U0, tInvSlots)
	if err != nil {
		return Specifications{}, fmt.Errorf("homchain: fuse tInv into U0: %w", err)
	}
	u1TInv, err := scaleRows(matrices.U1, tInvSlots)
	if err != nil {
		return Specifications{}, fmt.Errorf("homchain: fuse tInv into U1: %w", err)
	}
	v0T, err := scaleColumns(matrices.V0, tSlots)
	if err != nil {
		return Specifications{}, fmt.Errorf("homchain: fuse t into V0: %w", err)
	}
	v1T, err := scaleColumns(matrices.V1, tSlots)
	if err != nil {
		return Specifications{}, fmt.Errorf("homchain: fuse t into V1: %w", err)
	}

	build := func(name TransformName, matrix Matrix) (TransformSpec, error) {
		return newTransformSpec(name, matrix, words)
	}
	var result Specifications
	if result.U0, err = build(U0Normal, matrices.U0); err != nil {
		return Specifications{}, err
	}
	if result.U1, err = build(U1Normal, matrices.U1); err != nil {
		return Specifications{}, err
	}
	if result.V0, err = build(V0Normal, matrices.V0); err != nil {
		return Specifications{}, err
	}
	if result.V1, err = build(V1Normal, matrices.V1); err != nil {
		return Specifications{}, err
	}
	if result.V0SpecialB0, err = build(V0SpecialB0, v0B0); err != nil {
		return Specifications{}, err
	}
	if result.U0FusedTInv, err = build(U0FusedTInv, u0TInv); err != nil {
		return Specifications{}, err
	}
	if result.U1FusedTInv, err = build(U1FusedTInv, u1TInv); err != nil {
		return Specifications{}, err
	}
	if result.V0FusedT, err = build(V0FusedT, v0T); err != nil {
		return Specifications{}, err
	}
	if result.V1FusedT, err = build(V1FusedT, v1T); err != nil {
		return Specifications{}, err
	}
	return result, nil
}

func newTransformSpec(name TransformName, matrix Matrix, words int) (TransformSpec, error) {
	h := len(matrix)
	if h == 0 || !isPowerOfTwo(h) {
		return TransformSpec{}, fmt.Errorf("homchain: %s dimension %d is not a positive power of two", name, h)
	}
	if err := validateMatrix(matrix, h, h, string(name)); err != nil {
		return TransformSpec{}, err
	}
	if !isPowerOfTwo(words) {
		return TransformSpec{}, fmt.Errorf("homchain: word count %d is not a positive power of two", words)
	}

	precision := matrixPrecision(matrix)
	diagonals := make(ckkslintrans.Diagonals[*bignum.Complex], h)
	for diagonalIndex := 0; diagonalIndex < h; diagonalIndex++ {
		diagonal := make([]*bignum.Complex, words*h)
		nonZero := false
		for word := 0; word < words; word++ {
			for row := 0; row < h; row++ {
				value := matrix[row][(row+diagonalIndex)&(h-1)]
				diagonal[word*h+row] = value.Clone()
				nonZero = nonZero || !isZero(value)
			}
		}
		if nonZero {
			diagonals[diagonalIndex] = diagonal
		}
	}
	return TransformSpec{
		name:   name,
		layout: RepeatedRowLayout,
		logDimensions: ring.Dimensions{
			Rows: bits.Len(uint(words)) - 1,
			Cols: bits.Len(uint(h)) - 1,
		},
		diagonals: diagonals,
		matrix:    cloneMatrix(matrix),
		precision: precision,
		wordCount: words,
		halfWidth: h,
	}, nil
}

// FullSlot converts a compact repeated-row spec into an equivalent Lattigo
// CKKS transform over all L=words*(n/2) active slots. A global rotation by a
// signed offset in [-(h-1), h-1] is masked at each word boundary, yielding a
// repeated block-diagonal matrix without cross-block wraparound.
func (s TransformSpec) FullSlot() (TransformSpec, error) {
	if s.layout == FullSlotBlockDiagonalLayout {
		return s.clone(), nil
	}
	words := s.Words()
	h := s.HalfWidth()
	if !isPowerOfTwo(words) || !isPowerOfTwo(h) {
		return TransformSpec{}, fmt.Errorf("homchain: %s has invalid words=%d or half-width=%d", s.name, words, h)
	}
	if err := validateMatrix(s.matrix, h, h, string(s.name)); err != nil {
		return TransformSpec{}, err
	}
	totalSlots := words * h
	diagonals := make(ckkslintrans.Diagonals[*bignum.Complex], 2*h-1)
	for offset := -(h - 1); offset <= h-1; offset++ {
		index := offset
		if index < 0 {
			index += totalSlots
		}
		diagonal, exists := diagonals[index]
		if !exists {
			diagonal = make([]*bignum.Complex, totalSlots)
			for i := range diagonal {
				diagonal[i] = newComplex(s.precision)
			}
		}
		nonZero := false
		for word := 0; word < words; word++ {
			base := word * h
			for outputColumn := 0; outputColumn < h; outputColumn++ {
				inputColumn := outputColumn + offset
				if inputColumn < 0 || inputColumn >= h {
					continue
				}
				value := s.matrix[outputColumn][inputColumn]
				diagonal[base+outputColumn] = value.Clone()
				nonZero = nonZero || !isZero(value)
			}
		}
		if nonZero || exists {
			diagonals[index] = diagonal
		}
	}
	// A zero source diagonal can leave an all-zero entry after offsets that
	// collide when words=1. Remove such entries so Galois enumeration remains
	// exact for sparse matrices.
	for index, diagonal := range diagonals {
		if diagonalIsZero(diagonal) {
			delete(diagonals, index)
		}
	}
	return TransformSpec{
		name:          s.name,
		layout:        FullSlotBlockDiagonalLayout,
		logDimensions: ring.Dimensions{Rows: 0, Cols: bits.Len(uint(totalSlots)) - 1},
		diagonals:     diagonals,
		matrix:        cloneMatrix(s.matrix),
		precision:     s.precision,
		wordCount:     words,
		halfWidth:     h,
	}, nil
}

func (s TransformSpec) clone() TransformSpec {
	return TransformSpec{
		name:          s.name,
		layout:        s.layout,
		logDimensions: s.logDimensions,
		diagonals:     cloneDiagonals(s.diagonals),
		matrix:        cloneMatrix(s.matrix),
		precision:     s.precision,
		wordCount:     s.wordCount,
		halfWidth:     s.halfWidth,
	}
}

func diagonalIsZero(diagonal []*bignum.Complex) bool {
	for _, value := range diagonal {
		if !isZero(value) {
			return false
		}
	}
	return true
}

// EvaluatePlaintext applies the diagonal representation independently to
// every word row. It is a high-precision semantic oracle, not a CKKS simulator.
func (s TransformSpec) EvaluatePlaintext(input []*bignum.Complex) ([]*bignum.Complex, error) {
	rows := s.Words()
	columns := s.HalfWidth()
	if len(input) != rows*columns {
		return nil, fmt.Errorf("homchain: %s got %d plaintext values, want %d", s.name, len(input), rows*columns)
	}
	for index, value := range input {
		if value == nil || value.Real() == nil || value.Imag() == nil {
			return nil, fmt.Errorf("homchain: %s plaintext value %d is nil", s.name, index)
		}
	}
	result := make([]*bignum.Complex, len(input))
	for index := range result {
		result[index] = newComplex(s.precision)
	}
	if s.layout == FullSlotBlockDiagonalLayout {
		totalSlots := rows * columns
		for diagonalIndex, diagonal := range s.diagonals {
			rotation := diagonalIndex & (totalSlots - 1)
			for outputIndex := 0; outputIndex < totalSlots; outputIndex++ {
				term := multiplyComplex(diagonal[outputIndex], input[(outputIndex+rotation)&(totalSlots-1)])
				result[outputIndex] = addComplex(result[outputIndex], term)
			}
		}
	} else {
		for diagonalIndex, diagonal := range s.diagonals {
			rotation := diagonalIndex & (columns - 1)
			for row := 0; row < rows; row++ {
				base := row * columns
				for column := 0; column < columns; column++ {
					term := multiplyComplex(diagonal[base+column], input[base+((column+rotation)&(columns-1))])
					result[base+column] = addComplex(result[base+column], term)
				}
			}
		}
	}
	return result, nil
}

// ProjectRealPlaintext implements z+conj(z)=2*Re(z), the conjugate-half
// recovery used after V0/V1 in Gao--Zheng Z-To-C.
func ProjectRealPlaintext(input []*bignum.Complex) []*bignum.Complex {
	result := make([]*bignum.Complex, len(input))
	for index, value := range input {
		precision := value.Prec()
		result[index] = newComplex(precision)
		result[index].Real().Mul(value.Real(), newFloat(precision).SetInt64(2))
	}
	return result
}

// AddPlaintext adds two high-precision complex vectors.
func AddPlaintext(lhs, rhs []*bignum.Complex) ([]*bignum.Complex, error) {
	if len(lhs) != len(rhs) {
		return nil, fmt.Errorf("homchain: vector lengths differ: %d != %d", len(lhs), len(rhs))
	}
	result := make([]*bignum.Complex, len(lhs))
	for i := range result {
		if lhs[i] == nil || rhs[i] == nil {
			return nil, fmt.Errorf("homchain: nil vector entry %d", i)
		}
		result[i] = addComplex(lhs[i], rhs[i])
	}
	return result, nil
}
