// Package homchain implements the high-precision linear-transform layer used
// by Gao--Zheng's Z-To-C and C-To-Z conversions. It deliberately stops at
// linear transformations: truncation, modulus raising, and bootstrapping are
// separate protocols and are not modeled here.
package homchain

import (
	"fmt"
	"math/big"

	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

// Matrix is a row-major arbitrary-precision complex matrix.
type Matrix = [][]*bignum.Complex

// MatrixSet contains the four square halves of Gao--Zheng's rectangular
// transforms. If h=n/2, U=[U0 U1] is h-by-n and V=[V0; V1] is n-by-h.
type MatrixSet struct {
	U0 Matrix
	U1 Matrix
	V0 Matrix
	V1 Matrix
}

// NewMatrixSet validates and splits U and V into their square halves.
func NewMatrixSet(u, v Matrix) (MatrixSet, error) {
	h := len(u)
	if h < 2 || !isPowerOfTwo(h) {
		return MatrixSet{}, fmt.Errorf("homchain: U has %d rows, want a power of two of at least 2", h)
	}
	if err := validateMatrix(u, h, 2*h, "U"); err != nil {
		return MatrixSet{}, err
	}
	if err := validateMatrix(v, 2*h, h, "V"); err != nil {
		return MatrixSet{}, err
	}

	u0 := makeMatrix(h, h, matrixPrecision(u))
	u1 := makeMatrix(h, h, matrixPrecision(u))
	v0 := makeMatrix(h, h, matrixPrecision(v))
	v1 := makeMatrix(h, h, matrixPrecision(v))
	for row := 0; row < h; row++ {
		for column := 0; column < h; column++ {
			u0[row][column] = u[row][column].Clone()
			u1[row][column] = u[row][column+h].Clone()
			v0[row][column] = v[row][column].Clone()
			v1[row][column] = v[row+h][column].Clone()
		}
	}
	return MatrixSet{U0: u0, U1: u1, V0: v0, V1: v1}, nil
}

func validateMatrix(matrix Matrix, rows, columns int, name string) error {
	if len(matrix) != rows {
		return fmt.Errorf("homchain: %s has %d rows, want %d", name, len(matrix), rows)
	}
	for row := range matrix {
		if len(matrix[row]) != columns {
			return fmt.Errorf("homchain: %s row %d has %d columns, want %d", name, row, len(matrix[row]), columns)
		}
		for column, value := range matrix[row] {
			if value == nil || value.Real() == nil || value.Imag() == nil {
				return fmt.Errorf("homchain: %s[%d][%d] is nil", name, row, column)
			}
		}
	}
	return nil
}

func cloneMatrix(matrix Matrix) Matrix {
	result := make(Matrix, len(matrix))
	for row := range matrix {
		result[row] = make([]*bignum.Complex, len(matrix[row]))
		for column, value := range matrix[row] {
			result[row][column] = value.Clone()
		}
	}
	return result
}

func makeMatrix(rows, columns int, precision uint) Matrix {
	result := make(Matrix, rows)
	for row := range result {
		result[row] = make([]*bignum.Complex, columns)
		for column := range result[row] {
			result[row][column] = newComplex(precision)
		}
	}
	return result
}

func matrixPrecision(matrix Matrix) uint {
	var precision uint = 53
	for row := range matrix {
		for _, value := range matrix[row] {
			if value != nil && value.Prec() > precision {
				precision = value.Prec()
			}
		}
	}
	return precision
}

func scaleRows(matrix Matrix, factors []*bignum.Complex) (Matrix, error) {
	if len(matrix) != len(factors) {
		return nil, fmt.Errorf("homchain: got %d row factors, want %d", len(factors), len(matrix))
	}
	result := cloneMatrix(matrix)
	for row, factor := range factors {
		if factor == nil || factor.Real() == nil || factor.Imag() == nil {
			return nil, fmt.Errorf("homchain: row factor %d is nil", row)
		}
		for column := range result[row] {
			result[row][column] = multiplyComplex(factor, matrix[row][column])
		}
	}
	return result, nil
}

func scaleColumns(matrix Matrix, factors []*bignum.Complex) (Matrix, error) {
	if len(matrix) == 0 || len(matrix[0]) != len(factors) {
		return nil, fmt.Errorf("homchain: got %d column factors, want %d", len(factors), len(matrix[0]))
	}
	result := cloneMatrix(matrix)
	for row := range result {
		for column, factor := range factors {
			if factor == nil || factor.Real() == nil || factor.Imag() == nil {
				return nil, fmt.Errorf("homchain: column factor %d is nil", column)
			}
			result[row][column] = multiplyComplex(matrix[row][column], factor)
		}
	}
	return result, nil
}

func specialB0(matrix Matrix) (Matrix, error) {
	if len(matrix) < 2 {
		return nil, fmt.Errorf("homchain: special-b0 needs at least two V0 rows")
	}
	result := cloneMatrix(matrix)
	two := realComplex(2, matrixPrecision(matrix))
	for column := range result[0] {
		// This is the upstream convention exactly: V0'[0,j]=2*V0[1,j].
		result[0][column] = multiplyComplex(two, matrix[1][column])
	}
	return result, nil
}

func newComplex(precision uint) *bignum.Complex {
	return &bignum.Complex{newFloat(precision), newFloat(precision)}
}

func realComplex(value int64, precision uint) *bignum.Complex {
	result := newComplex(precision)
	result.Real().SetInt64(value)
	return result
}

func newFloat(precision uint) *big.Float {
	return new(big.Float).SetPrec(precision).SetMode(big.ToNearestEven)
}

func multiplyComplex(lhs, rhs *bignum.Complex) *bignum.Complex {
	precision := lhs.Prec()
	if rhs.Prec() > precision {
		precision = rhs.Prec()
	}
	ac := newFloat(precision).Mul(lhs.Real(), rhs.Real())
	bd := newFloat(precision).Mul(lhs.Imag(), rhs.Imag())
	ad := newFloat(precision).Mul(lhs.Real(), rhs.Imag())
	bc := newFloat(precision).Mul(lhs.Imag(), rhs.Real())
	return &bignum.Complex{
		newFloat(precision).Sub(ac, bd),
		newFloat(precision).Add(ad, bc),
	}
}

func addComplex(lhs, rhs *bignum.Complex) *bignum.Complex {
	precision := lhs.Prec()
	if rhs.Prec() > precision {
		precision = rhs.Prec()
	}
	return &bignum.Complex{
		newFloat(precision).Add(lhs.Real(), rhs.Real()),
		newFloat(precision).Add(lhs.Imag(), rhs.Imag()),
	}
}

func isZero(value *bignum.Complex) bool {
	return value.Real().Sign() == 0 && value.Imag().Sign() == 0
}

func isPowerOfTwo(value int) bool {
	return value > 0 && value&(value-1) == 0
}
