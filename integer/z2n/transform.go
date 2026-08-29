package z2n

import (
	"fmt"
	"math/big"

	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

type linearTransform struct {
	roots   []*bignum.Complex
	forward [][]*bignum.Complex // n/2 by n Vandermonde matrix U
	inverse [][]*bignum.Complex // n by n/2 closed-form matrix U^{-1}
}

func (r *Ring) buildLinearTransform() (*linearTransform, error) {
	constants := rootConstantTable[r.bits]
	roots := make([]*bignum.Complex, len(constants))
	for i, constant := range constants {
		value, err := r.complexFromConstant(constant)
		if err != nil {
			return nil, fmt.Errorf("z2n: parse root %d for n=%d: %w", i, r.bits, err)
		}
		roots[i] = value
	}

	n := int(r.bits)
	forward := make([][]*bignum.Complex, n/2)
	for row, xi := range roots {
		forward[row] = make([]*bignum.Complex, n)
		forward[row][0] = r.complexOne()
		for column := 1; column < n; column++ {
			forward[row][column] = r.complexMul(forward[row][column-1], xi)
		}
	}

	// Gao--Zheng's inverse is the closed-form inverse of the evaluation map
	// for f(X)=X^n-X+2. For root xi, f'(xi)=n*xi^(n-1)-1:
	//   V[0,j] = (xi^(n-1)-1)/f'(xi)
	//   V[i,j] = xi^(n-1-i)/f'(xi), i>0.
	// Only one root from each conjugate pair is stored. FromRootSlots adds the
	// conjugate contribution as 2*Re(V*s).
	inverse := make([][]*bignum.Complex, n)
	for i := range inverse {
		inverse[i] = make([]*bignum.Complex, n/2)
	}
	for column, xi := range roots {
		powers := make([]*bignum.Complex, n)
		powers[0] = r.complexOne()
		for exponent := 1; exponent < n; exponent++ {
			powers[exponent] = r.complexMul(powers[exponent-1], xi)
		}
		derivative := r.complexSub(
			r.complexMul(r.complexRealInt(int64(n)), powers[n-1]),
			r.complexOne(),
		)
		for row := 0; row < n; row++ {
			var numerator *bignum.Complex
			if row == 0 {
				numerator = r.complexSub(powers[n-1], r.complexOne())
			} else {
				numerator = powers[n-1-row]
			}
			inverse[row][column] = r.complexQuo(numerator, derivative)
		}
	}

	return &linearTransform{roots: roots, forward: forward, inverse: inverse}, nil
}

// Roots returns deep copies of the n/2 published roots in the upper half
// plane. These roots, not complex128 root finding, define the transform.
func (r *Ring) Roots() []*bignum.Complex {
	return cloneComplexVector(r.transform.roots)
}

// Vandermonde returns U[j][i]=xi_j^i, with dimensions n/2 by n.
func (r *Ring) Vandermonde() [][]*bignum.Complex {
	return cloneComplexMatrix(r.transform.forward)
}

// VandermondeInverse returns the n by n/2 closed-form matrix described in
// buildLinearTransform. Real coefficients are recovered as 2*Re(U^{-1}s).
func (r *Ring) VandermondeInverse() [][]*bignum.Complex {
	return cloneComplexMatrix(r.transform.inverse)
}

// ToRootSlots evaluates a polynomial at the n/2 published roots.
func (r *Ring) ToRootSlots(polynomial Polynomial) ([]*bignum.Complex, error) {
	if err := r.validate(polynomial); err != nil {
		return nil, err
	}
	result := make([]*bignum.Complex, len(r.transform.forward))
	for row := range r.transform.forward {
		sum := r.newComplex()
		for column, coefficient := range polynomial.coefficients {
			term := r.complexMulReal(r.transform.forward[row][column], coefficient)
			sum = r.complexAdd(sum, term)
		}
		result[row] = sum
	}
	return result, nil
}

// FromRootSlots applies the closed-form inverse and its implicit conjugate
// half to recover a real coefficient polynomial.
func (r *Ring) FromRootSlots(slots []*bignum.Complex) (Polynomial, error) {
	want := int(r.bits) / 2
	if len(slots) != want {
		return Polynomial{}, fmt.Errorf("z2n: got %d root slots, want %d", len(slots), want)
	}
	for i, slot := range slots {
		if slot == nil || slot.Real() == nil || slot.Imag() == nil {
			return Polynomial{}, fmt.Errorf("z2n: root slot %d is nil", i)
		}
	}

	result := r.zeroPolynomial()
	two := r.newFloat().SetInt64(2)
	for row := range r.transform.inverse {
		sum := r.newComplex()
		for column, slot := range slots {
			term := r.complexMul(r.transform.inverse[row][column], slot)
			sum = r.complexAdd(sum, term)
		}
		result.coefficients[row].Mul(two, sum.Real())
	}
	return result, nil
}

// ArithmeticRootSlots returns the high-precision root-slot vector for the
// standard arithmetic encoding tau^{-1}[word]_tau.
func (r *Ring) ArithmeticRootSlots(word uint64) []*bignum.Complex {
	slots, err := r.ToRootSlots(r.ArithmeticEncode(word))
	if err != nil {
		panic(err) // the polynomial was constructed by r
	}
	return slots
}

// RecoverWord reconstructs and decodes an arithmetic root-slot vector.
func (r *Ring) RecoverWord(slots []*bignum.Complex) (uint64, error) {
	polynomial, err := r.FromRootSlots(slots)
	if err != nil {
		return 0, err
	}
	return r.DecodeArithmetic(polynomial)
}

// Complex128 converts high-precision slots for logging or diagnostics. It is
// intentionally not used by any encoding, transform, or decoding path.
func Complex128(values []*bignum.Complex) []complex128 {
	result := make([]complex128, len(values))
	for i, value := range values {
		result[i] = value.Complex128()
	}
	return result
}

func (r *Ring) complexFromConstant(value RootConstant) (*bignum.Complex, error) {
	realPart, err := r.floatFromConstant(value.Real)
	if err != nil {
		return nil, fmt.Errorf("real part: %w", err)
	}
	imagPart, err := r.floatFromConstant(value.Imag)
	if err != nil {
		return nil, fmt.Errorf("imaginary part: %w", err)
	}
	return &bignum.Complex{realPart, imagPart}, nil
}

func (r *Ring) floatFromConstant(value FixedPointConstant) (*big.Float, error) {
	magnitude, ok := new(big.Int).SetString(value.Magnitude, 10)
	if !ok {
		return nil, fmt.Errorf("invalid magnitude %q", value.Magnitude)
	}
	result := r.newFloat().SetInt(magnitude)
	result.SetMantExp(result, -int(value.FractionBits))
	if value.Negative {
		result.Neg(result)
	}
	return result, nil
}

func (r *Ring) newComplex() *bignum.Complex {
	return &bignum.Complex{r.newFloat(), r.newFloat()}
}

func (r *Ring) complexOne() *bignum.Complex {
	result := r.newComplex()
	result.Real().SetInt64(1)
	return result
}

func (r *Ring) complexRealInt(value int64) *bignum.Complex {
	result := r.newComplex()
	result.Real().SetInt64(value)
	return result
}

func (r *Ring) complexAdd(lhs, rhs *bignum.Complex) *bignum.Complex {
	return &bignum.Complex{
		r.newFloat().Add(lhs.Real(), rhs.Real()),
		r.newFloat().Add(lhs.Imag(), rhs.Imag()),
	}
}

func (r *Ring) complexSub(lhs, rhs *bignum.Complex) *bignum.Complex {
	return &bignum.Complex{
		r.newFloat().Sub(lhs.Real(), rhs.Real()),
		r.newFloat().Sub(lhs.Imag(), rhs.Imag()),
	}
}

func (r *Ring) complexMul(lhs, rhs *bignum.Complex) *bignum.Complex {
	ac := r.newFloat().Mul(lhs.Real(), rhs.Real())
	bd := r.newFloat().Mul(lhs.Imag(), rhs.Imag())
	ad := r.newFloat().Mul(lhs.Real(), rhs.Imag())
	bc := r.newFloat().Mul(lhs.Imag(), rhs.Real())
	return &bignum.Complex{
		r.newFloat().Sub(ac, bd),
		r.newFloat().Add(ad, bc),
	}
}

func (r *Ring) complexMulReal(lhs *bignum.Complex, rhs *big.Float) *bignum.Complex {
	return &bignum.Complex{
		r.newFloat().Mul(lhs.Real(), rhs),
		r.newFloat().Mul(lhs.Imag(), rhs),
	}
}

func (r *Ring) complexQuo(numerator, denominator *bignum.Complex) *bignum.Complex {
	// (a+bi)/(c+di) = ((ac+bd)+(bc-ad)i)/(c^2+d^2).
	ac := r.newFloat().Mul(numerator.Real(), denominator.Real())
	bd := r.newFloat().Mul(numerator.Imag(), denominator.Imag())
	bc := r.newFloat().Mul(numerator.Imag(), denominator.Real())
	ad := r.newFloat().Mul(numerator.Real(), denominator.Imag())
	c2 := r.newFloat().Mul(denominator.Real(), denominator.Real())
	d2 := r.newFloat().Mul(denominator.Imag(), denominator.Imag())
	norm := r.newFloat().Add(c2, d2)
	return &bignum.Complex{
		r.newFloat().Quo(r.newFloat().Add(ac, bd), norm),
		r.newFloat().Quo(r.newFloat().Sub(bc, ad), norm),
	}
}

func cloneComplexVector(values []*bignum.Complex) []*bignum.Complex {
	result := make([]*bignum.Complex, len(values))
	for i, value := range values {
		result[i] = value.Clone()
	}
	return result
}

func cloneComplexMatrix(values [][]*bignum.Complex) [][]*bignum.Complex {
	result := make([][]*bignum.Complex, len(values))
	for i, row := range values {
		result[i] = cloneComplexVector(row)
	}
	return result
}
