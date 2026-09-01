package z2n

import (
	"fmt"
	"math/big"
)

// Polynomial is an element of R[X]/(X^n-X+2). Its coefficient slice is kept
// private; Coefficients returns a deep copy.
type Polynomial struct {
	bits         WordBits
	precision    uint
	coefficients []*big.Float
}

// NewPolynomial imports exactly n coefficients into the Ring's precision.
// Mixed caller precisions are accepted, but every imported coefficient must
// retain enough significance for Gao--Zheng's epsilon-shifted canonicalizer.
func (r *Ring) NewPolynomial(coefficients []*big.Float) (Polynomial, error) {
	n := int(r.bits)
	if len(coefficients) != n {
		return Polynomial{}, fmt.Errorf("z2n: got %d coefficients, want %d", len(coefficients), n)
	}
	result := r.zeroPolynomial()
	for i, coefficient := range coefficients {
		if coefficient == nil {
			return Polynomial{}, fmt.Errorf("z2n: coefficient %d is nil", i)
		}
		result.coefficients[i].Set(coefficient)
	}
	if err := r.validate(result); err != nil {
		return Polynomial{}, fmt.Errorf("z2n: import polynomial: %w", err)
	}
	return result, nil
}

// WordBits returns the ring degree associated with the polynomial.
func (p Polynomial) WordBits() WordBits { return p.bits }

// Precision returns the coefficient precision in bits.
func (p Polynomial) Precision() uint { return p.precision }

// Coefficients returns a deep copy in ascending degree order.
func (p Polynomial) Coefficients() []*big.Float {
	result := make([]*big.Float, len(p.coefficients))
	for i, coefficient := range p.coefficients {
		result[i] = new(big.Float).SetPrec(p.precision).Set(coefficient)
	}
	return result
}

// Zero returns the additive identity.
func (r *Ring) Zero() Polynomial { return r.zeroPolynomial() }

// One returns the multiplicative identity.
func (r *Ring) One() Polynomial {
	result := r.zeroPolynomial()
	result.coefficients[0].SetInt64(1)
	return result
}

// Tau returns X-2.
func (r *Ring) Tau() Polynomial {
	result := r.zeroPolynomial()
	result.coefficients[0].SetInt64(-2)
	result.coefficients[1].SetInt64(1)
	return result
}

// TauInverse returns the closed-form inverse of X-2 in
// R[X]/(X^n-X+2): (1-2^(n-1))/2^n at degree zero and
// -2^(n-1-i)/2^n at degree i > 0.
func (r *Ring) TauInverse() Polynomial {
	n := int(r.bits)
	result := r.zeroPolynomial()
	denominator := new(big.Int).Lsh(big.NewInt(1), uint(n))
	for i := 0; i < n; i++ {
		numerator := new(big.Int)
		if i == 0 {
			numerator.Sub(big.NewInt(1), new(big.Int).Lsh(big.NewInt(1), uint(n-1)))
		} else {
			numerator.Neg(new(big.Int).Lsh(big.NewInt(1), uint(n-1-i)))
		}
		result.coefficients[i].Quo(
			new(big.Float).SetPrec(r.prec).SetInt(numerator),
			new(big.Float).SetPrec(r.prec).SetInt(denominator),
		)
	}
	return result
}

// Add adds two ring elements coefficientwise.
func (r *Ring) Add(lhs, rhs Polynomial) (Polynomial, error) {
	if err := r.validatePair(lhs, rhs); err != nil {
		return Polynomial{}, err
	}
	result := r.zeroPolynomial()
	for i := range result.coefficients {
		result.coefficients[i].Add(lhs.coefficients[i], rhs.coefficients[i])
	}
	return result, nil
}

// Sub subtracts two ring elements coefficientwise.
func (r *Ring) Sub(lhs, rhs Polynomial) (Polynomial, error) {
	if err := r.validatePair(lhs, rhs); err != nil {
		return Polynomial{}, err
	}
	result := r.zeroPolynomial()
	for i := range result.coefficients {
		result.coefficients[i].Sub(lhs.coefficients[i], rhs.coefficients[i])
	}
	return result, nil
}

// Mul multiplies two elements and reduces X^n to X-2.
func (r *Ring) Mul(lhs, rhs Polynomial) (Polynomial, error) {
	if err := r.validatePair(lhs, rhs); err != nil {
		return Polynomial{}, err
	}
	n := int(r.bits)
	temporary := make([]*big.Float, 2*n-1)
	for i := range temporary {
		temporary[i] = r.newFloat()
	}
	product := r.newFloat()
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			product.Mul(lhs.coefficients[i], rhs.coefficients[j])
			temporary[i+j].Add(temporary[i+j], product)
		}
	}

	twice := r.newFloat()
	for degree := len(temporary) - 1; degree >= n; degree-- {
		// X^degree = X^(degree-n+1) - 2*X^(degree-n).
		temporary[degree-n+1].Add(temporary[degree-n+1], temporary[degree])
		twice.Mul(temporary[degree], new(big.Float).SetPrec(r.prec).SetInt64(2))
		temporary[degree-n].Sub(temporary[degree-n], twice)
	}

	result := r.zeroPolynomial()
	for i := 0; i < n; i++ {
		result.coefficients[i].Set(temporary[i])
	}
	return result, nil
}

// MulTau multiplies an element by X-2 in the quotient ring.
func (r *Ring) MulTau(value Polynomial) (Polynomial, error) {
	return r.Mul(value, r.Tau())
}

func (r *Ring) zeroPolynomial() Polynomial {
	coefficients := make([]*big.Float, int(r.bits))
	for i := range coefficients {
		coefficients[i] = r.newFloat()
	}
	return Polynomial{bits: r.bits, precision: r.prec, coefficients: coefficients}
}

func (r *Ring) newFloat() *big.Float {
	return new(big.Float).SetPrec(r.prec).SetMode(big.ToNearestEven)
}

func (r *Ring) validate(value Polynomial) error {
	if value.bits != r.bits || len(value.coefficients) != int(r.bits) {
		return fmt.Errorf("z2n: polynomial belongs to word size %d, ring uses %d", value.bits, r.bits)
	}
	if value.precision != r.prec {
		return fmt.Errorf("z2n: polynomial precision %d differs from ring precision %d", value.precision, r.prec)
	}
	epsilon := r.canonicalEpsilon()
	for i, coefficient := range value.coefficients {
		if coefficient == nil {
			return fmt.Errorf("z2n: polynomial coefficient %d is nil", i)
		}
		if coefficient.Prec() != r.prec {
			return fmt.Errorf("z2n: polynomial coefficient %d has precision %d, want %d", i, coefficient.Prec(), r.prec)
		}
		if shifted := r.newFloat().Sub(coefficient, epsilon); shifted.Cmp(coefficient) == 0 {
			return fmt.Errorf(
				"z2n: polynomial coefficient %d cannot resolve canonical epsilon 2^(-%d) at %d-bit precision",
				i, int(r.bits)+1, r.prec,
			)
		}
	}
	return nil
}

func (r *Ring) canonicalEpsilon() *big.Float {
	return r.newFloat().SetMantExp(r.newFloat().SetInt64(1), -int(r.bits)-1)
}

func (r *Ring) validatePair(lhs, rhs Polynomial) error {
	if err := r.validate(lhs); err != nil {
		return err
	}
	return r.validate(rhs)
}
