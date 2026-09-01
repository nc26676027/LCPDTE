package z2n

import "math/big"

// BinaryEncode returns [m]_tau: the little-endian bit polynomial whose
// evaluation at X=2 is m modulo 2^n.
func (r *Ring) BinaryEncode(word uint64) Polynomial {
	word &= r.wordMask()
	result := r.zeroPolynomial()
	for i := 0; i < int(r.bits); i++ {
		if (word>>uint(i))&1 == 1 {
			result.coefficients[i].SetInt64(1)
		}
	}
	return result
}

// ArithmeticEncode returns tau^{-1}[m]_tau in R[X]/(X^n-X+2).
func (r *Ring) ArithmeticEncode(word uint64) Polynomial {
	result, err := r.Mul(r.BinaryEncode(word), r.TauInverse())
	if err != nil {
		// Both operands were created by r, so this is unreachable.
		panic(err)
	}
	return result
}

// DecodeArithmetic implements the order prescribed by Gao--Zheng:
// multiply by tau, round every coefficient independently, then evaluate the
// integer polynomial at X=2, and only then reduce modulo 2^n.
func (r *Ring) DecodeArithmetic(encoded Polynomial) (uint64, error) {
	if err := r.validate(encoded); err != nil {
		return 0, err
	}
	timesTau, err := r.MulTau(encoded)
	if err != nil {
		return 0, err
	}

	rounded := make([]*big.Int, int(r.bits))
	for i, coefficient := range timesTau.coefficients {
		rounded[i] = r.roundToInt(coefficient)
	}

	// Horner evaluation is equivalent to Euclidean division by X-2, while
	// making the mandated coefficient-rounding boundary explicit above.
	value := new(big.Int).Set(rounded[len(rounded)-1])
	for i := len(rounded) - 2; i >= 0; i-- {
		value.Lsh(value, 1)
		value.Add(value, rounded[i])
	}
	modulus := new(big.Int).Lsh(big.NewInt(1), uint(r.bits))
	value.Mod(value, modulus)
	return value.Uint64(), nil
}

// CanonicalizeArithmetic reduces every coefficient modulo one using the
// epsilon-shifted boundary from Gao--Zheng's [.]_I operation. For word size n,
// epsilon is 2^(-n-1), so the represented interval is (-1+epsilon, epsilon].
func (r *Ring) CanonicalizeArithmetic(value Polynomial) (Polynomial, error) {
	if err := r.validate(value); err != nil {
		return Polynomial{}, err
	}
	epsilon := r.canonicalEpsilon()
	result := r.zeroPolynomial()
	for i, coefficient := range value.coefficients {
		shifted := r.newFloat().Sub(coefficient, epsilon)
		ceiling := r.ceilToInt(shifted)
		ceilingFloat := r.newFloat().SetInt(ceiling)
		result.coefficients[i].Sub(shifted, ceilingFloat)
		result.coefficients[i].Add(result.coefficients[i], epsilon)
	}
	return result, nil
}

// AddArithmetic adds two arithmetic encodings modulo 2^n.
func (r *Ring) AddArithmetic(lhs, rhs Polynomial) (Polynomial, error) {
	sum, err := r.Add(lhs, rhs)
	if err != nil {
		return Polynomial{}, err
	}
	return r.CanonicalizeArithmetic(sum)
}

// SubArithmetic subtracts two arithmetic encodings modulo 2^n.
func (r *Ring) SubArithmetic(lhs, rhs Polynomial) (Polynomial, error) {
	difference, err := r.Sub(lhs, rhs)
	if err != nil {
		return Polynomial{}, err
	}
	return r.CanonicalizeArithmetic(difference)
}

// MulArithmetic multiplies two arithmetic encodings. The extra tau converts
// tau^{-2}[m]_tau[m']_tau back to the standard tau^{-1} representation.
func (r *Ring) MulArithmetic(lhs, rhs Polynomial) (Polynomial, error) {
	product, err := r.Mul(lhs, rhs)
	if err != nil {
		return Polynomial{}, err
	}
	product, err = r.MulTau(product)
	if err != nil {
		return Polynomial{}, err
	}
	return r.CanonicalizeArithmetic(product)
}

func (r *Ring) wordMask() uint64 {
	if r.bits == Word64 {
		return ^uint64(0)
	}
	return (uint64(1) << r.bits) - 1
}

// roundToInt rounds to nearest with half-integers toward +infinity, matching
// the upstream BigFixedPoint::round convention.
func (r *Ring) roundToInt(value *big.Float) *big.Int {
	floor := r.floorToInt(value)
	floorFloat := r.newFloat().SetInt(floor)
	fraction := r.newFloat().Sub(value, floorFloat)
	half := r.newFloat().SetMantExp(r.newFloat().SetInt64(1), -1)
	if fraction.Cmp(half) >= 0 {
		return new(big.Int).Add(floor, big.NewInt(1))
	}
	return floor
}

func (r *Ring) floorToInt(value *big.Float) *big.Int {
	integer, _ := value.Int(nil) // truncates toward zero
	integerFloat := r.newFloat().SetInt(integer)
	if value.Cmp(integerFloat) < 0 {
		integer.Sub(integer, big.NewInt(1))
	}
	return integer
}

func (r *Ring) ceilToInt(value *big.Float) *big.Int {
	integer, _ := value.Int(nil) // truncates toward zero
	integerFloat := r.newFloat().SetInt(integer)
	if value.Cmp(integerFloat) > 0 {
		integer.Add(integer, big.NewInt(1))
	}
	return integer
}
