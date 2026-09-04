package evaluator

import (
	"fmt"
	"math"
	"math/big"

	"github.com/nc26676027/LCPDTE/integer/z2n"
	"github.com/nc26676027/LCPDTE/lattigo/utils/bignum"
)

// DecodeDiagnostics quantifies the strict-decoding safety margin after CKKS
// decryption. Values are converted to float64 only for reporting; root
// transforms, coefficient recovery, and rounding decisions remain at the
// configured arbitrary precision.
type DecodeDiagnostics struct {
	// MaxRootError is the maximum distance from a decoded slot to the exact
	// representative selected by strict coefficient rounding. Arithmetic mode
	// compares against tau^{-1} times the rounded integer polynomial; Short mode
	// compares against that integer polynomial directly. This preserves valid
	// non-canonical representatives of the same residue class.
	MaxRootError float64
	// MinimumRoundingMargin is the smallest distance from a recovered
	// tau-multiplied coefficient to the nearest half-integer boundary.
	MinimumRoundingMargin float64
}

// DecryptDecodeWithDiagnostics performs the same strict decode as
// DecryptDecode and additionally reports root error and coefficient-rounding
// margin for audit and test instrumentation.
func (c *Codec) DecryptDecodeWithDiagnostics(value *Value) ([]uint64, DecodeDiagnostics, error) {
	if c == nil || c.decryptor == nil {
		return nil, DecodeDiagnostics{}, fmt.Errorf("integer/evaluator: decryption key is unavailable")
	}
	if err := c.Validate(value); err != nil {
		return nil, DecodeDiagnostics{}, err
	}
	plaintext := c.decryptor.DecryptNew(value.Ciphertext)
	slots := make([]*bignum.Complex, c.parameters.CKKS.MaxSlots())
	if err := c.encoder.Decode(plaintext, slots); err != nil {
		return nil, DecodeDiagnostics{}, fmt.Errorf("integer/evaluator: decode CKKS slots: %w", err)
	}

	diagnostics := DecodeDiagnostics{MinimumRoundingMargin: math.Inf(1)}
	words := make([]uint64, value.Metadata.WordCount)
	blockSize := value.Metadata.SlotsPerWord
	for wordIndex := range words {
		block := slots[wordIndex*blockSize : (wordIndex+1)*blockSize]
		rawPolynomial, err := c.ring.FromRootSlots(block)
		if err != nil {
			return nil, DecodeDiagnostics{}, fmt.Errorf("integer/evaluator: recover word %d polynomial: %w", wordIndex, err)
		}
		arithmeticPolynomial, err := c.arithmeticPolynomial(rawPolynomial, value.Metadata.Parameters.Mode)
		if err != nil {
			return nil, DecodeDiagnostics{}, fmt.Errorf("integer/evaluator: normalize word %d representation: %w", wordIndex, err)
		}
		word, err := c.ring.DecodeArithmetic(arithmeticPolynomial)
		if err != nil {
			return nil, DecodeDiagnostics{}, fmt.Errorf("integer/evaluator: recover word %d: %w", wordIndex, err)
		}
		if err := c.validateRawWord(word); err != nil {
			return nil, DecodeDiagnostics{}, fmt.Errorf("integer/evaluator: recovered word %d: %w", wordIndex, err)
		}
		words[wordIndex] = word

		timesTau, err := c.ring.MulTau(arithmeticPolynomial)
		if err != nil {
			return nil, DecodeDiagnostics{}, fmt.Errorf("integer/evaluator: word %d multiply by tau for diagnostics: %w", wordIndex, err)
		}
		roundedCoefficients := make([]*big.Float, int(c.parameters.WordBits))
		for coefficientIndex, coefficient := range timesTau.Coefficients() {
			margin := diagnosticFloat(roundingMargin(coefficient, c.parameters.EncoderPrecision))
			if margin < diagnostics.MinimumRoundingMargin {
				diagnostics.MinimumRoundingMargin = margin
			}
			roundedCoefficients[coefficientIndex] = roundedFloat(coefficient, c.parameters.EncoderPrecision)
		}
		integerPolynomial, err := c.ring.NewPolynomial(roundedCoefficients)
		if err != nil {
			return nil, DecodeDiagnostics{}, fmt.Errorf("integer/evaluator: word %d construct rounded polynomial: %w", wordIndex, err)
		}
		exactPolynomial := integerPolynomial
		if value.Metadata.Parameters.Mode == Arithmetic {
			exactPolynomial, err = c.ring.Mul(integerPolynomial, c.ring.TauInverse())
			if err != nil {
				return nil, DecodeDiagnostics{}, fmt.Errorf("integer/evaluator: word %d restore arithmetic representative: %w", wordIndex, err)
			}
		}
		exactSlots, err := c.ring.ToRootSlots(exactPolynomial)
		if err != nil {
			return nil, DecodeDiagnostics{}, fmt.Errorf("integer/evaluator: reconstruct word %d root slots: %w", wordIndex, err)
		}
		for slotIndex := range block {
			errorMagnitude := complexErrorMagnitude(block[slotIndex], exactSlots[slotIndex], c.parameters.EncoderPrecision)
			if diagnosticFloat(errorMagnitude) > diagnostics.MaxRootError {
				diagnostics.MaxRootError = diagnosticFloat(errorMagnitude)
			}
		}
	}
	return words, diagnostics, nil
}

func (c *Codec) arithmeticPolynomial(polynomial z2n.Polynomial, mode Mode) (z2n.Polynomial, error) {
	switch mode {
	case Arithmetic:
		return polynomial, nil
	case Short:
		return c.ring.Mul(polynomial, c.ring.TauInverse())
	default:
		return z2n.Polynomial{}, fmt.Errorf("unsupported value mode %d", mode)
	}
}

func complexErrorMagnitude(actual, exact *bignum.Complex, precision uint) *big.Float {
	realError := new(big.Float).SetPrec(precision).Sub(actual.Real(), exact.Real())
	imaginaryError := new(big.Float).SetPrec(precision).Sub(actual.Imag(), exact.Imag())
	realSquared := new(big.Float).SetPrec(precision).Mul(realError, realError)
	imaginarySquared := new(big.Float).SetPrec(precision).Mul(imaginaryError, imaginaryError)
	return new(big.Float).SetPrec(precision).Sqrt(new(big.Float).SetPrec(precision).Add(realSquared, imaginarySquared))
}

func roundingMargin(value *big.Float, precision uint) *big.Float {
	_, integerFloat := floor(value, precision)
	fraction := new(big.Float).SetPrec(precision).Sub(value, integerFloat)
	oneMinusFraction := new(big.Float).SetPrec(precision).Sub(new(big.Float).SetPrec(precision).SetInt64(1), fraction)
	distanceToInteger := fraction
	if oneMinusFraction.Cmp(fraction) < 0 {
		distanceToInteger = oneMinusFraction
	}
	half := new(big.Float).SetPrec(precision).SetMantExp(new(big.Float).SetPrec(precision).SetInt64(1), -1)
	return new(big.Float).SetPrec(precision).Sub(half, distanceToInteger)
}

func roundedFloat(value *big.Float, precision uint) *big.Float {
	integer, integerFloat := floor(value, precision)
	fraction := new(big.Float).SetPrec(precision).Sub(value, integerFloat)
	half := new(big.Float).SetPrec(precision).SetMantExp(new(big.Float).SetPrec(precision).SetInt64(1), -1)
	if fraction.Cmp(half) >= 0 {
		integer.Add(integer, big.NewInt(1))
	}
	return new(big.Float).SetPrec(precision).SetInt(integer)
}

func floor(value *big.Float, precision uint) (*big.Int, *big.Float) {
	integer, _ := value.Int(nil) // truncates toward zero
	integerFloat := new(big.Float).SetPrec(precision).SetInt(integer)
	if value.Cmp(integerFloat) < 0 {
		integer.Sub(integer, big.NewInt(1))
		integerFloat.SetInt(integer)
	}
	return integer, integerFloat
}

func diagnosticFloat(value *big.Float) float64 {
	result, _ := value.Float64()
	return result
}
