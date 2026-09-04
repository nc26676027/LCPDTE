package z2n_test

import (
	"math/big"
	"math/rand"
	"testing"

	"github.com/nc26676027/LCPDTE/integer/z2n"
	"github.com/nc26676027/LCPDTE/lattigo/utils/bignum"
)

func TestRootConstantsRetainUpstreamFixedPointProvenance(t *testing.T) {
	ring8, err := z2n.New(z2n.Word8)
	if err != nil {
		t.Fatal(err)
	}
	constants8 := ring8.RootConstants()
	if len(constants8) != 4 {
		t.Fatalf("n=8 root constants: got %d, want 4", len(constants8))
	}
	first := constants8[0]
	if first.Real.Magnitude != "359124072811535186610690853057402903661" || !first.Real.Negative {
		t.Fatalf("n=8 first root real part changed: %+v", first.Real)
	}
	if first.Imag.Magnitude != "156682980275126563459473712549117854603" || first.Imag.Negative {
		t.Fatalf("n=8 first root imaginary part changed: %+v", first.Imag)
	}

	ring64, err := z2n.New(z2n.Word64)
	if err != nil {
		t.Fatal(err)
	}
	last := ring64.RootConstants()[31]
	if last.Real.Magnitude != "339897153198907268612807292144443989133" || last.Real.Negative {
		t.Fatalf("n=64 last root real part changed: %+v", last.Real)
	}
	if last.Imag.Magnitude != "16441351304266807328870060951377273088" || last.Imag.Negative {
		t.Fatalf("n=64 last root imaginary part changed: %+v", last.Imag)
	}
}

func TestPublishedRootsSatisfyXNMinusXPlusTwo(t *testing.T) {
	for _, bits := range []z2n.WordBits{z2n.Word8, z2n.Word16, z2n.Word32, z2n.Word64} {
		ring, err := z2n.New(bits)
		if err != nil {
			t.Fatal(err)
		}
		limit := new(big.Float).SetPrec(ring.Metadata().PrecisionBits).SetMantExp(
			new(big.Float).SetPrec(ring.Metadata().PrecisionBits).SetInt64(1), -116,
		)
		for i, root := range ring.Roots() {
			residual := evaluateModulus(root, int(bits), ring.Metadata().PrecisionBits)
			if absFloat(residual.Real()).Cmp(limit) >= 0 || absFloat(residual.Imag()).Cmp(limit) >= 0 {
				t.Fatalf("n=%d root %d residual=(%s,%s), want each component < 2^-116",
					bits, i, residual.Real().Text('e', 4), residual.Imag().Text('e', 4))
			}
		}
	}
}

func TestClosedFormVandermondeInverseRecoversCoefficients(t *testing.T) {
	for _, bits := range []z2n.WordBits{z2n.Word8, z2n.Word16, z2n.Word32, z2n.Word64} {
		ring, err := z2n.New(bits)
		if err != nil {
			t.Fatal(err)
		}
		coefficients := make([]*big.Float, int(bits))
		for i := range coefficients {
			numerator := int64((i*11)%17 - 8)
			coefficients[i] = new(big.Float).SetPrec(ring.Metadata().PrecisionBits).Quo(
				new(big.Float).SetPrec(ring.Metadata().PrecisionBits).SetInt64(numerator),
				new(big.Float).SetPrec(ring.Metadata().PrecisionBits).SetInt64(8),
			)
		}
		polynomial, err := ring.NewPolynomial(coefficients)
		if err != nil {
			t.Fatal(err)
		}
		slots, err := ring.ToRootSlots(polynomial)
		if err != nil {
			t.Fatal(err)
		}
		recovered, err := ring.FromRootSlots(slots)
		if err != nil {
			t.Fatal(err)
		}
		limit := new(big.Float).SetPrec(ring.Metadata().PrecisionBits).SetMantExp(
			new(big.Float).SetPrec(ring.Metadata().PrecisionBits).SetInt64(1), -108,
		)
		for i, got := range recovered.Coefficients() {
			difference := new(big.Float).SetPrec(ring.Metadata().PrecisionBits).Sub(got, coefficients[i])
			if absFloat(difference).Cmp(limit) >= 0 {
				t.Fatalf("n=%d coefficient %d: error %s, want < 2^-108", bits, i, difference.Text('e', 4))
			}
		}
	}
}

func TestArithmeticRootSlotsRecoverWords(t *testing.T) {
	for _, bits := range []z2n.WordBits{z2n.Word8, z2n.Word16, z2n.Word32, z2n.Word64} {
		ring, err := z2n.New(bits)
		if err != nil {
			t.Fatal(err)
		}
		mask := wordMask(bits)
		values := []uint64{0, 1, 2, mask >> 1, (mask >> 1) + 1, mask - 1, mask}
		rng := rand.New(rand.NewSource(0x726f6f74 + int64(bits)))
		for i := 0; i < 16; i++ {
			values = append(values, rng.Uint64()&mask)
		}
		for _, word := range values {
			slots := ring.ArithmeticRootSlots(word)
			if len(slots) != int(bits)/2 {
				t.Fatalf("n=%d slot count: got %d, want %d", bits, len(slots), int(bits)/2)
			}
			got, err := ring.RecoverWord(slots)
			if err != nil {
				t.Fatalf("n=%d recover %d: %v", bits, word, err)
			}
			if got != word {
				t.Fatalf("n=%d root-slot round-trip %d: got %d", bits, word, got)
			}
		}
	}
}

func TestComplex128ConversionIsDiagnosticAndDoesNotAliasSlots(t *testing.T) {
	ring, err := z2n.New(z2n.Word8)
	if err != nil {
		t.Fatal(err)
	}
	slots := ring.ArithmeticRootSlots(173)
	diagnostic := z2n.Complex128(slots)
	if len(diagnostic) != len(slots) {
		t.Fatalf("diagnostic slot count: got %d, want %d", len(diagnostic), len(slots))
	}
	original := new(big.Float).Set(slots[0].Real())
	slots[0].Real().SetInt64(12345)
	if real(diagnostic[0]) == 12345 || original.Cmp(slots[0].Real()) == 0 {
		t.Fatal("diagnostic conversion unexpectedly aliases high-precision slots")
	}
}

func evaluateModulus(root *bignum.Complex, n int, precision uint) *bignum.Complex {
	power := complexOne(precision)
	for i := 0; i < n; i++ {
		power = complexMul(power, root, precision)
	}
	result := complexSub(power, root, precision)
	result.Real().Add(result.Real(), new(big.Float).SetPrec(precision).SetInt64(2))
	return result
}

func complexOne(precision uint) *bignum.Complex {
	return &bignum.Complex{
		new(big.Float).SetPrec(precision).SetInt64(1),
		new(big.Float).SetPrec(precision),
	}
}

func complexMul(lhs, rhs *bignum.Complex, precision uint) *bignum.Complex {
	ac := new(big.Float).SetPrec(precision).Mul(lhs.Real(), rhs.Real())
	bd := new(big.Float).SetPrec(precision).Mul(lhs.Imag(), rhs.Imag())
	ad := new(big.Float).SetPrec(precision).Mul(lhs.Real(), rhs.Imag())
	bc := new(big.Float).SetPrec(precision).Mul(lhs.Imag(), rhs.Real())
	return &bignum.Complex{
		new(big.Float).SetPrec(precision).Sub(ac, bd),
		new(big.Float).SetPrec(precision).Add(ad, bc),
	}
}

func complexSub(lhs, rhs *bignum.Complex, precision uint) *bignum.Complex {
	return &bignum.Complex{
		new(big.Float).SetPrec(precision).Sub(lhs.Real(), rhs.Real()),
		new(big.Float).SetPrec(precision).Sub(lhs.Imag(), rhs.Imag()),
	}
}

func absFloat(value *big.Float) *big.Float {
	return new(big.Float).SetPrec(value.Prec()).Abs(value)
}
