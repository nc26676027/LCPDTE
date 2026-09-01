package z2n_test

import (
	"fmt"
	"math/big"
	"math/rand"
	"testing"

	"dt_go/integer/z2n"
)

func TestNewRingPublishesAuditableMetadata(t *testing.T) {
	for _, bits := range []z2n.WordBits{z2n.Word8, z2n.Word16, z2n.Word32, z2n.Word64} {
		ring, err := z2n.New(bits)
		if err != nil {
			t.Fatalf("New(%d): %v", bits, err)
		}

		metadata := ring.Metadata()
		if metadata.WordBits != bits {
			t.Fatalf("word bits: got %d, want %d", metadata.WordBits, bits)
		}
		if metadata.PrecisionBits < 128 {
			t.Fatalf("precision: got %d bits, want at least 128", metadata.PrecisionBits)
		}
		if metadata.RootFractionBits != 128 {
			t.Fatalf("root fixed-point scale: got %d, want 128", metadata.RootFractionBits)
		}
		if metadata.RootCount != int(bits)/2 {
			t.Fatalf("root count: got %d, want %d", metadata.RootCount, int(bits)/2)
		}
		if metadata.PolynomialModulus != "X^n-X+2" || metadata.Tau != "X-2" {
			t.Fatalf("unexpected ring metadata: %+v", metadata)
		}
		if metadata.RootSourceCommit != "08f1eb87434e7be072cba889270a8400bbffc08e" {
			t.Fatalf("root source commit: got %q", metadata.RootSourceCommit)
		}
	}
}

func TestBinaryAndArithmeticEncodingRoundTripEveryEightBitWord(t *testing.T) {
	ring, err := z2n.New(z2n.Word8)
	if err != nil {
		t.Fatal(err)
	}

	bits := ring.BinaryEncode(0b10100101).Coefficients()
	assertIntegerCoefficients(t, bits, []int64{1, 0, 1, 0, 0, 1, 0, 1})

	for word := uint64(0); word < 256; word++ {
		encoded := ring.ArithmeticEncode(word)
		decoded, err := ring.DecodeArithmetic(encoded)
		if err != nil {
			t.Fatalf("decode %d: %v", word, err)
		}
		if decoded != word {
			t.Fatalf("round-trip %d: got %d", word, decoded)
		}
	}
}

// This is the independent plaintext oracle for the first encrypted A2A-I
// slice. Adding an integral coefficient polynomial changes the arithmetic
// representative but not its residue because tau=X-2 vanishes at X=2.
// Coefficient-wise canonicalization must remove that overflow exactly.
func TestArithmeticIntegralOverflowPreservesResidueAndCanonicalizes(t *testing.T) {
	ring, err := z2n.New(z2n.Word8)
	if err != nil {
		t.Fatal(err)
	}
	overflow, err := ring.NewPolynomial(intCoefficients(3, -2, 1, 0, 0, 0, 0, 0))
	if err != nil {
		t.Fatal(err)
	}

	for _, word := range []uint64{0x00, 0x01, 0x0f, 0x10, 0x7f, 0x80, 0xff, 0xa5} {
		encoded := ring.ArithmeticEncode(word)
		withOverflow, err := ring.Add(encoded, overflow)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := ring.DecodeArithmetic(withOverflow); err != nil || got != word {
			t.Fatalf("word %#02x overflow decode: got %#02x, err=%v", word, got, err)
		}

		canonical, err := ring.CanonicalizeArithmetic(withOverflow)
		if err != nil {
			t.Fatal(err)
		}
		wantCanonical, err := ring.CanonicalizeArithmetic(encoded)
		if err != nil {
			t.Fatal(err)
		}
		gotCoefficients := canonical.Coefficients()
		wantCoefficients := wantCanonical.Coefficients()
		for i := range wantCoefficients {
			if gotCoefficients[i].Cmp(wantCoefficients[i]) != 0 {
				t.Fatalf(
					"word %#02x coefficient %d: canonical got %s, want %s",
					word,
					i,
					gotCoefficients[i].Text('g', -1),
					wantCoefficients[i].Text('g', -1),
				)
			}
		}
	}
}

func TestEightBitArithmeticAddAndMultiplyWrapExhaustively(t *testing.T) {
	ring, err := z2n.New(z2n.Word8)
	if err != nil {
		t.Fatal(err)
	}
	encoded := make([]z2n.Polynomial, 256)
	for word := range encoded {
		encoded[word] = ring.ArithmeticEncode(uint64(word))
	}

	for lhs := uint64(0); lhs < 256; lhs++ {
		for rhs := uint64(0); rhs < 256; rhs++ {
			sum, err := ring.AddArithmetic(encoded[lhs], encoded[rhs])
			if err != nil {
				t.Fatalf("add %d, %d: %v", lhs, rhs, err)
			}
			gotSum, err := ring.DecodeArithmetic(sum)
			if err != nil {
				t.Fatalf("decode add %d, %d: %v", lhs, rhs, err)
			}
			if want := (lhs + rhs) & 0xff; gotSum != want {
				t.Fatalf("%d + %d: got %d, want %d", lhs, rhs, gotSum, want)
			}

			product, err := ring.MulArithmetic(encoded[lhs], encoded[rhs])
			if err != nil {
				t.Fatalf("multiply %d, %d: %v", lhs, rhs, err)
			}
			gotProduct, err := ring.DecodeArithmetic(product)
			if err != nil {
				t.Fatalf("decode multiply %d, %d: %v", lhs, rhs, err)
			}
			if want := (lhs * rhs) & 0xff; gotProduct != want {
				t.Fatalf("%d * %d: got %d, want %d", lhs, rhs, gotProduct, want)
			}
		}
	}
}

func TestArithmeticRoundTripsAndWrapsAtLargerWordSizes(t *testing.T) {
	for _, bits := range []z2n.WordBits{z2n.Word16, z2n.Word32, z2n.Word64} {
		ring, err := z2n.New(bits)
		if err != nil {
			t.Fatal(err)
		}
		mask := wordMask(bits)
		boundaries := []uint64{0, 1, 2, mask >> 1, (mask >> 1) + 1, mask - 1, mask}
		rng := rand.New(rand.NewSource(0x5a3236 + int64(bits)))
		values := append([]uint64(nil), boundaries...)
		for i := 0; i < 64; i++ {
			values = append(values, rng.Uint64()&mask)
		}

		for i, lhs := range values {
			encoded := ring.ArithmeticEncode(lhs)
			decoded, err := ring.DecodeArithmetic(encoded)
			if err != nil || decoded != lhs {
				t.Fatalf("n=%d round-trip %d: got %d, err=%v", bits, lhs, decoded, err)
			}

			rhs := values[(i*17+3)%len(values)]
			sum, err := ring.AddArithmetic(encoded, ring.ArithmeticEncode(rhs))
			if err != nil {
				t.Fatal(err)
			}
			gotSum, err := ring.DecodeArithmetic(sum)
			if err != nil || gotSum != (lhs+rhs)&mask {
				t.Fatalf("n=%d add %d, %d: got %d, err=%v", bits, lhs, rhs, gotSum, err)
			}

			product, err := ring.MulArithmetic(encoded, ring.ArithmeticEncode(rhs))
			if err != nil {
				t.Fatal(err)
			}
			gotProduct, err := ring.DecodeArithmetic(product)
			if err != nil || gotProduct != (lhs*rhs)&mask {
				t.Fatalf("n=%d multiply %d, %d: got %d, err=%v", bits, lhs, rhs, gotProduct, err)
			}
		}
	}
}

func TestDecodeRoundsEveryCoefficientBeforeEvaluationAtTwo(t *testing.T) {
	ring, err := z2n.New(z2n.Word8)
	if err != nil {
		t.Fatal(err)
	}
	coefficients := make([]*big.Float, 8)
	for i := range coefficients {
		coefficients[i] = new(big.Float).SetPrec(z2n.DefaultPrecision)
	}
	// If q(2) were evaluated before rounding, 0.49 + 2*0.49 would round to 1.
	// The Gao--Zheng decoder first rounds q's coefficients, yielding zero.
	coefficients[0].Quo(big.NewFloat(49), big.NewFloat(100)).SetPrec(z2n.DefaultPrecision)
	coefficients[1].Quo(big.NewFloat(49), big.NewFloat(100)).SetPrec(z2n.DefaultPrecision)
	q, err := ring.NewPolynomial(coefficients)
	if err != nil {
		t.Fatal(err)
	}
	encodedLike, err := ring.Mul(q, ring.TauInverse())
	if err != nil {
		t.Fatal(err)
	}
	got, err := ring.DecodeArithmetic(encodedLike)
	if err != nil {
		t.Fatal(err)
	}
	if got != 0 {
		t.Fatalf("strict coefficient-first decode: got %d, want 0", got)
	}
}

func TestCanonicalizeArithmeticMatchesUpstreamEpsilonBoundary(t *testing.T) {
	for _, bits := range []z2n.WordBits{z2n.Word8, z2n.Word16, z2n.Word32, z2n.Word64} {
		t.Run(fmt.Sprintf("n=%d", bits), func(t *testing.T) {
			ring, err := z2n.New(bits)
			if err != nil {
				t.Fatal(err)
			}

			epsilonExponent := -int(bits) - 1
			epsilon := new(big.Float).SetPrec(z2n.DefaultPrecision).SetMantExp(
				new(big.Float).SetPrec(z2n.DefaultPrecision).SetInt64(1),
				epsilonExponent,
			)
			below := new(big.Float).SetPrec(z2n.DefaultPrecision).SetMantExp(
				new(big.Float).SetPrec(z2n.DefaultPrecision).SetInt64(1),
				epsilonExponent-1,
			)
			above := new(big.Float).SetPrec(z2n.DefaultPrecision).Add(
				epsilon,
				new(big.Float).SetPrec(z2n.DefaultPrecision).SetMantExp(
					new(big.Float).SetPrec(z2n.DefaultPrecision).SetInt64(1),
					epsilonExponent-3,
				),
			)

			tests := []struct {
				name  string
				input *big.Float
				want  *big.Float
			}{
				{name: "below epsilon stays positive", input: below, want: below},
				{name: "epsilon stays positive", input: epsilon, want: epsilon},
				{
					name:  "above epsilon wraps below zero",
					input: above,
					want: new(big.Float).SetPrec(z2n.DefaultPrecision).Sub(
						above,
						new(big.Float).SetPrec(z2n.DefaultPrecision).SetInt64(1),
					),
				},
			}

			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					coefficients := make([]*big.Float, int(bits))
					for i := range coefficients {
						coefficients[i] = new(big.Float).SetPrec(z2n.DefaultPrecision)
					}
					coefficients[0].Set(test.input)
					input, err := ring.NewPolynomial(coefficients)
					if err != nil {
						t.Fatal(err)
					}
					got, err := ring.CanonicalizeArithmetic(input)
					if err != nil {
						t.Fatal(err)
					}
					gotCoefficient := got.Coefficients()[0]
					if gotCoefficient.Cmp(test.want) != 0 {
						t.Fatalf("got %s, want %s", gotCoefficient.Text('g', -1), test.want.Text('g', -1))
					}
				})
			}
		})
	}
}

func wordMask(bits z2n.WordBits) uint64 {
	if bits == z2n.Word64 {
		return ^uint64(0)
	}
	return (uint64(1) << bits) - 1
}

func TestPolynomialArithmeticReducesModuloXNMinusXPlusTwo(t *testing.T) {
	ring, err := z2n.New(z2n.Word8)
	if err != nil {
		t.Fatal(err)
	}

	x7, err := ring.NewPolynomial(intCoefficients(0, 0, 0, 0, 0, 0, 0, 1))
	if err != nil {
		t.Fatal(err)
	}
	x, err := ring.NewPolynomial(intCoefficients(0, 1, 0, 0, 0, 0, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	product, err := ring.Mul(x7, x)
	if err != nil {
		t.Fatal(err)
	}
	assertIntegerCoefficients(t, product.Coefficients(), []int64{-2, 1, 0, 0, 0, 0, 0, 0})

	sum, err := ring.Add(product, x)
	if err != nil {
		t.Fatal(err)
	}
	difference, err := ring.Sub(sum, x)
	if err != nil {
		t.Fatal(err)
	}
	assertIntegerCoefficients(t, difference.Coefficients(), []int64{-2, 1, 0, 0, 0, 0, 0, 0})
}

func TestTauInverseIsTheMultiplicativeInverseOfTau(t *testing.T) {
	for _, bits := range []z2n.WordBits{z2n.Word8, z2n.Word16, z2n.Word32, z2n.Word64} {
		ring, err := z2n.New(bits)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ring.Mul(ring.Tau(), ring.TauInverse())
		if err != nil {
			t.Fatal(err)
		}
		want := make([]int64, int(bits))
		want[0] = 1
		assertIntegerCoefficients(t, got.Coefficients(), want)
	}
}

func intCoefficients(values ...int64) []*big.Float {
	result := make([]*big.Float, len(values))
	for i, value := range values {
		result[i] = new(big.Float).SetPrec(z2n.DefaultPrecision).SetInt64(value)
	}
	return result
}

func assertIntegerCoefficients(t *testing.T, got []*big.Float, want []int64) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("coefficient count: got %d, want %d", len(got), len(want))
	}
	for i := range got {
		wantFloat := new(big.Float).SetPrec(got[i].Prec()).SetInt64(want[i])
		if got[i].Cmp(wantFloat) != 0 {
			t.Fatalf("coefficient %d: got %s, want %d", i, got[i].Text('g', -1), want[i])
		}
	}
}

func TestNewRingRejectsUnsupportedWordSizeAndPrecision(t *testing.T) {
	if _, err := z2n.New(z2n.WordBits(12)); err == nil {
		t.Fatal("New(12) succeeded, want an unsupported-word-size error")
	}
	if _, err := z2n.NewWithPrecision(z2n.Word8, 127); err == nil {
		t.Fatal("NewWithPrecision(..., 127) succeeded, want a precision error")
	}
}

func TestNewPolynomialEnforcesCanonicalEpsilonSignificancePerCoefficient(t *testing.T) {
	for _, bits := range []z2n.WordBits{z2n.Word8, z2n.Word16, z2n.Word32, z2n.Word64} {
		t.Run(fmt.Sprintf("n=%d", bits), func(t *testing.T) {
			ring, err := z2n.New(bits)
			if err != nil {
				t.Fatal(err)
			}

			// Mixed caller precision is admissible when the imported values stay
			// inside the ring precision's canonicalization domain.
			mixed := make([]*big.Float, int(bits))
			for i := range mixed {
				mixed[i] = new(big.Float).SetPrec(53).SetInt64(int64(i & 1))
			}
			mixed[1] = new(big.Float).SetPrec(512).SetMantExp(
				new(big.Float).SetPrec(512).SetInt64(1),
				-int(bits)-2,
			)
			if _, err := ring.NewPolynomial(mixed); err != nil {
				t.Fatalf("safe mixed-precision polynomial rejected: %v", err)
			}

			// At 2^300 with a 256-bit significand, subtracting Gao's
			// epsilon=2^(-n-1) is unobservable. Import must fail instead of
			// silently changing the canonical interval.
			tooLarge := make([]*big.Float, int(bits))
			for i := range tooLarge {
				tooLarge[i] = new(big.Float).SetPrec(512)
			}
			tooLarge[0].SetMantExp(new(big.Float).SetPrec(512).SetInt64(1), 300)
			if _, err := ring.NewPolynomial(tooLarge); err == nil {
				t.Fatal("NewPolynomial accepted a coefficient that cannot resolve the canonical epsilon")
			}
		})
	}
}
