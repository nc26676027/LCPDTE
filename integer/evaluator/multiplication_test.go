package evaluator_test

import (
	"fmt"
	"math"
	"math/rand"
	"slices"
	"strings"
	"testing"

	inteval "dt_go/integer/evaluator"
	"dt_go/integer/z2n"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func TestN8AllPairsMultShortAndMultFullSIMDBatches(t *testing.T) {
	codec, parameters := testMultiplicationCodec(t, z2n.Word8, true)
	capacity := parameters.WordCapacity()
	const pairCount = 256 * 256
	wantBatches := (pairCount + capacity - 1) / capacity
	batches := 0
	maxRootError := 0.0
	minimumRoundingMargin := math.Inf(1)

	for start := 0; start < pairCount; start += capacity {
		end := min(start+capacity, pairCount)
		lhsWords := make([]uint64, end-start)
		rhsWords := make([]uint64, end-start)
		wantWords := make([]uint64, end-start)
		for i := range lhsWords {
			pair := start + i
			lhsWords[i] = uint64(pair >> 8)
			rhsWords[i] = uint64(pair & 0xff)
			wantWords[i] = (lhsWords[i] * rhsWords[i]) & 0xff
		}

		lhs, err := codec.EncodeEncrypt(lhsWords)
		if err != nil {
			t.Fatalf("batch %d lhs: %v", batches, err)
		}
		rhsArithmetic, err := codec.EncodeEncrypt(rhsWords)
		if err != nil {
			t.Fatalf("batch %d arithmetic rhs: %v", batches, err)
		}
		rhsShort, err := codec.EncodeShortEncrypt(rhsWords)
		if err != nil {
			t.Fatalf("batch %d short rhs: %v", batches, err)
		}

		shortProduct, err := codec.MultShort(lhs, rhsShort)
		if err != nil {
			t.Fatalf("batch %d MultShort: %v", batches, err)
		}
		fullProduct, err := codec.MultFull(lhs, rhsArithmetic)
		if err != nil {
			t.Fatalf("batch %d MultFull: %v", batches, err)
		}
		for name, product := range map[string]*inteval.Value{"short": shortProduct, "full": fullProduct} {
			got, diagnostics, err := codec.DecryptDecodeWithDiagnostics(product)
			if err != nil {
				t.Fatalf("batch %d %s decode: %v", batches, name, err)
			}
			if !slices.Equal(got, wantWords) {
				for i := range got {
					if got[i] != wantWords[i] {
						t.Fatalf("batch %d %s pair (%d,%d): got %d, want %d", batches, name, lhsWords[i], rhsWords[i], got[i], wantWords[i])
					}
				}
			}
			maxRootError = max(maxRootError, diagnostics.MaxRootError)
			minimumRoundingMargin = min(minimumRoundingMargin, diagnostics.MinimumRoundingMargin)
		}
		batches++
	}

	if batches != wantBatches {
		t.Fatalf("processed %d SIMD batches, want %d", batches, wantBatches)
	}
	if minimumRoundingMargin <= 0.45 {
		t.Fatalf("minimum exhaustive n=8 rounding margin %.6g is too small", minimumRoundingMargin)
	}
	if maxRootError >= 1e-4 {
		t.Fatalf("maximum exhaustive n=8 root error %.6g is too large", maxRootError)
	}
	t.Logf("exhausted %d ordered n=8 pairs in %d ciphertext batches (capacity=%d); min rounding margin=%.6g, max root error=%.6g", pairCount, batches, capacity, minimumRoundingMargin, maxRootError)
}

func TestMultiplicationBoundariesAndFixedRandomAtLargerWidths(t *testing.T) {
	for _, bits := range []z2n.WordBits{z2n.Word16, z2n.Word32, z2n.Word64} {
		t.Run(fmt.Sprintf("n=%d", bits), func(t *testing.T) {
			codec, parameters := testMultiplicationCodec(t, bits, true)
			mask := maskFor(bits)
			lhsWords := []uint64{0, 1, mask, mask, mask >> 1, (mask >> 1) + 1, 2, 3}
			rhsWords := []uint64{mask, mask, 0, 2, 2, 2, mask, mask}
			randomSource := rand.New(rand.NewSource(0x5eed + int64(bits)))
			for len(lhsWords) < min(parameters.WordCapacity(), 16) {
				lhsWords = append(lhsWords, randomSource.Uint64()&mask)
				rhsWords = append(rhsWords, randomSource.Uint64()&mask)
			}
			want := make([]uint64, len(lhsWords))
			for i := range want {
				want[i] = (lhsWords[i] * rhsWords[i]) & mask
			}

			lhs, err := codec.EncodeEncrypt(lhsWords)
			if err != nil {
				t.Fatal(err)
			}
			rhsArithmetic, err := codec.EncodeEncrypt(rhsWords)
			if err != nil {
				t.Fatal(err)
			}
			rhsShort, err := codec.EncodeShortEncrypt(rhsWords)
			if err != nil {
				t.Fatal(err)
			}
			shortProduct, err := codec.MultShort(lhs, rhsShort)
			if err != nil {
				t.Fatal(err)
			}
			fullProduct, err := codec.MultFull(lhs, rhsArithmetic)
			if err != nil {
				t.Fatal(err)
			}
			for name, product := range map[string]*inteval.Value{"short": shortProduct, "full": fullProduct} {
				got, diagnostics, err := codec.DecryptDecodeWithDiagnostics(product)
				if err != nil {
					t.Fatalf("%s decode: %v", name, err)
				}
				assertWordsEqual(t, got, want)
				if diagnostics.MinimumRoundingMargin <= 0.40 {
					t.Fatalf("%s rounding margin %.6g is too small", name, diagnostics.MinimumRoundingMargin)
				}
				if diagnostics.MaxRootError >= 1e-4 {
					t.Fatalf("%s root error %.6g is too large", name, diagnostics.MaxRootError)
				}
				t.Logf("%s: min rounding margin=%.6g, max root error=%.6g", name, diagnostics.MinimumRoundingMargin, diagnostics.MaxRootError)
			}
		})
	}
}

func TestMultiplicationRejectsModesPackingScaleLevelsAndMissingRelinearizationKey(t *testing.T) {
	codec, _ := testMultiplicationCodec(t, z2n.Word8, true)
	arithmetic, err := codec.EncodeEncrypt([]uint64{3, 7})
	if err != nil {
		t.Fatal(err)
	}
	otherArithmetic, err := codec.EncodeEncrypt([]uint64{5, 11})
	if err != nil {
		t.Fatal(err)
	}
	short, err := codec.EncodeShortEncrypt([]uint64{5, 11})
	if err != nil {
		t.Fatal(err)
	}

	assertMultiplicationErrorContains(t, "MultShort mode", func() error {
		_, err := codec.MultShort(arithmetic, otherArithmetic)
		return err
	}, "operand modes")
	assertMultiplicationErrorContains(t, "MultFull mode", func() error {
		_, err := codec.MultFull(arithmetic, short)
		return err
	}, "operand modes")

	oneWordShort, err := codec.EncodeShortEncrypt([]uint64{5})
	if err != nil {
		t.Fatal(err)
	}
	assertMultiplicationErrorContains(t, "packing", func() error {
		_, err := codec.MultShort(arithmetic, oneWordShort)
		return err
	}, "packing differs")

	scaleMismatch := short.CopyNew()
	scaleMismatch.Ciphertext.Scale = scaleMismatch.Ciphertext.Scale.Mul(rlwe.NewScale(2))
	scaleMismatch.Metadata.Scale = scaleMismatch.Ciphertext.Scale
	assertMultiplicationErrorContains(t, "scale", func() error {
		_, err := codec.MultShort(arithmetic, scaleMismatch)
		return err
	}, "scales differ")

	shortLevelZero := short.CopyNew()
	shortLevelZero.Ciphertext.Resize(shortLevelZero.Ciphertext.Degree(), 0)
	shortLevelZero.Metadata.Level = 0
	arithmeticLevelZero := arithmetic.CopyNew()
	arithmeticLevelZero.Ciphertext.Resize(arithmeticLevelZero.Ciphertext.Degree(), 0)
	arithmeticLevelZero.Metadata.Level = 0
	assertMultiplicationErrorContains(t, "MultShort level", func() error {
		_, err := codec.MultShort(arithmeticLevelZero, shortLevelZero)
		return err
	}, "needs 1 levels")

	lhsLevelOne := arithmetic.CopyNew()
	lhsLevelOne.Ciphertext.Resize(lhsLevelOne.Ciphertext.Degree(), 1)
	lhsLevelOne.Metadata.Level = 1
	rhsLevelOne := otherArithmetic.CopyNew()
	rhsLevelOne.Ciphertext.Resize(rhsLevelOne.Ciphertext.Degree(), 1)
	rhsLevelOne.Metadata.Level = 1
	assertMultiplicationErrorContains(t, "MultFull level", func() error {
		_, err := codec.MultFull(lhsLevelOne, rhsLevelOne)
		return err
	}, "needs 2 levels")

	noKeyCodec, _ := testMultiplicationCodec(t, z2n.Word8, false)
	noKeyArithmetic, err := noKeyCodec.EncodeEncrypt([]uint64{3})
	if err != nil {
		t.Fatal(err)
	}
	noKeyShort, err := noKeyCodec.EncodeShortEncrypt([]uint64{5})
	if err != nil {
		t.Fatal(err)
	}
	assertMultiplicationErrorContains(t, "missing relin", func() error {
		_, err := noKeyCodec.MultShort(noKeyArithmetic, noKeyShort)
		return err
	}, "relinearization key is unavailable")
}

func assertMultiplicationErrorContains(t *testing.T, name string, operation func() error, substring string) {
	t.Helper()
	if err := operation(); err == nil {
		t.Fatalf("%s: operation unexpectedly succeeded", name)
	} else if !strings.Contains(err.Error(), substring) {
		t.Fatalf("%s: error %q does not contain %q", name, err, substring)
	}
}

func TestGaoMultShortAndMultFullUseObservableRescaleChains(t *testing.T) {
	codec, parameters := testMultiplicationCodec(t, z2n.Word8, true)
	lhs, err := codec.EncodeEncrypt([]uint64{255, 17, 0, 37})
	if err != nil {
		t.Fatal(err)
	}
	rhsArithmetic, err := codec.EncodeEncrypt([]uint64{2, 15, 255, 7})
	if err != nil {
		t.Fatal(err)
	}
	rhsShort, err := codec.EncodeShortEncrypt([]uint64{2, 15, 255, 7})
	if err != nil {
		t.Fatal(err)
	}
	lhsSnapshot, rhsArithmeticSnapshot, rhsShortSnapshot := lhs.CopyNew(), rhsArithmetic.CopyNew(), rhsShort.CopyNew()

	shortProduct, err := codec.MultShort(lhs, rhsShort)
	if err != nil {
		t.Fatalf("MultShort: %v", err)
	}
	fullProduct, err := codec.MultFull(lhs, rhsArithmetic)
	if err != nil {
		t.Fatalf("MultFull: %v", err)
	}
	want := []uint64{254, 255, 0, 3}
	assertDecodedWords(t, codec, shortProduct, want)
	gotFull, diagnostics, err := codec.DecryptDecodeWithDiagnostics(fullProduct)
	if err != nil {
		t.Fatalf("full product diagnostic decode: %v", err)
	}
	assertWordsEqual(t, gotFull, want)
	if diagnostics.MinimumRoundingMargin <= 0.49 {
		t.Fatalf("full product minimum coefficient-rounding margin %.6g is too small", diagnostics.MinimumRoundingMargin)
	}
	if diagnostics.MaxRootError >= 1e-4 {
		t.Fatalf("full product maximum root-slot error %.6g is too large", diagnostics.MaxRootError)
	}

	if got, wantLevel := shortProduct.Ciphertext.Level(), parameters.InitialLevel-1; got != wantLevel {
		t.Fatalf("MultShort level: got %d, want %d", got, wantLevel)
	}
	if got, wantLevel := fullProduct.Ciphertext.Level(), parameters.InitialLevel-2; got != wantLevel {
		t.Fatalf("MultFull level: got %d, want %d", got, wantLevel)
	}
	q := parameters.CKKS.Q()
	wantShortScale := lhs.Ciphertext.Scale.Mul(rhsShort.Ciphertext.Scale).Div(rlwe.NewScale(q[parameters.InitialLevel]))
	if !shortProduct.Ciphertext.Scale.Equal(wantShortScale) {
		t.Fatalf("MultShort scale log2: got %.12f, want %.12f", shortProduct.Ciphertext.Scale.Log2(), wantShortScale.Log2())
	}
	firstFullScale := lhs.Ciphertext.Scale.Mul(rhsArithmetic.Ciphertext.Scale).Div(rlwe.NewScale(q[parameters.InitialLevel]))
	wantFullScale := firstFullScale.Mul(firstFullScale).Div(rlwe.NewScale(q[parameters.InitialLevel-1]))
	if !fullProduct.Ciphertext.Scale.Equal(wantFullScale) {
		t.Fatalf("MultFull scale log2: got %.12f, want %.12f", fullProduct.Ciphertext.Scale.Log2(), wantFullScale.Log2())
	}
	for name, product := range map[string]*inteval.Value{"short": shortProduct, "full": fullProduct} {
		if product.Metadata.Parameters.Mode != inteval.Arithmetic {
			t.Fatalf("%s product mode is %v, want Arithmetic", name, product.Metadata.Parameters.Mode)
		}
		if product.Ciphertext == lhs.Ciphertext || product.Ciphertext == rhsArithmetic.Ciphertext || product.Ciphertext == rhsShort.Ciphertext {
			t.Fatalf("%s product aliases an input", name)
		}
	}
	if !lhs.Ciphertext.Equal(lhsSnapshot.Ciphertext) ||
		!rhsArithmetic.Ciphertext.Equal(rhsArithmeticSnapshot.Ciphertext) ||
		!rhsShort.Ciphertext.Equal(rhsShortSnapshot.Ciphertext) {
		t.Fatal("multiplication mutated an input ciphertext")
	}
}

func testMultiplicationCodec(t *testing.T, bits z2n.WordBits, withRelinearizationKey bool) (*inteval.Codec, inteval.Parameters) {
	t.Helper()
	// N=1024 is a fast functional-demo boundary, not a secure CKKS parameter
	// set. SecurityBoundary: DemoOnly below makes that status machine-readable.
	ckksParameters, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            10,
		LogQ:            []int{55, 45, 45},
		LogP:            []int{55},
		LogDefaultScale: 45,
	})
	if err != nil {
		t.Fatalf("create multiplication demo parameters: %v", err)
	}
	if got := ckksParameters.LevelsConsumedPerRescaling(); got != 1 {
		t.Fatalf("demo parameters consume %d levels per rescale, want 1", got)
	}
	bounds, err := inteval.FullBounds(bits, inteval.Unsigned)
	if err != nil {
		t.Fatal(err)
	}
	parameters := inteval.Parameters{
		CKKS:             ckksParameters,
		WordBits:         bits,
		Mode:             inteval.Arithmetic,
		Signedness:       inteval.Unsigned,
		Bounds:           bounds,
		InitialLevel:     ckksParameters.MaxLevel(),
		EncoderPrecision: 192,
		SecurityBoundary: inteval.DemoOnly,
	}
	keyGenerator := ckks.NewKeyGenerator(ckksParameters)
	secretKey := keyGenerator.GenSecretKeyNew()
	var evaluationKeys rlwe.EvaluationKeySet
	if withRelinearizationKey {
		evaluationKeys = rlwe.NewMemEvaluationKeySet(keyGenerator.GenRelinearizationKeyNew(secretKey))
	}
	codec, err := inteval.NewCodecWithEvaluationKeys(parameters, secretKey, secretKey, evaluationKeys)
	if err != nil {
		t.Fatalf("new multiplication codec: %v", err)
	}
	return codec, parameters
}

func assertWordsEqual(t *testing.T, got, want []uint64) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("words: got %#x, want %#x", got, want)
	}
}
