package evaluator_test

import (
	"fmt"
	"math/big"
	"slices"
	"testing"

	inteval "github.com/nc26676027/LCPDTE/integer/evaluator"
	"github.com/nc26676027/LCPDTE/integer/z2n"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func TestCodecEncryptsAndStrictlyRecoversIsolatedWordsAtEveryWidth(t *testing.T) {
	for _, testCase := range []struct {
		bits  z2n.WordBits
		words []uint64
	}{
		{z2n.Word8, []uint64{0, 1, 127, 128, 254, 255, 37}},
		{z2n.Word16, []uint64{0, 1, 32767, 32768, 65534, 65535, 9137}},
		{z2n.Word32, []uint64{0, 1, 0x7fffffff, 0x80000000, 0xfffffffe, 0xffffffff, 0x12345678}},
		{z2n.Word64, []uint64{0, 1, 0x7fffffffffffffff, 0x8000000000000000, 0xfffffffffffffffe, 0xffffffffffffffff, 0x123456789abcdef0}},
	} {
		t.Run(fmt.Sprintf("n=%d", testCase.bits), func(t *testing.T) {
			codec, parameters := testCodec(t, testCase.bits, inteval.Unsigned)
			value, err := codec.EncodeEncrypt(testCase.words)
			if err != nil {
				t.Fatalf("encode/encrypt: %v", err)
			}
			if err := codec.Validate(value); err != nil {
				t.Fatalf("fresh value failed validation: %v", err)
			}
			if value.Metadata.WordCount != len(testCase.words) {
				t.Fatalf("word count: got %d, want %d", value.Metadata.WordCount, len(testCase.words))
			}
			if value.Metadata.SlotsPerWord != int(testCase.bits)/2 {
				t.Fatalf("slots per word: got %d, want %d", value.Metadata.SlotsPerWord, int(testCase.bits)/2)
			}
			if value.Metadata.SlotsUsed != len(testCase.words)*int(testCase.bits)/2 {
				t.Fatalf("slots used: got %d", value.Metadata.SlotsUsed)
			}
			if value.Metadata.Level != parameters.InitialLevel || value.Ciphertext.Level() != parameters.InitialLevel {
				t.Fatalf("level mismatch: metadata=%d ciphertext=%d want=%d", value.Metadata.Level, value.Ciphertext.Level(), parameters.InitialLevel)
			}
			if !value.Metadata.Scale.Equal(parameters.CKKS.DefaultScale()) || !value.Ciphertext.Scale.Equal(parameters.CKKS.DefaultScale()) {
				t.Fatal("fresh value scale differs from configured CKKS default")
			}

			got, err := codec.DecryptDecode(value)
			if err != nil {
				t.Fatalf("decrypt/decode: %v", err)
			}
			if !slices.Equal(got, testCase.words) {
				t.Fatalf("round-trip: got %#x, want %#x", got, testCase.words)
			}
		})
	}
}

func TestShortBinaryEncodingUsesExplicitModeAndStrictlyRecovers(t *testing.T) {
	codec, _ := testCodec(t, z2n.Word8, inteval.Unsigned)
	words := []uint64{0, 1, 2, 127, 128, 254, 255}
	value, err := codec.EncodeShortEncrypt(words)
	if err != nil {
		t.Fatalf("encode/encrypt [m]_tau: %v", err)
	}
	if got := value.Metadata.Parameters.Mode; got != inteval.Short {
		t.Fatalf("mode: got %v, want Short", got)
	}
	if err := codec.Validate(value); err != nil {
		t.Fatalf("short value failed validation: %v", err)
	}
	assertDecodedWords(t, codec, value, words)

	arithmetic, err := codec.EncodeEncrypt(words)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := codec.Add(arithmetic, value); err == nil {
		t.Fatal("linear arithmetic accepted a Short operand")
	}
}

func TestCodecRejectsSlotOverflowAndOutOfRangeRawWords(t *testing.T) {
	codec, parameters := testCodec(t, z2n.Word64, inteval.Unsigned)
	tooMany := make([]uint64, parameters.WordCapacity()+1)
	if _, err := codec.EncodeEncrypt(tooMany); err == nil {
		t.Fatalf("encoded %d words into capacity %d", len(tooMany), parameters.WordCapacity())
	}

	codec8, _ := testCodec(t, z2n.Word8, inteval.Unsigned)
	if _, err := codec8.EncodeEncrypt([]uint64{256}); err == nil {
		t.Fatal("silently truncated a raw value wider than eight bits")
	}
}

func TestLinearArithmeticWrapsPerWordWithoutMutatingInputs(t *testing.T) {
	codec, _ := testCodec(t, z2n.Word8, inteval.Unsigned)
	lhs, err := codec.EncodeEncrypt([]uint64{255, 0, 1, 200})
	if err != nil {
		t.Fatal(err)
	}
	rhs, err := codec.EncodeEncrypt([]uint64{1, 1, 2, 100})
	if err != nil {
		t.Fatal(err)
	}
	lhsSnapshot := lhs.CopyNew()
	rhsSnapshot := rhs.CopyNew()

	sum, err := codec.Add(lhs, rhs)
	if err != nil {
		t.Fatal(err)
	}
	assertDecodedWords(t, codec, sum, []uint64{0, 1, 3, 44})

	difference, err := codec.Sub(lhs, rhs)
	if err != nil {
		t.Fatal(err)
	}
	assertDecodedWords(t, codec, difference, []uint64{254, 255, 255, 100})

	negated, err := codec.Negate(lhs)
	if err != nil {
		t.Fatal(err)
	}
	assertDecodedWords(t, codec, negated, []uint64{1, 0, 255, 56})

	publicAdded, err := codec.AddPublic(lhs, []uint64{0, 7, 0, 0})
	if err != nil {
		t.Fatal(err)
	}
	assertDecodedWords(t, codec, publicAdded, []uint64{255, 7, 1, 200})

	publicSubtracted, err := codec.SubPublic(lhs, []uint64{0, 0, 2, 0})
	if err != nil {
		t.Fatal(err)
	}
	assertDecodedWords(t, codec, publicSubtracted, []uint64{255, 0, 255, 200})

	for name, output := range map[string]*inteval.Value{
		"sum": sum, "difference": difference, "negated": negated,
		"public-added": publicAdded, "public-subtracted": publicSubtracted,
	} {
		if output.Ciphertext == lhs.Ciphertext || output.Ciphertext == rhs.Ciphertext {
			t.Fatalf("%s aliases an input ciphertext", name)
		}
	}
	if !lhs.Ciphertext.Equal(lhsSnapshot.Ciphertext) || !rhs.Ciphertext.Equal(rhsSnapshot.Ciphertext) {
		t.Fatal("a linear operation mutated an input ciphertext")
	}
}

func TestLinearWraparoundAtEveryWordWidth(t *testing.T) {
	for _, bits := range []z2n.WordBits{z2n.Word8, z2n.Word16, z2n.Word32, z2n.Word64} {
		codec, _ := testCodec(t, bits, inteval.Unsigned)
		mask := maskFor(bits)
		maximum, err := codec.EncodeEncrypt([]uint64{mask})
		if err != nil {
			t.Fatal(err)
		}
		one, err := codec.EncodeEncrypt([]uint64{1})
		if err != nil {
			t.Fatal(err)
		}
		sum, err := codec.Add(maximum, one)
		if err != nil {
			t.Fatal(err)
		}
		assertDecodedWords(t, codec, sum, []uint64{0})
		publicSum, err := codec.AddPublic(maximum, []uint64{1})
		if err != nil {
			t.Fatal(err)
		}
		assertDecodedWords(t, codec, publicSum, []uint64{0})
		zero, err := codec.EncodeEncrypt([]uint64{0})
		if err != nil {
			t.Fatal(err)
		}
		publicDifference, err := codec.SubPublic(zero, []uint64{1})
		if err != nil {
			t.Fatal(err)
		}
		assertDecodedWords(t, codec, publicDifference, []uint64{mask})
		negativeOne, err := codec.Negate(one)
		if err != nil {
			t.Fatal(err)
		}
		assertDecodedWords(t, codec, negativeOne, []uint64{mask})
	}
}

func TestTwosComplementMetadataPreservesRawResidues(t *testing.T) {
	codec, _ := testCodec(t, z2n.Word8, inteval.TwosComplement)
	value, err := codec.EncodeEncrypt([]uint64{0x80, 0xff, 0x00, 0x7f})
	if err != nil {
		t.Fatal(err)
	}
	assertDecodedWords(t, codec, value, []uint64{0x80, 0xff, 0x00, 0x7f})
	negated, err := codec.Negate(value)
	if err != nil {
		t.Fatal(err)
	}
	assertDecodedWords(t, codec, negated, []uint64{0x80, 0x01, 0x00, 0x81})
}

func TestValidationRejectsMetadataLevelScaleAndCapacityMismatches(t *testing.T) {
	codec, parameters := testCodec(t, z2n.Word8, inteval.Unsigned)
	value, err := codec.EncodeEncrypt([]uint64{3, 7})
	if err != nil {
		t.Fatal(err)
	}

	wrongSemantics := value.CopyNew()
	wrongSemantics.Metadata.Parameters.Signedness = inteval.TwosComplement
	if err := codec.Validate(wrongSemantics); err == nil {
		t.Fatal("accepted mismatched signedness metadata")
	}

	wrongScale := value.CopyNew()
	wrongScale.Metadata.Scale = rlwe.NewScale(1)
	if err := codec.Validate(wrongScale); err == nil {
		t.Fatal("accepted mismatched scale metadata")
	}

	wrongSlots := value.CopyNew()
	wrongSlots.Metadata.SlotsUsed++
	if err := codec.Validate(wrongSlots); err == nil {
		t.Fatal("accepted inconsistent slots-used metadata")
	}

	overCapacity := value.CopyNew()
	overCapacity.Metadata.WordCount = parameters.WordCapacity() + 1
	overCapacity.Metadata.SlotsUsed = overCapacity.Metadata.WordCount * overCapacity.Metadata.SlotsPerWord
	if err := codec.Validate(overCapacity); err == nil {
		t.Fatal("accepted word metadata beyond slot capacity")
	}

	wrongLevel := value.CopyNew()
	wrongLevel.Ciphertext.Resize(wrongLevel.Ciphertext.Degree(), 0)
	if err := codec.Validate(wrongLevel); err == nil {
		t.Fatal("accepted ciphertext level differing from metadata")
	}

	lowerLevel := value.CopyNew()
	lowerLevel.Ciphertext.Resize(lowerLevel.Ciphertext.Degree(), 0)
	lowerLevel.Metadata.Level = 0
	if err := codec.Validate(lowerLevel); err != nil {
		t.Fatalf("valid lower-level value rejected: %v", err)
	}
	if _, err := codec.Add(value, lowerLevel); err == nil {
		t.Fatal("added operands at different levels")
	}

	codec16, _ := testCodec(t, z2n.Word16, inteval.Unsigned)
	if err := codec16.Validate(value); err == nil {
		t.Fatal("accepted a value under different word/CKKS parameters")
	}
	if _, err := codec.AddPublic(value, []uint64{1}); err == nil {
		t.Fatal("accepted a public vector with the wrong word count")
	}
}

func TestValueCopyDetachesCiphertextAndScaleMetadata(t *testing.T) {
	codec, parameters := testCodec(t, z2n.Word8, inteval.Unsigned)
	value, err := codec.EncodeEncrypt([]uint64{9})
	if err != nil {
		t.Fatal(err)
	}
	copyValue := value.CopyNew()
	copyValue.Metadata.Scale.Value.Mul(&copyValue.Metadata.Scale.Value, big.NewFloat(1.5))
	copyValue.Ciphertext.Scale.Value.Mul(&copyValue.Ciphertext.Scale.Value, big.NewFloat(1.25))
	if !value.Metadata.Scale.Equal(parameters.CKKS.DefaultScale()) {
		t.Fatal("mutating copied value metadata changed the source metadata scale")
	}
	if !value.Ciphertext.Scale.Equal(parameters.CKKS.DefaultScale()) {
		t.Fatal("mutating copied ciphertext metadata changed the source ciphertext scale")
	}
}

func assertDecodedWords(t *testing.T, codec *inteval.Codec, value *inteval.Value, want []uint64) {
	t.Helper()
	got, err := codec.DecryptDecode(value)
	if err != nil {
		t.Fatalf("decrypt/decode: %v", err)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("decoded words: got %#x, want %#x", got, want)
	}
}

func maskFor(bits z2n.WordBits) uint64 {
	if bits == z2n.Word64 {
		return ^uint64(0)
	}
	return (uint64(1) << uint(bits)) - 1
}

func TestParametersRequireExplicitArithmeticSemanticsAndDemoBoundary(t *testing.T) {
	ckksParameters := testCKKSParameters(t)
	bounds, err := inteval.FullBounds(z2n.Word8, inteval.Unsigned)
	if err != nil {
		t.Fatal(err)
	}
	parameters := inteval.Parameters{
		CKKS:             ckksParameters,
		WordBits:         z2n.Word8,
		Mode:             inteval.Arithmetic,
		Signedness:       inteval.Unsigned,
		Bounds:           bounds,
		InitialLevel:     ckksParameters.MaxLevel(),
		EncoderPrecision: 192,
		SecurityBoundary: inteval.DemoOnly,
	}
	if err := parameters.Validate(); err != nil {
		t.Fatalf("valid parameters rejected: %v", err)
	}
	shortParameters := parameters
	shortParameters.Mode = inteval.Short
	if err := shortParameters.Validate(); err != nil {
		t.Fatalf("explicit Short parameters rejected: %v", err)
	}
	if got, want := parameters.SlotsPerWord(), 4; got != want {
		t.Fatalf("slots per n=8 word: got %d, want %d", got, want)
	}
	if got, want := parameters.WordCapacity(), ckksParameters.MaxSlots()/4; got != want {
		t.Fatalf("word capacity: got %d, want %d", got, want)
	}

	invalid := parameters
	invalid.Mode = inteval.Mode(0)
	if err := invalid.Validate(); err == nil {
		t.Fatal("unspecified mode was accepted")
	}
	invalid = parameters
	invalid.Signedness = inteval.Signedness(0)
	if err := invalid.Validate(); err == nil {
		t.Fatal("unspecified signedness was accepted")
	}
	invalid = parameters
	invalid.SecurityBoundary = inteval.SecurityBoundary(0)
	if err := invalid.Validate(); err == nil {
		t.Fatal("unspecified security boundary was accepted")
	}
	invalid = parameters
	invalid.EncoderPrecision = 127
	if err := invalid.Validate(); err == nil {
		t.Fatal("sub-128-bit encoder precision was accepted")
	}
	invalid = parameters
	invalid.InitialLevel = ckksParameters.MaxLevel() + 1
	if err := invalid.Validate(); err == nil {
		t.Fatal("out-of-range initial level was accepted")
	}
}

func testCKKSParameters(t *testing.T) ckks.Parameters {
	t.Helper()
	// N=1024 is intentionally tiny for fast functional tests. DemoOnly below
	// records that this parameter tuple carries no security claim.
	parameters, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            10,
		LogQ:            []int{55, 45},
		LogDefaultScale: 40,
	})
	if err != nil {
		t.Fatalf("create demo CKKS parameters: %v", err)
	}
	return parameters
}

func testCodec(t *testing.T, bits z2n.WordBits, signedness inteval.Signedness) (*inteval.Codec, inteval.Parameters) {
	t.Helper()
	ckksParameters := testCKKSParameters(t)
	bounds, err := inteval.FullBounds(bits, signedness)
	if err != nil {
		t.Fatal(err)
	}
	parameters := inteval.Parameters{
		CKKS:             ckksParameters,
		WordBits:         bits,
		Mode:             inteval.Arithmetic,
		Signedness:       signedness,
		Bounds:           bounds,
		InitialLevel:     ckksParameters.MaxLevel(),
		EncoderPrecision: 192,
		SecurityBoundary: inteval.DemoOnly,
	}
	keyGenerator := ckks.NewKeyGenerator(ckksParameters)
	secretKey := keyGenerator.GenSecretKeyNew()
	codec, err := inteval.NewCodec(parameters, secretKey, secretKey)
	if err != nil {
		t.Fatalf("new codec: %v", err)
	}
	return codec, parameters
}
