package z2n_test

import (
	"reflect"
	"testing"

	"dt_go/integer/z2n"
)

func TestA2BTwoLUTOracleExhaustiveWidthFour(t *testing.T) {
	wantID := []string{
		"0",
		"-15/16", "-7/8", "-13/16", "-3/4",
		"-11/16", "-5/8", "-9/16", "-1/2",
		"-7/16", "-3/8", "-5/16", "-1/4",
		"-3/16", "-1/8", "-1/16",
	}
	wantMSB := []uint8{0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0}

	for code := uint64(0); code < 16; code++ {
		got, err := z2n.A2BTwoLUTOracle(code, 4)
		if err != nil {
			t.Fatalf("code %d: %v", code, err)
		}
		if got.ID == nil {
			t.Fatalf("code %d: nil ID output", code)
		}
		if got.ID.RatString() != wantID[code] {
			t.Fatalf("code %d: ID=%s, want %s", code, got.ID.RatString(), wantID[code])
		}
		if got.MSB != wantMSB[code] {
			t.Fatalf("code %d: MSB=%d, want %d", code, got.MSB, wantMSB[code])
		}
	}
}

func TestA2BTwoLUTOracleRejectsInvalidDomain(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		code  uint64
		width uint
	}{
		{name: "zero width", code: 0, width: 0},
		{name: "width exceeds uint64 word", code: 0, width: 65},
		{name: "code equals modulus", code: 16, width: 4},
		{name: "code above modulus", code: 31, width: 4},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := z2n.A2BTwoLUTOracle(testCase.code, testCase.width); err == nil {
				t.Fatal("invalid LUT input was accepted")
			}
		})
	}
}

func TestA2BBooleanHalvesOracleMatchesAuditedEightBitStrings(t *testing.T) {
	fixtures := []struct {
		word uint64
		low  string
		high string
	}{
		{word: 0x00, low: "0000", high: "0000"},
		{word: 0x01, low: "1000", high: "0000"},
		{word: 0x0f, low: "1111", high: "0000"},
		{word: 0x10, low: "0000", high: "1000"},
		{word: 0x7f, low: "1111", high: "1110"},
		{word: 0x80, low: "0000", high: "0001"},
		{word: 0xff, low: "1111", high: "1111"},
		{word: 0xa5, low: "1010", high: "0101"},
	}

	for _, fixture := range fixtures {
		halves, err := z2n.A2BBooleanHalvesOracle(fixture.word, z2n.Word8)
		if err != nil {
			t.Fatalf("word %#02x: %v", fixture.word, err)
		}
		if got := booleanBitString(halves.Low); got != fixture.low {
			t.Fatalf("word %#02x low=%q, want %q", fixture.word, got, fixture.low)
		}
		if got := booleanBitString(halves.High); got != fixture.high {
			t.Fatalf("word %#02x high=%q, want %q", fixture.word, got, fixture.high)
		}
	}
}

func TestB2AOracleRoundTripsEveryEightBitWord(t *testing.T) {
	for word := uint64(0); word < 256; word++ {
		halves, err := z2n.A2BBooleanHalvesOracle(word, z2n.Word8)
		if err != nil {
			t.Fatalf("A2B word %#02x: %v", word, err)
		}
		got, err := z2n.B2AOracle(z2n.Word8, halves)
		if err != nil {
			t.Fatalf("B2A word %#02x: %v", word, err)
		}
		if got != word {
			t.Fatalf("word %#02x reconstructed as %#02x", word, got)
		}
	}
}

func TestBooleanHalvesOraclesRejectMalformedPlaintextInputs(t *testing.T) {
	if _, err := z2n.A2BBooleanHalvesOracle(0x100, z2n.Word8); err == nil {
		t.Fatal("A2B oracle accepted a value outside an 8-bit word")
	}
	if _, err := z2n.A2BBooleanHalvesOracle(0, z2n.WordBits(12)); err == nil {
		t.Fatal("A2B oracle accepted an unsupported word width")
	}
	if _, err := z2n.B2AOracle(z2n.Word8, z2n.BooleanHalves{
		Low:  []uint8{0, 1, 0},
		High: []uint8{0, 1, 0},
	}); err == nil {
		t.Fatal("B2A oracle accepted halves with the wrong length")
	}
	if _, err := z2n.B2AOracle(z2n.Word8, z2n.BooleanHalves{
		Low:  []uint8{0, 1, 2, 0},
		High: []uint8{0, 1, 0, 1},
	}); err == nil {
		t.Fatal("B2A oracle accepted a non-Boolean bit")
	}
}

func booleanBitString(bits []uint8) string {
	result := make([]byte, len(bits))
	for i, bit := range bits {
		result[i] = '0' + bit
	}
	return string(result)
}

func TestA2BConfigValidatesChunkDivisibilityAndPackingMode(t *testing.T) {
	valid := []z2n.A2BConfig{
		{WordBits: z2n.Word8, ChunkWidth: 4, Packing: z2n.A2BFullPacking},
		{WordBits: z2n.Word16, ChunkWidth: 4, Packing: z2n.A2BSparsePacking},
		{WordBits: z2n.Word64, ChunkWidth: 8, Packing: z2n.A2BFullPacking},
	}
	for _, config := range valid {
		if err := config.Validate(); err != nil {
			t.Fatalf("valid config %+v rejected: %v", config, err)
		}
	}

	invalid := []z2n.A2BConfig{
		{WordBits: z2n.WordBits(12), ChunkWidth: 4, Packing: z2n.A2BFullPacking},
		{WordBits: z2n.Word8, ChunkWidth: 0, Packing: z2n.A2BFullPacking},
		{WordBits: z2n.Word8, ChunkWidth: 3, Packing: z2n.A2BFullPacking},
		{WordBits: z2n.Word8, ChunkWidth: 16, Packing: z2n.A2BFullPacking},
		{WordBits: z2n.Word8, ChunkWidth: 4, Packing: z2n.A2BPackingMode("unknown")},
	}
	for _, config := range invalid {
		if err := config.Validate(); err == nil {
			t.Fatalf("invalid config %+v was accepted", config)
		}
	}
}

func TestDirectBA2BOracleRejectsAnythingExceptOneFullEvenBatch(t *testing.T) {
	full := z2n.A2BConfig{WordBits: z2n.Word8, ChunkWidth: 4, Packing: z2n.A2BFullPacking}
	for _, words := range [][]uint64{
		nil,
		{0x12},
		{0x12, 0x34, 0x56},
	} {
		if _, err := z2n.DirectBA2BOracle(full, words); err == nil {
			t.Fatalf("direct B-A2B accepted input count %d; want exactly d=2", len(words))
		}
	}

	sparse := full
	sparse.Packing = z2n.A2BSparsePacking
	if _, err := z2n.DirectBA2BOracle(sparse, []uint64{0x12, 0x34}); err == nil {
		t.Fatal("direct B-A2B accepted sparse packing")
	}

	oddDigitCount := z2n.A2BConfig{WordBits: z2n.Word8, ChunkWidth: 8, Packing: z2n.A2BFullPacking}
	if _, err := z2n.DirectBA2BOracle(oddDigitCount, []uint64{0x12}); err == nil {
		t.Fatal("direct B-A2B accepted odd d=1")
	}
}

func TestDirectBA2BOracleUsesAuditedPairwiseOutputOrder(t *testing.T) {
	config := z2n.A2BConfig{WordBits: z2n.Word8, ChunkWidth: 4, Packing: z2n.A2BFullPacking}
	outputs, err := z2n.DirectBA2BOracle(config, []uint64{0xa5, 0x3c})
	if err != nil {
		t.Fatal(err)
	}
	wantOutputs := [][]uint8{
		{1, 0, 1, 0}, // A.low
		{0, 1, 0, 1}, // A.high
		{0, 0, 1, 1}, // B.low
		{1, 1, 0, 0}, // B.high
	}
	if !reflect.DeepEqual(outputs, wantOutputs) {
		t.Fatalf("outputs=%v, want %v", outputs, wantOutputs)
	}

	wantOrder := []z2n.BA2BOutputRef{
		{InputIndex: 0, Half: z2n.BooleanLowHalf},
		{InputIndex: 0, Half: z2n.BooleanHighHalf},
		{InputIndex: 1, Half: z2n.BooleanLowHalf},
		{InputIndex: 1, Half: z2n.BooleanHighHalf},
	}
	if got := z2n.BA2BOutputOrder(2); !reflect.DeepEqual(got, wantOrder) {
		t.Fatalf("output order=%v, want %v", got, wantOrder)
	}
}
