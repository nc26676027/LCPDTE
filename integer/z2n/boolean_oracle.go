package z2n

import (
	"fmt"
	"math/big"
)

// A2BTwoLUTValue is the exact plaintext output of Gao--Zheng's paired ID/MSB
// lookup tables. It is a conformance-oracle value; it is not a ciphertext and
// does not claim that homomorphic A2B has been implemented.
type A2BTwoLUTValue struct {
	ID  *big.Rat
	MSB uint8
}

// A2BTwoLUTOracle evaluates Gao--Zheng's paired A2B lookup tables exactly for
// a w-bit residue code. ID(0)=0 and ID(x)=(x-2^w)/2^w for x>0. MSB is one
// exactly on 1 <= x <= 2^(w-1). Widths up to 64 are supported.
//
// This function is a pure plaintext conformance oracle. It performs no CKKS
// encoding, lookup-table approximation, bootstrapping, or homomorphic A2B.
func A2BTwoLUTOracle(code uint64, chunkWidth uint) (A2BTwoLUTValue, error) {
	if chunkWidth == 0 || chunkWidth > 64 {
		return A2BTwoLUTValue{}, fmt.Errorf("z2n: A2B chunk width %d is outside [1,64]", chunkWidth)
	}
	if chunkWidth < 64 && code >= uint64(1)<<chunkWidth {
		return A2BTwoLUTValue{}, fmt.Errorf("z2n: A2B LUT code %d is outside [0,2^%d)", code, chunkWidth)
	}

	identity := new(big.Rat)
	if code != 0 {
		modulus := new(big.Int).Lsh(big.NewInt(1), chunkWidth)
		numerator := new(big.Int).Sub(new(big.Int).SetUint64(code), modulus)
		identity.SetFrac(numerator, modulus)
	}

	var msb uint8
	if code != 0 && code <= uint64(1)<<(chunkWidth-1) {
		msb = 1
	}
	return A2BTwoLUTValue{ID: identity, MSB: msb}, nil
}

// BooleanHalves is Gao--Zheng's breaking-into-halves representation of one
// Boolean word. Low and High are both LSB-first; High starts at word bit n/2.
type BooleanHalves struct {
	Low  []uint8
	High []uint8
}

// A2BBooleanHalvesOracle returns the exact full Boolean output for one n-bit
// plaintext word. This is a conformance oracle for the result of A2B, not an
// implementation of the homomorphic conversion protocol.
func A2BBooleanHalvesOracle(word uint64, bits WordBits) (BooleanHalves, error) {
	if !bits.supported() {
		return BooleanHalves{}, fmt.Errorf("z2n: unsupported A2B oracle word size %d", bits)
	}
	if bits < Word64 && word >= uint64(1)<<bits {
		return BooleanHalves{}, fmt.Errorf("z2n: word %d is outside [0,2^%d)", word, bits)
	}

	halfLength := int(bits) / 2
	halves := BooleanHalves{
		Low:  make([]uint8, halfLength),
		High: make([]uint8, halfLength),
	}
	for i := 0; i < halfLength; i++ {
		halves.Low[i] = uint8(word >> uint(i) & 1)
		halves.High[i] = uint8(word >> uint(i+halfLength) & 1)
	}
	return halves, nil
}

// B2AOracle reconstructs one arithmetic residue exactly from full Boolean
// halves. It specifies standalone B2A's plaintext result only; it performs no
// C-To-Z transform, metadata mutation, encryption, or homomorphic evaluation.
func B2AOracle(bits WordBits, halves BooleanHalves) (uint64, error) {
	if !bits.supported() {
		return 0, fmt.Errorf("z2n: unsupported B2A oracle word size %d", bits)
	}
	halfLength := int(bits) / 2
	if len(halves.Low) != halfLength || len(halves.High) != halfLength {
		return 0, fmt.Errorf(
			"z2n: B2A halves have lengths low=%d high=%d, want %d each for n=%d",
			len(halves.Low), len(halves.High), halfLength, bits,
		)
	}

	var word uint64
	for i := 0; i < halfLength; i++ {
		if halves.Low[i] > 1 {
			return 0, fmt.Errorf("z2n: B2A low bit %d is %d, want 0 or 1", i, halves.Low[i])
		}
		if halves.High[i] > 1 {
			return 0, fmt.Errorf("z2n: B2A high bit %d is %d, want 0 or 1", i, halves.High[i])
		}
		word |= uint64(halves.Low[i]) << uint(i)
		word |= uint64(halves.High[i]) << uint(i+halfLength)
	}
	return word, nil
}

// A2BPackingMode records the source protocol's packing precondition. It has no
// ciphertext behavior in this plaintext conformance-oracle package.
type A2BPackingMode string

const (
	A2BFullPacking   A2BPackingMode = "full"
	A2BSparsePacking A2BPackingMode = "sparse"
)

// A2BConfig is the typed public precondition set shared by the plaintext A2B
// conformance oracles. ChunkWidth must divide WordBits exactly.
type A2BConfig struct {
	WordBits   WordBits
	ChunkWidth uint
	Packing    A2BPackingMode
}

// Validate checks the word, chunk, and packing domains. It does not validate
// the stricter direct B-A2B batch contract.
func (c A2BConfig) Validate() error {
	if !c.WordBits.supported() {
		return fmt.Errorf("z2n: unsupported A2B word size %d", c.WordBits)
	}
	if c.ChunkWidth == 0 || c.ChunkWidth > uint(c.WordBits) {
		return fmt.Errorf("z2n: A2B chunk width %d is outside [1,%d]", c.ChunkWidth, c.WordBits)
	}
	if uint(c.WordBits)%c.ChunkWidth != 0 {
		return fmt.Errorf("z2n: A2B chunk width %d does not divide word size %d", c.ChunkWidth, c.WordBits)
	}
	if c.Packing != A2BFullPacking && c.Packing != A2BSparsePacking {
		return fmt.Errorf("z2n: unknown A2B packing mode %q", c.Packing)
	}
	return nil
}

// DigitCount returns d=n/w after validating the common A2B configuration.
func (c A2BConfig) DigitCount() (int, error) {
	if err := c.Validate(); err != nil {
		return 0, err
	}
	return int(uint(c.WordBits) / c.ChunkWidth), nil
}

// BooleanHalfKind names one breaking-into-halves output.
type BooleanHalfKind string

const (
	BooleanLowHalf  BooleanHalfKind = "low"
	BooleanHighHalf BooleanHalfKind = "high"
)

// BA2BOutputRef identifies one direct B-A2B output ciphertext position.
type BA2BOutputRef struct {
	InputIndex int
	Half       BooleanHalfKind
}

// BA2BOutputOrder returns the audited direct-output order
// [A.low, A.high, B.low, B.high, ...].
func BA2BOutputOrder(inputCount int) []BA2BOutputRef {
	if inputCount <= 0 {
		return nil
	}
	order := make([]BA2BOutputRef, 0, 2*inputCount)
	for inputIndex := 0; inputIndex < inputCount; inputIndex++ {
		order = append(order,
			BA2BOutputRef{InputIndex: inputIndex, Half: BooleanLowHalf},
			BA2BOutputRef{InputIndex: inputIndex, Half: BooleanHighHalf},
		)
	}
	return order
}

// DirectBA2BOracle returns exact Boolean halves in BA2BOutputOrder. It models
// only Gao--Zheng's direct, full-packing B-A2B conformance boundary: input must
// contain exactly d=n/w words and d must be even. It deliberately does not pad
// partial batches; padding belongs to an outer dispatcher, not this direct API.
//
// The returned bit slices are plaintext oracle values. This function does not
// implement the homomorphic B-A2B protocol or claim its costs/noise behavior.
func DirectBA2BOracle(config A2BConfig, words []uint64) ([][]uint8, error) {
	digitCount, err := config.DigitCount()
	if err != nil {
		return nil, err
	}
	if config.Packing != A2BFullPacking {
		return nil, fmt.Errorf("z2n: direct B-A2B requires full packing, got %q", config.Packing)
	}
	if digitCount%2 != 0 {
		return nil, fmt.Errorf("z2n: direct B-A2B requires even d=n/w, got %d", digitCount)
	}
	if len(words) != digitCount {
		return nil, fmt.Errorf("z2n: direct B-A2B input count=%d, want exactly d=%d", len(words), digitCount)
	}

	outputs := make([][]uint8, 0, 2*len(words))
	for inputIndex, word := range words {
		halves, err := A2BBooleanHalvesOracle(word, config.WordBits)
		if err != nil {
			return nil, fmt.Errorf("z2n: direct B-A2B input %d: %w", inputIndex, err)
		}
		outputs = append(outputs, halves.Low, halves.High)
	}
	return outputs, nil
}
