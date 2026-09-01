package evaluator

import (
	"fmt"
	"math/big"

	"dt_go/integer/z2n"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

// ValueMetadata binds a ciphertext to its integer interpretation and packing.
// Parameters is copied by value and contains Mode, Signedness, and Bounds.
type ValueMetadata struct {
	Parameters   Parameters
	WordCount    int
	SlotsPerWord int
	SlotsUsed    int
	Level        int
	Scale        rlwe.Scale
}

// Value is one encrypted vector of arithmetic Z/(2^n) words. Ciphertext is
// exported for Lattigo interoperability; every package operation validates it
// against Metadata before use and returns a newly allocated ciphertext.
type Value struct {
	Ciphertext *rlwe.Ciphertext
	Metadata   ValueMetadata
}

// CopyNew returns a deep ciphertext copy with value metadata copied by value.
func (v *Value) CopyNew() *Value {
	if v == nil {
		return nil
	}
	result := &Value{Metadata: v.Metadata}
	if v.Ciphertext != nil {
		result.Ciphertext = v.Ciphertext.CopyNew()
	}
	return result
}

// Codec owns the Lattigo encoder and optional encryption/decryption/evaluation
// keys for one explicit arithmetic word layout. It can emit both Arithmetic
// and Short values under that same layout.
type Codec struct {
	parameters     Parameters
	ring           *z2n.Ring
	encoder        *ckks.Encoder
	encryptor      *rlwe.Encryptor
	decryptor      *rlwe.Decryptor
	evaluator      *ckks.Evaluator
	evaluationKeys rlwe.EvaluationKeySet
}

// NewCodec constructs a linear arithmetic codec. encryptionKey and secretKey
// may be nil for a server-only instance, but EncodeEncrypt and DecryptDecode
// respectively fail until their required key is present.
func NewCodec(parameters Parameters, encryptionKey rlwe.EncryptionKey, secretKey *rlwe.SecretKey) (*Codec, error) {
	return NewCodecWithEvaluationKeys(parameters, encryptionKey, secretKey, nil)
}

// NewCodecWithEvaluationKeys additionally installs the keys needed by
// ciphertext-ciphertext multiplication. A relinearization key is mandatory
// for MultShort and MultFull but remains optional for linear-only codecs.
func NewCodecWithEvaluationKeys(parameters Parameters, encryptionKey rlwe.EncryptionKey, secretKey *rlwe.SecretKey, evaluationKeys rlwe.EvaluationKeySet) (*Codec, error) {
	if err := parameters.Validate(); err != nil {
		return nil, err
	}
	if parameters.Mode != Arithmetic {
		return nil, fmt.Errorf("integer/evaluator: codec base mode must be Arithmetic")
	}
	triangleRing, err := z2n.NewWithPrecision(parameters.WordBits, parameters.EncoderPrecision)
	if err != nil {
		return nil, fmt.Errorf("integer/evaluator: create triangle ring: %w", err)
	}
	codec := &Codec{
		parameters:     parameters,
		ring:           triangleRing,
		encoder:        ckks.NewEncoder(parameters.CKKS, parameters.EncoderPrecision),
		evaluator:      ckks.NewEvaluator(parameters.CKKS, evaluationKeys),
		evaluationKeys: evaluationKeys,
	}
	if encryptionKey != nil {
		codec.encryptor = ckks.NewEncryptor(parameters.CKKS, encryptionKey)
	}
	if secretKey != nil {
		if secretKey.Value.Q.N() != parameters.CKKS.N() {
			return nil, fmt.Errorf("integer/evaluator: secret-key ring degree %d does not match CKKS degree %d", secretKey.Value.Q.N(), parameters.CKKS.N())
		}
		codec.decryptor = ckks.NewDecryptor(parameters.CKKS, secretKey)
	}
	return codec, nil
}

// Parameters returns the immutable-by-convention configuration value.
func (c *Codec) Parameters() Parameters { return c.parameters }

// EncodeEncrypt packs each word into n/2 consecutive high-precision root
// slots, fills every unused CKKS slot with zero, encodes, and encrypts.
func (c *Codec) EncodeEncrypt(words []uint64) (*Value, error) {
	return c.encodeEncrypt(words, Arithmetic)
}

// EncodeShortEncrypt packs the binary polynomial [m]_tau without the
// tau^{-1} factor. A Short value is only accepted by MultShort (or by strict
// decryption for diagnostics); linear arithmetic rejects it.
func (c *Codec) EncodeShortEncrypt(words []uint64) (*Value, error) {
	return c.encodeEncrypt(words, Short)
}

func (c *Codec) encodeEncrypt(words []uint64, mode Mode) (*Value, error) {
	if c == nil || c.encryptor == nil {
		return nil, fmt.Errorf("integer/evaluator: encryption key is unavailable")
	}
	if len(words) == 0 {
		return nil, fmt.Errorf("integer/evaluator: cannot encode an empty word vector")
	}
	if len(words) > c.parameters.WordCapacity() {
		return nil, fmt.Errorf("integer/evaluator: %d words exceed ciphertext capacity %d", len(words), c.parameters.WordCapacity())
	}
	for i, word := range words {
		if err := c.validateRawWord(word); err != nil {
			return nil, fmt.Errorf("integer/evaluator: word %d: %w", i, err)
		}
	}

	slots := c.zeroSlots()
	blockSize := c.parameters.SlotsPerWord()
	for wordIndex, word := range words {
		var block []*bignum.Complex
		switch mode {
		case Arithmetic:
			block = c.ring.ArithmeticRootSlots(word)
		case Short:
			var err error
			block, err = c.ring.ToRootSlots(c.ring.BinaryEncode(word))
			if err != nil {
				return nil, fmt.Errorf("integer/evaluator: encode short word %d: %w", wordIndex, err)
			}
		default:
			return nil, fmt.Errorf("integer/evaluator: unsupported encoding mode %d", mode)
		}
		copy(slots[wordIndex*blockSize:(wordIndex+1)*blockSize], block)
	}

	plaintext := ckks.NewPlaintext(c.parameters.CKKS, c.parameters.InitialLevel)
	if err := c.encoder.Encode(slots, plaintext); err != nil {
		return nil, fmt.Errorf("integer/evaluator: encode root slots: %w", err)
	}
	ciphertext, err := c.encryptor.EncryptNew(plaintext)
	if err != nil {
		return nil, fmt.Errorf("integer/evaluator: encrypt root slots: %w", err)
	}
	value := c.newValueWithMode(ciphertext, len(words), mode)
	if err := c.Validate(value); err != nil {
		return nil, fmt.Errorf("integer/evaluator: fresh ciphertext failed validation: %w", err)
	}
	return value, nil
}

// DecryptDecode decrypts at the Value's current level, decodes root slots with
// Lattigo's arbitrary-precision path, and invokes z2n's strict coefficient-
// rounding decoder independently for every word block.
func (c *Codec) DecryptDecode(value *Value) ([]uint64, error) {
	words, _, err := c.DecryptDecodeWithDiagnostics(value)
	return words, err
}

// Validate fail-closes on custom metadata, Lattigo metadata, packing, level,
// scale, or parameter mismatches.
func (c *Codec) Validate(value *Value) error {
	if c == nil {
		return fmt.Errorf("integer/evaluator: codec is nil")
	}
	if value == nil || value.Ciphertext == nil {
		return fmt.Errorf("integer/evaluator: value or ciphertext is nil")
	}
	if value.Ciphertext.MetaData == nil {
		return fmt.Errorf("integer/evaluator: Lattigo metadata is nil")
	}
	metadata := value.Metadata
	if err := metadata.Parameters.Validate(); err != nil {
		return fmt.Errorf("integer/evaluator: invalid value parameters: %w", err)
	}
	if !metadata.Parameters.equalExceptMode(c.parameters) {
		return fmt.Errorf("integer/evaluator: value parameters do not match codec parameters")
	}
	if metadata.WordCount <= 0 {
		return fmt.Errorf("integer/evaluator: word count must be positive")
	}
	if metadata.SlotsPerWord != c.parameters.SlotsPerWord() {
		return fmt.Errorf("integer/evaluator: slots per word %d, want %d", metadata.SlotsPerWord, c.parameters.SlotsPerWord())
	}
	wantSlots := metadata.WordCount * metadata.SlotsPerWord
	if metadata.SlotsUsed != wantSlots {
		return fmt.Errorf("integer/evaluator: slots used %d, want %d", metadata.SlotsUsed, wantSlots)
	}
	if metadata.WordCount > c.parameters.WordCapacity() || metadata.SlotsUsed > value.Ciphertext.Slots() {
		return fmt.Errorf("integer/evaluator: packing exceeds slot capacity")
	}
	if value.Ciphertext.LogN() != c.parameters.CKKS.LogN() {
		return fmt.Errorf("integer/evaluator: ciphertext logN %d, want %d", value.Ciphertext.LogN(), c.parameters.CKKS.LogN())
	}
	if value.Ciphertext.Degree() != 1 {
		return fmt.Errorf("integer/evaluator: ciphertext degree %d, want 1", value.Ciphertext.Degree())
	}
	if metadata.Level != value.Ciphertext.Level() || metadata.Level < 0 || metadata.Level > c.parameters.InitialLevel {
		return fmt.Errorf("integer/evaluator: inconsistent or out-of-range level metadata=%d ciphertext=%d", metadata.Level, value.Ciphertext.Level())
	}
	if !metadata.Scale.Equal(value.Ciphertext.Scale) {
		return fmt.Errorf("integer/evaluator: scale metadata does not match ciphertext")
	}
	if metadata.Scale.Cmp(rlwe.NewScale(0)) <= 0 {
		return fmt.Errorf("integer/evaluator: ciphertext scale must be positive")
	}
	if !value.Ciphertext.IsBatched || !value.Ciphertext.IsNTT {
		return fmt.Errorf("integer/evaluator: ciphertext must use batched NTT encoding")
	}
	if value.Ciphertext.LogDimensions != c.parameters.CKKS.LogMaxDimensions() {
		return fmt.Errorf("integer/evaluator: ciphertext slot dimensions do not match parameters")
	}
	return nil
}

func (c *Codec) newValue(ciphertext *rlwe.Ciphertext, wordCount int) *Value {
	return c.newValueWithMode(ciphertext, wordCount, Arithmetic)
}

func (c *Codec) newValueWithMode(ciphertext *rlwe.Ciphertext, wordCount int, mode Mode) *Value {
	parameters := c.parameters
	parameters.Mode = mode
	return &Value{
		Ciphertext: ciphertext,
		Metadata: ValueMetadata{
			Parameters:   parameters,
			WordCount:    wordCount,
			SlotsPerWord: c.parameters.SlotsPerWord(),
			SlotsUsed:    wordCount * c.parameters.SlotsPerWord(),
			Level:        ciphertext.Level(),
			Scale:        ciphertext.Scale,
		},
	}
}

func (c *Codec) zeroSlots() []*bignum.Complex {
	precision := c.parameters.EncoderPrecision
	result := make([]*bignum.Complex, c.parameters.CKKS.MaxSlots())
	for i := range result {
		result[i] = &bignum.Complex{
			new(big.Float).SetPrec(precision),
			new(big.Float).SetPrec(precision),
		}
	}
	return result
}

func (c *Codec) validateRawWord(word uint64) error {
	bits := c.parameters.WordBits
	if bits != z2n.Word64 && word>>uint(bits) != 0 {
		return fmt.Errorf("raw residue %d exceeds %d bits", word, bits)
	}
	if !c.parameters.Bounds.containsRaw(word, bits, c.parameters.Signedness) {
		return fmt.Errorf("raw residue %d is outside configured bounds [%s,%s]", word, c.parameters.Bounds.MinInclusive, c.parameters.Bounds.MaxInclusive)
	}
	return nil
}
