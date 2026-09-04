package ckksint

import (
	"fmt"

	inteval "github.com/nc26676027/LCPDTE/integer/evaluator"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
)

// Context owns one complete arithmetic codec and binds every value to the key
// domain that created it.
type Context struct {
	parameters Parameters
	codec      *inteval.Codec
	token      *contextToken
}

// New constructs a Context from explicit parameters and Lattigo key material.
func New(parameters Parameters, keys KeyMaterial) (*Context, error) {
	if err := parameters.Validate(); err != nil {
		return nil, fmt.Errorf("ckksint: parameters: %w", err)
	}
	codec, err := inteval.NewCodecWithEvaluationKeys(
		parameters.evaluator(), keys.EncryptionKey, keys.SecretKey, keys.EvaluationKeys,
	)
	if err != nil {
		return nil, fmt.Errorf("ckksint: construct arithmetic context: %w", err)
	}
	return &Context{parameters: parameters, codec: codec, token: new(contextToken)}, nil
}

// NewDemo creates a self-contained functional Context with freshly generated
// keys. Its small CKKS tuple is suitable for examples and tests only.
func NewDemo(options DemoParameters) (*Context, error) {
	if options.WordBits == 0 {
		return nil, fmt.Errorf("ckksint: demo word width is required")
	}
	if options.Signedness == 0 {
		return nil, fmt.Errorf("ckksint: demo signedness is required")
	}
	ckksParameters, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            10,
		LogQ:            []int{55, 45, 45},
		LogP:            []int{55},
		LogDefaultScale: 45,
	})
	if err != nil {
		return nil, fmt.Errorf("ckksint: construct demo CKKS parameters: %w", err)
	}
	bounds, err := FullBounds(options.WordBits, options.Signedness)
	if err != nil {
		return nil, fmt.Errorf("ckksint: construct demo bounds: %w", err)
	}
	parameters := Parameters{
		CKKS:             ckksParameters,
		WordBits:         options.WordBits,
		Signedness:       options.Signedness,
		Bounds:           bounds,
		InitialLevel:     ckksParameters.MaxLevel(),
		EncoderPrecision: 192,
		SecurityBoundary: DemoOnly,
	}
	keyGenerator := ckks.NewKeyGenerator(ckksParameters)
	secretKey := keyGenerator.GenSecretKeyNew()
	keys := KeyMaterial{
		EncryptionKey: secretKey,
		SecretKey:     secretKey,
		EvaluationKeys: rlwe.NewMemEvaluationKeySet(
			keyGenerator.GenRelinearizationKeyNew(secretKey),
		),
	}
	return New(parameters, keys)
}

// Parameters returns the immutable-by-convention configuration value.
func (c *Context) Parameters() Parameters {
	if c == nil {
		return Parameters{}
	}
	return c.parameters
}

// Encrypt packs and encrypts raw residues.
func (c *Context) Encrypt(words []uint64) (*Value, error) {
	if err := c.ready(); err != nil {
		return nil, err
	}
	value, err := c.codec.EncodeEncrypt(words)
	if err != nil {
		return nil, fmt.Errorf("ckksint: encrypt arithmetic words: %w", err)
	}
	return c.wrap(value), nil
}

// EncryptSigned packs signed integers using two's-complement residues.
func (c *Context) EncryptSigned(words []int64) (*Value, error) {
	if err := c.ready(); err != nil {
		return nil, err
	}
	if c.parameters.Signedness != TwosComplement {
		return nil, fmt.Errorf("ckksint: EncryptSigned requires TwosComplement parameters")
	}
	residues := make([]uint64, len(words))
	bits := uint(c.parameters.WordBits)
	for index, word := range words {
		if bits < 64 {
			minimum := -(int64(1) << (bits - 1))
			maximum := (int64(1) << (bits - 1)) - 1
			if word < minimum || word > maximum {
				return nil, fmt.Errorf("ckksint: signed word %d=%d lies outside [%d,%d]", index, word, minimum, maximum)
			}
			residues[index] = uint64(word) & ((uint64(1) << bits) - 1)
		} else {
			residues[index] = uint64(word)
		}
	}
	return c.Encrypt(residues)
}

// EncryptShort packs and encrypts short/binary operands for MulShort.
func (c *Context) EncryptShort(words []uint64) (*ShortValue, error) {
	if err := c.ready(); err != nil {
		return nil, err
	}
	value, err := c.codec.EncodeShortEncrypt(words)
	if err != nil {
		return nil, fmt.Errorf("ckksint: encrypt short words: %w", err)
	}
	return &ShortValue{inner: value, owner: c.token}, nil
}

// Decrypt returns raw residues.
func (c *Context) Decrypt(value *Value) ([]uint64, error) {
	if err := c.owns(value); err != nil {
		return nil, err
	}
	words, err := c.codec.DecryptDecode(value.inner)
	if err != nil {
		return nil, fmt.Errorf("ckksint: decrypt arithmetic words: %w", err)
	}
	return words, nil
}

// DecryptSigned returns two's-complement integers.
func (c *Context) DecryptSigned(value *Value) ([]int64, error) {
	if c == nil || c.parameters.Signedness != TwosComplement {
		return nil, fmt.Errorf("ckksint: DecryptSigned requires TwosComplement parameters")
	}
	residues, err := c.Decrypt(value)
	if err != nil {
		return nil, err
	}
	bits := uint(c.parameters.WordBits)
	words := make([]int64, len(residues))
	for index, residue := range residues {
		if bits == 64 {
			words[index] = int64(residue)
			continue
		}
		if residue&(uint64(1)<<(bits-1)) != 0 {
			words[index] = int64(residue) - (int64(1) << bits)
		} else {
			words[index] = int64(residue)
		}
	}
	return words, nil
}

// DecryptShort returns raw residues from a diagnostic short value.
func (c *Context) DecryptShort(value *ShortValue) ([]uint64, error) {
	if err := c.ownsShort(value); err != nil {
		return nil, err
	}
	words, err := c.codec.DecryptDecode(value.inner)
	if err != nil {
		return nil, fmt.Errorf("ckksint: decrypt short words: %w", err)
	}
	return words, nil
}

// Add returns lhs+rhs modulo 2^n.
func (c *Context) Add(lhs, rhs *Value) (*Value, error) {
	if err := c.ownsBoth(lhs, rhs); err != nil {
		return nil, err
	}
	value, err := c.codec.Add(lhs.inner, rhs.inner)
	return c.operation("add", value, err)
}

// Sub returns lhs-rhs modulo 2^n.
func (c *Context) Sub(lhs, rhs *Value) (*Value, error) {
	if err := c.ownsBoth(lhs, rhs); err != nil {
		return nil, err
	}
	value, err := c.codec.Sub(lhs.inner, rhs.inner)
	return c.operation("subtract", value, err)
}

// Neg returns -value modulo 2^n.
func (c *Context) Neg(value *Value) (*Value, error) {
	if err := c.owns(value); err != nil {
		return nil, err
	}
	result, err := c.codec.Negate(value.inner)
	return c.operation("negate", result, err)
}

// AddPublic adds one public residue per encrypted word.
func (c *Context) AddPublic(value *Value, words []uint64) (*Value, error) {
	if err := c.owns(value); err != nil {
		return nil, err
	}
	result, err := c.codec.AddPublic(value.inner, words)
	return c.operation("add public", result, err)
}

// SubPublic subtracts one public residue per encrypted word.
func (c *Context) SubPublic(value *Value, words []uint64) (*Value, error) {
	if err := c.owns(value); err != nil {
		return nil, err
	}
	result, err := c.codec.SubPublic(value.inner, words)
	return c.operation("subtract public", result, err)
}

// Mul returns lhs*rhs modulo 2^n and consumes two modulus levels.
func (c *Context) Mul(lhs, rhs *Value) (*Value, error) {
	if err := c.ownsBoth(lhs, rhs); err != nil {
		return nil, err
	}
	value, err := c.codec.MultFull(lhs.inner, rhs.inner)
	return c.operation("multiply", value, err)
}

// MulShort multiplies an arithmetic value by a short/binary value and consumes
// one modulus level.
func (c *Context) MulShort(lhs *Value, rhs *ShortValue) (*Value, error) {
	if err := c.owns(lhs); err != nil {
		return nil, err
	}
	if err := c.ownsShort(rhs); err != nil {
		return nil, err
	}
	value, err := c.codec.MultShort(lhs.inner, rhs.inner)
	return c.operation("multiply short", value, err)
}

// ImportTrustedCiphertext admits a detached Lattigo arithmetic ciphertext
// under this Context's parameters, key domain, and word layout. The input is
// copied before structural validation.
//
// RLWE ciphertexts do not carry a verifiable key-domain identifier. Calling
// this method is therefore an explicit assertion that ciphertext was produced
// under this Context's keys and exact packing convention. Never import an
// untrusted ciphertext.
func (c *Context) ImportTrustedCiphertext(ciphertext *rlwe.Ciphertext, wordCount int) (*Value, error) {
	if err := c.ready(); err != nil {
		return nil, err
	}
	if ciphertext == nil {
		return nil, fmt.Errorf("ckksint: import nil ciphertext")
	}
	owned := ciphertext.CopyNew()
	parameters := c.parameters.evaluator()
	value := &inteval.Value{
		Ciphertext: owned,
		Metadata: inteval.ValueMetadata{
			Parameters:   parameters,
			WordCount:    wordCount,
			SlotsPerWord: parameters.SlotsPerWord(),
			SlotsUsed:    wordCount * parameters.SlotsPerWord(),
			Level:        owned.Level(),
			Scale:        owned.Scale,
		},
	}
	if err := c.codec.Validate(value); err != nil {
		return nil, fmt.Errorf("ckksint: import ciphertext: %w", err)
	}
	return c.wrap(value), nil
}

func (c *Context) operation(name string, value *inteval.Value, err error) (*Value, error) {
	if err != nil {
		return nil, fmt.Errorf("ckksint: %s: %w", name, err)
	}
	return c.wrap(value), nil
}

func (c *Context) wrap(value *inteval.Value) *Value {
	return &Value{inner: value, owner: c.token}
}

func (c *Context) ready() error {
	if c == nil || c.codec == nil || c.token == nil {
		return fmt.Errorf("ckksint: nil or incomplete context")
	}
	return nil
}

func (c *Context) owns(value *Value) error {
	if err := c.ready(); err != nil {
		return err
	}
	if value == nil || value.inner == nil || value.owner != c.token {
		return fmt.Errorf("ckksint: value does not belong to this context")
	}
	return nil
}

func (c *Context) ownsShort(value *ShortValue) error {
	if err := c.ready(); err != nil {
		return err
	}
	if value == nil || value.inner == nil || value.owner != c.token {
		return fmt.Errorf("ckksint: short value does not belong to this context")
	}
	return nil
}

func (c *Context) ownsBoth(lhs, rhs *Value) error {
	if err := c.owns(lhs); err != nil {
		return fmt.Errorf("ckksint: left operand: %w", err)
	}
	if err := c.owns(rhs); err != nil {
		return fmt.Errorf("ckksint: right operand: %w", err)
	}
	return nil
}
