package ckksint

import (
	"fmt"
	"math"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

type functional8ValueKind uint8

const (
	functional8Ingress functional8ValueKind = iota + 1
	functional8Converted
)

// EncryptedInt8 contains four packed signed int8 words. Values returned by
// B2A are decryptable but cannot be reused as fresh A2B/comparison ingress
// because the conversion intentionally exits at a lower modulus level.
type EncryptedInt8 struct {
	ciphertext           *rlwe.Ciphertext
	owner                *functional8Token
	kind                 functional8ValueKind
	comparisonAdmissible bool
}

// Boolean8 contains two encrypted LSB-first four-bit halves per lane.
type Boolean8 struct {
	low   *rlwe.Ciphertext
	high  *rlwe.Ciphertext
	owner *functional8Token
}

// Selector8 contains four encrypted arithmetic selectors in {0,1}.
type Selector8 struct {
	ciphertext *rlwe.Ciphertext
	owner      *functional8Token
}

// EncryptedReal8 contains four packed real-valued tree leaves, each repeated
// across its four-slot lane block.
type EncryptedReal8 struct {
	ciphertext *rlwe.Ciphertext
	owner      *functional8Token
}

// LattigoCiphertext returns a detached copy for explicit interoperability.
func (v *EncryptedInt8) LattigoCiphertext() *rlwe.Ciphertext {
	if v == nil || v.ciphertext == nil {
		return nil
	}
	return v.ciphertext.CopyNew()
}

// LattigoHalves returns detached low/high Boolean ciphertext copies.
func (v *Boolean8) LattigoHalves() (low, high *rlwe.Ciphertext) {
	if v == nil || v.low == nil || v.high == nil {
		return nil, nil
	}
	return v.low.CopyNew(), v.high.CopyNew()
}

// LattigoCiphertext returns a detached selector ciphertext copy.
func (v *Selector8) LattigoCiphertext() *rlwe.Ciphertext {
	if v == nil || v.ciphertext == nil {
		return nil
	}
	return v.ciphertext.CopyNew()
}

// LattigoCiphertext returns a detached real-result ciphertext copy.
func (v *EncryptedReal8) LattigoCiphertext() *rlwe.Ciphertext {
	if v == nil || v.ciphertext == nil {
		return nil
	}
	return v.ciphertext.CopyNew()
}

// Encrypt encodes four two's-complement int8 values at the circuit ingress.
func (f *Functional8) Encrypt(words [Functional8Lanes]int8) (*EncryptedInt8, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.ready(); err != nil {
		return nil, err
	}
	inputSlots := make([]*bignum.Complex, 0, f.params.MaxSlots())
	comparisonAdmissible := true
	for _, word := range words {
		if word < f.ranges.FeatureMin || word > f.ranges.FeatureMax {
			comparisonAdmissible = false
		}
		block, err := f.ringZ.ToRootSlots(f.ringZ.ArithmeticEncode(uint64(uint8(word))))
		if err != nil {
			return nil, fmt.Errorf("ckksint: encode functional8 word %d: %w", word, err)
		}
		inputSlots = append(inputSlots, block...)
	}
	plaintext := ckks.NewPlaintext(f.params, f.params.MaxLevel())
	plaintext.LogDimensions = f.params.LogMaxDimensions()
	plaintext.Scale = f.params.DefaultScale()
	if err := f.refreshEncoder.Encode(inputSlots, plaintext); err != nil {
		return nil, fmt.Errorf("ckksint: encode functional8 slots: %w", err)
	}
	ciphertext, err := f.encryptor.EncryptNew(plaintext)
	if err != nil {
		return nil, fmt.Errorf("ckksint: encrypt functional8 slots: %w", err)
	}
	return &EncryptedInt8{
		ciphertext: ciphertext, owner: f.token, kind: functional8Ingress,
		comparisonAdmissible: comparisonAdmissible,
	}, nil
}

// Decrypt recovers four two's-complement int8 values.
func (f *Functional8) Decrypt(value *EncryptedInt8) ([Functional8Lanes]int8, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.ownsInt(value, false); err != nil {
		return [Functional8Lanes]int8{}, err
	}
	residues, err := f.decryptArithmetic(value.ciphertext)
	if err != nil {
		return [Functional8Lanes]int8{}, err
	}
	var words [Functional8Lanes]int8
	for lane, residue := range residues {
		words[lane] = int8(uint8(residue))
	}
	return words, nil
}

// DecryptBits returns LSB-first bits for each lane.
func (f *Functional8) DecryptBits(value *Boolean8) ([Functional8Lanes][8]uint8, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.ownsBoolean(value); err != nil {
		return [Functional8Lanes][8]uint8{}, err
	}
	low, err := f.decodeComplex(value.low)
	if err != nil {
		return [Functional8Lanes][8]uint8{}, fmt.Errorf("ckksint: decrypt low Boolean half: %w", err)
	}
	high, err := f.decodeComplex(value.high)
	if err != nil {
		return [Functional8Lanes][8]uint8{}, fmt.Errorf("ckksint: decrypt high Boolean half: %w", err)
	}
	var bits [Functional8Lanes][8]uint8
	for lane := 0; lane < Functional8Lanes; lane++ {
		for offset := 0; offset < 4; offset++ {
			lowBit, err := roundedBit(low[4*lane+offset])
			if err != nil {
				return bits, fmt.Errorf("ckksint: lane %d low bit %d: %w", lane, offset, err)
			}
			highBit, err := roundedBit(high[4*lane+offset])
			if err != nil {
				return bits, fmt.Errorf("ckksint: lane %d high bit %d: %w", lane, offset, err)
			}
			bits[lane][offset] = lowBit
			bits[lane][offset+4] = highBit
		}
	}
	return bits, nil
}

// DecryptSelector recovers four GE branch decisions.
func (f *Functional8) DecryptSelector(value *Selector8) ([Functional8Lanes]bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.ownsSelector(value); err != nil {
		return [Functional8Lanes]bool{}, err
	}
	residues, err := f.decryptArithmetic(value.ciphertext)
	if err != nil {
		return [Functional8Lanes]bool{}, err
	}
	var selectors [Functional8Lanes]bool
	for lane, residue := range residues {
		if residue > 1 {
			return selectors, fmt.Errorf("ckksint: selector lane %d decoded to %d, want 0 or 1", lane, residue)
		}
		selectors[lane] = residue == 1
	}
	return selectors, nil
}

// DecryptReal recovers the four real-valued tree leaves.
func (f *Functional8) DecryptReal(value *EncryptedReal8) ([Functional8Lanes]float64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.ownsReal(value); err != nil {
		return [Functional8Lanes]float64{}, err
	}
	decoded, err := f.decodeComplex(value.ciphertext)
	if err != nil {
		return [Functional8Lanes]float64{}, fmt.Errorf("ckksint: decrypt real tree result: %w", err)
	}
	var result [Functional8Lanes]float64
	for lane := 0; lane < Functional8Lanes; lane++ {
		var sum float64
		for offset := 0; offset < 4; offset++ {
			value := decoded[4*lane+offset]
			if math.Abs(imag(value)) > 0.1 || math.IsNaN(real(value)) || math.IsInf(real(value), 0) {
				return result, fmt.Errorf("ckksint: non-real or non-finite tree output at lane %d slot %d: %v", lane, offset, value)
			}
			sum += real(value)
		}
		result[lane] = sum / 4
	}
	return result, nil
}

func (f *Functional8) decryptArithmetic(ciphertext *rlwe.Ciphertext) ([Functional8Lanes]uint64, error) {
	var result [Functional8Lanes]uint64
	if ciphertext == nil {
		return result, fmt.Errorf("ckksint: nil arithmetic ciphertext")
	}
	values := make([]*bignum.Complex, ciphertext.Slots())
	if err := f.integerEncoder.Decode(f.decryptor.DecryptNew(ciphertext), values); err != nil {
		return result, fmt.Errorf("ckksint: decode arithmetic slots: %w", err)
	}
	for lane := 0; lane < Functional8Lanes; lane++ {
		polynomial, err := f.ringZ.FromRootSlots(values[4*lane : 4*(lane+1)])
		if err != nil {
			return result, fmt.Errorf("ckksint: recover lane %d polynomial: %w", lane, err)
		}
		result[lane], err = f.ringZ.DecodeArithmetic(polynomial)
		if err != nil {
			return result, fmt.Errorf("ckksint: recover lane %d residue: %w", lane, err)
		}
	}
	return result, nil
}

func (f *Functional8) decodeComplex(ciphertext *rlwe.Ciphertext) ([]complex128, error) {
	if ciphertext == nil {
		return nil, fmt.Errorf("nil ciphertext")
	}
	values := make([]complex128, ciphertext.Slots())
	if err := f.integerEncoder.Decode(f.decryptor.DecryptNew(ciphertext), values); err != nil {
		return nil, err
	}
	return values, nil
}

func roundedBit(value complex128) (uint8, error) {
	if math.Abs(imag(value)) > 0.1 {
		return 0, fmt.Errorf("imaginary error %.3g exceeds 0.1", math.Abs(imag(value)))
	}
	rounded := math.Round(real(value))
	if (rounded != 0 && rounded != 1) || math.Abs(real(value)-rounded) > 0.1 {
		return 0, fmt.Errorf("value %v is not within 0.1 of a bit", value)
	}
	return uint8(rounded), nil
}

func (f *Functional8) ownsInt(value *EncryptedInt8, requireIngress bool) error {
	if err := f.ready(); err != nil {
		return err
	}
	if value == nil || value.ciphertext == nil || value.owner != f.token {
		return fmt.Errorf("ckksint: encrypted int8 value does not belong to this engine")
	}
	if requireIngress && value.kind != functional8Ingress {
		return fmt.Errorf("ckksint: operation requires a fresh level-%d functional8 ingress", f.profile.InputLevel)
	}
	return nil
}

func (f *Functional8) ownsBoolean(value *Boolean8) error {
	if err := f.ready(); err != nil {
		return err
	}
	if value == nil || value.low == nil || value.high == nil || value.owner != f.token {
		return fmt.Errorf("ckksint: Boolean8 value does not belong to this engine")
	}
	return nil
}

func (f *Functional8) ownsSelector(value *Selector8) error {
	if err := f.ready(); err != nil {
		return err
	}
	if value == nil || value.ciphertext == nil || value.owner != f.token {
		return fmt.Errorf("ckksint: Selector8 value does not belong to this engine")
	}
	return nil
}

func (f *Functional8) ownsReal(value *EncryptedReal8) error {
	if err := f.ready(); err != nil {
		return err
	}
	if value == nil || value.ciphertext == nil || value.owner != f.token {
		return fmt.Errorf("ckksint: EncryptedReal8 value does not belong to this engine")
	}
	return nil
}
