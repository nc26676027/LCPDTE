// Modified by the LCPDTE project for local module integration and, where applicable,
// runtime instrumentation. See lattigo/NOTICE for attribution and modification details.

package ckks

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"reflect"
	"sort"

	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/ring"
	"github.com/nc26676027/LCPDTE/lattigo/utils/bignum"
)

type sliceRuntimeIdentity struct {
	data uintptr
	len  int
	cap  int
}

func runtimeSliceIdentity[T any](values []T) sliceRuntimeIdentity {
	return sliceRuntimeIdentity{data: reflect.ValueOf(values).Pointer(), len: len(values), cap: cap(values)}
}

type bigComplexElementRuntimeIdentity struct {
	owner uintptr
	real  uintptr
	imag  uintptr
}

type complexBufferRuntimeIdentity struct {
	dynamicType     string
	backing         sliceRuntimeIdentity
	elements        []bigComplexElementRuntimeIdentity
	immutableDigest [sha256.Size]byte
}

func snapshotComplexBuffer(value any, immutable bool, label string) (complexBufferRuntimeIdentity, error) {
	switch values := value.(type) {
	case []complex128:
		identity := complexBufferRuntimeIdentity{
			dynamicType: "[]complex128",
			backing:     runtimeSliceIdentity(values),
		}
		if immutable {
			encoded := make([]byte, 16*len(values))
			for i, value := range values {
				binary.LittleEndian.PutUint64(encoded[16*i:], math.Float64bits(real(value)))
				binary.LittleEndian.PutUint64(encoded[16*i+8:], math.Float64bits(imag(value)))
			}
			identity.immutableDigest = sha256.Sum256(encoded)
		}
		return identity, nil
	case []*bignum.Complex:
		identity := complexBufferRuntimeIdentity{
			dynamicType: "[]*bignum.Complex",
			backing:     runtimeSliceIdentity(values),
			elements:    make([]bigComplexElementRuntimeIdentity, len(values)),
		}
		var encoded []byte
		for i, value := range values {
			if value == nil || value[0] == nil || value[1] == nil {
				return complexBufferRuntimeIdentity{}, fmt.Errorf("%s[%d] is nil or incomplete", label, i)
			}
			identity.elements[i] = bigComplexElementRuntimeIdentity{
				owner: reflect.ValueOf(value).Pointer(),
				real:  reflect.ValueOf(value[0]).Pointer(),
				imag:  reflect.ValueOf(value[1]).Pointer(),
			}
			if immutable {
				real, err := value[0].GobEncode()
				if err != nil {
					return complexBufferRuntimeIdentity{}, fmt.Errorf("cannot encode %s[%d].real: %w", label, i, err)
				}
				imag, err := value[1].GobEncode()
				if err != nil {
					return complexBufferRuntimeIdentity{}, fmt.Errorf("cannot encode %s[%d].imag: %w", label, i, err)
				}
				var size [8]byte
				binary.LittleEndian.PutUint64(size[:], uint64(len(real)))
				encoded = append(encoded, size[:]...)
				encoded = append(encoded, real...)
				binary.LittleEndian.PutUint64(size[:], uint64(len(imag)))
				encoded = append(encoded, size[:]...)
				encoded = append(encoded, imag...)
			}
		}
		if !immutable {
			// High-precision FFT/IFFT legitimately bit-reverses the pointers in
			// this scratch slice in place. Preserve the exact backing and the
			// complete element-pointer inventory while making its order irrelevant.
			sort.Slice(identity.elements, func(i, j int) bool {
				left, right := identity.elements[i], identity.elements[j]
				if left.owner != right.owner {
					return left.owner < right.owner
				}
				if left.real != right.real {
					return left.real < right.real
				}
				return left.imag < right.imag
			})
		}
		if immutable {
			identity.immutableDigest = sha256.Sum256(encoded)
		}
		return identity, nil
	default:
		return complexBufferRuntimeIdentity{}, fmt.Errorf("%s has unsupported dynamic type %T", label, value)
	}
}

// EncoderRuntimeIdentity is a value-only snapshot of an Encoder's immutable
// parameters and private mutable-buffer topology. Buffer values are excluded.
type EncoderRuntimeIdentity struct {
	owner            uintptr
	parametersDigest [sha256.Size]byte
	ringQ            uintptr
	ringP            uintptr
	precision        uint
	bigintCoeffs     sliceRuntimeIdentity
	qHalf            uintptr
	buff             ring.PolyRuntimeIdentity
	m                int
	rotGroup         sliceRuntimeIdentity
	rotGroupDigest   [sha256.Size]byte
	roots            complexBufferRuntimeIdentity
	buffCmplx        complexBufferRuntimeIdentity
}

// RuntimeIdentitySnapshot returns a fail-closed, value-only snapshot of the
// Encoder object graph. It never retains or exposes mutable Encoder storage.
func (ecd *Encoder) RuntimeIdentitySnapshot() (EncoderRuntimeIdentity, error) {
	if ecd == nil {
		return EncoderRuntimeIdentity{}, fmt.Errorf("CKKS Encoder is nil")
	}
	parameters, err := ecd.parameters.MarshalBinary()
	if err != nil {
		return EncoderRuntimeIdentity{}, fmt.Errorf("cannot marshal CKKS parameters: %w", err)
	}
	if ecd.parameters.RingQ() == nil {
		return EncoderRuntimeIdentity{}, fmt.Errorf("Encoder parameters RingQ is nil")
	}
	if ecd.qHalf == nil {
		return EncoderRuntimeIdentity{}, fmt.Errorf("Encoder qHalf is nil")
	}
	if ecd.m <= 0 || len(ecd.bigintCoeffs) != ecd.m>>1 || len(ecd.rotGroup) != ecd.m>>2 {
		return EncoderRuntimeIdentity{}, fmt.Errorf("Encoder private buffer shape is inconsistent with m=%d", ecd.m)
	}
	if len(ecd.buff.Coeffs) == 0 {
		return EncoderRuntimeIdentity{}, fmt.Errorf("Encoder polynomial buffer is empty")
	}
	roots, err := snapshotComplexBuffer(ecd.roots, true, "Encoder roots")
	if err != nil {
		return EncoderRuntimeIdentity{}, err
	}
	buffCmplx, err := snapshotComplexBuffer(ecd.buffCmplx, false, "Encoder complex buffer")
	if err != nil {
		return EncoderRuntimeIdentity{}, err
	}
	if roots.backing.len != ecd.m+1 || buffCmplx.backing.len == 0 {
		return EncoderRuntimeIdentity{}, fmt.Errorf("Encoder complex buffer shape is inconsistent with m=%d", ecd.m)
	}

	rotGroupEncoding := make([]byte, 8*len(ecd.rotGroup))
	for i, value := range ecd.rotGroup {
		binary.LittleEndian.PutUint64(rotGroupEncoding[8*i:], uint64(value))
	}
	identity := EncoderRuntimeIdentity{
		owner:            reflect.ValueOf(ecd).Pointer(),
		parametersDigest: sha256.Sum256(parameters),
		ringQ:            reflect.ValueOf(ecd.parameters.RingQ()).Pointer(),
		precision:        ecd.prec,
		bigintCoeffs:     runtimeSliceIdentity(ecd.bigintCoeffs),
		qHalf:            reflect.ValueOf(ecd.qHalf).Pointer(),
		buff:             ecd.buff.RuntimeIdentitySnapshot(),
		m:                ecd.m,
		rotGroup:         runtimeSliceIdentity(ecd.rotGroup),
		rotGroupDigest:   sha256.Sum256(rotGroupEncoding),
		roots:            roots,
		buffCmplx:        buffCmplx,
	}
	if ringP := ecd.parameters.RingP(); ringP != nil {
		identity.ringP = reflect.ValueOf(ringP).Pointer()
	}
	return identity, nil
}

// Equal reports whether two snapshots describe the same Encoder object graph,
// immutable configuration and mutable-buffer topology.
func (identity EncoderRuntimeIdentity) Equal(other EncoderRuntimeIdentity) bool {
	return reflect.DeepEqual(identity, other)
}

type evaluatorBuffersRuntimeIdentity struct {
	owner uintptr
	buffQ [3]ring.PolyRuntimeIdentity
}

func (buffers *evaluatorBuffers) runtimeIdentitySnapshot() (evaluatorBuffersRuntimeIdentity, error) {
	if buffers == nil {
		return evaluatorBuffersRuntimeIdentity{}, fmt.Errorf("CKKS evaluatorBuffers is nil")
	}
	identity := evaluatorBuffersRuntimeIdentity{owner: reflect.ValueOf(buffers).Pointer()}
	for i := range buffers.buffQ {
		if len(buffers.buffQ[i].Coeffs) == 0 {
			return evaluatorBuffersRuntimeIdentity{}, fmt.Errorf("CKKS evaluatorBuffers.buffQ[%d] is empty", i)
		}
		identity.buffQ[i] = buffers.buffQ[i].RuntimeIdentitySnapshot()
	}
	return identity, nil
}

// EvaluatorRuntimeIdentity is a value-only snapshot of a CKKS Evaluator's
// Encoder, private CKKS buffers and embedded RLWE Evaluator object graph.
type EvaluatorRuntimeIdentity struct {
	owner   uintptr
	encoder EncoderRuntimeIdentity
	buffers evaluatorBuffersRuntimeIdentity
	rlwe    rlwe.EvaluatorRuntimeIdentity
}

// RuntimeIdentitySnapshot returns a fail-closed, value-only snapshot of the
// complete CKKS evaluator runtime object graph.
func (eval *Evaluator) RuntimeIdentitySnapshot() (EvaluatorRuntimeIdentity, error) {
	if eval == nil {
		return EvaluatorRuntimeIdentity{}, fmt.Errorf("CKKS Evaluator is nil")
	}
	encoder, err := eval.Encoder.RuntimeIdentitySnapshot()
	if err != nil {
		return EvaluatorRuntimeIdentity{}, err
	}
	buffers, err := eval.evaluatorBuffers.runtimeIdentitySnapshot()
	if err != nil {
		return EvaluatorRuntimeIdentity{}, err
	}
	rlweIdentity, err := eval.Evaluator.RuntimeIdentitySnapshot()
	if err != nil {
		return EvaluatorRuntimeIdentity{}, err
	}
	return EvaluatorRuntimeIdentity{
		owner:   reflect.ValueOf(eval).Pointer(),
		encoder: encoder,
		buffers: buffers,
		rlwe:    rlweIdentity,
	}, nil
}

// Equal reports whether two snapshots describe the same complete CKKS
// evaluator object graph and backing topology.
func (identity EvaluatorRuntimeIdentity) Equal(other EvaluatorRuntimeIdentity) bool {
	return reflect.DeepEqual(identity, other)
}
