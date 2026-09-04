// Modified by the LCPDTE project for local module integration and, where applicable,
// runtime instrumentation. See lattigo/NOTICE for attribution and modification details.

package rlwe

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"reflect"
	"sort"

	"github.com/nc26676027/LCPDTE/lattigo/ring"
	"github.com/nc26676027/LCPDTE/lattigo/ring/ringqp"
)

type sliceRuntimeIdentity struct {
	data uintptr
	len  int
	cap  int
}

func runtimeSliceIdentity[T any](values []T) sliceRuntimeIdentity {
	return sliceRuntimeIdentity{data: reflect.ValueOf(values).Pointer(), len: len(values), cap: cap(values)}
}

type ringQPPolyRuntimeIdentity struct {
	q ring.PolyRuntimeIdentity
	p ring.PolyRuntimeIdentity
}

func snapshotRingQPPoly(poly ringqp.Poly) ringQPPolyRuntimeIdentity {
	return ringQPPolyRuntimeIdentity{
		q: poly.Q.RuntimeIdentitySnapshot(),
		p: poly.P.RuntimeIdentitySnapshot(),
	}
}

type ciphertextBufferRuntimeIdentity struct {
	owner    uintptr
	metadata uintptr
	value    sliceRuntimeIdentity
	polys    []ring.PolyRuntimeIdentity
}

func snapshotCiphertextBuffer(ct *Ciphertext) (ciphertextBufferRuntimeIdentity, error) {
	if ct == nil {
		return ciphertextBufferRuntimeIdentity{}, fmt.Errorf("BuffCt is nil")
	}
	identity := ciphertextBufferRuntimeIdentity{
		owner: reflect.ValueOf(ct).Pointer(),
		value: runtimeSliceIdentity(ct.Value),
		polys: make([]ring.PolyRuntimeIdentity, len(ct.Value)),
	}
	if ct.MetaData != nil {
		identity.metadata = reflect.ValueOf(ct.MetaData).Pointer()
	}
	for i := range ct.Value {
		identity.polys[i] = ct.Value[i].RuntimeIdentitySnapshot()
	}
	return identity, nil
}

// EvaluatorBuffersRuntimeIdentity is a value-only description of all public
// RLWE evaluator buffer backings. Scratch coefficient values are excluded.
type EvaluatorBuffersRuntimeIdentity struct {
	owner         uintptr
	buffCt        ciphertextBufferRuntimeIdentity
	buffQP        [6]ringQPPolyRuntimeIdentity
	buffInvNTT    ring.PolyRuntimeIdentity
	buffDecompQP  sliceRuntimeIdentity
	decompPolys   []ringQPPolyRuntimeIdentity
	buffBitDecomp sliceRuntimeIdentity
}

// RuntimeIdentitySnapshot returns a fail-closed, value-only snapshot of every
// evaluator buffer's outer and nested backing topology.
func (buffers *EvaluatorBuffers) RuntimeIdentitySnapshot() (EvaluatorBuffersRuntimeIdentity, error) {
	if buffers == nil {
		return EvaluatorBuffersRuntimeIdentity{}, fmt.Errorf("EvaluatorBuffers is nil")
	}
	buffCt, err := snapshotCiphertextBuffer(buffers.BuffCt)
	if err != nil {
		return EvaluatorBuffersRuntimeIdentity{}, err
	}
	identity := EvaluatorBuffersRuntimeIdentity{
		owner:         reflect.ValueOf(buffers).Pointer(),
		buffCt:        buffCt,
		buffInvNTT:    buffers.BuffInvNTT.RuntimeIdentitySnapshot(),
		buffDecompQP:  runtimeSliceIdentity(buffers.BuffDecompQP),
		decompPolys:   make([]ringQPPolyRuntimeIdentity, len(buffers.BuffDecompQP)),
		buffBitDecomp: runtimeSliceIdentity(buffers.BuffBitDecomp),
	}
	for i := range buffers.BuffQP {
		identity.buffQP[i] = snapshotRingQPPoly(buffers.BuffQP[i])
	}
	for i := range buffers.BuffDecompQP {
		identity.decompPolys[i] = snapshotRingQPPoly(buffers.BuffDecompQP[i])
	}
	return identity, nil
}

// Equal reports whether two snapshots describe the same buffer object graph,
// outer backings, nested polynomial backings and shapes.
func (identity EvaluatorBuffersRuntimeIdentity) Equal(other EvaluatorBuffersRuntimeIdentity) bool {
	return reflect.DeepEqual(identity, other)
}

type interfaceRuntimeIdentity struct {
	present     bool
	dynamicType string
	target      uintptr
}

func snapshotPointerInterface(value any, label string) (interfaceRuntimeIdentity, error) {
	if value == nil {
		return interfaceRuntimeIdentity{}, nil
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Map, reflect.Ptr, reflect.Slice, reflect.UnsafePointer:
		if v.IsNil() {
			return interfaceRuntimeIdentity{}, fmt.Errorf("%s contains a typed nil %T", label, value)
		}
		return interfaceRuntimeIdentity{present: true, dynamicType: v.Type().String(), target: v.Pointer()}, nil
	default:
		return interfaceRuntimeIdentity{}, fmt.Errorf("%s dynamic value %T has no stable identity", label, value)
	}
}

type automorphismEntryRuntimeIdentity struct {
	galEl  uint64
	values sliceRuntimeIdentity
	digest [sha256.Size]byte
}

type automorphismMapRuntimeIdentity struct {
	present bool
	target  uintptr
	entries []automorphismEntryRuntimeIdentity
}

func snapshotAutomorphismMap(values map[uint64][]uint64) automorphismMapRuntimeIdentity {
	if values == nil {
		return automorphismMapRuntimeIdentity{}
	}
	keys := make([]uint64, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	identity := automorphismMapRuntimeIdentity{
		present: true,
		target:  reflect.ValueOf(values).Pointer(),
		entries: make([]automorphismEntryRuntimeIdentity, len(keys)),
	}
	for i, key := range keys {
		indexes := values[key]
		encoded := make([]byte, 8*len(indexes))
		for j, index := range indexes {
			binary.LittleEndian.PutUint64(encoded[8*j:], index)
		}
		identity.entries[i] = automorphismEntryRuntimeIdentity{
			galEl:  key,
			values: runtimeSliceIdentity(indexes),
			digest: sha256.Sum256(encoded),
		}
	}
	return identity
}

// EvaluatorRuntimeIdentity is a value-only snapshot of an RLWE Evaluator's
// private configuration, dynamic key binding and mutable-buffer topology.
type EvaluatorRuntimeIdentity struct {
	owner             uintptr
	parametersDigest  [sha256.Size]byte
	ringQ             uintptr
	ringP             uintptr
	evaluationKeySet  interfaceRuntimeIdentity
	buffers           EvaluatorBuffersRuntimeIdentity
	automorphismIndex automorphismMapRuntimeIdentity
	hasBasisExtender  bool
	basisExtender     ring.BasisExtenderRuntimeIdentity
	decomposer        ring.DecomposerRuntimeIdentity
}

// RuntimeIdentitySnapshot returns a fail-closed, value-only snapshot of the
// evaluator runtime object graph. It hashes immutable parameters and cached
// automorphism indexes, but never hashes scratch coefficient values.
func (eval *Evaluator) RuntimeIdentitySnapshot() (EvaluatorRuntimeIdentity, error) {
	if eval == nil {
		return EvaluatorRuntimeIdentity{}, fmt.Errorf("RLWE Evaluator is nil")
	}
	parameters, err := eval.params.MarshalBinary()
	if err != nil {
		return EvaluatorRuntimeIdentity{}, fmt.Errorf("cannot marshal RLWE parameters: %w", err)
	}
	keySet, err := snapshotPointerInterface(eval.EvaluationKeySet, "EvaluationKeySet")
	if err != nil {
		return EvaluatorRuntimeIdentity{}, err
	}
	buffers, err := eval.EvaluatorBuffers.RuntimeIdentitySnapshot()
	if err != nil {
		return EvaluatorRuntimeIdentity{}, err
	}
	decomposer, err := eval.Decomposer.RuntimeIdentitySnapshot()
	if err != nil {
		return EvaluatorRuntimeIdentity{}, fmt.Errorf("invalid Decomposer: %w", err)
	}

	identity := EvaluatorRuntimeIdentity{
		owner:             reflect.ValueOf(eval).Pointer(),
		parametersDigest:  sha256.Sum256(parameters),
		evaluationKeySet:  keySet,
		buffers:           buffers,
		automorphismIndex: snapshotAutomorphismMap(eval.automorphismIndex),
		decomposer:        decomposer,
	}
	if ringQ := eval.params.RingQ(); ringQ != nil {
		identity.ringQ = reflect.ValueOf(ringQ).Pointer()
	} else {
		return EvaluatorRuntimeIdentity{}, fmt.Errorf("RLWE parameters RingQ is nil")
	}
	if ringP := eval.params.RingP(); ringP != nil {
		identity.ringP = reflect.ValueOf(ringP).Pointer()
	}
	if eval.BasisExtender != nil {
		identity.hasBasisExtender = true
		if identity.basisExtender, err = eval.BasisExtender.RuntimeIdentitySnapshot(); err != nil {
			return EvaluatorRuntimeIdentity{}, fmt.Errorf("invalid BasisExtender: %w", err)
		}
	} else if eval.params.RingP() != nil {
		return EvaluatorRuntimeIdentity{}, fmt.Errorf("BasisExtender is nil while RingP is present")
	}
	return identity, nil
}

// Equal reports whether two snapshots describe the same evaluator object
// graph, immutable configuration and scratch backing topology.
func (identity EvaluatorRuntimeIdentity) Equal(other EvaluatorRuntimeIdentity) bool {
	return reflect.DeepEqual(identity, other)
}
