package ring

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"reflect"
)

// sliceRuntimeIdentity describes a slice backing array without retaining or
// exposing the slice itself.
type sliceRuntimeIdentity struct {
	data uintptr
	len  int
	cap  int
}

func runtimeSliceIdentity[T any](values []T) sliceRuntimeIdentity {
	return sliceRuntimeIdentity{data: reflect.ValueOf(values).Pointer(), len: len(values), cap: cap(values)}
}

// PolyRuntimeIdentity is an immutable description of a Poly's backing
// topology. Coefficient values are deliberately excluded because Poly is also
// used as mutable evaluator scratch space.
type PolyRuntimeIdentity struct {
	coefficients sliceRuntimeIdentity
	rows         []sliceRuntimeIdentity
}

// RuntimeIdentitySnapshot returns a value-only description of the polynomial
// coefficient backing topology.
func (pol Poly) RuntimeIdentitySnapshot() PolyRuntimeIdentity {
	identity := PolyRuntimeIdentity{
		coefficients: runtimeSliceIdentity(pol.Coeffs),
		rows:         make([]sliceRuntimeIdentity, len(pol.Coeffs)),
	}
	for i := range pol.Coeffs {
		identity.rows[i] = runtimeSliceIdentity(pol.Coeffs[i])
	}
	return identity
}

// Equal reports whether two polynomial snapshots describe the same backing
// topology and shape.
func (identity PolyRuntimeIdentity) Equal(other PolyRuntimeIdentity) bool {
	return reflect.DeepEqual(identity, other)
}

type ringRuntimeIdentity struct {
	owner  uintptr
	digest [sha256.Size]byte
}

func snapshotRingRuntimeIdentity(r *Ring) (ringRuntimeIdentity, error) {
	if r == nil {
		return ringRuntimeIdentity{}, fmt.Errorf("ring is nil")
	}
	encoded, err := r.MarshalBinary()
	if err != nil {
		return ringRuntimeIdentity{}, fmt.Errorf("cannot marshal ring parameters: %w", err)
	}
	return ringRuntimeIdentity{owner: reflect.ValueOf(r).Pointer(), digest: sha256.Sum256(encoded)}, nil
}

type matrixRuntimeIdentity struct {
	outer sliceRuntimeIdentity
	rows  []sliceRuntimeIdentity
}

func snapshotUint64Matrix(values [][]uint64) matrixRuntimeIdentity {
	identity := matrixRuntimeIdentity{
		outer: runtimeSliceIdentity(values),
		rows:  make([]sliceRuntimeIdentity, len(values)),
	}
	for i := range values {
		identity.rows[i] = runtimeSliceIdentity(values[i])
	}
	return identity
}

type modUpConstantsRuntimeIdentity struct {
	qoverqiinvqi sliceRuntimeIdentity
	qoverqimodp  matrixRuntimeIdentity
	vtimesqmodp  matrixRuntimeIdentity
}

func snapshotModUpConstants(c ModUpConstants) modUpConstantsRuntimeIdentity {
	return modUpConstantsRuntimeIdentity{
		qoverqiinvqi: runtimeSliceIdentity(c.qoverqiinvqi),
		qoverqimodp:  snapshotUint64Matrix(c.qoverqimodp),
		vtimesqmodp:  snapshotUint64Matrix(c.vtimesqmodp),
	}
}

type modUpConstantsSliceRuntimeIdentity struct {
	outer  sliceRuntimeIdentity
	values []modUpConstantsRuntimeIdentity
}

func snapshotModUpConstantsSlice(values []ModUpConstants) modUpConstantsSliceRuntimeIdentity {
	identity := modUpConstantsSliceRuntimeIdentity{
		outer:  runtimeSliceIdentity(values),
		values: make([]modUpConstantsRuntimeIdentity, len(values)),
	}
	for i := range values {
		identity.values[i] = snapshotModUpConstants(values[i])
	}
	return identity
}

type runtimeIdentityHash struct {
	data []byte
}

func (h *runtimeIdentityHash) addUint64(value uint64) {
	var encoded [8]byte
	binary.LittleEndian.PutUint64(encoded[:], value)
	h.data = append(h.data, encoded[:]...)
}

func (h *runtimeIdentityHash) addUint64Slice(values []uint64) {
	h.addUint64(uint64(len(values)))
	for _, value := range values {
		h.addUint64(value)
	}
}

func (h *runtimeIdentityHash) addUint64Matrix(values [][]uint64) {
	h.addUint64(uint64(len(values)))
	for _, row := range values {
		h.addUint64Slice(row)
	}
}

func (h *runtimeIdentityHash) addModUpConstants(c ModUpConstants) {
	h.addUint64Slice(c.qoverqiinvqi)
	h.addUint64Matrix(c.qoverqimodp)
	h.addUint64Matrix(c.vtimesqmodp)
}

func (h *runtimeIdentityHash) addModUpConstantsSlice(values []ModUpConstants) {
	h.addUint64(uint64(len(values)))
	for _, c := range values {
		h.addModUpConstants(c)
	}
}

func (h *runtimeIdentityHash) sum() [sha256.Size]byte {
	return sha256.Sum256(h.data)
}

// BasisExtenderRuntimeIdentity is a value-only snapshot of the private rings,
// immutable constants and mutable-buffer backing topology of a BasisExtender.
// It does not contain coefficient values or writable references.
type BasisExtenderRuntimeIdentity struct {
	owner                    uintptr
	ringQ                    ringRuntimeIdentity
	ringP                    ringRuntimeIdentity
	constantsQtoP            modUpConstantsSliceRuntimeIdentity
	constantsPtoQ            modUpConstantsSliceRuntimeIdentity
	modDownConstantsPtoQ     matrixRuntimeIdentity
	modDownConstantsQtoP     matrixRuntimeIdentity
	immutableConstantsDigest [sha256.Size]byte
	buffQ                    PolyRuntimeIdentity
	buffP                    PolyRuntimeIdentity
}

// RuntimeIdentitySnapshot returns a fail-closed, value-only snapshot of the
// BasisExtender runtime object graph.
func (be *BasisExtender) RuntimeIdentitySnapshot() (BasisExtenderRuntimeIdentity, error) {
	if be == nil {
		return BasisExtenderRuntimeIdentity{}, fmt.Errorf("BasisExtender is nil")
	}
	ringQ, err := snapshotRingRuntimeIdentity(be.ringQ)
	if err != nil {
		return BasisExtenderRuntimeIdentity{}, fmt.Errorf("invalid ringQ: %w", err)
	}
	ringP, err := snapshotRingRuntimeIdentity(be.ringP)
	if err != nil {
		return BasisExtenderRuntimeIdentity{}, fmt.Errorf("invalid ringP: %w", err)
	}

	var hash runtimeIdentityHash
	hash.addModUpConstantsSlice(be.constantsQtoP)
	hash.addModUpConstantsSlice(be.constantsPtoQ)
	hash.addUint64Matrix(be.modDownConstantsPtoQ)
	hash.addUint64Matrix(be.modDownConstantsQtoP)

	return BasisExtenderRuntimeIdentity{
		owner:                    reflect.ValueOf(be).Pointer(),
		ringQ:                    ringQ,
		ringP:                    ringP,
		constantsQtoP:            snapshotModUpConstantsSlice(be.constantsQtoP),
		constantsPtoQ:            snapshotModUpConstantsSlice(be.constantsPtoQ),
		modDownConstantsPtoQ:     snapshotUint64Matrix(be.modDownConstantsPtoQ),
		modDownConstantsQtoP:     snapshotUint64Matrix(be.modDownConstantsQtoP),
		immutableConstantsDigest: hash.sum(),
		buffQ:                    be.buffQ.RuntimeIdentitySnapshot(),
		buffP:                    be.buffP.RuntimeIdentitySnapshot(),
	}, nil
}

// Equal reports whether two snapshots describe the same BasisExtender object
// graph, immutable configuration and scratch backing topology.
func (identity BasisExtenderRuntimeIdentity) Equal(other BasisExtenderRuntimeIdentity) bool {
	return reflect.DeepEqual(identity, other)
}

type decomposerLevelRuntimeIdentity struct {
	outer  sliceRuntimeIdentity
	groups []modUpConstantsSliceRuntimeIdentity
}

// DecomposerRuntimeIdentity is a value-only snapshot of the private rings and
// immutable constant backing topology of a Decomposer.
type DecomposerRuntimeIdentity struct {
	owner                    uintptr
	ringQ                    ringRuntimeIdentity
	ringP                    *ringRuntimeIdentity
	levels                   sliceRuntimeIdentity
	constants                []decomposerLevelRuntimeIdentity
	immutableConstantsDigest [sha256.Size]byte
}

// RuntimeIdentitySnapshot returns a fail-closed, value-only snapshot of the
// Decomposer runtime object graph.
func (decomposer *Decomposer) RuntimeIdentitySnapshot() (DecomposerRuntimeIdentity, error) {
	if decomposer == nil {
		return DecomposerRuntimeIdentity{}, fmt.Errorf("Decomposer is nil")
	}
	ringQ, err := snapshotRingRuntimeIdentity(decomposer.ringQ)
	if err != nil {
		return DecomposerRuntimeIdentity{}, fmt.Errorf("invalid ringQ: %w", err)
	}

	var ringP *ringRuntimeIdentity
	if decomposer.ringP != nil {
		identity, err := snapshotRingRuntimeIdentity(decomposer.ringP)
		if err != nil {
			return DecomposerRuntimeIdentity{}, fmt.Errorf("invalid ringP: %w", err)
		}
		ringP = &identity
	}

	constants := make([]decomposerLevelRuntimeIdentity, len(decomposer.ModUpConstants))
	var hash runtimeIdentityHash
	hash.addUint64(uint64(len(decomposer.ModUpConstants)))
	for i, level := range decomposer.ModUpConstants {
		constants[i] = decomposerLevelRuntimeIdentity{
			outer:  runtimeSliceIdentity(level),
			groups: make([]modUpConstantsSliceRuntimeIdentity, len(level)),
		}
		hash.addUint64(uint64(len(level)))
		for j, group := range level {
			constants[i].groups[j] = snapshotModUpConstantsSlice(group)
			hash.addModUpConstantsSlice(group)
		}
	}

	return DecomposerRuntimeIdentity{
		owner:                    reflect.ValueOf(decomposer).Pointer(),
		ringQ:                    ringQ,
		ringP:                    ringP,
		levels:                   runtimeSliceIdentity(decomposer.ModUpConstants),
		constants:                constants,
		immutableConstantsDigest: hash.sum(),
	}, nil
}

// Equal reports whether two snapshots describe the same Decomposer object
// graph, immutable configuration and backing topology.
func (identity DecomposerRuntimeIdentity) Equal(other DecomposerRuntimeIdentity) bool {
	return reflect.DeepEqual(identity, other)
}
