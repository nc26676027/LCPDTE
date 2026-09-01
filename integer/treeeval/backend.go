package treeeval

import "errors"

var (
	ErrInvalidBackend          = errors.New("invalid evaluator backend")
	ErrInvalidValue            = errors.New("invalid evaluator value")
	ErrBackendOperation        = errors.New("backend operation failed")
	ErrBackendProvenance       = errors.New("backend returned inconsistent provenance")
	ErrInvalidComparisonPolicy = errors.New("invalid comparison policy")
)

// ValueKind is explicit because HE cost and comparator type depend on whether
// an operand is a server-public scalar or an opaque/ciphertext value.
type ValueKind uint8

const (
	ValueInvalid ValueKind = iota
	ValuePublic
	ValueOpaque
)

func (k ValueKind) String() string {
	switch k {
	case ValuePublic:
		return "public"
	case ValueOpaque:
		return "opaque"
	default:
		return "invalid"
	}
}

// Backend is the minimal arithmetic/comparison seam required by both tree
// evaluators. A Lattigo adapter can map V to its ciphertext/public-constant
// union while preserving Kind exactly.
type Backend[V any] interface {
	PublicConstant(value PublicScalar) (V, error)
	Kind(value V) ValueKind
	Add(left, right V) (V, error)
	Sub(left, right V) (V, error)
	Mul(left, right V) (V, error)
	CompareGE(left, right V, policy ComparisonPolicy) (V, error)
}
