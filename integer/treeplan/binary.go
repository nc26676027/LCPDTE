package treeplan

import (
	"fmt"
	"math"
	"math/bits"
	"reflect"
)

// Ordered is the set of scalar numeric types accepted by plaintext split
// evaluators. Named types whose underlying type is listed are also supported.
type Ordered interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 |
		~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr |
		~float32 | ~float64
}

// BinarySplit is one numeric predicate. Branch 0 is value < threshold and
// branch 1 is value >= threshold.
type BinarySplit[T Ordered] struct {
	Feature   int `json:"feature"`
	Threshold T   `json:"threshold"`
}

// BinaryTree is a complete binary tree in breadth-first heap order. Splits has
// 2^Depth-1 entries. Leaves has 2^Depth entries in MSB-first path order.
type BinaryTree[T Ordered, L Ordered] struct {
	Depth  int              `json:"depth"`
	Splits []BinarySplit[T] `json:"splits"`
	Leaves []L              `json:"leaves"`
}

func validateFiniteFeatures[T Ordered](features []T) error {
	for i, feature := range features {
		if !finiteScalar(feature) {
			return fmt.Errorf("feature %d is non-finite", i)
		}
	}
	return nil
}

// finiteScalar accepts every integer and rejects NaN/Inf for both built-in and
// named floating-point types.
func finiteScalar(value any) bool {
	v := reflect.ValueOf(value)
	if !v.IsValid() {
		return true
	}
	switch v.Kind() {
	case reflect.Float32, reflect.Float64:
		f := v.Float()
		return !math.IsNaN(f) && !math.IsInf(f, 0)
	default:
		return true
	}
}

func fullTreeCounts(depth int) (splits, leaves int, err error) {
	if depth < 0 {
		return 0, 0, fmt.Errorf("depth must be non-negative: %d", depth)
	}
	if depth >= bits.UintSize-1 {
		return 0, 0, fmt.Errorf("depth %d cannot be represented by platform int", depth)
	}
	leaves = 1 << depth
	return leaves - 1, leaves, nil
}

// Validate checks the complete-tree shape and split feature identifiers.
func (t BinaryTree[T, L]) Validate() error {
	wantSplits, wantLeaves, err := fullTreeCounts(t.Depth)
	if err != nil {
		return err
	}
	if len(t.Splits) != wantSplits {
		return fmt.Errorf("split count=%d, want %d for depth %d", len(t.Splits), wantSplits, t.Depth)
	}
	if len(t.Leaves) != wantLeaves {
		return fmt.Errorf("leaf count=%d, want %d for depth %d", len(t.Leaves), wantLeaves, t.Depth)
	}
	for i, split := range t.Splits {
		if split.Feature < 0 {
			return fmt.Errorf("split %d has negative feature %d", i, split.Feature)
		}
		if !finiteScalar(split.Threshold) {
			return fmt.Errorf("split %d has a non-finite threshold", i)
		}
	}
	for i, leaf := range t.Leaves {
		if !finiteScalar(leaf) {
			return fmt.Errorf("leaf %d is non-finite", i)
		}
	}
	return nil
}

// Semantics identifies this tree as the binary reference model.
func (t BinaryTree[T, L]) Semantics() SemanticsClass { return SemanticsBinaryReference }

// Route returns the leaf index in MSB-first root-to-leaf path order.
func (t BinaryTree[T, L]) Route(features []T) (int, error) {
	if err := t.Validate(); err != nil {
		return 0, err
	}
	if err := validateFiniteFeatures(features); err != nil {
		return 0, err
	}
	node := 0
	leaf := 0
	for d := 0; d < t.Depth; d++ {
		split := t.Splits[node]
		if split.Feature >= len(features) {
			return 0, fmt.Errorf("split %d requires feature %d, input has %d features", node, split.Feature, len(features))
		}
		branch := 1
		if features[split.Feature] < split.Threshold {
			branch = 0
		}
		leaf = (leaf << 1) | branch
		node = 2*node + 1 + branch
	}
	return leaf, nil
}

// Evaluate returns the selected leaf value without converting or rewriting it.
func (t BinaryTree[T, L]) Evaluate(features []T) (L, error) {
	index, err := t.Route(features)
	if err != nil {
		var zero L
		return zero, err
	}
	return t.Leaves[index], nil
}

// Metrics returns the binary reference's logical active-path cost and fails
// closed for a malformed hand-built tree.
func (t BinaryTree[T, L]) Metrics() (CostVector, error) {
	if err := t.Validate(); err != nil {
		return CostVector{}, err
	}
	return binaryCost(t.Depth, len(t.Leaves)), nil
}
