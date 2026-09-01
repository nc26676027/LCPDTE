package treecompile

import (
	"fmt"
	"math"

	"dt_go/integer/treeplan"
)

// OrderedForestView identifies how a forest's split operands are represented.
// It is provenance for a comparator view, not a different trained model.
type OrderedForestView string

const (
	// OrderedFloat32R0ComparatorView is the R0 binary-comparator view obtained by
	// replacing each finite float32 operand with its order-preserving uint32 key.
	// Tree shape, routes, leaves, margins, and model semantics remain unchanged.
	OrderedFloat32R0ComparatorView OrderedForestView = "r0_ordered_float32_comparator"
)

// OrderedFloat32Key maps a finite IEEE-754 float32 to an unsigned comparison
// key. For all finite a and b, a < b iff key(a) < key(b), and a >= b iff
// key(a) >= key(b). IEEE-754 -0 and +0 compare equal and are therefore
// canonicalized to the same key. NaNs and infinities are rejected explicitly.
func OrderedFloat32Key(value float32) (uint32, error) {
	bits := math.Float32bits(value)
	if bits&0x7f800000 == 0x7f800000 {
		return 0, fmt.Errorf("%w: float32 bit pattern 0x%08x", ErrNonFiniteValue, bits)
	}
	if bits&0x7fffffff == 0 {
		return 0x80000000, nil
	}
	if bits&0x80000000 != 0 {
		return ^bits, nil
	}
	return bits ^ 0x80000000, nil
}

// OrderedForest is an integer-comparator view of a validated Forest. It is not
// a model rewrite: only split thresholds change representation. All other
// fields retain the source forest's values and ordering.
type OrderedForest struct {
	View            OrderedForestView                      `json:"view"`
	NumFeatures     int                                    `json:"num_features"`
	Depth           int                                    `json:"depth"`
	SourceBaseScore float64                                `json:"source_base_score"`
	BaseMargin      float64                                `json:"base_margin"`
	Semantics       ModelSemantics                         `json:"semantics"`
	Trees           []treeplan.BinaryTree[uint32, float64] `json:"trees"`
}

// CompileOrderedForest validates source and returns an independent R0 ordered
// comparator view. The source forest and all of its backing slices are left
// untouched and are not aliased by the result.
func CompileOrderedForest(source Forest) (OrderedForest, error) {
	if err := source.Validate(); err != nil {
		return OrderedForest{}, fmt.Errorf("ordered float32 comparator view: %w", err)
	}

	ordered := OrderedForest{
		View:            OrderedFloat32R0ComparatorView,
		NumFeatures:     source.NumFeatures,
		Depth:           source.Depth,
		SourceBaseScore: source.SourceBaseScore,
		BaseMargin:      source.BaseMargin,
		Semantics:       source.Semantics,
		Trees:           make([]treeplan.BinaryTree[uint32, float64], len(source.Trees)),
	}
	for treeIndex, sourceTree := range source.Trees {
		orderedTree := treeplan.BinaryTree[uint32, float64]{
			Depth:  sourceTree.Depth,
			Splits: make([]treeplan.BinarySplit[uint32], len(sourceTree.Splits)),
			Leaves: append([]float64(nil), sourceTree.Leaves...),
		}
		for splitIndex, sourceSplit := range sourceTree.Splits {
			threshold, err := OrderedFloat32Key(sourceSplit.Threshold)
			if err != nil {
				return OrderedForest{}, fmt.Errorf("tree %d split %d threshold: %w", treeIndex, splitIndex, err)
			}
			orderedTree.Splits[splitIndex] = treeplan.BinarySplit[uint32]{
				Feature:   sourceSplit.Feature,
				Threshold: threshold,
			}
		}
		ordered.Trees[treeIndex] = orderedTree
	}
	return ordered, nil
}
