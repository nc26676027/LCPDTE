package treecompile

import (
	"fmt"
	"math"

	"dt_go/integer/treeplan"
	"dt_go/treeio"
)

// MaxMaterializedDepth bounds complete-tree padding before allocation. The HE
// protocols under study use depths at most 12; callers needing a deeper complete
// representation should first revisit its exponential memory cost.
const MaxMaterializedDepth = 20

type rawTreeAnalysis struct {
	maxDepth int
}

func analyzeRawTree(raw treeio.RawTree, numFeatures int) (rawTreeAnalysis, error) {
	if numFeatures < 0 {
		return rawTreeAnalysis{}, fmt.Errorf("%w: negative feature count %d", ErrMalformedTree, numFeatures)
	}
	n := len(raw.Left)
	if n == 0 {
		return rawTreeAnalysis{}, fmt.Errorf("%w: tree has no root", ErrMalformedTree)
	}
	lengths := []struct {
		name string
		got  int
	}{
		{"right children", len(raw.Right)},
		{"split indices", len(raw.SplitIndex)},
		{"split conditions", len(raw.SplitCond)},
		{"default-left flags", len(raw.DefaultLeft)},
		{"split types", len(raw.SplitType)},
	}
	for _, length := range lengths {
		if length.got != n {
			return rawTreeAnalysis{}, fmt.Errorf("%w: %s length=%d, want %d", ErrMalformedTree, length.name, length.got, n)
		}
	}

	parents := make([]int, n)
	for i := 0; i < n; i++ {
		if raw.SplitType[i] != 0 {
			return rawTreeAnalysis{}, fmt.Errorf("%w: node %d has split type %d", ErrCategoricalSplit, i, raw.SplitType[i])
		}
		if raw.DefaultLeft[i] {
			return rawTreeAnalysis{}, fmt.Errorf("%w: node %d", ErrDefaultLeft, i)
		}
		if math.IsNaN(float64(raw.SplitCond[i])) || math.IsInf(float64(raw.SplitCond[i]), 0) {
			return rawTreeAnalysis{}, fmt.Errorf("%w: node %d has non-finite split/leaf value", ErrMalformedTree, i)
		}

		left, right := raw.Left[i], raw.Right[i]
		isLeaf := left == -1 && right == -1
		if (left == -1) != (right == -1) {
			return rawTreeAnalysis{}, fmt.Errorf("%w: node %d has one-sided children (%d,%d)", ErrMalformedTree, i, left, right)
		}
		if isLeaf {
			continue
		}
		feature := int(raw.SplitIndex[i])
		if feature < 0 || feature >= numFeatures {
			return rawTreeAnalysis{}, fmt.Errorf("%w: node %d feature=%d, feature count=%d", ErrMalformedTree, i, feature, numFeatures)
		}
		for _, child := range []int32{left, right} {
			if child < 0 || int(child) >= n {
				return rawTreeAnalysis{}, fmt.Errorf("%w: node %d child %d is out of range [0,%d)", ErrMalformedTree, i, child, n)
			}
			parents[int(child)]++
		}
	}
	if parents[0] != 0 {
		return rawTreeAnalysis{}, fmt.Errorf("%w: root has %d parents", ErrMalformedTree, parents[0])
	}
	for i := 1; i < n; i++ {
		if parents[i] != 1 {
			return rawTreeAnalysis{}, fmt.Errorf("%w: node %d has %d parents", ErrMalformedTree, i, parents[i])
		}
	}

	state := make([]uint8, n)
	maxDepth := 0
	var visit func(int, int) error
	visit = func(index, depth int) error {
		if state[index] == 1 {
			return fmt.Errorf("%w: cycle reaches node %d", ErrMalformedTree, index)
		}
		if state[index] == 2 {
			return nil
		}
		state[index] = 1
		if raw.Left[index] == -1 {
			if depth > maxDepth {
				maxDepth = depth
			}
		} else {
			if err := visit(int(raw.Left[index]), depth+1); err != nil {
				return err
			}
			if err := visit(int(raw.Right[index]), depth+1); err != nil {
				return err
			}
		}
		state[index] = 2
		return nil
	}
	if err := visit(0, 0); err != nil {
		return rawTreeAnalysis{}, err
	}
	for i, s := range state {
		if s != 2 {
			return rawTreeAnalysis{}, fmt.Errorf("%w: node %d is unreachable from root", ErrMalformedTree, i)
		}
	}
	if maxDepth > MaxMaterializedDepth {
		return rawTreeAnalysis{}, fmt.Errorf("%w: depth %d exceeds materialization limit %d", ErrMalformedTree, maxDepth, MaxMaterializedDepth)
	}
	return rawTreeAnalysis{maxDepth: maxDepth}, nil
}

// CompileTree pads a raw numeric XGBoost tree to its observed maximum depth.
func CompileTree(raw treeio.RawTree, numFeatures int) (treeplan.BinaryTree[float32, float64], error) {
	analysis, err := analyzeRawTree(raw, numFeatures)
	if err != nil {
		return treeplan.BinaryTree[float32, float64]{}, err
	}
	return CompileTreeAtDepth(raw, numFeatures, analysis.maxDepth)
}

// CompileTreeAtDepth pads a raw numeric tree to an explicit complete depth.
// It is used by CompileModel to give every forest member the same HE shape.
func CompileTreeAtDepth(raw treeio.RawTree, numFeatures, targetDepth int) (treeplan.BinaryTree[float32, float64], error) {
	analysis, err := analyzeRawTree(raw, numFeatures)
	if err != nil {
		return treeplan.BinaryTree[float32, float64]{}, err
	}
	if targetDepth < analysis.maxDepth {
		return treeplan.BinaryTree[float32, float64]{}, fmt.Errorf("%w: target depth %d is shallower than source depth %d", ErrMalformedTree, targetDepth, analysis.maxDepth)
	}
	if targetDepth > MaxMaterializedDepth {
		return treeplan.BinaryTree[float32, float64]{}, fmt.Errorf("%w: target depth %d exceeds materialization limit %d", ErrMalformedTree, targetDepth, MaxMaterializedDepth)
	}
	if targetDepth > 0 && numFeatures == 0 {
		return treeplan.BinaryTree[float32, float64]{}, fmt.Errorf("%w: padded splits require at least one feature", ErrMalformedTree)
	}

	leafCount := 1 << targetDepth
	out := treeplan.BinaryTree[float32, float64]{
		Depth:  targetDepth,
		Splits: make([]treeplan.BinarySplit[float32], leafCount-1),
		Leaves: make([]float64, leafCount),
	}
	// Every unused split has identical descendants, so this public dummy
	// predicate cannot change the selected value.
	for i := range out.Splits {
		out.Splits[i] = treeplan.BinarySplit[float32]{Feature: 0, Threshold: 0}
	}

	var fill func(rawIndex, depth, heapIndex, prefix int)
	fill = func(rawIndex, depth, heapIndex, prefix int) {
		if raw.Left[rawIndex] == -1 {
			remaining := targetDepth - depth
			start := prefix << remaining
			end := start + (1 << remaining)
			value := float64(raw.SplitCond[rawIndex])
			for i := start; i < end; i++ {
				out.Leaves[i] = value
			}
			return
		}

		out.Splits[heapIndex] = treeplan.BinarySplit[float32]{
			Feature:   int(raw.SplitIndex[rawIndex]),
			Threshold: raw.SplitCond[rawIndex],
		}
		fill(int(raw.Left[rawIndex]), depth+1, 2*heapIndex+1, prefix<<1)
		fill(int(raw.Right[rawIndex]), depth+1, 2*heapIndex+2, (prefix<<1)|1)
	}
	fill(0, 0, 0, 0)

	if err := out.Validate(); err != nil {
		return treeplan.BinaryTree[float32, float64]{}, fmt.Errorf("compiled tree invariant: %w", err)
	}
	return out, nil
}
