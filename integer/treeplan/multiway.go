package treeplan

import "fmt"

// ChildKind disambiguates node and leaf arena indices in JSON.
type ChildKind string

const (
	ChildNode ChildKind = "node"
	ChildLeaf ChildKind = "leaf"
)

// ChildRef references either an IntervalNode or a leaf value.
type ChildRef struct {
	Kind  ChildKind `json:"kind"`
	Index int       `json:"index"`
}

func NodeRef(index int) ChildRef { return ChildRef{Kind: ChildNode, Index: index} }
func LeafRef(index int) ChildRef { return ChildRef{Kind: ChildLeaf, Index: index} }

// IntervalNode has r-1 strictly increasing thresholds and r children. The
// selected child is the insertion interval for the feature value; equality is
// placed above its matching threshold, consistent with BinaryTree.
type IntervalNode[T Ordered] struct {
	Feature    int        `json:"feature"`
	Thresholds []T        `json:"thresholds"`
	Children   []ChildRef `json:"children"`
}

// MultiwayTree is an explicit R1 model. It is never inferred to be equivalent
// to a BinaryTree merely because it has the same number of leaves.
type MultiwayTree[T Ordered, L Ordered] struct {
	Root   ChildRef          `json:"root"`
	Nodes  []IntervalNode[T] `json:"nodes"`
	Leaves []L               `json:"leaves"`
}

func (t MultiwayTree[T, L]) validateRef(ref ChildRef) error {
	if ref.Index < 0 {
		return fmt.Errorf("%s reference has negative index %d", ref.Kind, ref.Index)
	}
	switch ref.Kind {
	case ChildNode:
		if ref.Index >= len(t.Nodes) {
			return fmt.Errorf("node reference %d is out of range [0,%d)", ref.Index, len(t.Nodes))
		}
	case ChildLeaf:
		if ref.Index >= len(t.Leaves) {
			return fmt.Errorf("leaf reference %d is out of range [0,%d)", ref.Index, len(t.Leaves))
		}
	default:
		return fmt.Errorf("unknown child kind %q", ref.Kind)
	}
	return nil
}

// Validate checks interval ordering, arity, references, cycles, and reachability.
func (t MultiwayTree[T, L]) Validate() error {
	if err := t.validateRef(t.Root); err != nil {
		return fmt.Errorf("invalid root: %w", err)
	}
	for i, node := range t.Nodes {
		if node.Feature < 0 {
			return fmt.Errorf("node %d has negative feature %d", i, node.Feature)
		}
		if len(node.Thresholds) == 0 {
			return fmt.Errorf("node %d has no thresholds", i)
		}
		for j, threshold := range node.Thresholds {
			if !finiteScalar(threshold) {
				return fmt.Errorf("node %d threshold %d is non-finite", i, j)
			}
		}
		if len(node.Children) != len(node.Thresholds)+1 {
			return fmt.Errorf("node %d has %d thresholds and %d children, want %d children", i, len(node.Thresholds), len(node.Children), len(node.Thresholds)+1)
		}
		for j := 1; j < len(node.Thresholds); j++ {
			if !(node.Thresholds[j-1] < node.Thresholds[j]) {
				return fmt.Errorf("node %d thresholds are not strictly increasing at %d", i, j)
			}
		}
		for j, child := range node.Children {
			if err := t.validateRef(child); err != nil {
				return fmt.Errorf("node %d child %d: %w", i, j, err)
			}
		}
	}
	for i, leaf := range t.Leaves {
		if !finiteScalar(leaf) {
			return fmt.Errorf("leaf %d is non-finite", i)
		}
	}

	state := make([]uint8, len(t.Nodes))
	reachedNodes := make([]bool, len(t.Nodes))
	reachedLeaves := make([]bool, len(t.Leaves))
	var visit func(ChildRef) error
	visit = func(ref ChildRef) error {
		if ref.Kind == ChildLeaf {
			reachedLeaves[ref.Index] = true
			return nil
		}
		index := ref.Index
		if state[index] == 1 {
			return fmt.Errorf("cycle reaches node %d", index)
		}
		if state[index] == 2 {
			return nil
		}
		state[index] = 1
		reachedNodes[index] = true
		for _, child := range t.Nodes[index].Children {
			if err := visit(child); err != nil {
				return err
			}
		}
		state[index] = 2
		return nil
	}
	if err := visit(t.Root); err != nil {
		return err
	}
	for i, reached := range reachedNodes {
		if !reached {
			return fmt.Errorf("node %d is unreachable from root", i)
		}
	}
	for i, reached := range reachedLeaves {
		if !reached {
			return fmt.Errorf("leaf %d is unreachable from root", i)
		}
	}
	return nil
}

func (t MultiwayTree[T, L]) Semantics() SemanticsClass { return SemanticsR1ModelChanging }

// Route returns the selected leaf arena index.
func (t MultiwayTree[T, L]) Route(features []T) (int, error) {
	if err := t.Validate(); err != nil {
		return 0, err
	}
	if err := validateFiniteFeatures(features); err != nil {
		return 0, err
	}
	ref := t.Root
	for ref.Kind == ChildNode {
		node := t.Nodes[ref.Index]
		if node.Feature >= len(features) {
			return 0, fmt.Errorf("node %d requires feature %d, input has %d features", ref.Index, node.Feature, len(features))
		}
		value := features[node.Feature]
		interval := len(node.Thresholds)
		for i, threshold := range node.Thresholds {
			if value < threshold {
				interval = i
				break
			}
		}
		ref = node.Children[interval]
	}
	return ref.Index, nil
}

func (t MultiwayTree[T, L]) Evaluate(features []T) (L, error) {
	index, err := t.Route(features)
	if err != nil {
		var zero L
		return zero, err
	}
	return t.Leaves[index], nil
}

type pathVector struct {
	comparisons int
	branchBits  int
	depth       int
	oneHot      int
	selectors   int
	bootstraps  int
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Metrics returns independent worst-case active-path counts and fails closed
// for a malformed hand-built tree.
func (t MultiwayTree[T, L]) Metrics() (CostVector, error) {
	cost := CostVector{LeafTerms: len(t.Leaves)}
	if err := t.Validate(); err != nil {
		return CostVector{}, err
	}

	memo := make([]pathVector, len(t.Nodes))
	done := make([]bool, len(t.Nodes))
	var walk func(ChildRef) pathVector
	walk = func(ref ChildRef) pathVector {
		if ref.Kind == ChildLeaf {
			return pathVector{}
		}
		if done[ref.Index] {
			return memo[ref.Index]
		}
		node := t.Nodes[ref.Index]
		childMax := pathVector{}
		for _, child := range node.Children {
			v := walk(child)
			childMax.comparisons = maxInt(childMax.comparisons, v.comparisons)
			childMax.branchBits = maxInt(childMax.branchBits, v.branchBits)
			childMax.depth = maxInt(childMax.depth, v.depth)
			childMax.oneHot = maxInt(childMax.oneHot, v.oneHot)
			childMax.selectors = maxInt(childMax.selectors, v.selectors)
			childMax.bootstraps = maxInt(childMax.bootstraps, v.bootstraps)
		}
		radix := len(node.Children)
		v := pathVector{
			comparisons: childMax.comparisons + radix - 1,
			branchBits:  childMax.branchBits + radix - 1,
			depth:       childMax.depth + 1,
			oneHot:      childMax.oneHot + radix,
			selectors:   childMax.selectors + radix,
			bootstraps:  childMax.bootstraps + 1,
		}
		done[ref.Index] = true
		memo[ref.Index] = v
		return v
	}

	v := walk(t.Root)
	cost.ThresholdComparisons = v.comparisons
	cost.BranchBits = v.branchBits
	cost.Depth = v.depth
	cost.DepthStatus = LogicalMetricDerivedEndToEnd
	cost.StructuralRounds = v.depth
	cost.OneHotStates = v.oneHot
	cost.SelectorTerms = v.selectors
	cost.LogicalBootstraps = v.bootstraps
	cost.LogicalBootstrapsStatus = LogicalMetricDerivedEndToEnd
	cost.Rotations = SymbolicRotationCost{
		Expression:           "sum_path ObliviousSelect(r_i)",
		DataDependentAllowed: false,
		Constraint:           encryptedIndexConstraint,
	}
	return cost, nil
}
