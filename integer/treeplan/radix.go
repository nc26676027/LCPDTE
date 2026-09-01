package treeplan

import (
	"crypto/sha256"
	"fmt"
)

// RadixSupernode contains the complete local binary subtree for one path prefix.
// Its Splits remain in local breadth-first order. It is not an interval node:
// the g decisions may use different features and thresholds.
type RadixSupernode[T Ordered] struct {
	Prefix int              `json:"prefix"`
	Splits []BinarySplit[T] `json:"splits"`
}

// RadixLevel groups Width consecutive binary levels beginning at StartDepth.
// There is one supernode for every binary path prefix of StartDepth bits.
type RadixLevel[T Ordered] struct {
	StartDepth int                 `json:"start_depth"`
	Width      int                 `json:"width"`
	Nodes      []RadixSupernode[T] `json:"nodes"`
}

// RadixTree is an R0 semantics-preserving grouping of a complete BinaryTree.
// GroupWidth is restricted to 1..4 by the registered experiment design.
type RadixTree[T Ordered, L Ordered] struct {
	BinaryDepth int             `json:"binary_depth"`
	GroupWidth  int             `json:"group_width"`
	Levels      []RadixLevel[T] `json:"levels"`
	Leaves      []L             `json:"leaves"`
	certificate r0Certificate
}

// r0Certificate is deliberately package-private: only CompileR0 can issue an
// R0 equivalence claim. The plan digest detects mutation after compilation;
// the source digest binds that immutable snapshot to one BinaryTree.
type r0Certificate struct {
	issued       bool
	sourceDigest [sha256.Size]byte
	planDigest   [sha256.Size]byte
}

// R0Certificate is a read-only reporting view of the compiler binding. These
// strings can be logged in experiment manifests; changing the returned copy
// cannot alter the private certificate used by Validate.
type R0Certificate struct {
	SourceSHA256 string `json:"source_sha256"`
	PlanSHA256   string `json:"plan_sha256"`
}

// CompileR0 groups consecutive binary levels into radix-2^g supernodes. Every
// original split appears exactly once, and Leaves keeps the reference order.
func CompileR0[T Ordered, L Ordered](tree BinaryTree[T, L], groupWidth int) (RadixTree[T, L], error) {
	if groupWidth < 1 || groupWidth > 4 {
		return RadixTree[T, L]{}, fmt.Errorf("R0 group width must be in [1,4]: %d", groupWidth)
	}
	if err := tree.Validate(); err != nil {
		return RadixTree[T, L]{}, fmt.Errorf("invalid binary source: %w", err)
	}

	out := RadixTree[T, L]{
		BinaryDepth: tree.Depth,
		GroupWidth:  groupWidth,
		Leaves:      append([]L(nil), tree.Leaves...),
	}

	for start := 0; start < tree.Depth; start += groupWidth {
		width := groupWidth
		if remaining := tree.Depth - start; width > remaining {
			width = remaining
		}
		level := RadixLevel[T]{
			StartDepth: start,
			Width:      width,
			Nodes:      make([]RadixSupernode[T], 1<<start),
		}

		for prefix := range level.Nodes {
			localSplits := make([]BinarySplit[T], (1<<width)-1)
			for localDepth := 0; localDepth < width; localDepth++ {
				globalBase := (1 << (start + localDepth)) - 1
				localBase := (1 << localDepth) - 1
				for suffix := 0; suffix < 1<<localDepth; suffix++ {
					globalIndex := globalBase + (prefix << localDepth) + suffix
					localSplits[localBase+suffix] = tree.Splits[globalIndex]
				}
			}
			level.Nodes[prefix] = RadixSupernode[T]{Prefix: prefix, Splits: localSplits}
		}
		out.Levels = append(out.Levels, level)
	}

	sourceDigest, err := digestBinaryTree(tree)
	if err != nil {
		return RadixTree[T, L]{}, fmt.Errorf("digest binary source: %w", err)
	}
	planDigest, err := digestRadixPlan(out)
	if err != nil {
		return RadixTree[T, L]{}, fmt.Errorf("digest radix plan: %w", err)
	}
	out.certificate = r0Certificate{issued: true, sourceDigest: sourceDigest, planDigest: planDigest}

	return out, nil
}

// validateStructure checks that a radix plan is structurally complete. It
// cannot establish source equivalence by shape alone.
func (t RadixTree[T, L]) validateStructure() error {
	if t.GroupWidth < 1 || t.GroupWidth > 4 {
		return fmt.Errorf("R0 group width must be in [1,4]: %d", t.GroupWidth)
	}
	_, wantLeaves, err := fullTreeCounts(t.BinaryDepth)
	if err != nil {
		return err
	}
	if len(t.Leaves) != wantLeaves {
		return fmt.Errorf("leaf count=%d, want %d for binary depth %d", len(t.Leaves), wantLeaves, t.BinaryDepth)
	}

	wantStart := 0
	for i, level := range t.Levels {
		if level.StartDepth != wantStart {
			return fmt.Errorf("radix level %d starts at %d, want %d", i, level.StartDepth, wantStart)
		}
		wantWidth := t.GroupWidth
		if remaining := t.BinaryDepth - wantStart; wantWidth > remaining {
			wantWidth = remaining
		}
		if level.Width != wantWidth {
			return fmt.Errorf("radix level %d width=%d, want %d", i, level.Width, wantWidth)
		}
		if len(level.Nodes) != 1<<wantStart {
			return fmt.Errorf("radix level %d node count=%d, want %d", i, len(level.Nodes), 1<<wantStart)
		}
		for prefix, node := range level.Nodes {
			if node.Prefix != prefix {
				return fmt.Errorf("radix level %d node %d has prefix %d", i, prefix, node.Prefix)
			}
			if len(node.Splits) != (1<<level.Width)-1 {
				return fmt.Errorf("radix level %d node %d split count=%d, want %d", i, prefix, len(node.Splits), (1<<level.Width)-1)
			}
			for j, split := range node.Splits {
				if split.Feature < 0 {
					return fmt.Errorf("radix level %d node %d split %d has negative feature %d", i, prefix, j, split.Feature)
				}
				if !finiteScalar(split.Threshold) {
					return fmt.Errorf("radix level %d node %d split %d has a non-finite threshold", i, prefix, j)
				}
			}
		}
		wantStart += level.Width
	}
	if wantStart != t.BinaryDepth {
		return fmt.Errorf("radix levels cover %d binary levels, want %d", wantStart, t.BinaryDepth)
	}
	for i, leaf := range t.Leaves {
		if !finiteScalar(leaf) {
			return fmt.Errorf("leaf %d is non-finite", i)
		}
	}
	return nil
}

func (t RadixTree[T, L]) validateCertificate() error {
	if !t.certificate.issued {
		return fmt.Errorf("R0 equivalence certificate is absent")
	}
	digest, err := digestRadixPlan(t)
	if err != nil {
		return fmt.Errorf("digest radix plan: %w", err)
	}
	if digest != t.certificate.planDigest {
		return fmt.Errorf("R0 equivalence certificate does not match the current plan")
	}
	return nil
}

// Validate checks both the public structure and the compiler-issued immutable
// plan certificate. A structural JSON copy is intentionally unverified.
func (t RadixTree[T, L]) Validate() error {
	if err := t.validateStructure(); err != nil {
		return err
	}
	return t.validateCertificate()
}

// VerifyAgainst proves that this still-untampered plan was issued for source.
// It also recompiles source and compares public plan digests, making the
// compiler mapping part of the check rather than relying on shape alone.
func (t RadixTree[T, L]) VerifyAgainst(source BinaryTree[T, L]) error {
	if err := t.Validate(); err != nil {
		return fmt.Errorf("invalid certified R0 plan: %w", err)
	}
	if err := source.Validate(); err != nil {
		return fmt.Errorf("invalid binary source: %w", err)
	}
	sourceDigest, err := digestBinaryTree(source)
	if err != nil {
		return fmt.Errorf("digest binary source: %w", err)
	}
	if sourceDigest != t.certificate.sourceDigest {
		return fmt.Errorf("R0 certificate belongs to a different binary source")
	}
	expected, err := CompileR0(source, t.GroupWidth)
	if err != nil {
		return fmt.Errorf("recompile binary source: %w", err)
	}
	expectedDigest, err := digestRadixPlan(expected)
	if err != nil {
		return fmt.Errorf("digest recompiled plan: %w", err)
	}
	if expectedDigest != t.certificate.planDigest {
		return fmt.Errorf("R0 plan does not match the compiler output for its source")
	}
	return nil
}

// Certificate returns stable audit identifiers for a valid, untampered plan.
func (t RadixTree[T, L]) Certificate() (R0Certificate, error) {
	if err := t.Validate(); err != nil {
		return R0Certificate{}, err
	}
	return R0Certificate{
		SourceSHA256: fmt.Sprintf("%x", t.certificate.sourceDigest),
		PlanSHA256:   fmt.Sprintf("%x", t.certificate.planDigest),
	}, nil
}

// Semantics reports R0 equivalence only while the compiler-issued plan
// certificate still matches the current public fields.
func (t RadixTree[T, L]) Semantics() SemanticsClass {
	if err := t.Validate(); err != nil {
		return SemanticsUnverified
	}
	return SemanticsR0Equivalent
}

// Route evaluates each supernode's local binary subtree and concatenates its
// radix digit to the MSB-first global leaf index.
func (t RadixTree[T, L]) Route(features []T) (int, error) {
	if err := t.Validate(); err != nil {
		return 0, err
	}
	if err := validateFiniteFeatures(features); err != nil {
		return 0, err
	}
	prefix := 0
	for levelIndex, level := range t.Levels {
		node := level.Nodes[prefix]
		localIndex := 0
		digit := 0
		for d := 0; d < level.Width; d++ {
			split := node.Splits[localIndex]
			if split.Feature >= len(features) {
				return 0, fmt.Errorf("radix level %d split %d requires feature %d, input has %d features", levelIndex, localIndex, split.Feature, len(features))
			}
			branch := 1
			if features[split.Feature] < split.Threshold {
				branch = 0
			}
			digit = (digit << 1) | branch
			localIndex = 2*localIndex + 1 + branch
		}
		prefix = (prefix << level.Width) | digit
	}
	return prefix, nil
}

// Evaluate returns exactly the leaf stored at Route(features).
func (t RadixTree[T, L]) Evaluate(features []T) (L, error) {
	index, err := t.Route(features)
	if err != nil {
		var zero L
		return zero, err
	}
	return t.Leaves[index], nil
}

// Metrics returns the source-faithful OBO cost. The conservative uniform
// CT-CT oracle remains available only through an explicit schedule request.
func (t RadixTree[T, L]) Metrics() (CostVector, error) {
	return t.MetricsForSchedule(R0SequentialSourceFaithfulOBO)
}

// MetricsForSchedule is a compatibility view of the detailed PlanSchedule
// contract. It exposes logical lower bounds only. Physical HE fields, including
// rotations and bootstraps, remain typed not-measured in the group profiles.
// State-aware fused LUTs require a proof-bearing R0ScheduleRequest and are
// therefore available only through PlanSchedule.
func (t RadixTree[T, L]) MetricsForSchedule(schedule R0Schedule) (CostVector, error) {
	plan, err := t.PlanSchedule(R0ScheduleRequest{Schedule: schedule})
	if err != nil {
		return CostVector{}, err
	}
	cost := CostVector{
		StructuralRounds:  len(t.Levels),
		LeafTerms:         len(t.Leaves),
		ExecutionSchedule: schedule,
		Rotations: SymbolicRotationCost{
			Expression:           "not_measured; see R0SchedulePlan.Groups",
			DataDependentAllowed: false,
			Constraint:           encryptedIndexConstraint,
		},
	}
	for _, group := range plan.Groups {
		cost.ThresholdComparisons += group.LogicalComparisons
		cost.SelectorTerms += group.LogicalSelectorTerms
		cost.Depth += group.PredicateDependencyRounds
	}
	switch schedule {
	case R0SequentialSourceFaithfulOBO, R0SequentialActiveCTCT:
		cost.BranchBits = t.BinaryDepth
		cost.OneHotStates = 2 * t.BinaryDepth
		cost.EligibilityConstraint = "predicate-stage lower bound only; end-to-end depth and every physical HE field are not_measured"
	case R0EagerActiveCTCT, R0EagerAllCTPT:
		cost.BranchBits = cost.ThresholdComparisons
		for _, level := range t.Levels {
			cost.OneHotStates += 1 << level.Width
		}
		cost.EligibilityConstraint = "logical lower bound only; digit/path graph and every physical HE field must be reported by the backend"
	default:
		return CostVector{}, fmt.Errorf("unknown R0 execution schedule %q", schedule)
	}
	cost.DepthStatus = LogicalMetricPredicateLowerBound
	cost.LogicalBootstraps = 0
	cost.LogicalBootstrapsStatus = LogicalMetricNotDerived
	return cost, nil
}
