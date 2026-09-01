package treeplan

import (
	"fmt"
)

// SemanticsClass prevents a model-changing R1 design from being reported as a
// semantics-preserving optimization.
type SemanticsClass string

const (
	SemanticsUnverified      SemanticsClass = "unverified"
	SemanticsBinaryReference SemanticsClass = "binary_reference"
	SemanticsR0Equivalent    SemanticsClass = "r0_binary_equivalent"
	SemanticsR1ModelChanging SemanticsClass = "r1_multiway_model_changing"
)

// SymbolicRotationCost records the selection primitive that an HE backend must
// instantiate. An encrypted child index is not a public Galois element, so it
// cannot be passed to a data-dependent Rotate operation.
type SymbolicRotationCost struct {
	Expression           string `json:"expression"`
	DataDependentAllowed bool   `json:"data_dependent_allowed"`
	Constraint           string `json:"constraint"`
}

// LogicalMetricStatus declares what an integer planning field actually means.
// In particular, a predicate-stage lower bound is not an end-to-end HE depth.
type LogicalMetricStatus string

const (
	LogicalMetricDerivedEndToEnd     LogicalMetricStatus = "derived_end_to_end"
	LogicalMetricPredicateLowerBound LogicalMetricStatus = "predicate_stage_lower_bound"
	LogicalMetricNotDerived          LogicalMetricStatus = "not_derived"
)

const encryptedIndexConstraint = "an encrypted child index cannot drive a data-dependent rotation; use an oblivious one-hot/diagonal selector with public rotations"

// CostVector is a JSON-friendly logical cost model. Counts are worst-case for
// one active root-to-leaf route, except LeafTerms, which is the final oblivious
// leaf selector width. They are deliberately not wall-clock predictions:
//
//   - ThresholdComparisons counts threshold predicates on the active route.
//   - BranchBits counts predicate bits produced on that route.
//   - StructuralRounds counts grouped plan rounds, independent of execution.
//   - Depth is qualified by DepthStatus. Binary/R1 costs are derived
//     end-to-end; R0 schedule compatibility views expose only a predicate/LUT
//     dependency lower bound.
//   - OneHotStates counts route indicators materialized across those rounds.
//   - SelectorTerms counts candidate terms consumed by those route selectors.
//   - LogicalBootstraps counts ideal batched branch-refresh stages.
//   - Rotations is symbolic because the concrete count depends on packing.
//   - LeafTerms is the number of final leaf candidates.
//
// A backend should report concrete HE operations separately and reconcile them
// with this vector instead of treating this model as a measured complexity.
type CostVector struct {
	ThresholdComparisons    int                  `json:"threshold_comparisons"`
	BranchBits              int                  `json:"branch_bits"`
	StructuralRounds        int                  `json:"structural_rounds"`
	Depth                   int                  `json:"depth"`
	DepthStatus             LogicalMetricStatus  `json:"depth_status"`
	OneHotStates            int                  `json:"one_hot_states"`
	SelectorTerms           int                  `json:"selector_terms"`
	LogicalBootstraps       int                  `json:"bootstraps_logical"`
	LogicalBootstrapsStatus LogicalMetricStatus  `json:"bootstraps_logical_status"`
	Rotations               SymbolicRotationCost `json:"rotations_symbolic"`
	LeafTerms               int                  `json:"leaf_terms"`
	ExecutionSchedule       R0Schedule           `json:"execution_schedule,omitempty"`
	EligibilityConstraint   string               `json:"eligibility_constraint,omitempty"`
}

// Plan is the stable metadata seam shared by plaintext plans and future HE
// evaluators. Concrete evaluators additionally consume their plan's split arena.
type Plan interface {
	Semantics() SemanticsClass
	Metrics() (CostVector, error)
}

func binaryCost(depth, leafTerms int) CostVector {
	return CostVector{
		ThresholdComparisons:    depth,
		BranchBits:              depth,
		StructuralRounds:        depth,
		Depth:                   depth,
		DepthStatus:             LogicalMetricDerivedEndToEnd,
		OneHotStates:            2 * depth,
		SelectorTerms:           2 * depth,
		LogicalBootstraps:       depth,
		LogicalBootstrapsStatus: LogicalMetricDerivedEndToEnd,
		Rotations: SymbolicRotationCost{
			Expression:           fmt.Sprintf("%d*ObliviousSelect(2)", depth),
			DataDependentAllowed: false,
			Constraint:           encryptedIndexConstraint,
		},
		LeafTerms: leafTerms,
	}
}

// CompleteMultiwayCost returns the logical cost of a complete, uniform radix-r
// interval tree with L leaves. It requires L=r^d. Each interval node evaluates
// r-1 thresholds, so its active-path comparison count is exactly
// (r-1)*log_r(L), not log_r(L).
func CompleteMultiwayCost(radix, leaves int) (CostVector, error) {
	if radix < 2 {
		return CostVector{}, fmt.Errorf("radix must be at least 2: %d", radix)
	}
	if leaves < 1 {
		return CostVector{}, fmt.Errorf("leaf count must be positive: %d", leaves)
	}

	depth := 0
	for n := leaves; n > 1; n /= radix {
		if n%radix != 0 {
			return CostVector{}, fmt.Errorf("leaf count %d is not an exact power of radix %d", leaves, radix)
		}
		depth++
	}

	return CostVector{
		ThresholdComparisons:    (radix - 1) * depth,
		BranchBits:              (radix - 1) * depth,
		StructuralRounds:        depth,
		Depth:                   depth,
		DepthStatus:             LogicalMetricDerivedEndToEnd,
		OneHotStates:            radix * depth,
		SelectorTerms:           radix * depth,
		LogicalBootstraps:       depth,
		LogicalBootstrapsStatus: LogicalMetricDerivedEndToEnd,
		Rotations: SymbolicRotationCost{
			Expression:           fmt.Sprintf("%d*ObliviousSelect(%d)", depth, radix),
			DataDependentAllowed: false,
			Constraint:           encryptedIndexConstraint,
		},
		LeafTerms: leaves,
	}, nil
}
