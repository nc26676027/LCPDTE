package treeplan

import (
	"encoding/json"
	"math"
	"math/rand"
	"strings"
	"testing"
)

type marshalZeroInt int64

func (marshalZeroInt) MarshalJSON() ([]byte, error) { return []byte("0"), nil }

func TestCompileR0EquivalentAtBoundaries(t *testing.T) {
	const depth = 4
	splits := make([]BinarySplit[int], (1<<depth)-1)
	for i := range splits {
		splits[i] = BinarySplit[int]{Feature: i % 3, Threshold: (i % 5) - 2}
	}

	leaves := make([]float64, 1<<depth)
	for i := range leaves {
		// Include signed zero and otherwise unusual finite bit patterns: evaluation
		// must return the selected leaf without numerically rewriting it.
		patterns := []uint64{
			0x0000000000000000,
			0x8000000000000000,
			0x3ff0000000000000,
			0xbff0000000000000,
			0x0010000000000000,
			0x8010000000000000,
			0x7fefffffffffffff,
			0xffefffffffffffff,
		}
		leaves[i] = math.Float64frombits(patterns[i%len(patterns)])
	}

	bt := BinaryTree[int, float64]{Depth: depth, Splits: splits, Leaves: leaves}
	if err := bt.Validate(); err != nil {
		t.Fatalf("valid binary tree rejected: %v", err)
	}

	for groupWidth := 1; groupWidth <= 4; groupWidth++ {
		rt, err := CompileR0(bt, groupWidth)
		if err != nil {
			t.Fatalf("CompileR0(g=%d): %v", groupWidth, err)
		}
		if rt.Semantics() != SemanticsR0Equivalent {
			t.Fatalf("g=%d semantics=%q, want %q", groupWidth, rt.Semantics(), SemanticsR0Equivalent)
		}

		for x0 := -3; x0 <= 3; x0++ {
			for x1 := -3; x1 <= 3; x1++ {
				for x2 := -3; x2 <= 3; x2++ {
					x := []int{x0, x1, x2}
					wantIndex, err := bt.Route(x)
					if err != nil {
						t.Fatal(err)
					}
					gotIndex, err := rt.Route(x)
					if err != nil {
						t.Fatal(err)
					}
					if gotIndex != wantIndex {
						t.Fatalf("g=%d x=%v leaf index=%d, want %d", groupWidth, x, gotIndex, wantIndex)
					}

					want, _ := bt.Evaluate(x)
					got, _ := rt.Evaluate(x)
					if math.Float64bits(got) != math.Float64bits(want) {
						t.Fatalf("g=%d x=%v leaf bits=%016x, want %016x", groupWidth, x, math.Float64bits(got), math.Float64bits(want))
					}
				}
			}
		}

		binaryCost, err := bt.Metrics()
		if err != nil {
			t.Fatal(err)
		}
		radixCost, err := rt.Metrics()
		if err != nil {
			t.Fatal(err)
		}
		if radixCost.ThresholdComparisons != binaryCost.ThresholdComparisons {
			t.Fatalf("g=%d comparisons=%d, binary=%d", groupWidth, radixCost.ThresholdComparisons, binaryCost.ThresholdComparisons)
		}
		if radixCost.BranchBits != binaryCost.BranchBits {
			t.Fatalf("g=%d branch bits=%d, binary=%d", groupWidth, radixCost.BranchBits, binaryCost.BranchBits)
		}
		wantStructuralRounds := (depth + groupWidth - 1) / groupWidth
		if radixCost.StructuralRounds != wantStructuralRounds {
			t.Fatalf("g=%d structural rounds=%d, want %d", groupWidth, radixCost.StructuralRounds, wantStructuralRounds)
		}
		if radixCost.Depth != depth {
			t.Fatalf("g=%d sequential HE depth=%d, want source depth %d", groupWidth, radixCost.Depth, depth)
		}
		if radixCost.DepthStatus != LogicalMetricPredicateLowerBound {
			t.Fatalf("g=%d depth status=%q, want predicate lower bound", groupWidth, radixCost.DepthStatus)
		}
		if radixCost.LogicalBootstraps != 0 || radixCost.LogicalBootstrapsStatus != LogicalMetricNotDerived {
			t.Fatalf("g=%d source-faithful physical bootstrap count was invented: %+v", groupWidth, radixCost)
		}
		if radixCost.LeafTerms != 1<<depth {
			t.Fatalf("g=%d leaf terms=%d, want %d", groupWidth, radixCost.LeafTerms, 1<<depth)
		}
		if radixCost.Rotations.DataDependentAllowed {
			t.Fatalf("g=%d incorrectly permits data-dependent rotations", groupWidth)
		}
		if !strings.Contains(strings.ToLower(radixCost.Rotations.Constraint), "data-dependent") {
			t.Fatalf("rotation constraint does not document encrypted-index limitation: %q", radixCost.Rotations.Constraint)
		}
	}
}

func TestR0ScheduleCostsAreSeparated(t *testing.T) {
	const depth = 4
	tree := BinaryTree[int, int]{
		Depth:  depth,
		Splits: make([]BinarySplit[int], (1<<depth)-1),
		Leaves: make([]int, 1<<depth),
	}
	radix, err := CompileR0(tree, 2)
	if err != nil {
		t.Fatal(err)
	}

	sequential, err := radix.MetricsForSchedule(R0SequentialActiveCTCT)
	if err != nil {
		t.Fatal(err)
	}
	if sequential.Depth != depth || sequential.DepthStatus != LogicalMetricPredicateLowerBound || sequential.StructuralRounds != 2 {
		t.Fatalf("sequential cost=%+v, want predicate-depth/structural=4/2", sequential)
	}
	if sequential.LogicalBootstraps != 0 || sequential.LogicalBootstrapsStatus != LogicalMetricNotDerived {
		t.Fatalf("sequential cost invented a bootstrap count: %+v", sequential)
	}
	if sequential.OneHotStates != 2*depth || sequential.SelectorTerms != 30 || !strings.Contains(sequential.Rotations.Expression, "not_measured") {
		t.Fatalf("sequential logical/physical boundary is wrong: %+v", sequential)
	}

	eager, err := radix.MetricsForSchedule(R0EagerActiveCTCT)
	if err != nil {
		t.Fatal(err)
	}
	if eager.ThresholdComparisons != 2*((1<<2)-1) || eager.Depth != 2 || eager.LogicalBootstrapsStatus != LogicalMetricNotDerived {
		t.Fatalf("eager cost=%+v, want comparisons/predicate-depth=6/2 and unknown bootstraps", eager)
	}

	all, err := radix.MetricsForSchedule(R0EagerAllCTPT)
	if err != nil {
		t.Fatal(err)
	}
	if all.ThresholdComparisons != 15 || all.SelectorTerms != 5 || all.Depth != 2 {
		t.Fatalf("all-supernode CT-plaintext cost=%+v, want comparisons/selector/depth=15/5/2", all)
	}
	if _, err := radix.MetricsForSchedule(R0StateAwareFusedLUT); err == nil {
		t.Fatal("proof-free fused compatibility metric accepted")
	}
	if _, err := radix.MetricsForSchedule(R0Schedule("invented")); err == nil {
		t.Fatal("unknown R0 schedule accepted")
	}
}

func TestR0CertificateRejectsMutationAndWrongSource(t *testing.T) {
	source := BinaryTree[int, int]{
		Depth:  2,
		Splits: []BinarySplit[int]{{Feature: 0, Threshold: 0}, {Feature: 1, Threshold: 1}, {Feature: 1, Threshold: 2}},
		Leaves: []int{10, 11, 12, 13},
	}
	plan, err := CompileR0(source, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.VerifyAgainst(source); err != nil {
		t.Fatalf("fresh certificate rejected: %v", err)
	}
	certificate, err := plan.Certificate()
	if err != nil {
		t.Fatal(err)
	}
	if len(certificate.SourceSHA256) != 64 || len(certificate.PlanSHA256) != 64 {
		t.Fatalf("certificate digests are not reportable SHA-256 values: %+v", certificate)
	}

	tampered := plan
	tampered.Levels = append([]RadixLevel[int](nil), plan.Levels...)
	tampered.Levels[0].Nodes = append([]RadixSupernode[int](nil), plan.Levels[0].Nodes...)
	tampered.Levels[0].Nodes[0].Splits = append([]BinarySplit[int](nil), plan.Levels[0].Nodes[0].Splits...)
	tampered.Levels[0].Nodes[0].Splits[0].Threshold++
	if err := tampered.VerifyAgainst(source); err == nil {
		t.Fatal("tampered R0 plan retained equivalence certificate")
	}
	if tampered.Semantics() == SemanticsR0Equivalent {
		t.Fatal("tampered R0 plan still reports R0 equivalence")
	}

	wrong := source
	wrong.Leaves = append([]int(nil), source.Leaves...)
	wrong.Leaves[0]++
	if err := plan.VerifyAgainst(wrong); err == nil {
		t.Fatal("R0 certificate accepted a different source tree")
	}

	forged := RadixTree[int, int]{
		BinaryDepth: plan.BinaryDepth,
		GroupWidth:  plan.GroupWidth,
		Levels:      plan.Levels,
		Leaves:      plan.Leaves,
	}
	if forged.Semantics() == SemanticsR0Equivalent {
		t.Fatal("hand-built structural copy forged R0 equivalence")
	}
	if err := forged.VerifyAgainst(source); err == nil {
		t.Fatal("hand-built structural copy verified without compiler certificate")
	}
}

func TestR0CanonicalDigestIgnoresJSONCustomization(t *testing.T) {
	source := BinaryTree[marshalZeroInt, marshalZeroInt]{
		Depth: 1,
		Splits: []BinarySplit[marshalZeroInt]{
			{Feature: 0, Threshold: 7},
		},
		Leaves: []marshalZeroInt{11, 13},
	}
	plan, err := CompileR0(source, 1)
	if err != nil {
		t.Fatal(err)
	}

	wrongSource := source
	wrongSource.Splits = append([]BinarySplit[marshalZeroInt](nil), source.Splits...)
	wrongSource.Splits[0].Threshold = 8
	if err := plan.VerifyAgainst(wrongSource); err == nil {
		t.Fatal("custom MarshalJSON hid a source-threshold mutation")
	}
	wrongLeafSource := source
	wrongLeafSource.Leaves = append([]marshalZeroInt(nil), source.Leaves...)
	wrongLeafSource.Leaves[0] = 12
	if err := plan.VerifyAgainst(wrongLeafSource); err == nil {
		t.Fatal("custom MarshalJSON hid a source-leaf mutation")
	}

	tamperedThreshold := plan
	tamperedThreshold.Levels = append([]RadixLevel[marshalZeroInt](nil), plan.Levels...)
	tamperedThreshold.Levels[0].Nodes = append([]RadixSupernode[marshalZeroInt](nil), plan.Levels[0].Nodes...)
	tamperedThreshold.Levels[0].Nodes[0].Splits = append([]BinarySplit[marshalZeroInt](nil), plan.Levels[0].Nodes[0].Splits...)
	tamperedThreshold.Levels[0].Nodes[0].Splits[0].Threshold = 8
	if tamperedThreshold.Semantics() == SemanticsR0Equivalent {
		t.Fatal("custom MarshalJSON hid a plan-threshold mutation")
	}

	tamperedLeaf := plan
	tamperedLeaf.Leaves = append([]marshalZeroInt(nil), plan.Leaves...)
	tamperedLeaf.Leaves[0] = 12
	if tamperedLeaf.Semantics() == SemanticsR0Equivalent {
		t.Fatal("custom MarshalJSON hid a plan-leaf mutation")
	}
}

func TestR0CanonicalDigestPreservesIEEEZeroBits(t *testing.T) {
	negativeZero := math.Copysign(0, -1)
	source := BinaryTree[float64, float64]{
		Depth:  1,
		Splits: []BinarySplit[float64]{{Feature: 0, Threshold: negativeZero}},
		Leaves: []float64{negativeZero, 1},
	}
	plan, err := CompileR0(source, 1)
	if err != nil {
		t.Fatal(err)
	}

	wrongSource := source
	wrongSource.Splits = append([]BinarySplit[float64](nil), source.Splits...)
	wrongSource.Splits[0].Threshold = 0
	if err := plan.VerifyAgainst(wrongSource); err == nil {
		t.Fatal("source digest collapsed -0 threshold to +0")
	}
	tampered := plan
	tampered.Leaves = append([]float64(nil), plan.Leaves...)
	tampered.Leaves[0] = 0
	if tampered.Semantics() == SemanticsR0Equivalent {
		t.Fatal("plan digest collapsed -0 leaf to +0")
	}
}

func TestPlansRejectNonFiniteThresholdsAndLeaves(t *testing.T) {
	for name, tree := range map[string]BinaryTree[float64, float64]{
		"nan-threshold": {Depth: 1, Splits: []BinarySplit[float64]{{Feature: 0, Threshold: math.NaN()}}, Leaves: []float64{0, 1}},
		"inf-threshold": {Depth: 1, Splits: []BinarySplit[float64]{{Feature: 0, Threshold: math.Inf(1)}}, Leaves: []float64{0, 1}},
		"nan-leaf":      {Depth: 0, Leaves: []float64{math.NaN()}},
		"inf-leaf":      {Depth: 0, Leaves: []float64{math.Inf(-1)}},
	} {
		if err := tree.Validate(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}

	multiway := MultiwayTree[float64, float64]{
		Root:   NodeRef(0),
		Nodes:  []IntervalNode[float64]{{Feature: 0, Thresholds: []float64{math.NaN()}, Children: []ChildRef{LeafRef(0), LeafRef(1)}}},
		Leaves: []float64{0, 1},
	}
	if err := multiway.Validate(); err == nil {
		t.Fatal("single NaN multiway threshold accepted")
	}
}

func TestRoutesRejectNonFiniteFeatureInputs(t *testing.T) {
	binary := BinaryTree[float64, int]{
		Depth:  1,
		Splits: []BinarySplit[float64]{{Feature: 0, Threshold: 0}},
		Leaves: []int{0, 1},
	}
	radix, err := CompileR0(binary, 1)
	if err != nil {
		t.Fatal(err)
	}
	multiway := MultiwayTree[float64, int]{
		Root: NodeRef(0),
		Nodes: []IntervalNode[float64]{
			{Feature: 0, Thresholds: []float64{0}, Children: []ChildRef{LeafRef(0), LeafRef(1)}},
		},
		Leaves: []int{0, 1},
	}

	for name, route := range map[string]func([]float64) (int, error){
		"binary":   binary.Route,
		"radix":    radix.Route,
		"multiway": multiway.Route,
	} {
		for _, features := range [][]float64{{math.NaN()}, {math.Inf(1)}, {0, math.Inf(-1)}} {
			if _, err := route(features); err == nil {
				t.Fatalf("%s accepted non-finite feature vector %v", name, features)
			}
		}
	}
}

func TestCompileR0RandomCompleteTrees(t *testing.T) {
	rng := rand.New(rand.NewSource(20260829))
	for depth := 1; depth <= 7; depth++ {
		splits := make([]BinarySplit[int32], (1<<depth)-1)
		for i := range splits {
			splits[i] = BinarySplit[int32]{Feature: rng.Intn(5), Threshold: int32(rng.Intn(31) - 15)}
		}
		leaves := make([]uint64, 1<<depth)
		for i := range leaves {
			leaves[i] = rng.Uint64()
		}
		bt := BinaryTree[int32, uint64]{Depth: depth, Splits: splits, Leaves: leaves}

		for groupWidth := 1; groupWidth <= 4; groupWidth++ {
			rt, err := CompileR0(bt, groupWidth)
			if err != nil {
				t.Fatalf("depth=%d g=%d: %v", depth, groupWidth, err)
			}
			for sample := 0; sample < 500; sample++ {
				x := make([]int32, 5)
				for i := range x {
					x[i] = int32(rng.Intn(41) - 20)
				}
				wantIndex, _ := bt.Route(x)
				gotIndex, err := rt.Route(x)
				if err != nil {
					t.Fatal(err)
				}
				if gotIndex != wantIndex {
					t.Fatalf("depth=%d g=%d sample=%d index=%d, want %d", depth, groupWidth, sample, gotIndex, wantIndex)
				}
				want, _ := bt.Evaluate(x)
				got, _ := rt.Evaluate(x)
				if got != want {
					t.Fatalf("depth=%d g=%d sample=%d value=%x, want %x", depth, groupWidth, sample, got, want)
				}
			}
		}
	}
}

func TestR0LeafIndexUsesMSBFirstPathDigits(t *testing.T) {
	const depth = 4
	splits := make([]BinarySplit[int], (1<<depth)-1)
	for d := 0; d < depth; d++ {
		base := (1 << d) - 1
		for i := 0; i < 1<<d; i++ {
			splits[base+i] = BinarySplit[int]{Feature: d, Threshold: 0}
		}
	}
	leaves := make([]int, 1<<depth)
	for i := range leaves {
		leaves[i] = i
	}
	bt := BinaryTree[int, int]{Depth: depth, Splits: splits, Leaves: leaves}

	for groupWidth := 1; groupWidth <= 4; groupWidth++ {
		rt, err := CompileR0(bt, groupWidth)
		if err != nil {
			t.Fatal(err)
		}
		for mask := 0; mask < 1<<depth; mask++ {
			x := make([]int, depth)
			for d := 0; d < depth; d++ {
				if mask&(1<<(depth-1-d)) != 0 {
					x[d] = 0 // equality routes right
				} else {
					x[d] = -1
				}
			}
			gotIndex, err := rt.Route(x)
			if err != nil {
				t.Fatal(err)
			}
			if gotIndex != mask {
				t.Fatalf("g=%d mask=%04b leaf index=%04b", groupWidth, mask, gotIndex)
			}
			got, _ := rt.Evaluate(x)
			if got != mask {
				t.Fatalf("g=%d mask=%04b leaf value=%d", groupWidth, mask, got)
			}
		}
	}
}

func TestR1IntervalTreeEvaluationAndClassification(t *testing.T) {
	mt := MultiwayTree[int, int]{
		Root: NodeRef(0),
		Nodes: []IntervalNode[int]{
			{
				Feature:    0,
				Thresholds: []int{0, 10, 20},
				Children:   []ChildRef{LeafRef(0), LeafRef(1), NodeRef(1), LeafRef(4)},
			},
			{
				Feature:    1,
				Thresholds: []int{5},
				Children:   []ChildRef{LeafRef(2), LeafRef(3)},
			},
		},
		Leaves: []int{0, 1, 2, 3, 4},
	}
	if err := mt.Validate(); err != nil {
		t.Fatalf("valid R1 tree rejected: %v", err)
	}
	if mt.Semantics() != SemanticsR1ModelChanging {
		t.Fatalf("R1 semantics=%q, want %q", mt.Semantics(), SemanticsR1ModelChanging)
	}
	if mt.Semantics() == SemanticsR0Equivalent {
		t.Fatal("R1 tree must not be labelled binary-equivalent")
	}

	cases := []struct {
		x         []int
		wantIndex int
		want      int
	}{
		{[]int{-1, 99}, 0, 0},
		{[]int{0, 99}, 1, 1},
		{[]int{9, 99}, 1, 1},
		{[]int{10, 4}, 2, 2},
		{[]int{19, 5}, 3, 3},
		{[]int{20, -99}, 4, 4},
	}
	for _, tc := range cases {
		gotIndex, err := mt.Route(tc.x)
		if err != nil {
			t.Fatalf("x=%v: %v", tc.x, err)
		}
		if gotIndex != tc.wantIndex {
			t.Fatalf("x=%v index=%d, want %d", tc.x, gotIndex, tc.wantIndex)
		}
		got, _ := mt.Evaluate(tc.x)
		if got != tc.want {
			t.Fatalf("x=%v value=%d, want %d", tc.x, got, tc.want)
		}
	}

	cost, err := mt.Metrics()
	if err != nil {
		t.Fatal(err)
	}
	if cost.ThresholdComparisons != 4 || cost.BranchBits != 4 {
		t.Fatalf("R1 worst-path comparisons/bits=%d/%d, want 4/4", cost.ThresholdComparisons, cost.BranchBits)
	}
	if cost.Depth != 2 || cost.OneHotStates != 6 || cost.SelectorTerms != 6 {
		t.Fatalf("unexpected R1 depth/state/selector cost: %+v", cost)
	}
	if cost.LogicalBootstraps != 2 || cost.LeafTerms != 5 {
		t.Fatalf("unexpected R1 bootstrap/leaf cost: %+v", cost)
	}
}

func TestCompleteMultiwayCostUsesRMinusOneLogRLeaves(t *testing.T) {
	cost, err := CompleteMultiwayCost(4, 64)
	if err != nil {
		t.Fatal(err)
	}
	if cost.Depth != 3 {
		t.Fatalf("depth=%d, want log_4(64)=3", cost.Depth)
	}
	if cost.ThresholdComparisons != 9 {
		t.Fatalf("comparisons=%d, want (4-1)*log_4(64)=9", cost.ThresholdComparisons)
	}
	if cost.BranchBits != 9 || cost.OneHotStates != 12 || cost.SelectorTerms != 12 {
		t.Fatalf("unexpected uniform R1 cost: %+v", cost)
	}
	if cost.LogicalBootstraps != 3 || cost.LeafTerms != 64 {
		t.Fatalf("unexpected uniform R1 bootstrap/leaf cost: %+v", cost)
	}
	if cost.Rotations.DataDependentAllowed {
		t.Fatal("uniform R1 cost permits encrypted-index rotation")
	}
	if !strings.Contains(cost.Rotations.Expression, "ObliviousSelect") {
		t.Fatalf("symbolic rotations=%q", cost.Rotations.Expression)
	}
}

func TestMetricsAreJSONFriendly(t *testing.T) {
	bt := BinaryTree[int, int]{
		Depth:  1,
		Splits: []BinarySplit[int]{{Feature: 0, Threshold: 3}},
		Leaves: []int{7, 11},
	}
	rt, err := CompileR0(bt, 1)
	if err != nil {
		t.Fatal(err)
	}
	want, err := rt.Metrics()
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal metrics: %v", err)
	}
	var got CostVector
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal metrics: %v", err)
	}
	if got != want {
		t.Fatalf("JSON roundtrip mismatch:\n got %+v\nwant %+v", got, want)
	}
}

func TestCompileR0RejectsUnsupportedGroupWidth(t *testing.T) {
	bt := BinaryTree[int, int]{Depth: 0, Leaves: []int{1}}
	for _, groupWidth := range []int{0, 5} {
		if _, err := CompileR0(bt, groupWidth); err == nil {
			t.Fatalf("group width %d accepted, want error", groupWidth)
		}
	}
}

func TestValidationRejectsAmbiguousOrCyclicModels(t *testing.T) {
	badBinary := BinaryTree[int, int]{Depth: 1, Leaves: []int{0, 1}}
	if err := badBinary.Validate(); err == nil {
		t.Fatal("binary tree with missing split accepted")
	}

	badIntervals := MultiwayTree[int, int]{
		Root: NodeRef(0),
		Nodes: []IntervalNode[int]{
			{Feature: 0, Thresholds: []int{2, 2}, Children: []ChildRef{LeafRef(0), LeafRef(0), LeafRef(0)}},
		},
		Leaves: []int{7},
	}
	if err := badIntervals.Validate(); err == nil {
		t.Fatal("non-strict interval thresholds accepted")
	}

	cycle := MultiwayTree[int, int]{
		Root: NodeRef(0),
		Nodes: []IntervalNode[int]{
			{Feature: 0, Thresholds: []int{0}, Children: []ChildRef{NodeRef(0), LeafRef(0)}},
		},
		Leaves: []int{7},
	}
	if err := cycle.Validate(); err == nil {
		t.Fatal("cyclic multiway tree accepted")
	}
}

func TestPlanMetadataSeam(t *testing.T) {
	bt := BinaryTree[int, int]{Depth: 0, Leaves: []int{7}}
	rt, err := CompileR0(bt, 4)
	if err != nil {
		t.Fatal(err)
	}
	mt := MultiwayTree[int, int]{Root: LeafRef(0), Leaves: []int{7}}

	plans := []Plan{bt, rt, mt}
	want := []SemanticsClass{SemanticsBinaryReference, SemanticsR0Equivalent, SemanticsR1ModelChanging}
	for i, plan := range plans {
		if plan.Semantics() != want[i] {
			t.Fatalf("plan %d semantics=%q, want %q", i, plan.Semantics(), want[i])
		}
		cost, err := plan.Metrics()
		if err != nil {
			t.Fatalf("plan %d metrics: %v", i, err)
		}
		if cost.LeafTerms != 1 {
			t.Fatalf("plan %d leaf terms=%d, want 1", i, cost.LeafTerms)
		}
	}
}
