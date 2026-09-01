package treeplan

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestR0SchedulesAreDistinctAuditLabels(t *testing.T) {
	schedules := []R0Schedule{
		R0SequentialSourceFaithfulOBO,
		R0SequentialActiveCTCT,
		R0EagerActiveCTCT,
		R0EagerAllCTPT,
		R0StateAwareFusedLUT,
	}
	want := []R0Schedule{
		"r0_sequential_source_faithful_obo",
		"r0_sequential_active_ct_ct",
		"r0_eager_active_ct_ct",
		"r0_eager_all_ct_pt",
		"r0_state_aware_fused_lut",
	}

	seen := make(map[R0Schedule]bool, len(schedules))
	for i, schedule := range schedules {
		if schedule != want[i] {
			t.Fatalf("schedule %d=%q, want %q", i, schedule, want[i])
		}
		if seen[schedule] {
			t.Fatalf("schedule %q is not mutually exclusive", schedule)
		}
		seen[schedule] = true
	}
	if seen[R0Schedule("r0_eager_candidate")] {
		t.Fatal("legacy combined eager placeholder remains a registered schedule")
	}
}

func TestPhysicalCountDistinguishesNotMeasuredFromMeasuredZero(t *testing.T) {
	unknown := NotMeasuredPhysicalCount()
	if unknown.Status != MeasurementNotMeasured || unknown.Value != nil {
		t.Fatalf("unknown count=%+v, want typed not-measured with no value", unknown)
	}

	zero, err := MeasuredPhysicalCount(0)
	if err != nil {
		t.Fatal(err)
	}
	if zero.Status != MeasurementMeasured || zero.Value == nil || *zero.Value != 0 {
		t.Fatalf("measured zero=%+v, want measured pointer to zero", zero)
	}
	if _, err := MeasuredPhysicalCount(-1); err == nil {
		t.Fatal("negative physical count accepted")
	}

	encoded, err := json.Marshal(unknown)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"status":"not_measured"`) || strings.Contains(string(encoded), `"value"`) {
		t.Fatalf("unknown JSON=%s, want explicit status without a zero value", encoded)
	}
}

func TestSequentialScheduleReportsEveryGroupAndUnknownPhysicalCounts(t *testing.T) {
	source := BinaryTree[int, int]{
		Depth:  4,
		Splits: make([]BinarySplit[int], 15),
		Leaves: make([]int, 16),
	}
	radix, err := CompileR0(source, 2)
	if err != nil {
		t.Fatal(err)
	}

	plan, err := radix.PlanSchedule(R0ScheduleRequest{Schedule: R0SequentialActiveCTCT})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Schedule != R0SequentialActiveCTCT || len(plan.Groups) != 2 {
		t.Fatalf("schedule plan=%+v, want sequential with two groups", plan)
	}
	if plan.Certificate.SourceSHA256 == "" || plan.Certificate.RadixPlanSHA256 == "" {
		t.Fatalf("schedule omitted the certified source/plan binding: %+v", plan.Certificate)
	}

	want := []struct {
		d, h, s, k           int
		widths               []int
		selectorTerms, depth int
	}{
		{d: 0, h: 2, s: 1, k: 3, widths: []int{1, 2}, selectorTerms: 6, depth: 2},
		{d: 2, h: 2, s: 4, k: 3, widths: []int{4, 8}, selectorTerms: 24, depth: 2},
	}
	for i, group := range plan.Groups {
		w := want[i]
		if group.StartDepth != w.d || group.Height != w.h || group.CandidateSupernodes != w.s || group.PredicatesPerSupernode != w.k {
			t.Fatalf("group %d geometry=%+v, want d/h/S/K=%d/%d/%d/%d", i, group, w.d, w.h, w.s, w.k)
		}
		if !hasOnlyComparatorCharge(group, ComparatorCTCT, w.h) || group.LogicalComparisons != w.h {
			t.Fatalf("group %d comparison charge=%+v, want %d dependent CT-CT comparisons", i, group, w.h)
		}
		if !reflect.DeepEqual(group.FeatureSelectorWidths, w.widths) || !reflect.DeepEqual(group.ThresholdSelectorWidths, w.widths) {
			t.Fatalf("group %d selector widths feature/threshold=%v/%v, want %v/%v", i, group.FeatureSelectorWidths, group.ThresholdSelectorWidths, w.widths, w.widths)
		}
		if group.LogicalSelectorTerms != w.selectorTerms || !group.SelectorTermsLowerBound || group.PredicateDependencyRounds != w.depth {
			t.Fatalf("group %d selector/dependency charge=%+v", i, group)
		}
		for name, count := range group.physicalCountsForTest() {
			if count.Status != MeasurementNotMeasured || count.Value != nil {
				t.Fatalf("group %d %s=%+v, want typed not-measured", i, name, count)
			}
		}
	}
}

func (g R0GroupProfile) physicalCountsForTest() map[string]PhysicalCount {
	counts := g.Physical.counts()
	counts["end-to-end dependency depth"] = g.EndToEndDependencyDepth
	for i, charge := range g.ComparatorCharges {
		for name, count := range charge.counts() {
			counts[fmt.Sprintf("comparator %d %s", i, name)] = count
		}
	}
	return counts
}

func hasOnlyComparatorCharge(group R0GroupProfile, provenance ComparatorProvenance, logical int) bool {
	return len(group.ComparatorCharges) == 1 && group.ComparatorCharges[0].Provenance == provenance &&
		group.ComparatorCharges[0].LogicalComparisons == logical
}

func TestEagerActiveCTCTChargesBothWidthSSelectionsForEveryPredicate(t *testing.T) {
	source := BinaryTree[int, int]{Depth: 4, Splits: make([]BinarySplit[int], 15), Leaves: make([]int, 16)}
	radix, err := CompileR0(source, 2)
	if err != nil {
		t.Fatal(err)
	}

	plan, err := radix.PlanSchedule(R0ScheduleRequest{Schedule: R0EagerActiveCTCT})
	if err != nil {
		t.Fatal(err)
	}
	wantWidths := [][]int{{1, 1, 1}, {4, 4, 4}}
	wantTerms := []int{6, 24}
	for i, group := range plan.Groups {
		if !hasOnlyComparatorCharge(group, ComparatorCTCT, 3) || group.LogicalComparisons != 3 {
			t.Fatalf("group %d comparisons=%+v, want three CT-CT comparisons", i, group)
		}
		if !reflect.DeepEqual(group.FeatureSelectorWidths, wantWidths[i]) || !reflect.DeepEqual(group.ThresholdSelectorWidths, wantWidths[i]) {
			t.Fatalf("group %d feature/threshold widths=%v/%v, want %v/%v", i, group.FeatureSelectorWidths, group.ThresholdSelectorWidths, wantWidths[i], wantWidths[i])
		}
		if group.LogicalSelectorTerms != wantTerms[i] || !group.SelectorTermsLowerBound || group.PredicateDependencyRounds != 1 {
			t.Fatalf("group %d selector/dependency charge=%+v", i, group)
		}
	}
}

func TestEagerAllCTPTChargesEverySupernodePredicateAndResultSelector(t *testing.T) {
	source := BinaryTree[int, int]{Depth: 4, Splits: make([]BinarySplit[int], 15), Leaves: make([]int, 16)}
	radix, err := CompileR0(source, 2)
	if err != nil {
		t.Fatal(err)
	}

	plan, err := radix.PlanSchedule(R0ScheduleRequest{Schedule: R0EagerAllCTPT})
	if err != nil {
		t.Fatal(err)
	}
	wantComparisons := []int{3, 12}
	wantResultWidths := [][]int{{1}, {4}}
	for i, group := range plan.Groups {
		if !hasOnlyComparatorCharge(group, ComparatorCTPlaintext, wantComparisons[i]) || group.LogicalComparisons != wantComparisons[i] {
			t.Fatalf("group %d comparison charge=%+v, want %d CT-plaintext comparisons", i, group, wantComparisons[i])
		}
		if len(group.FeatureSelectorWidths) != 0 || len(group.ThresholdSelectorWidths) != 0 {
			t.Fatalf("group %d selected features/thresholds before comparing: %+v", i, group)
		}
		if !reflect.DeepEqual(group.ResultSelectorWidths, wantResultWidths[i]) || group.LogicalSelectorTerms != wantResultWidths[i][0] {
			t.Fatalf("group %d result selector=%v terms=%d, want width/terms=%v/%d", i, group.ResultSelectorWidths, group.LogicalSelectorTerms, wantResultWidths[i], wantResultWidths[i][0])
		}
		if !group.SelectorTermsLowerBound || group.PredicateDependencyRounds != 1 {
			t.Fatalf("group %d selector/dependency metadata=%+v", i, group)
		}
	}
}

func TestRootFusedLUTRequiresAndChecksSameFeatureFiniteDomainProof(t *testing.T) {
	source := BinaryTree[int, int]{
		Depth: 2,
		Splits: []BinarySplit[int]{
			{Feature: 3, Threshold: 1},
			{Feature: 3, Threshold: 2},
			{Feature: 3, Threshold: 3},
		},
		Leaves: make([]int, 4),
	}
	radix, err := CompileR0(source, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := radix.PlanSchedule(R0ScheduleRequest{Schedule: R0StateAwareFusedLUT}); err == nil {
		t.Fatal("root fused LUT accepted without an equivalence proof")
	}

	request := R0ScheduleRequest{
		Schedule: R0StateAwareFusedLUT,
		FusedLUT: &FusedLUTOptions{
			RootSameFeatureFiniteDomainProof: testProofArtifact("root-same-feature-finite-domain", 256),
		},
	}
	plan, err := radix.PlanSchedule(request)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Groups) != 1 {
		t.Fatalf("group count=%d, want one", len(plan.Groups))
	}
	group := plan.Groups[0]
	if !reflect.DeepEqual(group.EquivalenceProof, request.FusedLUT.RootSameFeatureFiniteDomainProof) {
		t.Fatalf("root fused profile omitted its proof reference: %+v", group)
	}
	if len(group.ComparatorCharges) != 0 || group.LogicalComparisons != 0 || group.LogicalLUTEvaluations != 1 {
		t.Fatalf("root fused charge=%+v, want one LUT and no comparator", group)
	}
	if len(group.ResultSelectorWidths) != 0 || group.LogicalSelectorTerms != 0 || group.PredicateDependencyRounds != 1 {
		t.Fatalf("root fused selector/dependency charge=%+v", group)
	}

	badSource := source
	badSource.Splits = append([]BinarySplit[int](nil), source.Splits...)
	badSource.Splits[2].Feature = 4
	badRadix, err := CompileR0(badSource, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := badRadix.PlanSchedule(request); err == nil {
		t.Fatal("same-feature proof reference accepted a root whose predicates use different features")
	}

	emptyReference := request
	emptyOptions := *request.FusedLUT
	emptyProof := *request.FusedLUT.RootSameFeatureFiniteDomainProof
	emptyProof.URI = " \t"
	emptyOptions.RootSameFeatureFiniteDomainProof = &emptyProof
	emptyReference.FusedLUT = &emptyOptions
	if _, err := radix.PlanSchedule(emptyReference); err == nil {
		t.Fatal("root fused LUT accepted an empty proof reference")
	}
}

func TestBelowRootFusedLUTAllSupernodesChargesSLUTsAndWidthSSelector(t *testing.T) {
	source := BinaryTree[int, int]{Depth: 4, Splits: make([]BinarySplit[int], 15), Leaves: make([]int, 16)}
	radix, err := CompileR0(source, 2)
	if err != nil {
		t.Fatal(err)
	}

	request := R0ScheduleRequest{
		Schedule: R0StateAwareFusedLUT,
		FusedLUT: &FusedLUTOptions{
			RootSameFeatureFiniteDomainProof:      testProofArtifact("root-same-feature-finite-domain", 256),
			BelowRootStrategy:                     FusedLUTAllSupernodesAndSelect,
			BelowRootSameFeatureFiniteDomainProof: testProofArtifact("below-root-same-feature-finite-domain", 256),
		},
	}
	plan, err := radix.PlanSchedule(request)
	if err != nil {
		t.Fatal(err)
	}
	belowRoot := plan.Groups[1]
	if belowRoot.StartDepth != 2 || belowRoot.CandidateSupernodes != 4 {
		t.Fatalf("below-root geometry=%+v", belowRoot)
	}
	if !reflect.DeepEqual(belowRoot.EquivalenceProof, request.FusedLUT.BelowRootSameFeatureFiniteDomainProof) {
		t.Fatalf("below-root fused profile omitted its proof reference: %+v", belowRoot)
	}
	if belowRoot.FusedLUTStrategy != FusedLUTAllSupernodesAndSelect || belowRoot.LogicalLUTEvaluations != 4 {
		t.Fatalf("below-root LUT charge=%+v, want four supernode LUTs", belowRoot)
	}
	if !reflect.DeepEqual(belowRoot.ResultSelectorWidths, []int{4}) || belowRoot.LogicalSelectorTerms != 4 || !belowRoot.SelectorTermsLowerBound {
		t.Fatalf("below-root selector charge=%+v, want one width-four selector", belowRoot)
	}

	missingProof := request
	copyOptions := *request.FusedLUT
	copyOptions.BelowRootSameFeatureFiniteDomainProof = nil
	missingProof.FusedLUT = &copyOptions
	if _, err := radix.PlanSchedule(missingProof); err == nil {
		t.Fatal("all-supernode fused LUT accepted without below-root equivalence proof")
	}
}

func TestBelowRootGlobalDomainFusedLUTRequiresProofAndChargesDeclaredDomain(t *testing.T) {
	source := BinaryTree[int, int]{Depth: 4, Splits: make([]BinarySplit[int], 15), Leaves: make([]int, 16)}
	radix, err := CompileR0(source, 2)
	if err != nil {
		t.Fatal(err)
	}

	request := R0ScheduleRequest{
		Schedule: R0StateAwareFusedLUT,
		FusedLUT: &FusedLUTOptions{
			RootSameFeatureFiniteDomainProof: testProofArtifact("root-same-feature-finite-domain", 256),
			BelowRootStrategy:                FusedLUTGlobalStateDomain,
			GlobalDomainProofs: map[int]ProofArtifactReference{
				2: *testProofArtifact("global-domain-equivalence", 1024),
			},
		},
	}
	plan, err := radix.PlanSchedule(request)
	if err != nil {
		t.Fatal(err)
	}
	belowRoot := plan.Groups[1]
	if belowRoot.FusedLUTStrategy != FusedLUTGlobalStateDomain || belowRoot.LogicalLUTEvaluations != 1 || belowRoot.DeclaredGlobalDomainSize != 1024 {
		t.Fatalf("global-domain charge=%+v", belowRoot)
	}
	if !reflect.DeepEqual(belowRoot.EquivalenceProof, testProofArtifact("global-domain-equivalence", 1024)) {
		t.Fatalf("global-domain profile omitted its proof reference: %+v", belowRoot)
	}
	if len(belowRoot.ResultSelectorWidths) != 0 || belowRoot.LogicalSelectorTerms != 0 {
		t.Fatalf("global-domain strategy silently charged an all-function selector: %+v", belowRoot)
	}

	missingProof := request
	optionsWithoutProof := *request.FusedLUT
	optionsWithoutProof.GlobalDomainProofs = nil
	missingProof.FusedLUT = &optionsWithoutProof
	if _, err := radix.PlanSchedule(missingProof); err == nil {
		t.Fatal("global-domain LUT accepted without equivalence proof")
	}

	missingDomain := request
	optionsWithoutDomain := *request.FusedLUT
	badDomain := *testProofArtifact("global-domain-equivalence", 0)
	optionsWithoutDomain.GlobalDomainProofs = map[int]ProofArtifactReference{2: badDomain}
	missingDomain.FusedLUT = &optionsWithoutDomain
	if _, err := radix.PlanSchedule(missingDomain); err == nil {
		t.Fatal("global-domain LUT accepted without a positive declared domain at every below-root group")
	}
}

func TestLegacyMetricsWrapperAcceptsNewNonFusedSchedulesAndRejectsPlaceholders(t *testing.T) {
	source := BinaryTree[int, int]{Depth: 4, Splits: make([]BinarySplit[int], 15), Leaves: make([]int, 16)}
	radix, err := CompileR0(source, 2)
	if err != nil {
		t.Fatal(err)
	}

	wantComparisons := map[R0Schedule]int{
		R0SequentialActiveCTCT: 4,
		R0EagerActiveCTCT:      6,
		R0EagerAllCTPT:         15,
	}
	for schedule, want := range wantComparisons {
		cost, err := radix.MetricsForSchedule(schedule)
		if err != nil {
			t.Fatalf("%s: %v", schedule, err)
		}
		if cost.ExecutionSchedule != schedule || cost.ThresholdComparisons != want {
			t.Fatalf("%s cost=%+v, want %d comparisons", schedule, cost, want)
		}
	}
	if _, err := radix.MetricsForSchedule(R0StateAwareFusedLUT); err == nil {
		t.Fatal("legacy metrics wrapper accepted fused LUT without its required proof/strategy request")
	}
	for _, legacy := range []R0Schedule{
		"r0_sequential_active_path",
		"r0_eager_candidate",
		"r0_fused_lut",
	} {
		if _, err := radix.MetricsForSchedule(legacy); err == nil {
			t.Fatalf("legacy placeholder %q remains executable", legacy)
		}
	}
}

func TestFusedProofOptionsCannotBeAttachedToAnotherSchedule(t *testing.T) {
	source := BinaryTree[int, int]{Depth: 1, Splits: make([]BinarySplit[int], 1), Leaves: make([]int, 2)}
	radix, err := CompileR0(source, 1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = radix.PlanSchedule(R0ScheduleRequest{
		Schedule: R0SequentialActiveCTCT,
		FusedLUT: &FusedLUTOptions{
			RootSameFeatureFiniteDomainProof: testProofArtifact("root-same-feature-finite-domain", 256),
		},
	})
	if err == nil {
		t.Fatal("sequential schedule accepted fused-LUT proof options")
	}
}
