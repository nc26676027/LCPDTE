package treeplan

import (
	"strings"
	"testing"
)

func testProofArtifact(name string, domainSize int64) *ProofArtifactReference {
	return &ProofArtifactReference{
		URI:              "artifact://" + name,
		SHA256:           strings.Repeat("a", 64),
		DomainDescriptor: "uint8:" + name,
		DomainSize:       domainSize,
	}
}

func TestScheduleCertificateRejectsLogicalProofAndPhysicalTampering(t *testing.T) {
	source := BinaryTree[int, int]{Depth: 2, Splits: make([]BinarySplit[int], 3), Leaves: make([]int, 4)}
	radix, err := CompileR0(source, 2)
	if err != nil {
		t.Fatal(err)
	}
	request := R0ScheduleRequest{
		Schedule: R0StateAwareFusedLUT,
		FusedLUT: &FusedLUTOptions{
			RootSameFeatureFiniteDomainProof: testProofArtifact("root", 256),
		},
	}
	plan, err := radix.PlanSchedule(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("fresh schedule plan is invalid: %v", err)
	}
	if plan.Certificate.SourceSHA256 == "" || plan.Certificate.RadixPlanSHA256 == "" ||
		plan.Certificate.RequestSHA256 == "" || plan.Certificate.StructureSHA256 == "" ||
		plan.Certificate.FullPlanSHA256 == "" {
		t.Fatalf("incomplete schedule certificate: %+v", plan.Certificate)
	}
	if plan.BenchmarkEligibility != BenchmarkIneligibleExternalProofUnverified {
		t.Fatalf("fused plan eligibility=%q, want external-proof-unverified", plan.BenchmarkEligibility)
	}
	if got := plan.Groups[0].EquivalenceProofStatus; got != ProofExternalUnverified {
		t.Fatalf("proof status=%q, want external-unverified", got)
	}
	if err := VerifyScheduleAgainst(plan, source, request); err != nil {
		t.Fatalf("fresh plan does not verify against source/request: %v", err)
	}

	// PlanSchedule must detach the plan from mutable request pointers.
	request.FusedLUT.RootSameFeatureFiniteDomainProof.URI = "artifact://mutated-request"
	if err := plan.Validate(); err != nil {
		t.Fatalf("mutating the request changed the issued plan: %v", err)
	}
	request.FusedLUT.RootSameFeatureFiniteDomainProof.URI = "artifact://root"

	tests := []struct {
		name   string
		mutate func(*R0SchedulePlan)
	}{
		{name: "schedule", mutate: func(p *R0SchedulePlan) { p.Schedule = R0EagerAllCTPT }},
		{name: "logical-count", mutate: func(p *R0SchedulePlan) { p.Groups[0].LogicalComparisons++ }},
		{name: "proof", mutate: func(p *R0SchedulePlan) { p.Groups[0].EquivalenceProof.URI = "artifact://forged" }},
		{name: "physical", mutate: func(p *R0SchedulePlan) {
			count, err := MeasuredPhysicalCount(0)
			if err != nil {
				t.Fatal(err)
			}
			p.Groups[0].Physical.Rotations = count
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			forged := plan.Clone()
			test.mutate(&forged)
			if err := forged.Validate(); err == nil {
				t.Fatal("tampered schedule plan retained a valid certificate")
			}
		})
	}
}

func TestStructuredProofReferenceRejectsOpaqueOrMalformedClaims(t *testing.T) {
	source := BinaryTree[int, int]{Depth: 2, Splits: make([]BinarySplit[int], 3), Leaves: make([]int, 4)}
	radix, err := CompileR0(source, 2)
	if err != nil {
		t.Fatal(err)
	}
	valid := testProofArtifact("root", 256)
	tests := []struct {
		name   string
		mutate func(*ProofArtifactReference)
	}{
		{name: "missing-uri", mutate: func(p *ProofArtifactReference) { p.URI = "x" }},
		{name: "bad-hash", mutate: func(p *ProofArtifactReference) { p.SHA256 = "abc" }},
		{name: "missing-domain", mutate: func(p *ProofArtifactReference) { p.DomainDescriptor = "" }},
		{name: "zero-domain", mutate: func(p *ProofArtifactReference) { p.DomainSize = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			proof := *valid
			test.mutate(&proof)
			_, err := radix.PlanSchedule(R0ScheduleRequest{
				Schedule: R0StateAwareFusedLUT,
				FusedLUT: &FusedLUTOptions{RootSameFeatureFiniteDomainProof: &proof},
			})
			if err == nil {
				t.Fatal("malformed proof artifact unlocked a fused schedule")
			}
		})
	}
}

func TestSchedulePhysicalProfileIsCompleteTypedAndAttachedFailClosed(t *testing.T) {
	source := BinaryTree[int, int]{Depth: 1, Splits: make([]BinarySplit[int], 1), Leaves: make([]int, 2)}
	radix, err := CompileR0(source, 1)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := radix.PlanSchedule(R0ScheduleRequest{Schedule: R0EagerAllCTPT})
	if err != nil {
		t.Fatal(err)
	}
	for name, count := range plan.Groups[0].Physical.counts() {
		if count.Status != MeasurementNotMeasured || count.Value != nil {
			t.Fatalf("%s=%+v, want typed not-measured", name, count)
		}
	}
	if err := plan.Groups[0].Physical.Validate(); err != nil {
		t.Fatalf("initial unknown physical profile is invalid: %v", err)
	}

	measurement := UnknownR0PhysicalProfile()
	measurement.Packing = R0PackingObservation{
		Status: MeasurementMeasured, Mode: PackingFull, WordWidth: 8, LogSlots: 15,
		WordSlotOccupancy: 4096, BA2BGroupOccupancy: 2,
	}
	measurement.PhysicalComparatorStreams, _ = MeasuredPhysicalCount(1)
	measurement.CiphertextPlaintextMultiplications, _ = MeasuredPhysicalCount(0)
	measurement.CiphertextCiphertextMultiplications, _ = MeasuredPhysicalCount(0)
	measurement.CiphertextAdditions, _ = MeasuredPhysicalCount(0)
	measurement.KeySwitches, _ = MeasuredPhysicalCount(0)
	measurement.Transforms, _ = MeasuredPhysicalCount(0)
	measurement.LUTInputStreams, _ = MeasuredPhysicalCount(0)
	measurement.LUTOutputStreams, _ = MeasuredPhysicalCount(0)
	measurement.WallTimeNanoseconds, _ = MeasuredPhysicalCount(0)
	comparator := UnknownComparatorPhysicalObservation(ComparatorCTPlaintext)
	comparator.StreamsPerLogicalComparison, _ = MeasuredPhysicalCount(1)
	comparator.PhysicalComparatorStreams, _ = MeasuredPhysicalCount(1)
	comparator.RefreshesPerComparatorStream, _ = MeasuredPhysicalCount(0)
	comparator.BootstrapsPerComparatorStream, _ = MeasuredPhysicalCount(0)
	comparator.Refreshes, _ = MeasuredPhysicalCount(0)
	comparator.Bootstraps, _ = MeasuredPhysicalCount(0)
	zeroEndToEndDepth, _ := MeasuredPhysicalCount(0)
	if _, err := plan.WithPhysicalMeasurements([]R0GroupPhysicalMeasurements{{
		GroupIndex: 0, StartDepth: 0, Height: 1,
		ComparatorCharges:       []ComparatorPhysicalObservation{comparator},
		EndToEndDependencyDepth: zeroEndToEndDepth,
		Physical:                measurement,
	}}); err == nil {
		t.Fatal("zero end-to-end depth was accepted below the predicate-stage lower bound")
	}
	endToEndDepth, _ := MeasuredPhysicalCount(1)
	if _, err := plan.WithPhysicalMeasurements([]R0GroupPhysicalMeasurements{{
		GroupIndex: 0, StartDepth: 1, Height: 1,
		ComparatorCharges:       []ComparatorPhysicalObservation{comparator},
		EndToEndDependencyDepth: endToEndDepth,
		Physical:                measurement,
	}}); err == nil {
		t.Fatal("measurement for the wrong group identity was accepted")
	}

	attached, err := plan.WithPhysicalMeasurements([]R0GroupPhysicalMeasurements{{
		GroupIndex: 0, StartDepth: 0, Height: 1,
		ComparatorCharges:       []ComparatorPhysicalObservation{comparator},
		EndToEndDependencyDepth: endToEndDepth,
		Physical:                measurement,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := attached.Validate(); err != nil {
		t.Fatalf("attached plan is invalid: %v", err)
	}
	if err := VerifyScheduleAgainst(attached, source, R0ScheduleRequest{Schedule: R0EagerAllCTPT}); err != nil {
		t.Fatalf("physical attachment broke source/request binding: %v", err)
	}
	if plan.Groups[0].Physical.Packing.Status != MeasurementNotMeasured {
		t.Fatal("WithPhysicalMeasurements mutated the source plan")
	}
	if got := *attached.Groups[0].ComparatorCharges[0].PhysicalComparatorStreams.Value; got != 1 {
		t.Fatalf("attached provenance-specific comparator streams=%d, want 1", got)
	}
	withSelectorOverhead := measurement
	withSelectorOverhead.Refreshes, _ = MeasuredPhysicalCount(2)
	withSelectorOverhead.Bootstraps, _ = MeasuredPhysicalCount(1)
	if _, err := plan.WithPhysicalMeasurements([]R0GroupPhysicalMeasurements{{
		GroupIndex: 0, StartDepth: 0, Height: 1,
		ComparatorCharges:       []ComparatorPhysicalObservation{comparator},
		EndToEndDependencyDepth: endToEndDepth,
		Physical:                withSelectorOverhead,
	}}); err != nil {
		t.Fatalf("valid non-comparator refresh/bootstrap overhead was rejected: %v", err)
	}
	inconsistent := comparator
	inconsistent.PhysicalComparatorStreams, _ = MeasuredPhysicalCount(2)
	if _, err := plan.WithPhysicalMeasurements([]R0GroupPhysicalMeasurements{{
		GroupIndex: 0, StartDepth: 0, Height: 1,
		ComparatorCharges:       []ComparatorPhysicalObservation{inconsistent},
		EndToEndDependencyDepth: endToEndDepth,
		Physical:                measurement,
	}}); err == nil {
		t.Fatal("inconsistent C_cmp product was accepted")
	}

	forged := attached.Clone()
	*forged.Groups[0].Physical.PhysicalComparatorStreams.Value = 2
	if err := forged.Validate(); err == nil {
		t.Fatal("mutating a measured physical value retained a valid certificate")
	}
}

func TestScheduleTailGroupUsesRemainingHeight(t *testing.T) {
	source := BinaryTree[int, int]{Depth: 5, Splits: make([]BinarySplit[int], 31), Leaves: make([]int, 32)}
	radix, err := CompileR0(source, 3)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := radix.PlanSchedule(R0ScheduleRequest{Schedule: R0EagerActiveCTCT})
	if err != nil {
		t.Fatal(err)
	}
	want := [][4]int{{0, 3, 1, 7}, {3, 2, 8, 3}}
	if len(plan.Groups) != len(want) {
		t.Fatalf("groups=%d, want %d", len(plan.Groups), len(want))
	}
	for i, group := range plan.Groups {
		got := [4]int{group.StartDepth, group.Height, group.CandidateSupernodes, group.PredicatesPerSupernode}
		if got != want[i] {
			t.Fatalf("group %d geometry=%v, want %v", i, got, want[i])
		}
	}
}

func TestSourceFaithfulOBOSeparatesRootCTPlaintextFromSelectedCTCT(t *testing.T) {
	source := BinaryTree[int, int]{Depth: 4, Splits: make([]BinarySplit[int], 15), Leaves: make([]int, 16)}
	radix, err := CompileR0(source, 2)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := radix.PlanSchedule(R0ScheduleRequest{Schedule: R0SequentialSourceFaithfulOBO})
	if err != nil {
		t.Fatal(err)
	}
	root := plan.Groups[0]
	if len(root.ComparatorCharges) != 2 || root.ComparatorCharges[0].Provenance != ComparatorCTPlaintext ||
		root.ComparatorCharges[0].LogicalComparisons != 1 || root.ComparatorCharges[1].Provenance != ComparatorCTCT ||
		root.ComparatorCharges[1].LogicalComparisons != 1 {
		t.Fatalf("root comparator charges=%+v, want CT-PT=1 and CT-CT=1", root.ComparatorCharges)
	}
	if len(root.FeatureSelectorWidths) != 1 || root.FeatureSelectorWidths[0] != 2 ||
		len(root.ThresholdSelectorWidths) != 1 || root.ThresholdSelectorWidths[0] != 2 ||
		root.LogicalSelectorTerms != 4 {
		t.Fatalf("root selectors=%v/%v terms=%d, want no width-one root selector and one width-two pair",
			root.FeatureSelectorWidths, root.ThresholdSelectorWidths, root.LogicalSelectorTerms)
	}
	below := plan.Groups[1]
	if !hasOnlyComparatorCharge(below, ComparatorCTCT, 2) {
		t.Fatalf("below-root comparator charges=%+v, want CT-CT=2", below.ComparatorCharges)
	}

	cost, err := radix.Metrics()
	if err != nil {
		t.Fatal(err)
	}
	if cost.ExecutionSchedule != R0SequentialSourceFaithfulOBO || cost.ThresholdComparisons != 4 {
		t.Fatalf("default metrics=%+v, want explicit source-faithful OBO", cost)
	}
}

func TestMetricsFailsClosedForMutatedR0Plan(t *testing.T) {
	source := BinaryTree[int, int]{Depth: 1, Splits: make([]BinarySplit[int], 1), Leaves: make([]int, 2)}
	radix, err := CompileR0(source, 1)
	if err != nil {
		t.Fatal(err)
	}
	radix.Leaves[0]++
	if _, err := radix.Metrics(); err == nil {
		t.Fatal("mutated R0 certificate was silently represented as a zero cost")
	}
}

func TestComparatorMeasurementCannotSwapCTPTAndCTCTProvenance(t *testing.T) {
	source := BinaryTree[int, int]{Depth: 2, Splits: make([]BinarySplit[int], 3), Leaves: make([]int, 4)}
	radix, err := CompileR0(source, 2)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := radix.PlanSchedule(R0ScheduleRequest{Schedule: R0SequentialSourceFaithfulOBO})
	if err != nil {
		t.Fatal(err)
	}
	ctpt := UnknownComparatorPhysicalObservation(ComparatorCTPlaintext)
	ctct := UnknownComparatorPhysicalObservation(ComparatorCTCT)
	if _, err := plan.WithPhysicalMeasurements([]R0GroupPhysicalMeasurements{{
		GroupIndex: 0, StartDepth: 0, Height: 2,
		ComparatorCharges:       []ComparatorPhysicalObservation{ctct, ctpt},
		EndToEndDependencyDepth: NotMeasuredPhysicalCount(),
		Physical:                UnknownR0PhysicalProfile(),
	}}); err == nil {
		t.Fatal("swapped CT-PT/CT-CT physical observations were accepted by position")
	}
	measured := func(provenance ComparatorProvenance, streamsPerLogical, refreshesPerStream int64) ComparatorPhysicalObservation {
		observation := UnknownComparatorPhysicalObservation(provenance)
		observation.StreamsPerLogicalComparison, _ = MeasuredPhysicalCount(streamsPerLogical)
		observation.PhysicalComparatorStreams, _ = MeasuredPhysicalCount(streamsPerLogical)
		observation.RefreshesPerComparatorStream, _ = MeasuredPhysicalCount(refreshesPerStream)
		observation.Refreshes, _ = MeasuredPhysicalCount(streamsPerLogical * refreshesPerStream)
		observation.BootstrapsPerComparatorStream, _ = MeasuredPhysicalCount(0)
		observation.Bootstraps, _ = MeasuredPhysicalCount(0)
		return observation
	}
	ctptMeasured := measured(ComparatorCTPlaintext, 1, 2)
	ctctMeasured := measured(ComparatorCTCT, 3, 4)
	physical := UnknownR0PhysicalProfile()
	physical.PhysicalComparatorStreams, _ = MeasuredPhysicalCount(4)
	physical.Refreshes, _ = MeasuredPhysicalCount(15) // 14 comparator + 1 selector overhead.
	physical.Bootstraps, _ = MeasuredPhysicalCount(0)
	depth, _ := MeasuredPhysicalCount(2)
	if _, err := plan.WithPhysicalMeasurements([]R0GroupPhysicalMeasurements{{
		GroupIndex: 0, StartDepth: 0, Height: 2,
		ComparatorCharges:       []ComparatorPhysicalObservation{ctptMeasured, ctctMeasured},
		EndToEndDependencyDepth: depth,
		Physical:                physical,
	}}); err != nil {
		t.Fatalf("valid provenance-separated C_cmp/B_cmp accounting was rejected: %v", err)
	}
	physical.PhysicalComparatorStreams, _ = MeasuredPhysicalCount(3)
	if _, err := plan.WithPhysicalMeasurements([]R0GroupPhysicalMeasurements{{
		GroupIndex: 0, StartDepth: 0, Height: 2,
		ComparatorCharges:       []ComparatorPhysicalObservation{ctptMeasured, ctctMeasured},
		EndToEndDependencyDepth: depth,
		Physical:                physical,
	}}); err == nil {
		t.Fatal("aggregate comparator streams below the CT-PT/CT-CT sum were accepted")
	}
}
