package treeplan

import (
	"crypto/sha256"
	"fmt"
	"sort"
)

func (p *R0SchedulePlan) issue(request R0ScheduleRequest) error {
	requestDigest, err := digestScheduleRequest(request)
	if err != nil {
		return err
	}
	p.certificate.requestDigest = requestDigest
	return p.reissue()
}

func (p *R0SchedulePlan) reissue() error {
	if p.Certificate.SourceSHA256 == "" || p.Certificate.RadixPlanSHA256 == "" {
		return fmt.Errorf("treeplan: schedule certificate lacks source/radix binding")
	}
	if p.certificate.requestDigest == ([sha256.Size]byte{}) {
		return fmt.Errorf("treeplan: schedule certificate lacks request binding")
	}
	if err := p.validatePublic(); err != nil {
		return err
	}
	structureDigest := digestSchedulePlan(*p, false)
	fullDigest := digestSchedulePlan(*p, true)
	p.certificate.issued = true
	p.certificate.structureDigest = structureDigest
	p.certificate.fullDigest = fullDigest
	p.Certificate.RequestSHA256 = fmt.Sprintf("%x", p.certificate.requestDigest)
	p.Certificate.StructureSHA256 = fmt.Sprintf("%x", structureDigest)
	p.Certificate.FullPlanSHA256 = fmt.Sprintf("%x", fullDigest)
	return nil
}

// Validate detects mutation of the schedule, logical profiles, proof
// references, physical observations, or public reporting certificate.
func (p R0SchedulePlan) Validate() error {
	if !p.certificate.issued {
		return fmt.Errorf("treeplan: schedule certificate is absent")
	}
	if err := p.validatePublic(); err != nil {
		return err
	}
	if got, want := p.Certificate.RequestSHA256, fmt.Sprintf("%x", p.certificate.requestDigest); got != want {
		return fmt.Errorf("treeplan: public request digest does not match the private schedule certificate")
	}
	structureDigest := digestSchedulePlan(p, false)
	if structureDigest != p.certificate.structureDigest || p.Certificate.StructureSHA256 != fmt.Sprintf("%x", structureDigest) {
		return fmt.Errorf("treeplan: schedule structure certificate does not match the current plan")
	}
	fullDigest := digestSchedulePlan(p, true)
	if fullDigest != p.certificate.fullDigest || p.Certificate.FullPlanSHA256 != fmt.Sprintf("%x", fullDigest) {
		return fmt.Errorf("treeplan: full schedule certificate does not match the current plan")
	}
	return nil
}

func (p R0SchedulePlan) validatePublic() error {
	if p.GroupWidth < 1 || p.GroupWidth > 4 {
		return fmt.Errorf("treeplan: schedule group width must be in [1,4]: %d", p.GroupWidth)
	}
	if p.Certificate.SourceSHA256 == "" || p.Certificate.RadixPlanSHA256 == "" {
		return fmt.Errorf("treeplan: schedule source/radix certificate is incomplete")
	}
	switch p.BenchmarkEligibility {
	case BenchmarkPendingPhysicalMeasurement:
		if p.Schedule == R0StateAwareFusedLUT {
			return fmt.Errorf("treeplan: fused schedule cannot claim ordinary pending-measurement eligibility")
		}
	case BenchmarkIneligibleExternalProofUnverified:
		if p.Schedule != R0StateAwareFusedLUT {
			return fmt.Errorf("treeplan: non-fused schedule carries external-proof ineligibility")
		}
	default:
		return fmt.Errorf("treeplan: unknown benchmark eligibility %q", p.BenchmarkEligibility)
	}
	if p.BinaryDepth < 0 {
		return fmt.Errorf("treeplan: schedule binary depth is negative: %d", p.BinaryDepth)
	}
	if p.BinaryDepth > 0 && len(p.Groups) == 0 {
		return fmt.Errorf("treeplan: non-leaf schedule has no groups")
	}
	if p.BinaryDepth == 0 && len(p.Groups) != 0 {
		return fmt.Errorf("treeplan: leaf-only schedule carries groups")
	}
	wantStart := 0
	for i := range p.Groups {
		group := p.Groups[i]
		if group.StartDepth != wantStart {
			return fmt.Errorf("treeplan: schedule group %d starts at %d, want %d", i, group.StartDepth, wantStart)
		}
		if err := group.Validate(p.Schedule); err != nil {
			return fmt.Errorf("treeplan: schedule group %d: %w", i, err)
		}
		wantStart += group.Height
	}
	if wantStart != p.BinaryDepth {
		return fmt.Errorf("treeplan: schedule groups cover depth %d, want %d", wantStart, p.BinaryDepth)
	}
	return nil
}

// Validate checks the internal consistency of one issued group profile. The
// enclosing plan certificate still supplies the tamper-evident binding.
func (g R0GroupProfile) Validate(schedule R0Schedule) error {
	if g.StartDepth < 0 || g.Height <= 0 || g.Height > 4 {
		return fmt.Errorf("invalid d/h=%d/%d", g.StartDepth, g.Height)
	}
	if g.CandidateSupernodes != 1<<g.StartDepth || g.PredicatesPerSupernode != (1<<g.Height)-1 {
		return fmt.Errorf("invalid S/K=%d/%d for d/h=%d/%d", g.CandidateSupernodes, g.PredicatesPerSupernode, g.StartDepth, g.Height)
	}
	logicalComparisons := 0
	seenProvenance := map[ComparatorProvenance]bool{}
	for i, charge := range g.ComparatorCharges {
		if err := charge.Validate(); err != nil {
			return fmt.Errorf("comparator charge %d: %w", i, err)
		}
		if seenProvenance[charge.Provenance] {
			return fmt.Errorf("duplicate comparator provenance %q", charge.Provenance)
		}
		seenProvenance[charge.Provenance] = true
		logicalComparisons += charge.LogicalComparisons
	}
	if logicalComparisons != g.LogicalComparisons {
		return fmt.Errorf("comparator charges sum to %d, logical total is %d", logicalComparisons, g.LogicalComparisons)
	}
	for _, widths := range [][]int{g.FeatureSelectorWidths, g.ThresholdSelectorWidths, g.ResultSelectorWidths} {
		for _, width := range widths {
			if width <= 0 {
				return fmt.Errorf("selector width is non-positive: %d", width)
			}
		}
	}
	if g.LogicalSelectorTerms < 0 || g.PredicateDependencyRounds <= 0 || g.LogicalLUTEvaluations < 0 {
		return fmt.Errorf("negative/zero logical schedule count")
	}
	if err := g.EndToEndDependencyDepth.Validate(); err != nil {
		return fmt.Errorf("end-to-end dependency depth: %w", err)
	}
	if g.EndToEndDependencyDepth.Status == MeasurementMeasured && *g.EndToEndDependencyDepth.Value < int64(g.PredicateDependencyRounds) {
		return fmt.Errorf(
			"measured end-to-end dependency depth %d is below predicate/LUT lower bound %d",
			*g.EndToEndDependencyDepth.Value, g.PredicateDependencyRounds,
		)
	}
	if err := g.Physical.Validate(); err != nil {
		return fmt.Errorf("physical profile: %w", err)
	}
	if err := validateChargeAggregate("physical comparator streams", g.Physical.PhysicalComparatorStreams, g.ComparatorCharges, true, func(c ComparatorCharge) PhysicalCount {
		return c.PhysicalComparatorStreams
	}); err != nil {
		return err
	}
	if err := validateChargeAggregate("refreshes", g.Physical.Refreshes, g.ComparatorCharges, false, func(c ComparatorCharge) PhysicalCount {
		return c.Refreshes
	}); err != nil {
		return err
	}
	if err := validateChargeAggregate("bootstraps", g.Physical.Bootstraps, g.ComparatorCharges, false, func(c ComparatorCharge) PhysicalCount {
		return c.Bootstraps
	}); err != nil {
		return err
	}
	if schedule == R0StateAwareFusedLUT {
		if len(g.ComparatorCharges) != 0 || g.LogicalComparisons != 0 {
			return fmt.Errorf("fused LUT group carries comparator charges")
		}
		if err := validateProofArtifact(g.EquivalenceProof); err != nil {
			return fmt.Errorf("equivalence proof: %w", err)
		}
		if g.EquivalenceProofStatus != ProofExternalUnverified {
			return fmt.Errorf("unsupported proof verification status %q", g.EquivalenceProofStatus)
		}
	} else if g.EquivalenceProof != nil || g.EquivalenceProofStatus != "" || g.FusedLUTStrategy != "" {
		return fmt.Errorf("non-fused group carries fused-LUT evidence")
	}
	return nil
}

func validateChargeAggregate(name string, aggregate PhysicalCount, charges []ComparatorCharge, exactWhenComplete bool, selectCount func(ComparatorCharge) PhysicalCount) error {
	if aggregate.Status != MeasurementMeasured || len(charges) == 0 {
		return nil
	}
	const maxInt64 = int64(^uint64(0) >> 1)
	var sum int64
	complete := true
	for _, charge := range charges {
		count := selectCount(charge)
		if count.Status != MeasurementMeasured {
			complete = false
			continue
		}
		if *count.Value > maxInt64-sum {
			return fmt.Errorf("%s aggregate overflows int64", name)
		}
		sum += *count.Value
	}
	got := *aggregate.Value
	if got < sum {
		return fmt.Errorf("aggregate %s=%d is below measured provenance subtotal %d", name, got, sum)
	}
	if exactWhenComplete && complete && got != sum {
		return fmt.Errorf("aggregate %s=%d, complete provenance charges sum to %d", name, got, sum)
	}
	return nil
}

// Clone returns a fully detached plan while preserving its private
// certificate. Mutating either copy cannot affect the other.
func (p R0SchedulePlan) Clone() R0SchedulePlan {
	out := p
	out.Groups = make([]R0GroupProfile, len(p.Groups))
	for i := range p.Groups {
		out.Groups[i] = cloneR0GroupProfile(p.Groups[i])
	}
	return out
}

func cloneR0GroupProfile(group R0GroupProfile) R0GroupProfile {
	out := group
	out.ComparatorCharges = make([]ComparatorCharge, len(group.ComparatorCharges))
	for i, charge := range group.ComparatorCharges {
		out.ComparatorCharges[i] = cloneComparatorCharge(charge)
	}
	out.FeatureSelectorWidths = append([]int(nil), group.FeatureSelectorWidths...)
	out.ThresholdSelectorWidths = append([]int(nil), group.ThresholdSelectorWidths...)
	out.ResultSelectorWidths = append([]int(nil), group.ResultSelectorWidths...)
	out.EquivalenceProof = cloneProofArtifact(group.EquivalenceProof)
	out.EndToEndDependencyDepth = clonePhysicalCount(group.EndToEndDependencyDepth)
	out.Physical = cloneR0PhysicalProfile(group.Physical)
	return out
}

func cloneComparatorCharge(charge ComparatorCharge) ComparatorCharge {
	out := charge
	out.StreamsPerLogicalComparison = clonePhysicalCount(charge.StreamsPerLogicalComparison)
	out.PhysicalComparatorStreams = clonePhysicalCount(charge.PhysicalComparatorStreams)
	out.RefreshesPerComparatorStream = clonePhysicalCount(charge.RefreshesPerComparatorStream)
	out.BootstrapsPerComparatorStream = clonePhysicalCount(charge.BootstrapsPerComparatorStream)
	out.Refreshes = clonePhysicalCount(charge.Refreshes)
	out.Bootstraps = clonePhysicalCount(charge.Bootstraps)
	return out
}

func clonePhysicalCount(count PhysicalCount) PhysicalCount {
	out := count
	if count.Value != nil {
		value := *count.Value
		out.Value = &value
	}
	return out
}

func cloneR0PhysicalProfile(profile R0PhysicalProfile) R0PhysicalProfile {
	out := profile
	out.PhysicalComparatorStreams = clonePhysicalCount(profile.PhysicalComparatorStreams)
	out.LUTInputStreams = clonePhysicalCount(profile.LUTInputStreams)
	out.LUTOutputStreams = clonePhysicalCount(profile.LUTOutputStreams)
	out.CiphertextCiphertextMultiplications = clonePhysicalCount(profile.CiphertextCiphertextMultiplications)
	out.CiphertextPlaintextMultiplications = clonePhysicalCount(profile.CiphertextPlaintextMultiplications)
	out.CiphertextAdditions = clonePhysicalCount(profile.CiphertextAdditions)
	out.A2B = clonePhysicalCount(profile.A2B)
	out.B2A = clonePhysicalCount(profile.B2A)
	out.Rotations = clonePhysicalCount(profile.Rotations)
	out.Relinearizations = clonePhysicalCount(profile.Relinearizations)
	out.Rescales = clonePhysicalCount(profile.Rescales)
	out.KeySwitches = clonePhysicalCount(profile.KeySwitches)
	out.Transforms = clonePhysicalCount(profile.Transforms)
	out.Refreshes = clonePhysicalCount(profile.Refreshes)
	out.Bootstraps = clonePhysicalCount(profile.Bootstraps)
	out.PeakLiveCiphertexts = clonePhysicalCount(profile.PeakLiveCiphertexts)
	out.PeakLiveBytes = clonePhysicalCount(profile.PeakLiveBytes)
	out.WallTimeNanoseconds = clonePhysicalCount(profile.WallTimeNanoseconds)
	return out
}

// WithPhysicalMeasurements attaches backend observations through a validated
// copy and reissues the full-plan digest. Provenance and logical comparator
// counts remain compiler-owned; callers can only attach their physical fields.
func (p R0SchedulePlan) WithPhysicalMeasurements(measurements []R0GroupPhysicalMeasurements) (R0SchedulePlan, error) {
	if err := p.Validate(); err != nil {
		return R0SchedulePlan{}, err
	}
	if len(measurements) != len(p.Groups) {
		return R0SchedulePlan{}, fmt.Errorf("treeplan: physical measurement groups=%d, want %d", len(measurements), len(p.Groups))
	}
	out := p.Clone()
	for i, measurement := range measurements {
		if measurement.GroupIndex != i || measurement.StartDepth != out.Groups[i].StartDepth || measurement.Height != out.Groups[i].Height {
			return R0SchedulePlan{}, fmt.Errorf(
				"treeplan: physical measurement group identity %d/%d/%d, want %d/%d/%d",
				measurement.GroupIndex, measurement.StartDepth, measurement.Height,
				i, out.Groups[i].StartDepth, out.Groups[i].Height,
			)
		}
		if len(measurement.ComparatorCharges) != len(out.Groups[i].ComparatorCharges) {
			return R0SchedulePlan{}, fmt.Errorf(
				"treeplan: physical comparator observations in group %d=%d, want %d",
				i, len(measurement.ComparatorCharges), len(out.Groups[i].ComparatorCharges),
			)
		}
		if err := measurement.EndToEndDependencyDepth.Validate(); err != nil {
			return R0SchedulePlan{}, fmt.Errorf("treeplan: end-to-end dependency depth in group %d: %w", i, err)
		}
		if err := measurement.Physical.Validate(); err != nil {
			return R0SchedulePlan{}, fmt.Errorf("treeplan: physical measurement group %d: %w", i, err)
		}
		for j, observation := range measurement.ComparatorCharges {
			if err := observation.Validate(); err != nil {
				return R0SchedulePlan{}, fmt.Errorf("treeplan: comparator observation group %d charge %d: %w", i, j, err)
			}
			charge := &out.Groups[i].ComparatorCharges[j]
			if observation.Provenance != charge.Provenance {
				return R0SchedulePlan{}, fmt.Errorf(
					"treeplan: comparator observation group %d charge %d provenance=%q, want %q",
					i, j, observation.Provenance, charge.Provenance,
				)
			}
			charge.StreamsPerLogicalComparison = clonePhysicalCount(observation.StreamsPerLogicalComparison)
			charge.PhysicalComparatorStreams = clonePhysicalCount(observation.PhysicalComparatorStreams)
			charge.RefreshesPerComparatorStream = clonePhysicalCount(observation.RefreshesPerComparatorStream)
			charge.BootstrapsPerComparatorStream = clonePhysicalCount(observation.BootstrapsPerComparatorStream)
			charge.Refreshes = clonePhysicalCount(observation.Refreshes)
			charge.Bootstraps = clonePhysicalCount(observation.Bootstraps)
		}
		out.Groups[i].EndToEndDependencyDepth = clonePhysicalCount(measurement.EndToEndDependencyDepth)
		out.Groups[i].Physical = cloneR0PhysicalProfile(measurement.Physical)
	}
	if err := out.reissue(); err != nil {
		return R0SchedulePlan{}, err
	}
	return out, nil
}

// VerifyScheduleAgainst binds an issued schedule to both the exact source
// tree and the exact request. Attached physical observations are validated by
// the full certificate but do not alter the structural equivalence check.
func VerifyScheduleAgainst[T Ordered, L Ordered](plan R0SchedulePlan, source BinaryTree[T, L], request R0ScheduleRequest) error {
	if err := plan.Validate(); err != nil {
		return err
	}
	radix, err := CompileR0(source, plan.GroupWidth)
	if err != nil {
		return err
	}
	if err := radix.VerifyAgainst(source); err != nil {
		return err
	}
	expected, err := radix.PlanSchedule(request)
	if err != nil {
		return err
	}
	if expected.certificate.requestDigest != plan.certificate.requestDigest {
		return fmt.Errorf("treeplan: schedule request does not match the issued plan")
	}
	if expected.certificate.structureDigest != plan.certificate.structureDigest {
		return fmt.Errorf("treeplan: schedule structure does not match source/request")
	}
	return nil
}

func digestScheduleRequest(request R0ScheduleRequest) ([sha256.Size]byte, error) {
	e := newCanonicalEncoder("LCPDTE/treeplan/R0ScheduleRequest/v1")
	e.writeBytes([]byte(request.Schedule))
	if request.FusedLUT == nil {
		e.writeUint64(0)
		return e.sum(), nil
	}
	e.writeUint64(1)
	writeProofArtifact(e, request.FusedLUT.RootSameFeatureFiniteDomainProof)
	e.writeBytes([]byte(request.FusedLUT.BelowRootStrategy))
	writeProofArtifact(e, request.FusedLUT.BelowRootSameFeatureFiniteDomainProof)
	depths := make([]int, 0, len(request.FusedLUT.GlobalDomainProofs))
	for depth := range request.FusedLUT.GlobalDomainProofs {
		depths = append(depths, depth)
	}
	sort.Ints(depths)
	e.writeUint64(uint64(len(depths)))
	for _, depth := range depths {
		e.writeInt(depth)
		proof := request.FusedLUT.GlobalDomainProofs[depth]
		writeProofArtifact(e, &proof)
	}
	return e.sum(), nil
}

func digestSchedulePlan(plan R0SchedulePlan, includePhysical bool) [sha256.Size]byte {
	domain := "LCPDTE/treeplan/R0ScheduleStructure/v1"
	if includePhysical {
		domain = "LCPDTE/treeplan/R0ScheduleFull/v1"
	}
	e := newCanonicalEncoder(domain)
	e.writeBytes([]byte(plan.Schedule))
	e.writeInt(plan.BinaryDepth)
	e.writeInt(plan.GroupWidth)
	e.writeBytes([]byte(plan.BenchmarkEligibility))
	e.writeBytes([]byte(plan.Certificate.SourceSHA256))
	e.writeBytes([]byte(plan.Certificate.RadixPlanSHA256))
	e.writeBytes(plan.certificate.requestDigest[:])
	e.writeUint64(uint64(len(plan.Groups)))
	for _, group := range plan.Groups {
		e.writeInt(group.StartDepth)
		e.writeInt(group.Height)
		e.writeInt(group.CandidateSupernodes)
		e.writeInt(group.PredicatesPerSupernode)
		e.writeInt(group.LogicalComparisons)
		e.writeUint64(uint64(len(group.ComparatorCharges)))
		for _, charge := range group.ComparatorCharges {
			e.writeBytes([]byte(charge.Provenance))
			e.writeInt(charge.LogicalComparisons)
			if includePhysical {
				for _, count := range []PhysicalCount{
					charge.StreamsPerLogicalComparison, charge.PhysicalComparatorStreams,
					charge.RefreshesPerComparatorStream, charge.BootstrapsPerComparatorStream,
					charge.Refreshes, charge.Bootstraps,
				} {
					writePhysicalCount(e, count)
				}
			}
		}
		writeIntSlice(e, group.FeatureSelectorWidths)
		writeIntSlice(e, group.ThresholdSelectorWidths)
		writeIntSlice(e, group.ResultSelectorWidths)
		e.writeInt(group.LogicalSelectorTerms)
		if group.SelectorTermsLowerBound {
			e.writeUint64(1)
		} else {
			e.writeUint64(0)
		}
		e.writeInt(group.PredicateDependencyRounds)
		e.writeInt(group.LogicalLUTEvaluations)
		e.writeBytes([]byte(group.FusedLUTStrategy))
		writeProofArtifact(e, group.EquivalenceProof)
		e.writeBytes([]byte(group.EquivalenceProofStatus))
		e.writeUint64(uint64(group.DeclaredGlobalDomainSize))
		if includePhysical {
			writePhysicalCount(e, group.EndToEndDependencyDepth)
			writePhysicalProfile(e, group.Physical)
		}
	}
	return e.sum()
}

func writeProofArtifact(e *canonicalEncoder, proof *ProofArtifactReference) {
	if proof == nil {
		e.writeUint64(0)
		return
	}
	e.writeUint64(1)
	e.writeBytes([]byte(proof.URI))
	e.writeBytes([]byte(proof.SHA256))
	e.writeBytes([]byte(proof.DomainDescriptor))
	e.writeUint64(uint64(proof.DomainSize))
}

func writeIntSlice(e *canonicalEncoder, values []int) {
	e.writeUint64(uint64(len(values)))
	for _, value := range values {
		e.writeInt(value)
	}
}

func writePhysicalCount(e *canonicalEncoder, count PhysicalCount) {
	e.writeBytes([]byte(count.Status))
	if count.Value == nil {
		e.writeUint64(0)
		return
	}
	e.writeUint64(1)
	e.writeUint64(uint64(*count.Value))
}

func writePhysicalProfile(e *canonicalEncoder, profile R0PhysicalProfile) {
	e.writeBytes([]byte(profile.Packing.Status))
	e.writeBytes([]byte(profile.Packing.Mode))
	e.writeInt(profile.Packing.WordWidth)
	e.writeInt(profile.Packing.LogSlots)
	e.writeUint64(uint64(profile.Packing.WordSlotOccupancy))
	e.writeUint64(uint64(profile.Packing.BA2BGroupOccupancy))
	for _, count := range []PhysicalCount{
		profile.PhysicalComparatorStreams, profile.LUTInputStreams, profile.LUTOutputStreams,
		profile.CiphertextCiphertextMultiplications, profile.CiphertextPlaintextMultiplications,
		profile.CiphertextAdditions, profile.A2B, profile.B2A, profile.Rotations,
		profile.Relinearizations, profile.Rescales, profile.KeySwitches, profile.Transforms,
		profile.Refreshes, profile.Bootstraps, profile.PeakLiveCiphertexts, profile.PeakLiveBytes,
		profile.WallTimeNanoseconds,
	} {
		writePhysicalCount(e, count)
	}
}
