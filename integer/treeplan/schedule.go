package treeplan

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
)

// R0Schedule identifies one audited execution schedule for a certified R0
// plan. The operand provenance is part of the name so CT-CT and CT-plaintext
// comparator costs cannot be combined accidentally.
type R0Schedule string

const (
	// R0SequentialSourceFaithfulOBO reproduces the pinned LCPDTE operand
	// provenance: one root CT-plaintext comparison and D-1 selected CT-CT
	// comparisons. It is distinct from the conservative uniform oracle.
	R0SequentialSourceFaithfulOBO R0Schedule = "r0_sequential_source_faithful_obo"
	R0SequentialActiveCTCT        R0Schedule = "r0_sequential_active_ct_ct"
	R0EagerActiveCTCT             R0Schedule = "r0_eager_active_ct_ct"
	R0EagerAllCTPT                R0Schedule = "r0_eager_all_ct_pt"
	R0StateAwareFusedLUT          R0Schedule = "r0_state_aware_fused_lut"
)

// MeasurementStatus distinguishes an observed zero from a field for which no
// encrypted backend measurement exists yet.
type MeasurementStatus string

const (
	MeasurementNotMeasured MeasurementStatus = "not_measured"
	MeasurementMeasured    MeasurementStatus = "measured"
)

// PhysicalCount is an audit-safe physical-operation measurement. Value is nil
// exactly when Status is MeasurementNotMeasured; a measured zero is retained
// as a non-nil pointer to zero.
type PhysicalCount struct {
	Status MeasurementStatus `json:"status"`
	Value  *int64            `json:"value,omitempty"`
}

func NotMeasuredPhysicalCount() PhysicalCount {
	return PhysicalCount{Status: MeasurementNotMeasured}
}

func MeasuredPhysicalCount(value int64) (PhysicalCount, error) {
	if value < 0 {
		return PhysicalCount{}, fmt.Errorf("physical count must be non-negative: %d", value)
	}
	copyOfValue := value
	return PhysicalCount{Status: MeasurementMeasured, Value: &copyOfValue}, nil
}

func (c PhysicalCount) Validate() error {
	switch c.Status {
	case MeasurementNotMeasured:
		if c.Value != nil {
			return fmt.Errorf("not-measured physical count carries a value")
		}
	case MeasurementMeasured:
		if c.Value == nil {
			return fmt.Errorf("measured physical count has no value")
		}
		if *c.Value < 0 {
			return fmt.Errorf("measured physical count is negative: %d", *c.Value)
		}
	default:
		return fmt.Errorf("unknown physical measurement status %q", c.Status)
	}
	return nil
}

// ComparatorProvenance records the HE operand class required by a schedule.
// A fused LUT is separate because it does not issue a comparator call.
type ComparatorProvenance string

const (
	ComparatorCTCT          ComparatorProvenance = "ct_ct"
	ComparatorCTPlaintext   ComparatorProvenance = "ct_plaintext"
	ComparatorStateAwareLUT ComparatorProvenance = "state_aware_fused_lut"
)

// BenchmarkEligibility prevents a structurally constructible planning row
// from being mistaken for an eligible measured result.
type BenchmarkEligibility string

const (
	BenchmarkPendingPhysicalMeasurement        BenchmarkEligibility = "pending_physical_measurement"
	BenchmarkIneligibleExternalProofUnverified BenchmarkEligibility = "ineligible_external_proof_unverified"
)

// ProofVerificationStatus is assigned by this package, not supplied by the
// caller. PlanSchedule only records external proof artifacts; it does not
// verify their mathematical contents.
type ProofVerificationStatus string

const ProofExternalUnverified ProofVerificationStatus = "external_unverified"

// ProofArtifactReference is an auditable locator and claimed content digest
// for a finite-domain equivalence proof. A well-formed reference remains
// external-unverified until a later integrity stage reads and verifies the
// artifact; it never makes a fused row benchmark-eligible by itself.
type ProofArtifactReference struct {
	URI              string `json:"uri"`
	SHA256           string `json:"sha256"`
	DomainDescriptor string `json:"domain_descriptor"`
	DomainSize       int64  `json:"domain_size"`
}

func validateProofArtifact(reference *ProofArtifactReference) error {
	if reference == nil {
		return fmt.Errorf("proof artifact reference is absent")
	}
	parsed, err := url.Parse(strings.TrimSpace(reference.URI))
	if err != nil || parsed.Scheme == "" || (parsed.Host == "" && parsed.Path == "" && parsed.Opaque == "") {
		return fmt.Errorf("proof artifact URI %q is not absolute", reference.URI)
	}
	hashBytes, err := hex.DecodeString(reference.SHA256)
	if err != nil || len(hashBytes) != 32 {
		return fmt.Errorf("proof artifact SHA-256 must be exactly 64 hexadecimal characters")
	}
	if strings.TrimSpace(reference.DomainDescriptor) == "" {
		return fmt.Errorf("proof artifact domain descriptor is empty")
	}
	if reference.DomainSize <= 0 {
		return fmt.Errorf("proof artifact domain size must be positive: %d", reference.DomainSize)
	}
	return nil
}

// R0ScheduleRequest selects one execution schedule for an already certified
// R0 structural plan.
type R0ScheduleRequest struct {
	Schedule R0Schedule       `json:"schedule"`
	FusedLUT *FusedLUTOptions `json:"fused_lut,omitempty"`
}

// FusedLUTOptions supplies proof-artifact references that cannot be inferred
// from structural grouping. The planner additionally checks every
// same-feature precondition against the certified split arena.
type FusedLUTOptions struct {
	RootSameFeatureFiniteDomainProof      *ProofArtifactReference        `json:"root_same_feature_finite_domain_proof,omitempty"`
	BelowRootStrategy                     FusedLUTStrategy               `json:"below_root_strategy,omitempty"`
	BelowRootSameFeatureFiniteDomainProof *ProofArtifactReference        `json:"below_root_same_feature_finite_domain_proof,omitempty"`
	GlobalDomainProofs                    map[int]ProofArtifactReference `json:"global_domain_proofs,omitempty"`
}

type FusedLUTStrategy string

const (
	FusedLUTRootSingle             FusedLUTStrategy = "root_single_lut"
	FusedLUTAllSupernodesAndSelect FusedLUTStrategy = "all_supernode_luts_and_select"
	FusedLUTGlobalStateDomain      FusedLUTStrategy = "global_state_domain"
)

// PackingMode is the concrete word-packing layout observed by an encrypted
// backend. The planner itself starts with an unmeasured packing observation.
type PackingMode string

const (
	PackingFull   PackingMode = "full"
	PackingSparse PackingMode = "sparse"
)

// R0PackingObservation records the physical packing denominator. A measured
// word-slot occupancy is positive; BA2BGroupOccupancy may be zero when the
// schedule does not invoke B-A2B.
type R0PackingObservation struct {
	Status             MeasurementStatus `json:"status"`
	Mode               PackingMode       `json:"mode,omitempty"`
	WordWidth          int               `json:"word_width,omitempty"`
	LogSlots           int               `json:"log_slots,omitempty"`
	WordSlotOccupancy  int64             `json:"word_slot_occupancy,omitempty"`
	BA2BGroupOccupancy int64             `json:"ba2b_group_occupancy,omitempty"`
}

func (p R0PackingObservation) Validate() error {
	switch p.Status {
	case MeasurementNotMeasured:
		if p.Mode != "" || p.WordWidth != 0 || p.LogSlots != 0 || p.WordSlotOccupancy != 0 || p.BA2BGroupOccupancy != 0 {
			return fmt.Errorf("not-measured packing carries observed fields")
		}
	case MeasurementMeasured:
		if p.Mode != PackingFull && p.Mode != PackingSparse {
			return fmt.Errorf("measured packing has unknown mode %q", p.Mode)
		}
		if p.WordWidth <= 0 || p.LogSlots <= 0 {
			return fmt.Errorf("measured packing requires positive word width and LogSlots")
		}
		if p.WordSlotOccupancy <= 0 || p.BA2BGroupOccupancy < 0 {
			return fmt.Errorf("measured packing requires positive word-slot occupancy and non-negative B-A2B occupancy")
		}
	default:
		return fmt.Errorf("unknown packing measurement status %q", p.Status)
	}
	return nil
}

// ComparatorCharge preserves operand provenance even for the source-faithful
// root group, which contains both CT-plaintext and CT-CT comparisons. Physical
// stream/refresh factors remain typed not-measured until attached by a backend.
type ComparatorCharge struct {
	Provenance                    ComparatorProvenance `json:"provenance"`
	LogicalComparisons            int                  `json:"logical_comparisons"`
	StreamsPerLogicalComparison   PhysicalCount        `json:"streams_per_logical_comparison"`
	PhysicalComparatorStreams     PhysicalCount        `json:"physical_comparator_streams"`
	RefreshesPerComparatorStream  PhysicalCount        `json:"refreshes_per_comparator_stream"`
	BootstrapsPerComparatorStream PhysicalCount        `json:"bootstraps_per_comparator_stream"`
	Refreshes                     PhysicalCount        `json:"refreshes"`
	Bootstraps                    PhysicalCount        `json:"bootstraps"`
}

func unknownComparatorCharge(provenance ComparatorProvenance, logical int) ComparatorCharge {
	return ComparatorCharge{
		Provenance: provenance, LogicalComparisons: logical,
		StreamsPerLogicalComparison:   NotMeasuredPhysicalCount(),
		PhysicalComparatorStreams:     NotMeasuredPhysicalCount(),
		RefreshesPerComparatorStream:  NotMeasuredPhysicalCount(),
		BootstrapsPerComparatorStream: NotMeasuredPhysicalCount(),
		Refreshes:                     NotMeasuredPhysicalCount(),
		Bootstraps:                    NotMeasuredPhysicalCount(),
	}
}

func (c ComparatorCharge) Validate() error {
	if c.Provenance != ComparatorCTCT && c.Provenance != ComparatorCTPlaintext {
		return fmt.Errorf("comparator charge has unsupported provenance %q", c.Provenance)
	}
	if c.LogicalComparisons <= 0 {
		return fmt.Errorf("comparator charge has non-positive logical count %d", c.LogicalComparisons)
	}
	for name, count := range c.counts() {
		if err := count.Validate(); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if err := validateMeasuredProduct(
		"physical comparator streams", int64(c.LogicalComparisons), c.StreamsPerLogicalComparison, c.PhysicalComparatorStreams,
	); err != nil {
		return err
	}
	if c.PhysicalComparatorStreams.Status == MeasurementMeasured {
		streams := *c.PhysicalComparatorStreams.Value
		if err := validateMeasuredProduct("comparator refreshes", streams, c.RefreshesPerComparatorStream, c.Refreshes); err != nil {
			return err
		}
		if err := validateMeasuredProduct("comparator bootstraps", streams, c.BootstrapsPerComparatorStream, c.Bootstraps); err != nil {
			return err
		}
	}
	return nil
}

func validateMeasuredProduct(name string, multiplicand int64, factor, product PhysicalCount) error {
	if factor.Status != MeasurementMeasured || product.Status != MeasurementMeasured {
		return nil
	}
	const maxInt64 = int64(^uint64(0) >> 1)
	if multiplicand != 0 && *factor.Value > maxInt64/multiplicand {
		return fmt.Errorf("%s product overflows int64", name)
	}
	want := multiplicand * *factor.Value
	if got := *product.Value; got != want {
		return fmt.Errorf("%s=%d, want %d from measured factors", name, got, want)
	}
	return nil
}

func (c ComparatorCharge) counts() map[string]PhysicalCount {
	return map[string]PhysicalCount{
		"streams per logical comparison":   c.StreamsPerLogicalComparison,
		"physical comparator streams":      c.PhysicalComparatorStreams,
		"refreshes per comparator stream":  c.RefreshesPerComparatorStream,
		"bootstraps per comparator stream": c.BootstrapsPerComparatorStream,
		"comparator refreshes":             c.Refreshes,
		"comparator bootstraps":            c.Bootstraps,
	}
}

// ComparatorPhysicalObservation attaches the backend factors for one existing
// provenance charge without allowing the caller to rewrite its provenance or
// logical comparison count.
type ComparatorPhysicalObservation struct {
	Provenance                    ComparatorProvenance `json:"provenance"`
	StreamsPerLogicalComparison   PhysicalCount        `json:"streams_per_logical_comparison"`
	PhysicalComparatorStreams     PhysicalCount        `json:"physical_comparator_streams"`
	RefreshesPerComparatorStream  PhysicalCount        `json:"refreshes_per_comparator_stream"`
	BootstrapsPerComparatorStream PhysicalCount        `json:"bootstraps_per_comparator_stream"`
	Refreshes                     PhysicalCount        `json:"refreshes"`
	Bootstraps                    PhysicalCount        `json:"bootstraps"`
}

func UnknownComparatorPhysicalObservation(provenance ComparatorProvenance) ComparatorPhysicalObservation {
	return ComparatorPhysicalObservation{
		Provenance:                    provenance,
		StreamsPerLogicalComparison:   NotMeasuredPhysicalCount(),
		PhysicalComparatorStreams:     NotMeasuredPhysicalCount(),
		RefreshesPerComparatorStream:  NotMeasuredPhysicalCount(),
		BootstrapsPerComparatorStream: NotMeasuredPhysicalCount(),
		Refreshes:                     NotMeasuredPhysicalCount(),
		Bootstraps:                    NotMeasuredPhysicalCount(),
	}
}

func (o ComparatorPhysicalObservation) Validate() error {
	if o.Provenance != ComparatorCTCT && o.Provenance != ComparatorCTPlaintext {
		return fmt.Errorf("unsupported comparator observation provenance %q", o.Provenance)
	}
	for name, count := range map[string]PhysicalCount{
		"streams per logical comparison":   o.StreamsPerLogicalComparison,
		"physical comparator streams":      o.PhysicalComparatorStreams,
		"refreshes per comparator stream":  o.RefreshesPerComparatorStream,
		"bootstraps per comparator stream": o.BootstrapsPerComparatorStream,
		"comparator refreshes":             o.Refreshes,
		"comparator bootstraps":            o.Bootstraps,
	} {
		if err := count.Validate(); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

// R0PhysicalProfile is the complete encrypted-backend tuple required by the
// frozen benchmark contract. Every count is explicitly measured or
// not-measured; zero never stands for unknown.
type R0PhysicalProfile struct {
	Packing                             R0PackingObservation `json:"packing"`
	PhysicalComparatorStreams           PhysicalCount        `json:"physical_comparator_streams"`
	LUTInputStreams                     PhysicalCount        `json:"lut_input_streams"`
	LUTOutputStreams                    PhysicalCount        `json:"lut_output_streams"`
	CiphertextCiphertextMultiplications PhysicalCount        `json:"ciphertext_ciphertext_multiplications"`
	CiphertextPlaintextMultiplications  PhysicalCount        `json:"ciphertext_plaintext_multiplications"`
	CiphertextAdditions                 PhysicalCount        `json:"ciphertext_additions"`
	A2B                                 PhysicalCount        `json:"a2b"`
	B2A                                 PhysicalCount        `json:"b2a"`
	Rotations                           PhysicalCount        `json:"rotations"`
	Relinearizations                    PhysicalCount        `json:"relinearizations"`
	Rescales                            PhysicalCount        `json:"rescales"`
	KeySwitches                         PhysicalCount        `json:"key_switches"`
	Transforms                          PhysicalCount        `json:"transforms"`
	Refreshes                           PhysicalCount        `json:"refreshes"`
	Bootstraps                          PhysicalCount        `json:"bootstraps"`
	PeakLiveCiphertexts                 PhysicalCount        `json:"peak_live_ciphertexts"`
	PeakLiveBytes                       PhysicalCount        `json:"peak_live_bytes"`
	WallTimeNanoseconds                 PhysicalCount        `json:"wall_time_nanoseconds"`
}

// R0GroupPhysicalMeasurements is the controlled attachment payload for one
// group. Comparator observations are positional against the issued,
// provenance-separated ComparatorCharges and cannot alter their logical data.
type R0GroupPhysicalMeasurements struct {
	GroupIndex              int                             `json:"group_index"`
	StartDepth              int                             `json:"start_depth"`
	Height                  int                             `json:"height"`
	ComparatorCharges       []ComparatorPhysicalObservation `json:"comparator_charges"`
	EndToEndDependencyDepth PhysicalCount                   `json:"end_to_end_dependency_depth"`
	Physical                R0PhysicalProfile               `json:"physical"`
}

func UnknownR0PhysicalProfile() R0PhysicalProfile {
	unknown := NotMeasuredPhysicalCount
	return R0PhysicalProfile{
		Packing:                   R0PackingObservation{Status: MeasurementNotMeasured},
		PhysicalComparatorStreams: unknown(), LUTInputStreams: unknown(), LUTOutputStreams: unknown(),
		CiphertextCiphertextMultiplications: unknown(), CiphertextPlaintextMultiplications: unknown(),
		CiphertextAdditions: unknown(), A2B: unknown(), B2A: unknown(), Rotations: unknown(),
		Relinearizations: unknown(), Rescales: unknown(), KeySwitches: unknown(), Transforms: unknown(),
		Refreshes: unknown(), Bootstraps: unknown(), PeakLiveCiphertexts: unknown(), PeakLiveBytes: unknown(),
		WallTimeNanoseconds: unknown(),
	}
}

func (p R0PhysicalProfile) Validate() error {
	if err := p.Packing.Validate(); err != nil {
		return fmt.Errorf("packing: %w", err)
	}
	for name, count := range p.counts() {
		if err := count.Validate(); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

func (p R0PhysicalProfile) counts() map[string]PhysicalCount {
	return map[string]PhysicalCount{
		"physical comparator streams": p.PhysicalComparatorStreams,
		"LUT input streams":           p.LUTInputStreams, "LUT output streams": p.LUTOutputStreams,
		"ciphertext-ciphertext multiplications": p.CiphertextCiphertextMultiplications,
		"ciphertext-plaintext multiplications":  p.CiphertextPlaintextMultiplications,
		"ciphertext additions":                  p.CiphertextAdditions, "A2B": p.A2B, "B2A": p.B2A,
		"rotations": p.Rotations, "relinearizations": p.Relinearizations, "rescales": p.Rescales,
		"key switches": p.KeySwitches, "transforms": p.Transforms, "refreshes": p.Refreshes,
		"bootstraps": p.Bootstraps, "peak live ciphertexts": p.PeakLiveCiphertexts,
		"peak live bytes": p.PeakLiveBytes, "wall time nanoseconds": p.WallTimeNanoseconds,
	}
}

// R0GroupProfile is the auditable per-group accounting contract. Logical
// fields are derived lower bounds. Physical fields remain explicitly
// not-measured until a concrete encrypted backend supplies observations.
type R0GroupProfile struct {
	StartDepth int `json:"d"`
	Height     int `json:"h"`
	// CandidateSupernodes is S=2^d possible supernode states. Exactly one
	// candidate is encrypted-active during evaluation.
	CandidateSupernodes       int                     `json:"S"`
	PredicatesPerSupernode    int                     `json:"K"`
	ComparatorCharges         []ComparatorCharge      `json:"comparator_charges"`
	LogicalComparisons        int                     `json:"logical_comparisons"`
	FeatureSelectorWidths     []int                   `json:"feature_selector_widths"`
	ThresholdSelectorWidths   []int                   `json:"threshold_selector_widths"`
	ResultSelectorWidths      []int                   `json:"result_selector_widths"`
	LogicalSelectorTerms      int                     `json:"logical_selector_terms"`
	SelectorTermsLowerBound   bool                    `json:"selector_terms_lower_bound"`
	PredicateDependencyRounds int                     `json:"predicate_dependency_rounds"`
	EndToEndDependencyDepth   PhysicalCount           `json:"end_to_end_dependency_depth"`
	LogicalLUTEvaluations     int                     `json:"logical_lut_evaluations"`
	FusedLUTStrategy          FusedLUTStrategy        `json:"fused_lut_strategy,omitempty"`
	EquivalenceProof          *ProofArtifactReference `json:"equivalence_proof,omitempty"`
	EquivalenceProofStatus    ProofVerificationStatus `json:"equivalence_proof_status,omitempty"`
	DeclaredGlobalDomainSize  int64                   `json:"declared_global_domain_size,omitempty"`
	Physical                  R0PhysicalProfile       `json:"physical"`
}

// R0SchedulePlan binds schedule accounting to the same private compiler
// certificate used by RadixTree.Validate and VerifyAgainst.
type R0SchedulePlan struct {
	Schedule             R0Schedule            `json:"schedule"`
	BinaryDepth          int                   `json:"binary_depth"`
	GroupWidth           int                   `json:"group_width"`
	BenchmarkEligibility BenchmarkEligibility  `json:"benchmark_eligibility"`
	Certificate          R0ScheduleCertificate `json:"certificate"`
	Groups               []R0GroupProfile      `json:"groups"`
	certificate          scheduleCertificate
}

// R0ScheduleCertificate binds the source, certified radix arena, exact
// request, logical structure, and attached physical observations separately.
type R0ScheduleCertificate struct {
	SourceSHA256    string `json:"source_sha256"`
	RadixPlanSHA256 string `json:"radix_plan_sha256"`
	RequestSHA256   string `json:"request_sha256"`
	StructureSHA256 string `json:"structure_sha256"`
	FullPlanSHA256  string `json:"full_plan_sha256"`
}

type scheduleCertificate struct {
	issued          bool
	requestDigest   [32]byte
	structureDigest [32]byte
	fullDigest      [32]byte
}

// PlanSchedule derives per-group logical charges without inventing physical HE
// measurements. It fails closed if the R0 arena or its private certificate was
// mutated after CompileR0.
func (t RadixTree[T, L]) PlanSchedule(request R0ScheduleRequest) (R0SchedulePlan, error) {
	if err := t.Validate(); err != nil {
		return R0SchedulePlan{}, fmt.Errorf("invalid certified R0 plan: %w", err)
	}
	if request.Schedule != R0SequentialSourceFaithfulOBO && request.Schedule != R0SequentialActiveCTCT && request.Schedule != R0EagerActiveCTCT && request.Schedule != R0EagerAllCTPT && request.Schedule != R0StateAwareFusedLUT {
		return R0SchedulePlan{}, fmt.Errorf("schedule %q is not implemented", request.Schedule)
	}
	if request.Schedule != R0StateAwareFusedLUT && request.FusedLUT != nil {
		return R0SchedulePlan{}, fmt.Errorf("schedule %q cannot carry fused-LUT proof options", request.Schedule)
	}
	if request.Schedule == R0StateAwareFusedLUT {
		if request.FusedLUT == nil {
			return R0SchedulePlan{}, fmt.Errorf("root fused LUT requires a structured same-feature finite-domain proof artifact")
		}
		if err := validateProofArtifact(request.FusedLUT.RootSameFeatureFiniteDomainProof); err != nil {
			return R0SchedulePlan{}, fmt.Errorf("root fused LUT proof: %w", err)
		}
		if len(t.Levels) > 1 {
			switch request.FusedLUT.BelowRootStrategy {
			case FusedLUTAllSupernodesAndSelect:
				if err := validateProofArtifact(request.FusedLUT.BelowRootSameFeatureFiniteDomainProof); err != nil {
					return R0SchedulePlan{}, fmt.Errorf("below-root all-supernode LUT proof: %w", err)
				}
			case FusedLUTGlobalStateDomain:
				for _, level := range t.Levels[1:] {
					proof, exists := request.FusedLUT.GlobalDomainProofs[level.StartDepth]
					if !exists {
						return R0SchedulePlan{}, fmt.Errorf("below-root global-domain LUT at depth %d requires a proof artifact", level.StartDepth)
					}
					if err := validateProofArtifact(&proof); err != nil {
						return R0SchedulePlan{}, fmt.Errorf("below-root global-domain LUT proof at depth %d: %w", level.StartDepth, err)
					}
				}
			default:
				return R0SchedulePlan{}, fmt.Errorf("below-root fused LUT strategy is missing or unsupported")
			}
		}
	}
	certificate, err := t.Certificate()
	if err != nil {
		return R0SchedulePlan{}, err
	}
	plan := R0SchedulePlan{
		Schedule: request.Schedule, BinaryDepth: t.BinaryDepth, GroupWidth: t.GroupWidth,
		BenchmarkEligibility: BenchmarkPendingPhysicalMeasurement,
		Certificate: R0ScheduleCertificate{
			SourceSHA256: certificate.SourceSHA256, RadixPlanSHA256: certificate.PlanSHA256,
		},
		Groups: make([]R0GroupProfile, len(t.Levels)),
	}
	if request.Schedule == R0StateAwareFusedLUT {
		plan.BenchmarkEligibility = BenchmarkIneligibleExternalProofUnverified
	}
	for i, level := range t.Levels {
		group := R0GroupProfile{
			StartDepth:              level.StartDepth,
			Height:                  level.Width,
			CandidateSupernodes:     1 << level.StartDepth,
			PredicatesPerSupernode:  (1 << level.Width) - 1,
			SelectorTermsLowerBound: true,
			EndToEndDependencyDepth: NotMeasuredPhysicalCount(),
			Physical:                UnknownR0PhysicalProfile(),
		}
		switch request.Schedule {
		case R0SequentialSourceFaithfulOBO:
			group.LogicalComparisons = level.Width
			group.FeatureSelectorWidths = make([]int, 0, level.Width)
			group.ThresholdSelectorWidths = make([]int, 0, level.Width)
			group.PredicateDependencyRounds = level.Width
			for relativeDepth := 0; relativeDepth < level.Width; relativeDepth++ {
				globalDepth := level.StartDepth + relativeDepth
				if globalDepth == 0 {
					group.ComparatorCharges = append(group.ComparatorCharges, unknownComparatorCharge(ComparatorCTPlaintext, 1))
					continue
				}
				width := 1 << globalDepth
				group.FeatureSelectorWidths = append(group.FeatureSelectorWidths, width)
				group.ThresholdSelectorWidths = append(group.ThresholdSelectorWidths, width)
				group.LogicalSelectorTerms += 2 * width
			}
			ctct := level.Width
			if level.StartDepth == 0 {
				ctct--
			}
			if ctct > 0 {
				group.ComparatorCharges = append(group.ComparatorCharges, unknownComparatorCharge(ComparatorCTCT, ctct))
			}
		case R0SequentialActiveCTCT:
			group.LogicalComparisons = level.Width
			group.ComparatorCharges = []ComparatorCharge{unknownComparatorCharge(ComparatorCTCT, level.Width)}
			group.FeatureSelectorWidths = make([]int, level.Width)
			group.ThresholdSelectorWidths = make([]int, level.Width)
			group.PredicateDependencyRounds = level.Width
			for relativeDepth := 0; relativeDepth < level.Width; relativeDepth++ {
				width := 1 << (level.StartDepth + relativeDepth)
				group.FeatureSelectorWidths[relativeDepth] = width
				group.ThresholdSelectorWidths[relativeDepth] = width
				group.LogicalSelectorTerms += 2 * width
			}
		case R0EagerActiveCTCT:
			group.LogicalComparisons = group.PredicatesPerSupernode
			group.ComparatorCharges = []ComparatorCharge{unknownComparatorCharge(ComparatorCTCT, group.LogicalComparisons)}
			group.FeatureSelectorWidths = make([]int, group.PredicatesPerSupernode)
			group.ThresholdSelectorWidths = make([]int, group.PredicatesPerSupernode)
			group.PredicateDependencyRounds = 1
			for predicate := 0; predicate < group.PredicatesPerSupernode; predicate++ {
				group.FeatureSelectorWidths[predicate] = group.CandidateSupernodes
				group.ThresholdSelectorWidths[predicate] = group.CandidateSupernodes
				group.LogicalSelectorTerms += 2 * group.CandidateSupernodes
			}
		case R0EagerAllCTPT:
			group.LogicalComparisons = group.CandidateSupernodes * group.PredicatesPerSupernode
			group.ComparatorCharges = []ComparatorCharge{unknownComparatorCharge(ComparatorCTPlaintext, group.LogicalComparisons)}
			group.ResultSelectorWidths = []int{group.CandidateSupernodes}
			group.LogicalSelectorTerms = group.CandidateSupernodes
			group.PredicateDependencyRounds = 1
		case R0StateAwareFusedLUT:
			group.PredicateDependencyRounds = 1
			if level.StartDepth == 0 {
				if !eachSupernodeUsesOneFeature(level.Nodes) {
					return R0SchedulePlan{}, fmt.Errorf("root fused LUT same-feature precondition does not match the certified split features")
				}
				group.FusedLUTStrategy = FusedLUTRootSingle
				group.EquivalenceProof = cloneProofArtifact(request.FusedLUT.RootSameFeatureFiniteDomainProof)
				group.EquivalenceProofStatus = ProofExternalUnverified
				group.LogicalLUTEvaluations = 1
			} else {
				switch request.FusedLUT.BelowRootStrategy {
				case FusedLUTAllSupernodesAndSelect:
					if !eachSupernodeUsesOneFeature(level.Nodes) {
						return R0SchedulePlan{}, fmt.Errorf("below-root fused LUT same-feature precondition does not match the certified split features at depth %d", level.StartDepth)
					}
					group.FusedLUTStrategy = FusedLUTAllSupernodesAndSelect
					group.EquivalenceProof = cloneProofArtifact(request.FusedLUT.BelowRootSameFeatureFiniteDomainProof)
					group.EquivalenceProofStatus = ProofExternalUnverified
					group.LogicalLUTEvaluations = group.CandidateSupernodes
					group.ResultSelectorWidths = []int{group.CandidateSupernodes}
					group.LogicalSelectorTerms = group.CandidateSupernodes
				case FusedLUTGlobalStateDomain:
					group.FusedLUTStrategy = FusedLUTGlobalStateDomain
					proof := request.FusedLUT.GlobalDomainProofs[level.StartDepth]
					group.EquivalenceProof = cloneProofArtifact(&proof)
					group.EquivalenceProofStatus = ProofExternalUnverified
					group.LogicalLUTEvaluations = 1
					group.DeclaredGlobalDomainSize = proof.DomainSize
				}
			}
		}
		plan.Groups[i] = group
	}
	if err := plan.issue(request); err != nil {
		return R0SchedulePlan{}, err
	}
	return plan, nil
}

func eachSupernodeUsesOneFeature[T Ordered](nodes []RadixSupernode[T]) bool {
	for _, node := range nodes {
		if len(node.Splits) == 0 {
			return false
		}
		feature := node.Splits[0].Feature
		for _, split := range node.Splits[1:] {
			if split.Feature != feature {
				return false
			}
		}
	}
	return true
}

func cloneProofArtifact(reference *ProofArtifactReference) *ProofArtifactReference {
	if reference == nil {
		return nil
	}
	copyOfReference := *reference
	return &copyOfReference
}
