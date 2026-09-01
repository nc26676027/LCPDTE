package secureprofile

import "errors"

const (
	gaoN16PackingL11PhasePlanSchema    = "gao-n16-lattigo-packing-l11-phase-capacity-plan-v1"
	gaoN16PackingL11PhaseProbeSchema   = "gao-n16-lattigo-packing-l11-phase-capacity-probe-v1"
	gaoN16PackingL11PhaseReportSchema  = "gao-n16-lattigo-packing-l11-phase-capacity-report-v1"
	gaoN16PackingL11PhasePermitSchema  = "gao-n16-lattigo-packing-l11-phase-capacity-permit-v1"
	gaoN16PackingL11PhaseEvidenceScope = "runtime_phase_capacity_only"
)

// GaoN16PackingL11CapacityPhase names a closed, lineage-relative live-memory
// gate. The original combined plan remains the whole-lifecycle admission
// contract used before a BuildPermit is minted.
type GaoN16PackingL11CapacityPhase string

const (
	GaoN16PackingL11PhaseBeginBuild                 GaoN16PackingL11CapacityPhase = "begin-build"
	GaoN16PackingL11PhaseAuthorizeReady             GaoN16PackingL11CapacityPhase = "authorize-ready"
	GaoN16PackingL11PhaseInstall                    GaoN16PackingL11CapacityPhase = "install"
	GaoN16PackingL11PhasePreflight                  GaoN16PackingL11CapacityPhase = "preflight"
	GaoN16PackingL11PhaseA2BFirstRound              GaoN16PackingL11CapacityPhase = "a2b-first-round"
	GaoN16PackingL11PhaseA2BFull                    GaoN16PackingL11CapacityPhase = "a2b-full"
	GaoN16PackingL11PhaseSigned8RootTree            GaoN16PackingL11CapacityPhase = "signed8-root-tree"
	GaoN16PackingL11PhaseSigned8Depth2NodeBatch     GaoN16PackingL11CapacityPhase = "signed8-depth2-node-batch"
	GaoN16PackingL11PhaseSigned8Depth2SelectedChild GaoN16PackingL11CapacityPhase = "signed8-depth2-selected-child"
	GaoN16PackingL11PhaseSigned8Radix4Node          GaoN16PackingL11CapacityPhase = "signed8-radix4-node"
)

func validateGaoN16PackingL11CapacityPhase(phase GaoN16PackingL11CapacityPhase) error {
	switch phase {
	case GaoN16PackingL11PhaseBeginBuild, GaoN16PackingL11PhaseAuthorizeReady,
		GaoN16PackingL11PhaseInstall, GaoN16PackingL11PhasePreflight,
		GaoN16PackingL11PhaseA2BFirstRound, GaoN16PackingL11PhaseA2BFull,
		GaoN16PackingL11PhaseSigned8RootTree, GaoN16PackingL11PhaseSigned8Depth2NodeBatch,
		GaoN16PackingL11PhaseSigned8Depth2SelectedChild, GaoN16PackingL11PhaseSigned8Radix4Node:
		return nil
	default:
		return artifactCapacityBlocked("L11 runtime capacity phase is invalid", nil)
	}
}

// GaoN16PackingL11PhaseCapacityComponent is one immutable component of a
// phase-relative incremental peak. Source identifies the accepted combined
// plan field or named estimate from which Bytes was derived.
type GaoN16PackingL11PhaseCapacityComponent struct {
	name, source string
	bytes        uint64
}

func (c GaoN16PackingL11PhaseCapacityComponent) Name() string   { return c.name }
func (c GaoN16PackingL11PhaseCapacityComponent) Source() string { return c.source }
func (c GaoN16PackingL11PhaseCapacityComponent) Bytes() uint64  { return c.bytes }

// GaoN16PackingL11PhaseCapacityPlan binds one phase-relative incremental
// envelope to the unchanged combined-plan identity and 80% capacity policy.
type GaoN16PackingL11PhaseCapacityPlan struct {
	schema, adaptationLabel, evidenceScope               string
	maturity                                             Maturity
	sourceFaithful, fullPacked                           bool
	phase                                                GaoN16PackingL11CapacityPhase
	basePlanDigest, parameterDigest, profileDigest       string
	shapeDigest, policyDigest, digest                    string
	profile                                              GaoN16PackingL11Profile
	shape                                                GaoN16PackingL11CapacityShape
	policy                                               CapacityPolicy
	components                                           []GaoN16PackingL11PhaseCapacityComponent
	fullArtifactPeakBytes, projectedIncrementalPeakBytes uint64
}

func NewGaoN16PackingL11PhaseCapacityPlan(
	profile GaoN16PackingL11Profile,
	shape GaoN16PackingL11CapacityShape,
	policy CapacityPolicy,
	phase GaoN16PackingL11CapacityPhase,
) (GaoN16PackingL11PhaseCapacityPlan, error) {
	if err := validateGaoN16PackingL11CapacityPhase(phase); err != nil {
		return GaoN16PackingL11PhaseCapacityPlan{}, err
	}
	base, err := NewGaoN16PackingL11CapacityPlan(profile, shape, policy)
	if err != nil {
		return GaoN16PackingL11PhaseCapacityPlan{}, err
	}
	shape = cloneGaoN16PackingL11CapacityShape(shape)
	estimates := make(map[string]GaoN16PackingL11CapacityEstimate, len(base.estimates))
	for _, estimate := range base.estimates {
		if _, exists := estimates[estimate.name]; exists {
			return GaoN16PackingL11PhaseCapacityPlan{}, artifactCapacityBlocked("duplicate L11 capacity estimate name", nil)
		}
		estimates[estimate.name] = estimate
	}
	fromEstimate := func(name string) (GaoN16PackingL11PhaseCapacityComponent, error) {
		estimate, ok := estimates[name]
		if !ok || estimate.bytes == 0 || estimate.formula == "" {
			return GaoN16PackingL11PhaseCapacityComponent{}, artifactCapacityBlocked("missing L11 phase capacity component "+name, nil)
		}
		return GaoN16PackingL11PhaseCapacityComponent{name: name, source: estimate.formula, bytes: estimate.bytes}, nil
	}
	validationEnvelope := GaoN16PackingL11PhaseCapacityComponent{
		name:   "resident_validation_max_encoded_factor_envelope",
		source: "GaoN16PackingL11CapacityPlan.MaxEncodedFactorBytes",
		bytes:  base.maxEncodedFactorBytes,
	}
	componentNames := []string(nil)
	switch phase {
	case GaoN16PackingL11PhaseBeginBuild:
		componentNames = []string{"full_artifact_construction_peak"}
	case GaoN16PackingL11PhaseAuthorizeReady:
		componentNames = []string{"n_coefficient_scratch_bound"}
	case GaoN16PackingL11PhaseInstall:
		componentNames = []string{
			"dft_trace_conjugation_evaluation_keys_bound",
			"fixed_evaluation_keys_bound",
			"evaluator_fixed_buffers_bound",
			"max_factor_baby_step_prerotated_ciphertexts_bound",
			"n_coefficient_scratch_bound",
		}
	case GaoN16PackingL11PhasePreflight:
		componentNames = []string{
			"max_factor_baby_step_prerotated_ciphertexts_bound",
			"n_coefficient_scratch_bound",
		}
	case GaoN16PackingL11PhaseA2BFirstRound, GaoN16PackingL11PhaseA2BFull,
		GaoN16PackingL11PhaseSigned8RootTree, GaoN16PackingL11PhaseSigned8Depth2NodeBatch,
		GaoN16PackingL11PhaseSigned8Depth2SelectedChild, GaoN16PackingL11PhaseSigned8Radix4Node:
		componentNames = []string{
			"transform_specifications_bound",
			"compiled_transform_pair_bound",
			"q_only_masks_bound",
			"polynomial_operands_bound",
			"max_factor_baby_step_prerotated_ciphertexts_bound",
			"n_coefficient_scratch_bound",
		}
	}
	components := make([]GaoN16PackingL11PhaseCapacityComponent, 0, len(componentNames)+1)
	if phase != GaoN16PackingL11PhaseBeginBuild {
		components = append(components, validationEnvelope)
	}
	for _, name := range componentNames {
		component, componentErr := fromEstimate(name)
		if componentErr != nil {
			return GaoN16PackingL11PhaseCapacityPlan{}, componentErr
		}
		components = append(components, component)
	}
	if phase == GaoN16PackingL11PhaseA2BFull || phase == GaoN16PackingL11PhaseSigned8RootTree ||
		phase == GaoN16PackingL11PhaseSigned8Depth2NodeBatch ||
		phase == GaoN16PackingL11PhaseSigned8Depth2SelectedChild ||
		phase == GaoN16PackingL11PhaseSigned8Radix4Node {
		secondRoundComponents, componentErr := gaoN16PackingL11A2BFullComponents(shape)
		if componentErr != nil {
			return GaoN16PackingL11PhaseCapacityPlan{}, componentErr
		}
		components = append(components, secondRoundComponents...)
	}
	if phase == GaoN16PackingL11PhaseSigned8RootTree {
		treeComponents, componentErr := gaoN16PackingL11Signed8RootTreeComponents(shape)
		if componentErr != nil {
			return GaoN16PackingL11PhaseCapacityPlan{}, componentErr
		}
		components = append(components, treeComponents...)
	}
	if phase == GaoN16PackingL11PhaseSigned8Depth2NodeBatch || phase == GaoN16PackingL11PhaseSigned8Radix4Node {
		depth2Components, componentErr := gaoN16PackingL11Signed8Depth2NodeBatchComponents(shape)
		if componentErr != nil {
			return GaoN16PackingL11PhaseCapacityPlan{}, componentErr
		}
		components = append(components, depth2Components...)
	}
	if phase == GaoN16PackingL11PhaseSigned8Depth2SelectedChild {
		selectedChildComponents, componentErr := gaoN16PackingL11Signed8Depth2SelectedChildComponents(shape)
		if componentErr != nil {
			return GaoN16PackingL11PhaseCapacityPlan{}, componentErr
		}
		components = append(components, selectedChildComponents...)
	}
	requirement := uint64(0)
	for _, component := range components {
		var sumErr error
		requirement, sumErr = checkedUint64Sum(requirement, component.bytes)
		if sumErr != nil {
			return GaoN16PackingL11PhaseCapacityPlan{}, artifactCapacityBlocked("L11 phase capacity requirement overflow", sumErr)
		}
	}
	plan := GaoN16PackingL11PhaseCapacityPlan{
		schema: gaoN16PackingL11PhasePlanSchema, adaptationLabel: base.adaptationLabel,
		evidenceScope: gaoN16PackingL11PhaseEvidenceScope, maturity: ArtifactCapacityOnlyUnverified,
		sourceFaithful: false, fullPacked: false, phase: phase,
		basePlanDigest: base.digest, parameterDigest: base.parameterDigest, profileDigest: base.profileDigest,
		shapeDigest: base.shapeDigest, policyDigest: base.policyDigest,
		profile: profile, shape: shape, policy: policy,
		components:            append([]GaoN16PackingL11PhaseCapacityComponent(nil), components...),
		fullArtifactPeakBytes: base.fullArtifactPeakBytes, projectedIncrementalPeakBytes: requirement,
	}
	plan.digest, err = digestGaoN16PackingL11PhasePlan(plan)
	if err != nil {
		return GaoN16PackingL11PhaseCapacityPlan{}, err
	}
	return plan, nil
}

// gaoN16PackingL11Signed8Depth2NodeBatchComponents accounts only for the
// public-model depth-2 wrapper around the separately charged complete A2B.
func gaoN16PackingL11Signed8Depth2NodeBatchComponents(shape GaoN16PackingL11CapacityShape) ([]GaoN16PackingL11PhaseCapacityComponent, error) {
	component := func(name, source string, factors ...uint64) (GaoN16PackingL11PhaseCapacityComponent, error) {
		value, err := checkedUint64Product(factors...)
		if err != nil {
			return GaoN16PackingL11PhaseCapacityComponent{}, artifactCapacityBlocked("L11 "+name+" overflow", err)
		}
		return GaoN16PackingL11PhaseCapacityComponent{name: name, source: source, bytes: value}, nil
	}
	definitions := []struct {
		name, source string
		factors      []uint64
	}{
		{"signed8_depth2_threshold_plaintext_bound", "RingDegree * CoefficientBytes * ((LevelQ=20)+1)", []uint64{shape.ringDegree, shape.coefficientBytes, 21}},
		{"signed8_depth2_threshold_numeric_bound", "Slots * ComplexEntryBoundBytes", []uint64{shape.slots, shape.complexEntryBoundBytes}},
		{"signed8_depth2_broadcast_encoded_bound", "4 * RingDegree * CoefficientBytes * (((LevelQ=4)+1)+((LevelP=6)+1))", []uint64{4, shape.ringDegree, shape.coefficientBytes, 12}},
		{"signed8_depth2_broadcast_numeric_bound", "4 * Slots * ComplexEntryBoundBytes", []uint64{4, shape.slots, shape.complexEntryBoundBytes}},
		{"signed8_depth2_global_one_plaintext_bound", "RingDegree * CoefficientBytes * ((LevelQ=3)+1)", []uint64{shape.ringDegree, shape.coefficientBytes, 4}},
		{"signed8_depth2_root_one_plaintext_bound", "RingDegree * CoefficientBytes * ((LevelQ=2)+1)", []uint64{shape.ringDegree, shape.coefficientBytes, 3}},
		{"signed8_depth2_role_masks_plaintext_bound", "3 * RingDegree * CoefficientBytes * ((LevelQ=3)+1)", []uint64{3, shape.ringDegree, shape.coefficientBytes, 4}},
		{"signed8_depth2_leaf_deltas_plaintext_bound", "3 * RingDegree * CoefficientBytes * ((LevelQ=1)+1)", []uint64{3, shape.ringDegree, shape.coefficientBytes, 2}},
		{"signed8_depth2_base_leaf_plaintext_bound", "RingDegree * CoefficientBytes * ((LevelQ=0)+1)", []uint64{shape.ringDegree, shape.coefficientBytes, 1}},
		{"signed8_depth2_retained_ciphertexts_bound", "16 * CiphertextComponents * RingDegree * CoefficientBytes * ((LevelQ=4)+1)", []uint64{16, shape.ciphertextComponents, shape.ringDegree, shape.coefficientBytes, 5}},
	}
	result := make([]GaoN16PackingL11PhaseCapacityComponent, len(definitions))
	for index, definition := range definitions {
		value, err := component(definition.name, definition.source, definition.factors...)
		if err != nil {
			return nil, err
		}
		result[index] = value
	}
	return result, nil
}

// gaoN16PackingL11Signed8Depth2SelectedChildComponents accounts for the
// feature-vector copies, phase selector, low-ingress A2Sign adapter and
// bilinear leaf mux added around the separately charged complete A2B spine.
func gaoN16PackingL11Signed8Depth2SelectedChildComponents(shape GaoN16PackingL11CapacityShape) ([]GaoN16PackingL11PhaseCapacityComponent, error) {
	component := func(name, source string, factors ...uint64) (GaoN16PackingL11PhaseCapacityComponent, error) {
		value, err := checkedUint64Product(factors...)
		if err != nil {
			return GaoN16PackingL11PhaseCapacityComponent{}, artifactCapacityBlocked("L11 "+name+" overflow", err)
		}
		return GaoN16PackingL11PhaseCapacityComponent{name: name, source: source, bytes: value}, nil
	}
	definitions := []struct {
		name, source string
		factors      []uint64
	}{
		{"selected_child_feature_vector_bound", "3 * CiphertextComponents * RingDegree * CoefficientBytes * ((LevelQ=20)+1)", []uint64{3, shape.ciphertextComponents, shape.ringDegree, shape.coefficientBytes, 21}},
		{"selected_child_root_threshold_plaintext_bound", "RingDegree * CoefficientBytes * ((LevelQ=20)+1)", []uint64{shape.ringDegree, shape.coefficientBytes, 21}},
		{"selected_child_phase_broadcast_encoded_bound", "4 * RingDegree * CoefficientBytes * (((LevelQ=4)+1)+((LevelP=6)+1))", []uint64{4, shape.ringDegree, shape.coefficientBytes, 12}},
		{"selected_child_phase_broadcast_numeric_bound", "4 * Slots * ComplexEntryBoundBytes", []uint64{4, shape.slots, shape.complexEntryBoundBytes}},
		{"selected_child_periodic_affine_plaintexts_bound", "RingDegree * CoefficientBytes * (((LevelQ=9)+1)+((LevelQ=8)+1))", []uint64{shape.ringDegree, shape.coefficientBytes, 19}},
		{"selected_child_conditioner_plaintext_bound", "RingDegree * CoefficientBytes * (((LevelQ=8)+1)+((LevelQ=7)+1))", []uint64{shape.ringDegree, shape.coefficientBytes, 17}},
		{"selected_child_threshold_plaintexts_bound", "RingDegree * CoefficientBytes * (((LevelQ=7)+1)+((LevelQ=6)+1))", []uint64{shape.ringDegree, shape.coefficientBytes, 15}},
		{"selected_child_low_special_b0_encoded_bound", "8 * RingDegree * CoefficientBytes * (((LevelQ=5)+1)+((LevelP=6)+1))", []uint64{8, shape.ringDegree, shape.coefficientBytes, 13}},
		{"selected_child_low_mask_plaintext_bound", "RingDegree * CoefficientBytes * ((LevelQ=4)+1)", []uint64{shape.ringDegree, shape.coefficientBytes, 5}},
		{"selected_child_terminal_plaintexts_bound", "RingDegree * CoefficientBytes * (3*((LevelQ=3)+1)+((LevelQ=1)+1))", []uint64{shape.ringDegree, shape.coefficientBytes, 14}},
		{"selected_child_retained_ciphertexts_bound", "20 * CiphertextComponents * RingDegree * CoefficientBytes * ((LevelQ=8)+1)", []uint64{20, shape.ciphertextComponents, shape.ringDegree, shape.coefficientBytes, 9}},
	}
	result := make([]GaoN16PackingL11PhaseCapacityComponent, len(definitions))
	for index, definition := range definitions {
		value, err := component(definition.name, definition.source, definition.factors...)
		if err != nil {
			return nil, err
		}
		result[index] = value
	}
	return result, nil
}

// gaoN16PackingL11Signed8RootTreeComponents accounts for the objects added by
// the public-threshold signed-int8 root comparator, direct Boolean-column
// broadcast, and real-leaf selection. The complete A2B components are added
// separately above and are not repeated here.
func gaoN16PackingL11Signed8RootTreeComponents(shape GaoN16PackingL11CapacityShape) ([]GaoN16PackingL11PhaseCapacityComponent, error) {
	thresholdPlaintext, err := checkedUint64Product(shape.ringDegree, shape.coefficientBytes, 20+1)
	if err != nil {
		return nil, artifactCapacityBlocked("L11 signed8 root threshold plaintext bound overflow", err)
	}
	thresholdNumeric, err := checkedUint64Product(shape.slots, shape.complexEntryBoundBytes)
	if err != nil {
		return nil, artifactCapacityBlocked("L11 signed8 root threshold numeric bound overflow", err)
	}
	broadcastEncoded, err := checkedUint64Product(4, shape.ringDegree, shape.coefficientBytes, (4+1)+(6+1))
	if err != nil {
		return nil, artifactCapacityBlocked("L11 signed8 root broadcast encoded bound overflow", err)
	}
	broadcastNumeric, err := checkedUint64Product(4, shape.slots, shape.complexEntryBoundBytes)
	if err != nil {
		return nil, artifactCapacityBlocked("L11 signed8 root broadcast numeric bound overflow", err)
	}
	scalarOne, err := checkedUint64Product(shape.ringDegree, shape.coefficientBytes, 3+1)
	if err != nil {
		return nil, artifactCapacityBlocked("L11 signed8 root scalar-one plaintext bound overflow", err)
	}
	leafDelta, err := checkedUint64Product(shape.ringDegree, shape.coefficientBytes, 3+1)
	if err != nil {
		return nil, artifactCapacityBlocked("L11 signed8 root leaf-delta plaintext bound overflow", err)
	}
	leftLeaf, err := checkedUint64Product(shape.ringDegree, shape.coefficientBytes, 2+1)
	if err != nil {
		return nil, artifactCapacityBlocked("L11 signed8 root left-leaf plaintext bound overflow", err)
	}
	retained, err := checkedUint64Product(5, shape.ciphertextComponents, shape.ringDegree, shape.coefficientBytes, 4+1)
	if err != nil {
		return nil, artifactCapacityBlocked("L11 signed8 root retained-ciphertext bound overflow", err)
	}
	return []GaoN16PackingL11PhaseCapacityComponent{
		{
			name:   "signed8_root_threshold_plaintext_bound",
			source: "RingDegree * CoefficientBytes * ((LevelQ=20)+1)",
			bytes:  thresholdPlaintext,
		},
		{
			name:   "signed8_root_threshold_numeric_bound",
			source: "Slots * ComplexEntryBoundBytes",
			bytes:  thresholdNumeric,
		},
		{
			name:   "signed8_root_broadcast_encoded_bound",
			source: "4 * RingDegree * CoefficientBytes * (((LevelQ=4)+1)+((LevelP=6)+1))",
			bytes:  broadcastEncoded,
		},
		{
			name:   "signed8_root_broadcast_numeric_bound",
			source: "4 * Slots * ComplexEntryBoundBytes",
			bytes:  broadcastNumeric,
		},
		{
			name:   "signed8_root_scalar_one_plaintext_bound",
			source: "RingDegree * CoefficientBytes * ((LevelQ=3)+1)",
			bytes:  scalarOne,
		},
		{
			name:   "signed8_root_leaf_delta_plaintext_bound",
			source: "RingDegree * CoefficientBytes * ((LevelQ=3)+1)",
			bytes:  leafDelta,
		},
		{
			name:   "signed8_root_left_leaf_plaintext_bound",
			source: "RingDegree * CoefficientBytes * ((LevelQ=2)+1)",
			bytes:  leftLeaf,
		},
		{
			name:   "signed8_root_retained_ciphertexts_bound",
			source: "5 * CiphertextComponents * RingDegree * CoefficientBytes * ((LevelQ=4)+1)",
			bytes:  retained,
		},
	}, nil
}

// gaoN16PackingL11A2BFullComponents accounts only for the live objects added
// by the second nibble round. The installed L18->L16 STC is immutable and is
// therefore not relabelled as the required L3->L1 transform.
func gaoN16PackingL11A2BFullComponents(shape GaoN16PackingL11CapacityShape) ([]GaoN16PackingL11PhaseCapacityComponent, error) {
	secondSTCDiagonals, err := checkedUint64Sum(shape.stcFactorDiagonalCounts...)
	if err != nil {
		return nil, artifactCapacityBlocked("L11 full A2B second STC diagonal count overflow", err)
	}
	secondSTCLimbs, err := checkedUint64Sum(3+1, uint64(shape.stcLevelP+1))
	if err != nil {
		return nil, artifactCapacityBlocked("L11 full A2B second STC limb count overflow", err)
	}
	secondSTCEncoded, err := checkedUint64Product(secondSTCDiagonals, shape.ringDegree, shape.coefficientBytes, secondSTCLimbs)
	if err != nil {
		return nil, artifactCapacityBlocked("L11 full A2B second STC encoded bound overflow", err)
	}
	secondSTCNumeric, err := checkedUint64Product(secondSTCDiagonals, shape.slots, shape.complexEntryBoundBytes)
	if err != nil {
		return nil, artifactCapacityBlocked("L11 full A2B second STC numeric bound overflow", err)
	}
	secondSTCText, err := checkedUint64Product(secondSTCDiagonals, shape.slots, shape.textComplexBoundBytes, shape.textCopies)
	if err != nil {
		return nil, artifactCapacityBlocked("L11 full A2B second STC digest-text bound overflow", err)
	}
	idScalePlaintext, err := checkedUint64Product(shape.ringDegree, shape.coefficientBytes, 5+1)
	if err != nil {
		return nil, artifactCapacityBlocked("L11 full A2B ID-scale plaintext bound overflow", err)
	}
	retainedCiphertexts, err := checkedUint64Product(12, shape.ciphertextComponents, shape.ringDegree, shape.coefficientBytes, 19+1)
	if err != nil {
		return nil, artifactCapacityBlocked("L11 full A2B retained-ciphertext bound overflow", err)
	}
	return []GaoN16PackingL11PhaseCapacityComponent{
		{
			name:   "second_stc_l3_p6_encoded_resident_bound",
			source: "sum(STCFactorDiagonalCounts) * RingDegree * CoefficientBytes * ((LevelQ=3)+1+(LevelP=6)+1)",
			bytes:  secondSTCEncoded,
		},
		{
			name:   "second_stc_high_precision_numeric_bound",
			source: "sum(STCFactorDiagonalCounts) * Slots * ComplexEntryBoundBytes",
			bytes:  secondSTCNumeric,
		},
		{
			name:   "second_stc_digest_text_bound",
			source: "sum(STCFactorDiagonalCounts) * Slots * TextComplexBoundBytes * TextCopies",
			bytes:  secondSTCText,
		},
		{
			name:   "serial_id_scale_plaintext_bound",
			source: "RingDegree * CoefficientBytes * ((LevelQ=5)+1)",
			bytes:  idScalePlaintext,
		},
		{
			name:   "serial_retained_ciphertexts_bound",
			source: "12 * CiphertextComponents * RingDegree * CoefficientBytes * ((LevelQ=19)+1)",
			bytes:  retainedCiphertexts,
		},
	}, nil
}

func (p GaoN16PackingL11PhaseCapacityPlan) SchemaVersion() string   { return p.schema }
func (p GaoN16PackingL11PhaseCapacityPlan) Maturity() Maturity      { return p.maturity }
func (p GaoN16PackingL11PhaseCapacityPlan) AdaptationLabel() string { return p.adaptationLabel }
func (p GaoN16PackingL11PhaseCapacityPlan) EvidenceScope() string   { return p.evidenceScope }
func (p GaoN16PackingL11PhaseCapacityPlan) IsSourceFaithful() bool  { return p.sourceFaithful }
func (p GaoN16PackingL11PhaseCapacityPlan) IsFullPacked() bool      { return p.fullPacked }
func (p GaoN16PackingL11PhaseCapacityPlan) Phase() GaoN16PackingL11CapacityPhase {
	return p.phase
}
func (p GaoN16PackingL11PhaseCapacityPlan) BasePlanDigest() string  { return p.basePlanDigest }
func (p GaoN16PackingL11PhaseCapacityPlan) ParameterDigest() string { return p.parameterDigest }
func (p GaoN16PackingL11PhaseCapacityPlan) ProfileDigest() string   { return p.profileDigest }
func (p GaoN16PackingL11PhaseCapacityPlan) ShapeDigest() string     { return p.shapeDigest }
func (p GaoN16PackingL11PhaseCapacityPlan) PolicyDigest() string    { return p.policyDigest }
func (p GaoN16PackingL11PhaseCapacityPlan) Digest() string          { return p.digest }
func (p GaoN16PackingL11PhaseCapacityPlan) FullArtifactPeakBytes() uint64 {
	return p.fullArtifactPeakBytes
}
func (p GaoN16PackingL11PhaseCapacityPlan) ProjectedIncrementalPeakBytes() uint64 {
	return p.projectedIncrementalPeakBytes
}
func (p GaoN16PackingL11PhaseCapacityPlan) Components() []GaoN16PackingL11PhaseCapacityComponent {
	return append([]GaoN16PackingL11PhaseCapacityComponent(nil), p.components...)
}

type gaoN16PackingL11PhaseComponentDigestRecord struct {
	Name, Source string
	Bytes        uint64
}

type gaoN16PackingL11PhasePlanDigestRecord struct {
	SchemaVersion, AdaptationLabel, EvidenceScope               string
	Maturity                                                    Maturity
	SourceFaithful, FullPacked                                  bool
	Phase                                                       GaoN16PackingL11CapacityPhase
	BasePlanDigest, ParameterDigest, ProfileDigest, ShapeDigest string
	PolicyDigest                                                string
	Components                                                  []gaoN16PackingL11PhaseComponentDigestRecord
	FullArtifactPeakBytes, ProjectedIncrementalPeakBytes        uint64
}

func digestGaoN16PackingL11PhasePlan(plan GaoN16PackingL11PhaseCapacityPlan) (string, error) {
	components := make([]gaoN16PackingL11PhaseComponentDigestRecord, len(plan.components))
	for index, component := range plan.components {
		components[index] = gaoN16PackingL11PhaseComponentDigestRecord{
			Name: component.name, Source: component.source, Bytes: component.bytes,
		}
	}
	return digestCapacityRecord(gaoN16PackingL11PhasePlanDigestRecord{
		SchemaVersion: plan.schema, AdaptationLabel: plan.adaptationLabel, EvidenceScope: plan.evidenceScope,
		Maturity: plan.maturity, SourceFaithful: plan.sourceFaithful, FullPacked: plan.fullPacked,
		Phase: plan.phase, BasePlanDigest: plan.basePlanDigest, ParameterDigest: plan.parameterDigest,
		ProfileDigest: plan.profileDigest, ShapeDigest: plan.shapeDigest, PolicyDigest: plan.policyDigest,
		Components: components, FullArtifactPeakBytes: plan.fullArtifactPeakBytes,
		ProjectedIncrementalPeakBytes: plan.projectedIncrementalPeakBytes,
	}, "Gao N16 packing L11 phase capacity plan")
}

func equalGaoN16PackingL11PhaseComponents(a, b []GaoN16PackingL11PhaseCapacityComponent) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

func (p GaoN16PackingL11PhaseCapacityPlan) validate() error {
	if err := validateGaoN16PackingL11CapacityPhase(p.phase); err != nil {
		return err
	}
	if err := validateGaoN16PackingL11Profile(p.profile); err != nil {
		return err
	}
	if err := validateGaoN16PackingL11ShapeSeal(p.shape); err != nil {
		return err
	}
	if err := validateArtifactCapacityPolicy(p.policy); err != nil {
		return err
	}
	expected, err := NewGaoN16PackingL11PhaseCapacityPlan(p.profile, p.shape, p.policy, p.phase)
	if err != nil {
		return err
	}
	digest, err := digestGaoN16PackingL11PhasePlan(p)
	if err != nil {
		return err
	}
	if p.digest == "" || p.digest != digest || p.digest != expected.digest ||
		p.schema != expected.schema || p.adaptationLabel != expected.adaptationLabel ||
		p.evidenceScope != expected.evidenceScope || p.maturity != expected.maturity ||
		p.sourceFaithful || p.fullPacked || p.basePlanDigest != expected.basePlanDigest ||
		p.parameterDigest != expected.parameterDigest || p.profileDigest != expected.profileDigest ||
		p.shapeDigest != expected.shapeDigest || p.policyDigest != expected.policyDigest ||
		p.fullArtifactPeakBytes != expected.fullArtifactPeakBytes ||
		p.projectedIncrementalPeakBytes != expected.projectedIncrementalPeakBytes ||
		!equalGaoN16PackingL11PhaseComponents(p.components, expected.components) {
		return artifactCapacityBlocked("L11 phase capacity plan drifted or was promoted", nil)
	}
	return nil
}

func (p GaoN16PackingL11PhaseCapacityPlan) Evaluate(snapshot PhysicalMemorySnapshot) (GaoN16PackingL11CapacityReport, GaoN16PackingL11CapacityPermit, error) {
	report, err := p.evaluateReport(snapshot)
	if err != nil {
		return report, GaoN16PackingL11CapacityPermit{}, err
	}
	permit := GaoN16PackingL11CapacityPermit{
		schema: gaoN16PackingL11PhasePermitSchema, adaptationLabel: report.adaptationLabel,
		evidenceScope: report.evidenceScope, maturity: report.maturity, decision: report.decision,
		sourceFaithful: false, fullPacked: false,
		planDigest: report.planDigest, parameterDigest: report.parameterDigest,
		profileDigest: report.profileDigest, shapeDigest: report.shapeDigest,
		policyDigest: report.policyDigest, probeDigest: report.probeDigest, reportDigest: report.digest,
	}
	permit.sealDigest, err = digestGaoN16PackingL11Permit(permit)
	if err != nil {
		return GaoN16PackingL11CapacityReport{}, GaoN16PackingL11CapacityPermit{}, err
	}
	return report, permit, nil
}

func (p GaoN16PackingL11PhaseCapacityPlan) evaluateReport(snapshot PhysicalMemorySnapshot) (GaoN16PackingL11CapacityReport, error) {
	if err := p.validate(); err != nil {
		return GaoN16PackingL11CapacityReport{}, err
	}
	if err := validatePhysicalMemorySnapshot(snapshot); err != nil {
		return GaoN16PackingL11CapacityReport{}, err
	}
	probe, err := digestGaoN16PackingL11PhaseProbe(p, snapshot)
	if err != nil {
		return GaoN16PackingL11CapacityReport{}, err
	}
	currentUsed := snapshot.TotalPhysicalBytes - snapshot.AvailablePhysicalBytes
	limitProduct, err := checkedUint64Product(snapshot.TotalPhysicalBytes, p.policy.limitNumerator)
	if err != nil {
		return GaoN16PackingL11CapacityReport{}, artifactCapacityBlocked("L11 phase capacity limit overflow", err)
	}
	limit := limitProduct / p.policy.limitDenominator
	guardProduct, err := checkedUint64Product(p.projectedIncrementalPeakBytes, p.policy.relativeGuardNumerator)
	if err != nil {
		return GaoN16PackingL11CapacityReport{}, artifactCapacityBlocked("L11 phase relative guard overflow", err)
	}
	guard := guardProduct / p.policy.relativeGuardDenominator
	if guard < p.policy.minimumGuardBytes {
		guard = p.policy.minimumGuardBytes
	}
	guarded, err := checkedUint64Sum(p.projectedIncrementalPeakBytes, guard)
	if err != nil {
		return GaoN16PackingL11CapacityReport{}, artifactCapacityBlocked("L11 phase guarded requirement overflow", err)
	}
	projected, err := checkedUint64Sum(currentUsed, guarded)
	if err != nil {
		return GaoN16PackingL11CapacityReport{}, artifactCapacityBlocked("L11 phase projected system use overflow", err)
	}
	decision := Admitted
	remaining := uint64(0)
	if projected >= limit {
		decision = ResourceBlocked
	} else {
		remaining = limit - projected
	}
	report := GaoN16PackingL11CapacityReport{
		schema: gaoN16PackingL11PhaseReportSchema, adaptationLabel: p.adaptationLabel,
		evidenceScope: p.evidenceScope, maturity: ArtifactCapacityOnlyUnverified, decision: decision,
		sourceFaithful: false, fullPacked: false,
		planDigest: p.digest, parameterDigest: p.parameterDigest, profileDigest: p.profileDigest,
		shapeDigest: p.shapeDigest, policyDigest: p.policyDigest, probeDigest: probe, snapshot: snapshot,
		currentSystemUsedBytes: currentUsed, capacityLimitBytes: limit,
		projectedIncrementalPeakBytes: p.projectedIncrementalPeakBytes, guardBytes: guard,
		guardedRequirementBytes: guarded, projectedSystemUsedBytes: projected, remainingBytes: remaining,
	}
	report.digest, err = digestGaoN16PackingL11Report(report)
	if err != nil {
		return GaoN16PackingL11CapacityReport{}, err
	}
	if decision == ResourceBlocked {
		return report, artifactCapacityBlocked("L11 phase projected use is at or over the strict 80% boundary", nil)
	}
	return report, nil
}

func (p GaoN16PackingL11PhaseCapacityPlan) ValidateReport(snapshot PhysicalMemorySnapshot, report GaoN16PackingL11CapacityReport) error {
	expected, evaluationErr := p.evaluateReport(snapshot)
	if report != expected || report.digest == "" {
		return artifactCapacityBlocked("L11 phase capacity report is zero, stale, foreign, tampered, or promoted", nil)
	}
	digest, err := digestGaoN16PackingL11Report(report)
	if err != nil {
		return err
	}
	if digest != report.digest {
		return artifactCapacityBlocked("L11 phase capacity report seal changed", nil)
	}
	if evaluationErr != nil {
		var blocked *ErrArtifactCapacityBlocked
		if !errors.As(evaluationErr, &blocked) {
			return evaluationErr
		}
	}
	return nil
}

func (p GaoN16PackingL11PhaseCapacityPlan) ValidatePermit(snapshot PhysicalMemorySnapshot, permit GaoN16PackingL11CapacityPermit) error {
	report, err := p.evaluateReport(snapshot)
	if err != nil {
		return err
	}
	if report.decision != Admitted {
		return artifactCapacityBlocked("L11 phase capacity report is not admitted", nil)
	}
	expected := GaoN16PackingL11CapacityPermit{
		schema: gaoN16PackingL11PhasePermitSchema, adaptationLabel: report.adaptationLabel,
		evidenceScope: report.evidenceScope, maturity: report.maturity, decision: report.decision,
		sourceFaithful: false, fullPacked: false,
		planDigest: report.planDigest, parameterDigest: report.parameterDigest,
		profileDigest: report.profileDigest, shapeDigest: report.shapeDigest,
		policyDigest: report.policyDigest, probeDigest: report.probeDigest, reportDigest: report.digest,
	}
	expected.sealDigest, err = digestGaoN16PackingL11Permit(expected)
	if err != nil {
		return err
	}
	if permit != expected || !isArtifactCapacityDigest(permit.reportDigest) || !isArtifactCapacityDigest(permit.sealDigest) {
		return artifactCapacityBlocked("L11 phase capacity permit is zero, blocked, stale, foreign, tampered, or promoted", nil)
	}
	return nil
}

type gaoN16PackingL11PhaseProbeDigestRecord struct {
	SchemaVersion, AdaptationLabel, EvidenceScope, PlanDigest, PolicyDigest string
	Phase                                                                   GaoN16PackingL11CapacityPhase
	SnapshotID                                                              string
	TotalPhysicalBytes, AvailablePhysicalBytes                              uint64
}

func digestGaoN16PackingL11PhaseProbe(plan GaoN16PackingL11PhaseCapacityPlan, snapshot PhysicalMemorySnapshot) (string, error) {
	return digestCapacityRecord(gaoN16PackingL11PhaseProbeDigestRecord{
		SchemaVersion: plan.schema, AdaptationLabel: plan.adaptationLabel, EvidenceScope: plan.evidenceScope,
		PlanDigest: plan.digest, PolicyDigest: plan.policyDigest, Phase: plan.phase,
		SnapshotID: snapshot.SnapshotID, TotalPhysicalBytes: snapshot.TotalPhysicalBytes,
		AvailablePhysicalBytes: snapshot.AvailablePhysicalBytes,
	}, "Gao N16 packing L11 phase capacity probe")
}
