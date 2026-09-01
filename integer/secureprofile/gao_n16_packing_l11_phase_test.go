package secureprofile

import (
	"errors"
	"reflect"
	"testing"
)

func TestGaoN16PackingL11PhaseCapacityPlansSealExactIncrementalEnvelopes(t *testing.T) {
	profile, err := NewGaoN16PackingL11Profile()
	if err != nil {
		t.Fatal(err)
	}
	shape := DefaultGaoN16PackingL11CapacityShape()
	policy := DefaultArtifactCapacityPolicy()
	base, err := NewGaoN16PackingL11CapacityPlan(profile, shape, policy)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		phase       GaoN16PackingL11CapacityPhase
		requirement uint64
		guarded     uint64
		components  []string
	}{
		{
			phase: GaoN16PackingL11PhaseBeginBuild, requirement: 2_968_063_744, guarded: 3_504_934_656,
			components: []string{"full_artifact_construction_peak"},
		},
		{
			phase: GaoN16PackingL11PhaseAuthorizeReady, requirement: 872_939_520, guarded: 1_409_810_432,
			components: []string{"resident_validation_max_encoded_factor_envelope", "n_coefficient_scratch_bound"},
		},
		{
			phase: GaoN16PackingL11PhaseInstall, requirement: 5_034_213_376, guarded: 5_571_084_288,
			components: []string{
				"resident_validation_max_encoded_factor_envelope",
				"dft_trace_conjugation_evaluation_keys_bound",
				"fixed_evaluation_keys_bound",
				"evaluator_fixed_buffers_bound",
				"max_factor_baby_step_prerotated_ciphertexts_bound",
				"n_coefficient_scratch_bound",
			},
		},
		{
			phase: GaoN16PackingL11PhasePreflight, requirement: 981_991_424, guarded: 1_518_862_336,
			components: []string{
				"resident_validation_max_encoded_factor_envelope",
				"max_factor_baby_step_prerotated_ciphertexts_bound",
				"n_coefficient_scratch_bound",
			},
		},
		{
			phase: GaoN16PackingL11PhaseA2BFirstRound, requirement: 1_227_427_584, guarded: 1_764_298_496,
			components: []string{
				"resident_validation_max_encoded_factor_envelope",
				"transform_specifications_bound",
				"compiled_transform_pair_bound",
				"q_only_masks_bound",
				"polynomial_operands_bound",
				"max_factor_baby_step_prerotated_ciphertexts_bound",
				"n_coefficient_scratch_bound",
			},
		},
		{
			phase: GaoN16PackingL11PhaseA2BFull, requirement: 2_381_123_328, guarded: 2_917_994_240,
			components: []string{
				"resident_validation_max_encoded_factor_envelope",
				"transform_specifications_bound",
				"compiled_transform_pair_bound",
				"q_only_masks_bound",
				"polynomial_operands_bound",
				"max_factor_baby_step_prerotated_ciphertexts_bound",
				"n_coefficient_scratch_bound",
				"second_stc_l3_p6_encoded_resident_bound",
				"second_stc_high_precision_numeric_bound",
				"second_stc_digest_text_bound",
				"serial_id_scale_plaintext_bound",
				"serial_retained_ciphertexts_bound",
			},
		},
		{
			phase: GaoN16PackingL11PhaseSigned8RootTree, requirement: 2_451_902_208, guarded: 2_988_773_120,
			components: []string{
				"resident_validation_max_encoded_factor_envelope",
				"transform_specifications_bound",
				"compiled_transform_pair_bound",
				"q_only_masks_bound",
				"polynomial_operands_bound",
				"max_factor_baby_step_prerotated_ciphertexts_bound",
				"n_coefficient_scratch_bound",
				"second_stc_l3_p6_encoded_resident_bound",
				"second_stc_high_precision_numeric_bound",
				"second_stc_digest_text_bound",
				"serial_id_scale_plaintext_bound",
				"serial_retained_ciphertexts_bound",
				"signed8_root_threshold_plaintext_bound",
				"signed8_root_threshold_numeric_bound",
				"signed8_root_broadcast_encoded_bound",
				"signed8_root_broadcast_numeric_bound",
				"signed8_root_scalar_one_plaintext_bound",
				"signed8_root_leaf_delta_plaintext_bound",
				"signed8_root_left_leaf_plaintext_bound",
				"signed8_root_retained_ciphertexts_bound",
			},
		},
		{
			phase: GaoN16PackingL11PhaseSigned8Depth2NodeBatch, requirement: 2_517_438_208, guarded: 3_054_309_120,
			components: []string{
				"resident_validation_max_encoded_factor_envelope",
				"transform_specifications_bound",
				"compiled_transform_pair_bound",
				"q_only_masks_bound",
				"polynomial_operands_bound",
				"max_factor_baby_step_prerotated_ciphertexts_bound",
				"n_coefficient_scratch_bound",
				"second_stc_l3_p6_encoded_resident_bound",
				"second_stc_high_precision_numeric_bound",
				"second_stc_digest_text_bound",
				"serial_id_scale_plaintext_bound",
				"serial_retained_ciphertexts_bound",
				"signed8_depth2_threshold_plaintext_bound",
				"signed8_depth2_threshold_numeric_bound",
				"signed8_depth2_broadcast_encoded_bound",
				"signed8_depth2_broadcast_numeric_bound",
				"signed8_depth2_global_one_plaintext_bound",
				"signed8_depth2_root_one_plaintext_bound",
				"signed8_depth2_role_masks_plaintext_bound",
				"signed8_depth2_leaf_deltas_plaintext_bound",
				"signed8_depth2_base_leaf_plaintext_bound",
				"signed8_depth2_retained_ciphertexts_bound",
			},
		},
		{
			phase: GaoN16PackingL11PhaseSigned8Depth2SelectedChild, requirement: 2_765_426_432, guarded: 3_302_297_344,
			components: []string{
				"resident_validation_max_encoded_factor_envelope",
				"transform_specifications_bound",
				"compiled_transform_pair_bound",
				"q_only_masks_bound",
				"polynomial_operands_bound",
				"max_factor_baby_step_prerotated_ciphertexts_bound",
				"n_coefficient_scratch_bound",
				"second_stc_l3_p6_encoded_resident_bound",
				"second_stc_high_precision_numeric_bound",
				"second_stc_digest_text_bound",
				"serial_id_scale_plaintext_bound",
				"serial_retained_ciphertexts_bound",
				"selected_child_feature_vector_bound",
				"selected_child_root_threshold_plaintext_bound",
				"selected_child_phase_broadcast_encoded_bound",
				"selected_child_phase_broadcast_numeric_bound",
				"selected_child_periodic_affine_plaintexts_bound",
				"selected_child_conditioner_plaintext_bound",
				"selected_child_threshold_plaintexts_bound",
				"selected_child_low_special_b0_encoded_bound",
				"selected_child_low_mask_plaintext_bound",
				"selected_child_terminal_plaintexts_bound",
				"selected_child_retained_ciphertexts_bound",
			},
		},
		{
			phase: GaoN16PackingL11PhaseSigned8Radix4Node, requirement: 2_517_438_208, guarded: 3_054_309_120,
			components: []string{
				"resident_validation_max_encoded_factor_envelope",
				"transform_specifications_bound",
				"compiled_transform_pair_bound",
				"q_only_masks_bound",
				"polynomial_operands_bound",
				"max_factor_baby_step_prerotated_ciphertexts_bound",
				"n_coefficient_scratch_bound",
				"second_stc_l3_p6_encoded_resident_bound",
				"second_stc_high_precision_numeric_bound",
				"second_stc_digest_text_bound",
				"serial_id_scale_plaintext_bound",
				"serial_retained_ciphertexts_bound",
				"signed8_depth2_threshold_plaintext_bound",
				"signed8_depth2_threshold_numeric_bound",
				"signed8_depth2_broadcast_encoded_bound",
				"signed8_depth2_broadcast_numeric_bound",
				"signed8_depth2_global_one_plaintext_bound",
				"signed8_depth2_root_one_plaintext_bound",
				"signed8_depth2_role_masks_plaintext_bound",
				"signed8_depth2_leaf_deltas_plaintext_bound",
				"signed8_depth2_base_leaf_plaintext_bound",
				"signed8_depth2_retained_ciphertexts_bound",
			},
		},
	}
	for _, test := range tests {
		t.Run(string(test.phase), func(t *testing.T) {
			plan, planErr := NewGaoN16PackingL11PhaseCapacityPlan(profile, shape, policy, test.phase)
			if planErr != nil {
				t.Fatal(planErr)
			}
			if plan.Phase() != test.phase || plan.BasePlanDigest() != base.Digest() ||
				plan.ParameterDigest() != base.ParameterDigest() || plan.ProfileDigest() != base.ProfileDigest() ||
				plan.ShapeDigest() != base.ShapeDigest() || plan.PolicyDigest() != base.PolicyDigest() ||
				plan.FullArtifactPeakBytes() != base.FullArtifactPeakBytes() ||
				plan.ProjectedIncrementalPeakBytes() != test.requirement || plan.Digest() == "" {
				t.Fatalf("phase plan identity or requirement changed: %+v", plan)
			}
			components := plan.Components()
			names := make([]string, len(components))
			var sum uint64
			for index, component := range components {
				names[index] = component.Name()
				if component.Source() == "" || component.Bytes() == 0 {
					t.Fatalf("empty component: %+v", component)
				}
				sum += component.Bytes()
			}
			if !reflect.DeepEqual(names, test.components) || sum != test.requirement {
				t.Fatalf("phase components=%v sum=%d, want %v/%d", names, sum, test.components, test.requirement)
			}

			snapshot := PhysicalMemorySnapshot{
				SnapshotID: "phase-envelope-fixture", TotalPhysicalBytes: 33_618_251_776,
				AvailablePhysicalBytes: 20_000_000_000,
			}
			report, permit, evaluateErr := plan.Evaluate(snapshot)
			if evaluateErr != nil {
				t.Fatal(evaluateErr)
			}
			if report.ProjectedIncrementalPeakBytes() != test.requirement ||
				report.GuardBytes() != 536_870_912 || report.GuardedRequirementBytes() != test.guarded ||
				report.PlanDigest() != plan.Digest() || permit.PlanDigest() != plan.Digest() ||
				permit.ReportDigest() != report.Digest() {
				t.Fatalf("phase report/permit changed: report=%+v permit=%+v", report, permit)
			}
			if plan.ValidateReport(snapshot, report) != nil || plan.ValidatePermit(snapshot, permit) != nil {
				t.Fatal("canonical phase report or permit did not validate")
			}
		})
	}
}

func TestGaoN16PackingL11PreflightPhaseAdmitsObservedInstalledSnapshot(t *testing.T) {
	profile, err := NewGaoN16PackingL11Profile()
	if err != nil {
		t.Fatal(err)
	}
	shape := DefaultGaoN16PackingL11CapacityShape()
	policy := DefaultArtifactCapacityPolicy()
	snapshot := PhysicalMemorySnapshot{
		SnapshotID:             "blocked-installed-preflight-2026-09-01",
		TotalPhysicalBytes:     33_618_251_776,
		AvailablePhysicalBytes: 13_602_926_592,
	}
	base, err := NewGaoN16PackingL11CapacityPlan(profile, shape, policy)
	if err != nil {
		t.Fatal(err)
	}
	blockedReport, blockedPermit, err := base.Evaluate(snapshot)
	if !errors.As(err, new(*ErrArtifactCapacityBlocked)) || blockedReport.Decision() != ResourceBlocked || !blockedPermit.IsZero() ||
		blockedReport.ProjectedSystemUsedBytes() != 27_858_173_260 {
		t.Fatalf("combined plan did not reproduce the observed block: report=%+v permit=%+v err=%v", blockedReport, blockedPermit, err)
	}
	phase, err := NewGaoN16PackingL11PhaseCapacityPlan(profile, shape, policy, GaoN16PackingL11PhasePreflight)
	if err != nil {
		t.Fatal(err)
	}
	report, permit, err := phase.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if report.Decision() != Admitted || report.CurrentSystemUsedBytes() != 20_015_325_184 ||
		report.CapacityLimitBytes() != 26_894_601_420 || report.ProjectedSystemUsedBytes() != 21_534_187_520 ||
		report.RemainingBelowLimitBytes() != 5_360_413_900 || permit.IsZero() {
		t.Fatalf("phase plan did not admit the observed installed snapshot: %+v/%+v", report, permit)
	}
}

func TestGaoN16PackingL11PhaseCapacityRejectsForeignPhaseAndTampering(t *testing.T) {
	profile, err := NewGaoN16PackingL11Profile()
	if err != nil {
		t.Fatal(err)
	}
	shape := DefaultGaoN16PackingL11CapacityShape()
	policy := DefaultArtifactCapacityPolicy()
	if plan, planErr := NewGaoN16PackingL11PhaseCapacityPlan(profile, shape, policy, GaoN16PackingL11CapacityPhase("foreign")); !errors.As(planErr, new(*ErrArtifactCapacityBlocked)) || plan.Digest() != "" {
		t.Fatalf("foreign phase returned plan/error=%+v/%v", plan, planErr)
	}
	plan, err := NewGaoN16PackingL11PhaseCapacityPlan(profile, shape, policy, GaoN16PackingL11PhaseInstall)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := PhysicalMemorySnapshot{SnapshotID: "phase-tamper", TotalPhysicalBytes: 33_618_251_776, AvailablePhysicalBytes: 20_000_000_000}
	report, permit, err := plan.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	tamperedPlan := plan
	tamperedPlan.projectedIncrementalPeakBytes++
	if _, _, err = tamperedPlan.Evaluate(snapshot); !errors.As(err, new(*ErrArtifactCapacityBlocked)) {
		t.Fatalf("tampered phase plan error=%v", err)
	}
	tamperedReport := report
	tamperedReport.projectedIncrementalPeakBytes++
	if err = plan.ValidateReport(snapshot, tamperedReport); !errors.As(err, new(*ErrArtifactCapacityBlocked)) {
		t.Fatalf("tampered phase report error=%v", err)
	}
	tamperedPermit := permit
	tamperedPermit.planDigest = "foreign"
	if err = plan.ValidatePermit(snapshot, tamperedPermit); !errors.As(err, new(*ErrArtifactCapacityBlocked)) {
		t.Fatalf("tampered phase permit error=%v", err)
	}
	components := plan.Components()
	components[0].bytes++
	if plan.Components()[0].Bytes() == components[0].Bytes() {
		t.Fatal("phase plan exposes mutable component backing")
	}
}
