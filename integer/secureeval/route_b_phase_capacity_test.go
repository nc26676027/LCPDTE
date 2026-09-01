package secureeval

import (
	"errors"
	"testing"
)

func TestRouteBAuthorityUsesCanonicalPhaseRelativeCapacity(t *testing.T) {
	const total = uint64(33_618_251_776)
	const available = uint64(20_000_000_000)
	tests := []struct {
		gate        routeBCapacityGate
		operation   string
		incremental uint64
		guarded     uint64
	}{
		{routeBCapacityGateBeginBuild, routeBRuntimeOperationBeginBuild, 2_968_063_744, 3_504_934_656},
		{routeBCapacityGateAuthorizeReady, routeBRuntimeOperationAuthorizeReady, 872_939_520, 1_409_810_432},
		{routeBCapacityGateInstall, routeBRuntimeOperationInstall, 5_034_213_376, 5_571_084_288},
		{routeBCapacityGatePreflight, routeBRuntimeOperationPreflight, 981_991_424, 1_518_862_336},
		{routeBCapacityGateA2BFirstRound, routeBRuntimeOperationA2BFirstRound, 1_227_427_584, 1_764_298_496},
		{routeBCapacityGateA2BFull, routeBRuntimeOperationA2BFull, 2_381_123_328, 2_917_994_240},
		{routeBCapacityGateSigned8RootTree, routeBRuntimeOperationSigned8RootTree, 2_451_902_208, 2_988_773_120},
		{routeBCapacityGateSigned8Depth2NodeBatch, routeBRuntimeOperationSigned8Depth2NodeBatch, 2_517_438_208, 3_054_309_120},
		{routeBCapacityGateSigned8Depth2SelectedChild, routeBRuntimeOperationSigned8Depth2SelectedChild, 2_765_426_432, 3_302_297_344},
		{routeBCapacityGateSigned8Radix4Node, routeBRuntimeOperationSigned8Radix4Node, 2_517_438_208, 3_054_309_120},
	}
	for _, test := range tests {
		t.Run(test.operation, func(t *testing.T) {
			sampler := &scriptedPhysicalMemorySampler{results: []scriptedPhysicalMemoryResult{{
				totals: physicalMemoryTotals{total: total, available: available},
			}}}
			authority, err := newRouteBAuthorityWithSampler(sampler)
			if err != nil {
				t.Fatal(err)
			}
			evidence, err := authority.cell.sampleAndEvaluateCapacity(test.gate)
			if err != nil {
				t.Fatal(err)
			}
			if evidence.gate != test.gate || evidence.peak.PreGuardIncrementalPeakBytes != test.incremental ||
				evidence.peak.GuardedRequirementBytes != test.guarded ||
				evidence.peak.RemainingBelowLimitBytes != (total*4)/5-(total-available)-test.guarded {
				t.Fatalf("phase evidence changed: %+v", evidence)
			}
			lineage := RBAUTHDigest{1}
			runtime := newRuntimeCapacityEvidence(test.operation, evidence, lineage)
			if err = runtime.Validate(); err != nil {
				t.Fatalf("canonical runtime evidence failed: %v", err)
			}
			wrongOperation := routeBRuntimeOperationPreflight
			if wrongOperation == test.operation {
				wrongOperation = routeBRuntimeOperationInstall
			}
			mismatched := newRuntimeCapacityEvidence(wrongOperation, evidence, lineage)
			if err = mismatched.Validate(); !errors.Is(err, ErrRBAUTHLineage) {
				t.Fatalf("operation/phase mismatch error=%v", err)
			}
			tampered := runtime
			tampered.Peak.PreGuardIncrementalPeakBytes++
			if err = tampered.Validate(); !errors.Is(err, ErrRBAUTHLineage) {
				t.Fatalf("tampered phase peak error=%v", err)
			}
			tampered = runtime
			tampered.Capacity.CapacityPlanDigest[0] ^= 1
			if err = tampered.Validate(); !errors.Is(err, ErrRBAUTHLineage) {
				t.Fatalf("tampered phase binding error=%v", err)
			}
		})
	}
}

func TestRouteBAuthorityPreflightPhaseRepairsObservedDoubleCountWithoutRelaxingLimit(t *testing.T) {
	totals := physicalMemoryTotals{total: 33_618_251_776, available: 13_602_926_592}
	fullSampler := &scriptedPhysicalMemorySampler{results: []scriptedPhysicalMemoryResult{{totals: totals}}}
	fullAuthority, err := newRouteBAuthorityWithSampler(fullSampler)
	if err != nil {
		t.Fatal(err)
	}
	if evidence, fullErr := fullAuthority.cell.sampleAndEvaluateCapacity(routeBCapacityGateAuthorizeBuild); !errors.Is(fullErr, ErrRBAUTHBlocked) || evidence != (routeBCapacityEvidence{}) {
		t.Fatalf("whole-lifecycle plan did not reproduce observed block: evidence=%+v err=%v", evidence, fullErr)
	}
	phaseSampler := &scriptedPhysicalMemorySampler{results: []scriptedPhysicalMemoryResult{{totals: totals}}}
	phaseAuthority, err := newRouteBAuthorityWithSampler(phaseSampler)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := phaseAuthority.cell.sampleAndEvaluateCapacity(routeBCapacityGatePreflight)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.peak.PreGuardIncrementalPeakBytes != 981_991_424 ||
		evidence.peak.GuardedRequirementBytes != 1_518_862_336 ||
		evidence.peak.RemainingBelowLimitBytes != 5_360_413_900 ||
		evidence.binding.TotalPhysicalBytes != totals.total || evidence.binding.AvailablePhysicalBytes != totals.available {
		t.Fatalf("observed preflight phase evidence changed: %+v", evidence)
	}
}

func TestRouteBCapacityGateCannotBeZeroOrForeign(t *testing.T) {
	for _, gate := range []routeBCapacityGate{0, 255} {
		sampler := &scriptedPhysicalMemorySampler{results: []scriptedPhysicalMemoryResult{{
			totals: physicalMemoryTotals{total: 33_618_251_776, available: 20_000_000_000},
		}}}
		authority, err := newRouteBAuthorityWithSampler(sampler)
		if err != nil {
			t.Fatal(err)
		}
		if evidence, gateErr := authority.cell.sampleAndEvaluateCapacity(gate); !errors.Is(gateErr, ErrRBAUTHLineage) || evidence != (routeBCapacityEvidence{}) {
			t.Fatalf("gate %d returned evidence/error=%+v/%v", gate, evidence, gateErr)
		}
	}
}
