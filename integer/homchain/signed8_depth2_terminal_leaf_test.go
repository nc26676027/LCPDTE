package homchain

import (
	"math"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/nc26676027/LCPDTE/integer/treeplan"

	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
)

func TestSigned8Depth2TerminalLeafCertificateUsesExactLeavesAndFixedProfile(t *testing.T) {
	circuit := newSigned8Depth2TerminalLeafCircuitForTree(t, signed8Depth2TestTree())
	profile := circuit.Profile()
	certificate := profile.MagnitudeCertificate()

	if profile.Fidelity() != Signed8Depth2TerminalLeafFunctionalNotSecure ||
		profile.ParameterDigest() != circuit.child.Profile().ParameterDigest() ||
		profile.ChildProfileDigest() != circuit.child.Profile().Digest() ||
		profile.DecoderProfileDigest() != circuit.decoder.Profile().Digest() ||
		profile.TreeDigest() != circuit.child.prefix.Profile().TreeDigest() ||
		profile.ScheduleDigest() != circuit.child.prefix.Profile().ScheduleDigest() ||
		profile.Digest() == "" || certificate.Digest() == "" {
		t.Fatalf("terminal profile is incomplete: %+v", profile)
	}
	wantBits := [4]uint64{
		math.Float64bits(-1.25), math.Float64bits(2.5),
		math.Float64bits(-3.75), math.Float64bits(5),
	}
	if got := certificate.LeafBits(); got != wantBits ||
		certificate.CacheRoundingPolicy() != signed8Depth2CacheRoundingPolicy ||
		certificate.IdealHeadroomPolicy() != signed8Depth2IdealHeadroomPolicy ||
		certificate.MinimumIdealCenteredHeadroomBits() < signed8Depth2MinimumIdealCenteredHeadroomBits {
		t.Fatalf("terminal certificate changed: bits=%x min=%d", got, certificate.MinimumIdealCenteredHeadroomBits())
	}
	for index, leaf := range []float64{-1.25, 2.5, -3.75, 5} {
		want := new(big.Rat).SetFloat64(leaf)
		if want == nil {
			t.Fatalf("cannot construct independent exact leaf %d", index)
		}
		got := certificate.Leaves()[index].Rat()
		if got == nil || got.Cmp(want) != 0 {
			t.Fatalf("leaf %d exact rational=%v, want %v", index, got, want)
		}
	}

	wantCounts := Signed8Depth2TerminalLeafOperationCounts{
		CiphertextPlaintextMultiplications:  2,
		CiphertextCiphertextMultiplications: 1,
		Relinearizations:                    1,
		Rescales:                            3,
		PlaintextVectorAdditions:            2,
		CiphertextAdditions:                 1,
		LevelDrops:                          1,
	}
	if got := profile.OperationCounts(); got != wantCounts || got.Rotations != 0 {
		t.Fatalf("terminal operation ledger=%+v, want %+v", got, wantCounts)
	}
	wantBytes := Signed8Depth2TerminalLeafSerializedBytes{
		DecodedChild: 5054, RootSelector: 4526,
		RawA: 5054, RescaledA: 4526, AffineA: 4526,
		RawD: 5054, RescaledD: 4526, AffineD: 4526,
		RawY: 4526, RescaledY: 3998, AlignedA: 3998, Output: 3998,
	}
	if got := profile.ExpectedSerializedBytes(); got != wantBytes ||
		got.InternalInputBytes() != 9580 || got.RetainedLocalBytes() != 40734 ||
		got.OnlineOutputBytes() != 3998 || got.TotalBytes() != 54312 {
		t.Fatalf("terminal byte ledger=%+v", got)
	}
	states := profile.ExpectedStates()
	if len(states) != 12 || states[0].Stage != Signed8Depth2TerminalStageDecodedChild ||
		states[0].Level != 8 || states[1].Stage != Signed8Depth2TerminalStageRootSelector ||
		states[1].Level != 7 || states[11].Stage != Signed8Depth2TerminalStageOutput ||
		states[11].Level != 6 {
		t.Fatalf("terminal state ledger changed: %+v", states)
	}
	if len(profile.RequiredGaloisElements()) != 7 || !profile.RequiresRelinearization() {
		t.Fatalf("terminal key union changed: %v relin=%v", profile.RequiredGaloisElements(), profile.RequiresRelinearization())
	}
}

func TestSigned8Depth2TerminalLeafCertificateEdgeHeadroomLedger(t *testing.T) {
	tree := signed8Depth2TestTree()
	tree.Leaves = []float64{1 << 16, -(1 << 16), -(1 << 16), 1 << 16}
	circuit := newSigned8Depth2TerminalLeafCircuitForTree(t, tree)
	certificate := circuit.Profile().MagnitudeCertificate()

	want := map[string]uint{
		"b1":        289,
		"b0":        254,
		"PT(dL)":    272,
		"PT(cross)": 271,
		"PT(l00)":   238,
		"PT(dX)":    237,
		"rawA":      237,
		"a":         237,
		"A":         237,
		"rawD":      236,
		"d":         236,
		"D":         236,
		"rawY":      201,
		"z":         201,
		"A6":        202,
		"y":         200,
	}
	states := certificate.HeadroomStates()
	if len(states) != 16 {
		t.Fatalf("headroom states=%d, want 16", len(states))
	}
	for _, state := range states {
		if wantBits, ok := want[state.Name()]; !ok || state.FloorIdealCenteredHeadroomBits() != wantBits {
			t.Fatalf("headroom %s=%d, want %d (known=%v)", state.Name(), state.FloorIdealCenteredHeadroomBits(), wantBits, ok)
		}
	}
	if certificate.MinimumIdealCenteredHeadroomBits() != 200 {
		t.Fatalf("minimum headroom=%d, want 200", certificate.MinimumIdealCenteredHeadroomBits())
	}
	if got := certificate.OutputTolerance().RatString(); got != "13320193/4096" {
		t.Fatalf("edge tolerance=%s, want 13320193/4096", got)
	}
}

func TestSigned8Depth2TerminalLeafCertificateRejectsOutOfRangeLeaves(t *testing.T) {
	tree := signed8Depth2TestTree()
	tree.Leaves[0] = (1 << 16) + 1
	child := newSigned8Depth2TerminalLeafChildForTree(t, tree)
	if circuit, err := NewSigned8Depth2TerminalLeafCircuit(child); err == nil || circuit != nil {
		t.Fatalf("oversized terminal leaf admitted: circuit=%p err=%v", circuit, err)
	}
}

func TestSigned8Depth2TerminalLeafZeroDeltasKeepFixedCachesAndLedger(t *testing.T) {
	tree := signed8Depth2TestTree()
	tree.Leaves = []float64{0, 0, 0, 0}
	circuit := newSigned8Depth2TerminalLeafCircuitForTree(t, tree)
	if circuit.deltaL == nil || circuit.cross == nil || circuit.leaf00 == nil || circuit.deltaX == nil ||
		circuit.deltaL == circuit.cross || circuit.leaf00 == circuit.deltaX {
		t.Fatal("zero-delta terminal omitted or aliased a required cached plaintext")
	}
	if got := circuit.Profile().OperationCounts(); got != (Signed8Depth2TerminalLeafOperationCounts{
		CiphertextPlaintextMultiplications: 2, CiphertextCiphertextMultiplications: 1,
		Relinearizations: 1, Rescales: 3, PlaintextVectorAdditions: 2,
		CiphertextAdditions: 1, LevelDrops: 1,
	}) {
		t.Fatalf("zero-delta operation ledger changed: %+v", got)
	}
	if circuit.Profile().MagnitudeCertificate().OutputTolerance().Rat().Sign() <= 0 {
		t.Fatal("zero-delta certificate lost the fixed arithmetic-slack tolerance")
	}
}

func TestSigned8Depth2TerminalLeafCertificateAccessorsAreDetached(t *testing.T) {
	circuit := newSigned8Depth2TerminalLeafCircuitForTree(t, signed8Depth2TestTree())
	profile := circuit.Profile()
	states := profile.ExpectedStates()
	headroom := profile.MagnitudeCertificate().HeadroomStates()
	leaves := profile.MagnitudeCertificate().Leaves()
	keys := profile.RequiredGaloisElements()
	states[0].Level = 99
	headroom[0].name = "changed"
	leaves[0].numerator = "999"
	keys[0] = 0
	current := circuit.Profile()
	if current.ExpectedStates()[0].Level != 8 || current.MagnitudeCertificate().HeadroomStates()[0].Name() != "b1" ||
		current.MagnitudeCertificate().Leaves()[0].RatString() != "-5/4" || current.RequiredGaloisElements()[0] != 5 {
		t.Fatal("terminal profile/certificate accessor aliases sealed state")
	}
}

func TestSigned8Depth2TerminalLeafBindChildResultRejectsUnmintedPair(t *testing.T) {
	circuit := newSigned8Depth2TerminalLeafCircuitForTree(t, signed8Depth2TestTree())
	input, err := circuit.BindChildResult(Signed8Depth2ChildComparatorInput{}, Signed8Depth2ChildComparatorResult{})
	if err == nil || !reflect.DeepEqual(input, Signed8Depth2TerminalLeafInput{}) {
		t.Fatalf("unminted child pair admitted: input=%+v err=%v", input, err)
	}
}

func TestSigned8Depth2TerminalLeafCircuitAndCacheMutationMatrixFailsClosed(t *testing.T) {
	circuit := newSigned8Depth2TerminalLeafCircuitForTree(t, signed8Depth2TestTree())
	if err := circuit.validate(); err != nil {
		t.Fatal(err)
	}
	mutations := []struct {
		name   string
		mutate func(*Signed8Depth2TerminalLeafCircuit)
	}{
		{"nil-child", func(value *Signed8Depth2TerminalLeafCircuit) {
			value.child = nil
		}},
		{"nil-child-seal", func(value *Signed8Depth2TerminalLeafCircuit) {
			value.childSeal = nil
		}},
		{"nil-decoder", func(value *Signed8Depth2TerminalLeafCircuit) {
			value.decoder = nil
		}},
		{"nil-encoder", func(value *Signed8Depth2TerminalLeafCircuit) {
			value.encoder = nil
		}},
		{"nil-cache-plaintext", func(value *Signed8Depth2TerminalLeafCircuit) {
			value.deltaL = nil
		}},
		{"nil-cache-plaintext-seal", func(value *Signed8Depth2TerminalLeafCircuit) {
			value.deltaLSeal = nil
		}},
		{"nil-cache-source", func(value *Signed8Depth2TerminalLeafCircuit) {
			value.cacheSources[0] = nil
		}},
		{"nil-cache-source-seal", func(value *Signed8Depth2TerminalLeafCircuit) {
			value.cacheSourceSeals[0] = nil
		}},
		{"graph-circuit", func(value *Signed8Depth2TerminalLeafCircuit) {
			value.graph.circuit = nil
		}},
		{"graph-circuit-seal", func(value *Signed8Depth2TerminalLeafCircuit) {
			value.graph.circuitSeal = nil
		}},
		{"graph-child", func(value *Signed8Depth2TerminalLeafCircuit) {
			value.graph.child = nil
		}},
		{"graph-decoder", func(value *Signed8Depth2TerminalLeafCircuit) {
			value.graph.decoder = nil
		}},
		{"graph-encoder", func(value *Signed8Depth2TerminalLeafCircuit) {
			value.graph.encoder = nil
		}},
		{"graph-cache-source", func(value *Signed8Depth2TerminalLeafCircuit) {
			value.graph.cacheSources[0] = nil
		}},
		{"graph-cache-source-seal", func(value *Signed8Depth2TerminalLeafCircuit) {
			value.graph.cacheSourceSeals[0] = nil
		}},
		{"graph-cache-plaintext", func(value *Signed8Depth2TerminalLeafCircuit) {
			value.graph.deltaL = nil
		}},
		{"graph-cache-plaintext-seal", func(value *Signed8Depth2TerminalLeafCircuit) {
			value.graph.deltaLSeal = nil
		}},
		{"graph-profile", func(value *Signed8Depth2TerminalLeafCircuit) {
			value.graph.profileDigest = "tampered"
		}},
		{"graph-certificate", func(value *Signed8Depth2TerminalLeafCircuit) {
			value.graph.certificateDigest = "tampered"
		}},
		{"profile-cache-digest", func(value *Signed8Depth2TerminalLeafCircuit) {
			value.profile.cachePayloadDigests[0] = "tampered"
		}},
		{"certificate-leaf-bit", func(value *Signed8Depth2TerminalLeafCircuit) {
			value.profile.certificate.leafBits[0] ^= 1
		}},
		{"certificate-headroom", func(value *Signed8Depth2TerminalLeafCircuit) {
			value.profile.certificate.states[0].floorIdealCenteredHeadroomBits--
		}},
		{"cache-plaintext", func(value *Signed8Depth2TerminalLeafCircuit) {
			value.deltaL = value.deltaL.CopyNew()
		}},
		{"cache-plaintext-payload", func(value *Signed8Depth2TerminalLeafCircuit) {
			value.deltaL = value.deltaL.CopyNew()
			value.graph.deltaL = value.deltaL
			value.deltaL.Value.Coeffs[0][0] ^= 1
		}},
		{"cache-source-pointer", func(value *Signed8Depth2TerminalLeafCircuit) {
			value.cacheSources[0] = new(big.Float).Copy(value.cacheSources[0])
		}},
		{"cache-source-value", func(value *Signed8Depth2TerminalLeafCircuit) {
			value.cacheSources[0] = new(big.Float).Copy(value.cacheSources[0])
			value.graph.cacheSources[0] = value.cacheSources[0]
			value.cacheSources[0].Add(value.cacheSources[0], new(big.Float).SetPrec(256).SetInt64(1))
		}},
		{"cache-source-seal-pointer", func(value *Signed8Depth2TerminalLeafCircuit) {
			value.cacheSourceSeals[0] = new(big.Float).Copy(value.cacheSourceSeals[0])
		}},
		{"encoder-runtime", func(value *Signed8Depth2TerminalLeafCircuit) {
			replacement := *value.encoder
			value.encoder = &replacement
			value.graph.encoder = &replacement
		}},
		{"profile-operation-count", func(value *Signed8Depth2TerminalLeafCircuit) {
			value.profile.counts.CiphertextAdditions++
		}},
		{"certificate-digest", func(value *Signed8Depth2TerminalLeafCircuit) {
			value.profile.certificate.digest = "tampered"
		}},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			tampered := *circuit
			tampered.profile = cloneSigned8Depth2TerminalLeafProfile(circuit.profile)
			tampered.graph = circuit.graph
			tampered.graph.circuit = &tampered
			tampered.graph.circuitSeal = &tampered
			test.mutate(&tampered)
			if err := tampered.validate(); err == nil {
				t.Fatal("mutated terminal circuit admitted")
			}
		})
	}
	if err := circuit.validate(); err != nil {
		t.Fatalf("accepted terminal circuit changed after detached mutation tests: %v", err)
	}
	if got := len(mutations); got != 30 {
		t.Fatalf("terminal circuit/cache mutation cases=%d, want 30", got)
	}
}

func TestSigned8Depth2TerminalLeafBindEvaluatorRejectsNilSource(t *testing.T) {
	circuit := newSigned8Depth2TerminalLeafCircuitForTree(t, signed8Depth2TestTree())
	if evaluator, err := circuit.BindEvaluator(nil); err == nil || evaluator != nil {
		t.Fatalf("nil terminal source admitted: evaluator=%p err=%v", evaluator, err)
	}
}

func TestSigned8Depth2TerminalLeafFailureProgressLedgerIsExact(t *testing.T) {
	ledger := signed8Depth2TerminalLeafOperationProgressLedger()
	if len(ledger) != 10 {
		t.Fatalf("terminal operation progress entries=%d, want 10", len(ledger))
	}
	accepted := 0
	for _, progress := range ledger {
		if progress.dispatchCanReturnError {
			if !validSigned8Depth2TerminalLeafProgress(
				progress.stage, progress.statesBefore, progress.completedBefore, progress.attemptedOnDispatch,
			) {
				t.Fatalf("valid dispatch-failure progress rejected at %s", progress.stage)
			}
			accepted++
		} else if validSigned8Depth2TerminalLeafProgress(
			progress.stage, progress.statesBefore, progress.completedBefore, progress.attemptedOnDispatch,
		) {
			t.Fatalf("infallible dispatch admitted an uncompleted progress point at %s", progress.stage)
		}
		for _, stateCount := range []int{progress.statesBefore, progress.statesBefore + 1} {
			if !validSigned8Depth2TerminalLeafProgress(
				progress.stage, stateCount, progress.completedAfter, progress.attemptedAfter,
			) {
				t.Fatalf("valid completed progress rejected at %s with %d states", progress.stage, stateCount)
			}
			accepted++
		}
		foreignAttempt := progress.attemptedAfter
		foreignAttempt.Rotations++
		if validSigned8Depth2TerminalLeafProgress(
			progress.stage, progress.statesBefore+1, progress.completedAfter, foreignAttempt,
		) {
			t.Fatalf("resealed foreign attempted ledger admitted at %s", progress.stage)
		}
	}
	zero := Signed8Depth2TerminalLeafOperationCounts{}
	full := ledger[len(ledger)-1].completedAfter
	for _, initial := range []struct {
		stage  Signed8Depth2TerminalLeafStage
		states int
		counts Signed8Depth2TerminalLeafOperationCounts
	}{
		{Signed8Depth2TerminalStageDecodedChild, 0, zero},
		{Signed8Depth2TerminalStageRootSelector, 0, zero},
		{Signed8Depth2TerminalStageAdmission, 0, zero},
		{Signed8Depth2TerminalStageAdmission, 12, full},
		{Signed8Depth2TerminalStagePreflight, 12, full},
	} {
		if !validSigned8Depth2TerminalLeafProgress(initial.stage, initial.states, initial.counts, initial.counts) {
			t.Fatalf("valid terminal boundary progress rejected: %+v", initial)
		}
		accepted++
	}
	if accepted != 34 {
		t.Fatalf("accepted terminal progress points=%d, want 34", accepted)
	}
	if ledger[6].stage != Signed8Depth2TerminalStageRawY ||
		ledger[6].attemptedOnDispatch.Relinearizations != 0 ||
		ledger[6].attemptedAfter.Relinearizations != 1 {
		t.Fatalf("fused MulRelin lower-bound split changed: %+v", ledger[6])
	}
}

func TestSigned8Depth2TerminalLeafPropagatesAuthenticatedDecoderPartialFailure(t *testing.T) {
	circuit := newSigned8Depth2TerminalLeafCircuitForTree(t, signed8Depth2TestTree())
	childInput, childResult := newSigned8Depth2ChildDecodeAdmissionPair(
		t, circuit.child, Signed8PublicThresholdCTPT, 37,
	)
	input, err := circuit.BindChildResult(childInput, childResult)
	if err != nil {
		t.Fatal(err)
	}
	stateScale, err := NewExactScaleSnapshot(input.decoderInput.branch.Scale)
	if err != nil {
		t.Fatal(err)
	}
	helper := SelectorReraiseDecodeTrace{
		states: []SelectorReraiseDecodeCiphertextState{{
			Stage: SelectorStageInput, Lane: SelectorReraiseDecodeWhole,
			Level: input.decoderInput.branch.Level(), Degree: input.decoderInput.branch.Degree(),
			LogDimensions: input.decoderInput.branch.LogDimensions, Scale: stateScale,
		}},
		logicalPeakLive: 2,
	}
	preflight := A2BRefreshKeyPreflight{
		Checked: true, GraphChecked: true, GraphMatched: true,
		RelinearizationPresent: true, RelinearizationMatched: true, DenseNoSwitchingMatched: true,
	}
	decoderResult, decoderPartial, err := finalizeSigned8Depth2ChildSelectorDecodeFailure(
		circuit.decoder, input.decoderInput, helper, preflight,
		Signed8Depth2ChildSelectorStageVRaw,
		Signed8Depth2ChildSelectorDecodeOperationCounts{LinearTransformations: 2},
		time.Millisecond,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoderResult, Signed8Depth2ChildSelectorDecodeResult{}) {
		t.Fatal("decoder failure fixture exposed a result token")
	}

	result, trace, err := finalizeSigned8Depth2TerminalLeafDecoderFailure(
		circuit, input, decoderResult, decoderPartial, time.Millisecond,
	)
	if err != nil {
		t.Fatal(err)
	}
	wantAttempted := Signed8Depth2TerminalLeafComposedOperationCounts{
		ChildDecoder: decoderPartial.AttemptedOperationLowerBound(),
	}
	wantCompleted := Signed8Depth2TerminalLeafComposedOperationCounts{
		ChildDecoder: decoderPartial.OperationCounts(),
	}
	if !reflect.DeepEqual(result, Signed8Depth2TerminalLeafResult{}) ||
		reflect.DeepEqual(trace, Signed8Depth2TerminalLeafTrace{}) ||
		trace.FailureStage() != Signed8Depth2TerminalStageDecoderFailure ||
		trace.DecoderTrace().Digest() != decoderPartial.Digest() ||
		!reflect.DeepEqual(trace.DecoderResult(), Signed8Depth2ChildSelectorDecodeResult{}) ||
		trace.DecoderResultDigest() != "" || trace.DecoderTraceDigest() != decoderPartial.Digest() ||
		trace.OperationCounts() != (Signed8Depth2TerminalLeafOperationCounts{}) ||
		trace.AttemptedOperationLowerBound() != wantAttempted ||
		trace.CompletedComposedOperationCounts() != wantCompleted ||
		len(trace.States()) != 0 || trace.SerializedBytes().TotalBytes() != 0 ||
		trace.UniqueComposedMeasuredBytes() != decoderPartial.SerializedBytes().ModuleTotal() ||
		trace.InputProvenanceDigest() != input.ProvenanceDigest() || trace.Digest() == "" {
		t.Fatalf("terminal decoder partial evidence is incomplete: result=%+v trace=%+v", result, trace)
	}
	if err = circuit.validateFailureTrace(input, trace); err != nil {
		t.Fatalf("terminal decoder partial trace did not validate: %v", err)
	}

	childCopy := trace.DecoderTrace()
	childCopy.states[0].Level++
	if trace.DecoderTrace().States()[0].Level == childCopy.States()[0].Level {
		t.Fatal("terminal decoder partial accessor aliases sealed child evidence")
	}

	resealChild := func(value *Signed8Depth2TerminalLeafTrace) {
		value.decoderTrace.traceDigest = digestSigned8Depth2ChildSelectorDecodeTrace(value.decoderTrace)
		value.decoderTraceDigest = value.decoderTrace.Digest()
	}
	type partialMutation struct {
		name        string
		mutate      func(*Signed8Depth2TerminalLeafTrace)
		outerReseal bool
	}
	mutations := []partialMutation{
		{"profile", func(value *Signed8Depth2TerminalLeafTrace) { value.profileDigest = "tampered" }, true},
		{"input-provenance", func(value *Signed8Depth2TerminalLeafTrace) { value.inputProvenanceDigest = "tampered" }, true},
		{"child-input-binding", func(value *Signed8Depth2TerminalLeafTrace) { value.childInputBindingDigest = "tampered" }, true},
		{"mode", func(value *Signed8Depth2TerminalLeafTrace) { value.operandMode = Signed8OpaqueThresholdCTCT }, true},
		{"failure-stage", func(value *Signed8Depth2TerminalLeafTrace) { value.failureStage = Signed8Depth2TerminalStageRawA }, true},
		{"nested-result", func(value *Signed8Depth2TerminalLeafTrace) {
			value.decoderResult.profileDigest = "tampered"
			value.decoderResult.provenanceDigest = digestSigned8Depth2ChildSelectorDecodeResult(value.decoderResult)
			value.decoderResultDigest = value.decoderResult.Digest()
		}, true},
		{"nested-state", func(value *Signed8Depth2TerminalLeafTrace) {
			value.decoderTrace.states[0].Level++
			resealChild(value)
		}, true},
		{"nested-state-prefix", func(value *Signed8Depth2TerminalLeafTrace) {
			value.decoderTrace.states = nil
			resealChild(value)
		}, true},
		{"nested-lower-bound", func(value *Signed8Depth2TerminalLeafTrace) {
			value.decoderTrace.attemptedOperationLowerBound = Signed8Depth2ChildSelectorDecodeOperationCounts{}
			resealChild(value)
		}, true},
		{"nested-byte-ledger", func(value *Signed8Depth2TerminalLeafTrace) {
			value.decoderTrace.serializedBytes.ChildArithmeticInput++
			resealChild(value)
		}, true},
		{"nested-provenance", func(value *Signed8Depth2TerminalLeafTrace) {
			value.decoderTrace.inputProvenanceDigest = "tampered"
			resealChild(value)
		}, true},
		{"nested-result-link", func(value *Signed8Depth2TerminalLeafTrace) {
			value.decoderTrace.resultProvenanceDigest = "tampered"
			resealChild(value)
		}, true},
		{"nested-digest", func(value *Signed8Depth2TerminalLeafTrace) {
			value.decoderTrace.traceDigest = "tampered"
			value.decoderTraceDigest = value.decoderTrace.Digest()
		}, true},
		{"outer-decoder-digest", func(value *Signed8Depth2TerminalLeafTrace) { value.decoderTraceDigest = "tampered" }, true},
		{"outer-lower-bound-child", func(value *Signed8Depth2TerminalLeafTrace) {
			value.attemptedOperationLowerBound.ChildDecoder.LinearTransformations++
		}, true},
		{"outer-lower-bound-terminal", func(value *Signed8Depth2TerminalLeafTrace) {
			value.attemptedOperationLowerBound.TerminalMux.Rescales++
		}, true},
		{"outer-completed-terminal", func(value *Signed8Depth2TerminalLeafTrace) { value.counts.Rescales++ }, true},
		{"outer-byte-ledger", func(value *Signed8Depth2TerminalLeafTrace) { value.serializedBytes.DecodedChild++ }, true},
		{"outer-state-prefix", func(value *Signed8Depth2TerminalLeafTrace) {
			value.states = append(value.states, circuit.profile.expectedStates[0])
		}, true},
		{"runtime-keys", func(value *Signed8Depth2TerminalLeafTrace) { value.runtimeGalois[0] = 0 }, true},
		{"relinearization", func(value *Signed8Depth2TerminalLeafTrace) { value.relinearizationMatched = false }, true},
		{"wall-time", func(value *Signed8Depth2TerminalLeafTrace) { value.wallTime = 0 }, true},
		{"trace-digest", func(value *Signed8Depth2TerminalLeafTrace) { value.traceDigest = "tampered" }, false},
	}
	for _, mutation := range mutations {
		t.Run("partial-mutation-"+mutation.name, func(t *testing.T) {
			changed := cloneSigned8Depth2TerminalLeafTrace(trace)
			mutation.mutate(&changed)
			if mutation.outerReseal {
				changed.traceDigest = digestSigned8Depth2TerminalLeafTrace(changed)
			}
			if err := circuit.validateFailureTrace(input, changed); err == nil {
				t.Fatal("mutated terminal decoder partial trace validated")
			}
		})
	}
	if len(mutations) != 23 {
		t.Fatalf("terminal decoder partial mutation cases=%d, want 23", len(mutations))
	}

	brokenChild := cloneSigned8Depth2ChildSelectorDecodeTrace(decoderPartial)
	brokenChild.attemptedOperationLowerBound = Signed8Depth2ChildSelectorDecodeOperationCounts{}
	brokenChild.traceDigest = digestSigned8Depth2ChildSelectorDecodeTrace(brokenChild)
	_, bestEffort, finalizeErr := finalizeSigned8Depth2TerminalLeafDecoderFailure(
		circuit, input, Signed8Depth2ChildSelectorDecodeResult{}, brokenChild, time.Millisecond,
	)
	if finalizeErr == nil || reflect.DeepEqual(bestEffort, Signed8Depth2TerminalLeafTrace{}) ||
		bestEffort.Digest() == "" || bestEffort.DecoderTraceDigest() != brokenChild.Digest() ||
		bestEffort.FailureStage() != Signed8Depth2TerminalStageDecoderFailure {
		t.Fatalf("terminal failure finalizer discarded best-effort evidence: trace=%+v err=%v", bestEffort, finalizeErr)
	}

	wantStates := circuit.Profile().ExpectedStates()
	for prefixLength := 0; prefixLength <= len(wantStates); prefixLength++ {
		prefixBytes, prefixErr := signed8Depth2TerminalBytesFromStatePrefix(wantStates[:prefixLength])
		if prefixErr != nil {
			t.Fatalf("valid terminal state prefix %d rejected: %v", prefixLength, prefixErr)
		}
		wantTotal := 0
		for _, state := range wantStates[:prefixLength] {
			wantTotal += state.SerializedBytes
		}
		if prefixBytes.TotalBytes() != wantTotal {
			t.Fatalf("terminal state prefix %d bytes=%d, want %d", prefixLength, prefixBytes.TotalBytes(), wantTotal)
		}
	}
	wrongOrder := append([]Signed8Depth2TerminalLeafState(nil), wantStates[:2]...)
	wrongOrder[1].Stage = Signed8Depth2TerminalStageRawA
	if _, prefixErr := signed8Depth2TerminalBytesFromStatePrefix(wrongOrder); prefixErr == nil {
		t.Fatal("out-of-order terminal state prefix admitted")
	}
}

func newSigned8Depth2TerminalLeafCircuitForTree(t *testing.T, tree treeplan.BinaryTree[int8, float64]) *Signed8Depth2TerminalLeafCircuit {
	t.Helper()
	child := newSigned8Depth2TerminalLeafChildForTree(t, tree)
	circuit, err := NewSigned8Depth2TerminalLeafCircuit(child)
	if err != nil {
		t.Fatal(err)
	}
	return circuit
}

func newSigned8Depth2TerminalLeafChildForTree(t *testing.T, tree treeplan.BinaryTree[int8, float64]) *Signed8Depth2ChildComparatorCircuit {
	t.Helper()
	params, err := GaoA2BKernelFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	ranges, err := NewSigned8NoOverflowRange(-8, 7, -8, 7)
	if err != nil {
		t.Fatal(err)
	}
	producer, err := NewSigned8ComparatorCircuit(
		params,
		ckks.NewEncoder(params, signed8RefreshEncoderPrecision),
		ckks.NewEncoder(params, signed8IntegerEncoderPrecision),
		ranges,
	)
	if err != nil {
		t.Fatal(err)
	}
	selector, err := NewSelectorReraiseDecodeCircuit(producer)
	if err != nil {
		t.Fatal(err)
	}
	prefix, err := NewSigned8Depth2SourcePrefixCircuit(selector, tree)
	if err != nil {
		t.Fatal(err)
	}
	child, err := NewSigned8Depth2ChildComparatorCircuit(prefix)
	if err != nil {
		t.Fatal(err)
	}
	return child
}
