package homchain

import (
	"math"
	"reflect"
	"testing"

	"dt_go/integer/z2n"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

func TestSigned8RootTreeCircuitProfilesSealCorrectedOperands(t *testing.T) {
	params, err := GaoA2BKernelFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	refreshEncoder := ckks.NewEncoder(params, signed8RefreshEncoderPrecision)
	integerEncoder := ckks.NewEncoder(params, signed8IntegerEncoderPrecision)
	ranges, err := NewSigned8NoOverflowRange(-8, 7, -8, 7)
	if err != nil {
		t.Fatal(err)
	}
	leaves := Signed8PackedLeaves{
		{Left: -128, Right: 127},
		{Left: 127, Right: -128},
		{Left: -7, Right: 19},
		{Left: 42, Right: -99},
	}
	circuit, err := NewSigned8RootTreeCircuit(params, refreshEncoder, integerEncoder, ranges, leaves)
	if err != nil {
		t.Fatal(err)
	}

	public, opaque := circuit.PublicProfile(), circuit.OpaqueProfile()
	// T0's canonical narrow fixture is an audit anchor in its own right.  Keep
	// these literals independent from the constructor so a coordinated change
	// to profile construction and validation cannot prove itself.
	wantFrozen := struct {
		publicProfile, opaqueProfile    string
		leaves, leftSource, deltaSource string
		leftPayload, deltaPayload       string
	}{
		publicProfile: "217dee6f265ec8c53819552838d9c9d64ea56e43df185b936f97d360b1e17be3",
		opaqueProfile: "09e8c10628c8a6820dbc439d31f9fa6f61d1e6d1ef607db7a8a8b977edeb5073",
		leaves:        "c19e4bfefafb24ae95e85f170b28412db58b8875f113d6dbb327cc3686de5dfd",
		leftSource:    "aff26b45421f4d1bee7d2c6c7e7bc85267b5d6a391c2e64da12dfd3071f6ec85",
		deltaSource:   "228fac2755adcc26725318cb44919b83b1c5d5d43325088631bf496bef573251",
		leftPayload:   "e668d439e8ba6fe95fa9fb6522a3a012a54ab1cd508608af778fdf9d02190f71",
		deltaPayload:  "78d37dba79cef9d7bac05130cc16bb8d47567c973b7b664765d21a7662419e58",
	}
	gotFrozen := struct {
		publicProfile, opaqueProfile    string
		leaves, leftSource, deltaSource string
		leftPayload, deltaPayload       string
	}{
		publicProfile: public.Digest(),
		opaqueProfile: opaque.Digest(),
		leaves:        public.LeavesDigest(),
		leftSource:    public.LeftOperandSourceDigest(),
		deltaSource:   public.CorrectedDeltaSourceDigest(),
		leftPayload:   public.LeftOperandPayloadDigest(),
		deltaPayload:  public.CorrectedDeltaPayloadDigest(),
	}
	if gotFrozen != wantFrozen {
		t.Fatalf("freeze the canonical T0 narrow fixture: got=%+v", gotFrozen)
	}
	if public.LeavesDigest() != opaque.LeavesDigest() ||
		public.LeftOperandSourceDigest() != opaque.LeftOperandSourceDigest() ||
		public.CorrectedDeltaSourceDigest() != opaque.CorrectedDeltaSourceDigest() ||
		public.LeftOperandPayloadDigest() != opaque.LeftOperandPayloadDigest() ||
		public.CorrectedDeltaPayloadDigest() != opaque.CorrectedDeltaPayloadDigest() {
		t.Fatal("canonical T0 public and opaque profiles do not seal the same leaf operands")
	}
	for _, profile := range []Signed8RootTreeProfile{public, opaque} {
		if profile.Fidelity() != Signed8RootTreeFunctionalNotSecure || profile.WordBits() != z2n.Word8 ||
			profile.Words() != signed8RootTreeWords || profile.Slots() != signed8RootTreeSlots || profile.RangeDigest() != ranges.Digest() ||
			profile.Leaves() != leaves || profile.OutputEncoding() != Signed8RootTreeArithmeticRootSlots ||
			profile.ParameterDigest() != signed8RootTreeAcceptedComparatorParameterDigest || profile.LeavesDigest() == "" ||
			profile.ComparatorAdmissionDigest() != signed8RootTreeAcceptedComparatorAdmissionDigest ||
			profile.ComparatorParameterDigest() != signed8RootTreeAcceptedComparatorParameterDigest ||
			profile.ComparatorArithmeticOnePayloadDigest() != signed8RootTreeAcceptedComparatorOnePayloadDigest ||
			profile.LeftOperandSourceDigest() == "" || profile.CorrectedDeltaSourceDigest() == "" ||
			profile.LeftOperandPayloadDigest() == "" || profile.CorrectedDeltaPayloadDigest() == "" ||
			profile.ComparatorProfileDigest() == "" || profile.MeasurementPolicy() != signed8RootTreeMeasurementPolicy ||
			profile.RepresentativePolicy() != Signed8RootTreeSourceScheduledArithmeticRepresentative || profile.Digest() == "" {
			t.Fatalf("root-tree profile is incomplete: %+v", profile)
		}
		if profile.OperationCounts() != (Signed8RootTreeOperationCounts{
			ComparatorInvocations: 1, CiphertextPlaintextMultiplications: 1, Rescales: 1,
			CiphertextPlaintextVectorAdditions: 1,
		}) || profile.SetupCounts() != (Signed8RootTreeSetupCounts{LeftPlaintextEncodings: 1, CorrectedDeltaPlaintextEncodings: 1}) {
			t.Fatalf("root-tree counts changed: operations=%+v setup=%+v", profile.OperationCounts(), profile.SetupCounts())
		}
		states := profile.States()
		if len(states) != signed8RootTreeStateCount {
			t.Fatalf("root-tree profile states=%d, want %d", len(states), signed8RootTreeStateCount)
		}
		wantStages := []Signed8RootTreeStage{
			Signed8RootTreeStageComparatorGE, Signed8RootTreeStageRawProduct,
			Signed8RootTreeStageRescaledProduct, Signed8RootTreeStageOutput,
		}
		wantLevels := []int{signed8RootTreeBranchLevel, signed8RootTreeBranchLevel, signed8RootTreeOutputLevel, signed8RootTreeOutputLevel}
		for index, state := range states {
			if state.Stage() != wantStages[index] || state.Level() != wantLevels[index] || state.Degree() != 1 ||
				state.LogDimensions() != params.LogMaxDimensions() {
				t.Fatalf("state[%d]=%+v", index, state)
			}
		}
		if !states[signed8RootTreeComparatorStateIndex].Scale().EqualScale(params.DefaultScale()) ||
			!states[signed8RootTreeRawProductStateIndex].Scale().EqualScale(params.DefaultScale().Mul(rlwe.NewScale(params.Q()[signed8RootTreeBranchLevel]))) ||
			!states[signed8RootTreeRescaledStateIndex].Scale().EqualScale(params.DefaultScale()) ||
			!states[signed8RootTreeOutputStateIndex].Scale().EqualScale(params.DefaultScale()) {
			t.Fatal("root-tree exact scale ledger changed")
		}
	}
	if public.ComparatorOperandMode() != Signed8PublicThresholdCTPT || opaque.ComparatorOperandMode() != Signed8OpaqueThresholdCTCT ||
		public.ComparatorProfileDigest() != signed8RootTreeAcceptedComparatorPublicDigest ||
		opaque.ComparatorProfileDigest() != signed8RootTreeAcceptedComparatorOpaqueDigest ||
		public.ComparatorProfileDigest() != circuit.comparator.PublicProfile().Digest() ||
		opaque.ComparatorProfileDigest() != circuit.comparator.OpaqueProfile().Digest() ||
		public.Digest() == opaque.Digest() {
		t.Fatal("root-tree public/opaque comparator binding changed")
	}
	if !reflect.DeepEqual(public.RequiredGaloisElements(), circuit.comparator.PublicProfile().RequiredGaloisElements()) ||
		!reflect.DeepEqual(opaque.RequiredGaloisElements(), circuit.comparator.OpaqueProfile().RequiredGaloisElements()) ||
		!public.RequiresRelinearization() || !opaque.RequiresRelinearization() || public.AdditionalEvaluationKeys() != 0 || opaque.AdditionalEvaluationKeys() != 0 {
		t.Fatal("root-tree key policy is not the exact comparator key policy")
	}
}

func TestSigned8RootTreeRejectsAnyChangedAcceptedComparatorPin(t *testing.T) {
	circuit := newSigned8RootTreeUnitCircuit(t)
	public, opaque := circuit.comparator.PublicProfile(), circuit.comparator.OpaqueProfile()
	for _, test := range []struct {
		name   string
		mutate func(*Signed8ComparatorProfile, *Signed8ComparatorProfile)
	}{
		{name: "public profile", mutate: func(public, _ *Signed8ComparatorProfile) { public.digest = "foreign" }},
		{name: "opaque profile", mutate: func(_, opaque *Signed8ComparatorProfile) { opaque.digest = "foreign" }},
		{name: "admission", mutate: func(public, _ *Signed8ComparatorProfile) { public.inputBindingDigest = "foreign" }},
		{name: "parameter", mutate: func(_, opaque *Signed8ComparatorProfile) { opaque.parameterDigest = "foreign" }},
		{name: "arithmetic one", mutate: func(public, _ *Signed8ComparatorProfile) { public.arithmeticOnePayloadDigest = "foreign" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changedPublic, changedOpaque := public, opaque
			test.mutate(&changedPublic, &changedOpaque)
			if err := validateSigned8RootTreeAcceptedComparatorProfiles(changedPublic, changedOpaque); err == nil {
				t.Fatalf("changed accepted comparator %s pin was admitted", test.name)
			}
		})
	}
}

func TestSigned8RootTreeCanonicalAuditPinsRejectEveryMutation(t *testing.T) {
	circuit := newSigned8RootTreeUnitCircuit(t)
	public, opaque := circuit.PublicProfile(), circuit.OpaqueProfile()
	if err := validateSigned8RootTreeCanonicalAuditPins(circuit.Ranges(), circuit.Leaves(), public, opaque); err != nil {
		t.Fatalf("canonical narrow T0 pins were rejected: %v", err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*Signed8RootTreeProfile, *Signed8RootTreeProfile)
	}{
		{name: "public profile digest", mutate: func(p, _ *Signed8RootTreeProfile) { p.digest = "foreign" }},
		{name: "opaque profile digest", mutate: func(_, p *Signed8RootTreeProfile) { p.digest = "foreign" }},
		{name: "public leaves digest", mutate: func(p, _ *Signed8RootTreeProfile) { p.leavesDigest = "foreign" }},
		{name: "opaque leaves digest", mutate: func(_, p *Signed8RootTreeProfile) { p.leavesDigest = "foreign" }},
		{name: "public left source", mutate: func(p, _ *Signed8RootTreeProfile) { p.leftSourceDigest = "foreign" }},
		{name: "opaque left source", mutate: func(_, p *Signed8RootTreeProfile) { p.leftSourceDigest = "foreign" }},
		{name: "public corrected delta source", mutate: func(p, _ *Signed8RootTreeProfile) { p.correctedDeltaSourceDigest = "foreign" }},
		{name: "opaque corrected delta source", mutate: func(_, p *Signed8RootTreeProfile) { p.correctedDeltaSourceDigest = "foreign" }},
		{name: "public left payload", mutate: func(p, _ *Signed8RootTreeProfile) { p.leftPayloadDigest = "foreign" }},
		{name: "opaque left payload", mutate: func(_, p *Signed8RootTreeProfile) { p.leftPayloadDigest = "foreign" }},
		{name: "public corrected delta payload", mutate: func(p, _ *Signed8RootTreeProfile) { p.correctedDeltaPayloadDigest = "foreign" }},
		{name: "opaque corrected delta payload", mutate: func(_, p *Signed8RootTreeProfile) { p.correctedDeltaPayloadDigest = "foreign" }},
		{name: "public output witness", mutate: func(p, _ *Signed8RootTreeProfile) { p.outputEncoding = Signed8RootTreeOutputEncoding("foreign") }},
		{name: "opaque output witness", mutate: func(_, p *Signed8RootTreeProfile) { p.outputEncoding = Signed8RootTreeOutputEncoding("foreign") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changedPublic, changedOpaque := cloneSigned8RootTreeProfile(public), cloneSigned8RootTreeProfile(opaque)
			test.mutate(&changedPublic, &changedOpaque)
			if err := validateSigned8RootTreeCanonicalAuditPins(circuit.Ranges(), circuit.Leaves(), changedPublic, changedOpaque); err == nil {
				t.Fatalf("canonical T0 accepted mutated %s pin", test.name)
			}
		})
	}
}

func TestSigned8RootTreeProfileAccessorsAreDefensive(t *testing.T) {
	circuit := newSigned8RootTreeUnitCircuit(t)
	want := circuit.PublicProfile()
	states := want.States()
	states[signed8RootTreeComparatorStateIndex].level = 99
	keys := want.RequiredGaloisElements()
	if len(keys) == 0 {
		t.Fatal("accepted comparator key union is unexpectedly empty")
	}
	keys[0] ^= 1
	got := circuit.PublicProfile()
	if got.States()[signed8RootTreeComparatorStateIndex].Level() != signed8RootTreeBranchLevel || reflect.DeepEqual(keys, got.RequiredGaloisElements()) || got.Digest() != want.Digest() {
		t.Fatal("public profile accessor mutation reached the sealed circuit")
	}
	exposedLeaves := circuit.Leaves()
	exposedLeaves[0].Left++
	if circuit.Leaves() != want.Leaves() {
		t.Fatal("leaf accessor mutation reached the sealed circuit")
	}
}

func TestSigned8RootTreeConstructorFailsClosed(t *testing.T) {
	params, err := GaoA2BKernelFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	ranges, err := NewSigned8NoOverflowRange(-8, 7, -8, 7)
	if err != nil {
		t.Fatal(err)
	}
	leaves := Signed8PackedLeaves{{Left: -1, Right: 1}, {Left: 1, Right: -1}, {Left: -128, Right: 127}, {Left: 127, Right: -128}}
	refreshEncoder := ckks.NewEncoder(params, signed8RefreshEncoderPrecision)
	integerEncoder := ckks.NewEncoder(params, signed8IntegerEncoderPrecision)
	badRange := ranges
	badRange.digest = ""
	for _, test := range []struct {
		name             string
		refresh, integer *ckks.Encoder
		ranges           Signed8NoOverflowRange
	}{
		{name: "nil refresh", refresh: nil, integer: integerEncoder, ranges: ranges},
		{name: "nil integer", refresh: refreshEncoder, integer: nil, ranges: ranges},
		{name: "wrong refresh precision", refresh: ckks.NewEncoder(params, signed8IntegerEncoderPrecision), integer: integerEncoder, ranges: ranges},
		{name: "wrong integer precision", refresh: refreshEncoder, integer: ckks.NewEncoder(params, signed8RefreshEncoderPrecision), ranges: ranges},
		{name: "forged range", refresh: refreshEncoder, integer: integerEncoder, ranges: badRange},
	} {
		t.Run(test.name, func(t *testing.T) {
			if circuit, err := NewSigned8RootTreeCircuit(params, test.refresh, test.integer, test.ranges, leaves); err == nil || circuit != nil {
				t.Fatalf("constructor accepted %s", test.name)
			}
		})
	}

	reorderedQ := append([]uint64(nil), params.Q()...)
	reorderedQ[1], reorderedQ[2] = reorderedQ[2], reorderedQ[1]
	reordered, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN: params.LogN(), Q: reorderedQ, P: append([]uint64(nil), params.P()...), LogDefaultScale: params.LogDefaultScale(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if circuit, err := NewSigned8RootTreeCircuit(reordered, ckks.NewEncoder(reordered, 192), ckks.NewEncoder(reordered, 256), ranges, leaves); err == nil || circuit != nil {
		t.Fatal("constructor accepted a same-bit reordered Q chain")
	}
	if circuit, err := NewSigned8RootTreeCircuit(params, ckks.NewEncoder(reordered, 192), integerEncoder, ranges, leaves); err == nil || circuit != nil {
		t.Fatal("constructor accepted an encoder from a reordered Q chain")
	}
}

func TestSigned8RootTreeProfileChangesWithPublicLeaves(t *testing.T) {
	first := newSigned8RootTreeUnitCircuit(t)
	secondLeaves := first.Leaves()
	secondLeaves[2].Right++
	second, err := NewSigned8RootTreeCircuit(first.params, first.refreshEncoder, first.integerEncoder, first.ranges, secondLeaves)
	if err != nil {
		t.Fatal(err)
	}
	firstProfile, secondProfile := first.PublicProfile(), second.PublicProfile()
	if firstProfile.Digest() == secondProfile.Digest() || firstProfile.LeavesDigest() == secondProfile.LeavesDigest() ||
		firstProfile.CorrectedDeltaSourceDigest() == secondProfile.CorrectedDeltaSourceDigest() ||
		firstProfile.CorrectedDeltaPayloadDigest() == secondProfile.CorrectedDeltaPayloadDigest() {
		t.Fatal("changing a public right leaf did not change every sealed leaf/delta witness")
	}
	if firstProfile.LeftOperandSourceDigest() != secondProfile.LeftOperandSourceDigest() ||
		firstProfile.LeftOperandPayloadDigest() != secondProfile.LeftOperandPayloadDigest() {
		t.Fatal("changing only a right leaf unexpectedly changed the left operand")
	}
}

func TestSigned8RootTreeCircuitRejectsEqualPayloadOperandReplacement(t *testing.T) {
	circuit := newSigned8RootTreeUnitCircuit(t)
	changed := *circuit
	changed.graph.circuit = &changed
	changed.left = circuit.left.CopyNew()
	if err := changed.validate(); err == nil {
		t.Fatal("equal-payload left plaintext pointer replacement was accepted")
	}
	changed = *circuit
	changed.graph.circuit = &changed
	changed.correctedDelta = circuit.correctedDelta.CopyNew()
	if err := changed.validate(); err == nil {
		t.Fatal("equal-payload corrected-delta plaintext pointer replacement was accepted")
	}
}

func TestSigned8RootTreeCircuitEncodesActualTauCorrectedPayloads(t *testing.T) {
	circuit := newSigned8RootTreeUnitCircuit(t)
	ringZ, err := z2n.NewWithPrecision(z2n.Word8, signed8IntegerEncoderPrecision)
	if err != nil {
		t.Fatal(err)
	}
	leftValues, deltaValues := make([]complex128, signed8RootTreeSlots), make([]complex128, signed8RootTreeSlots)
	if err = circuit.integerEncoder.Decode(circuit.left, leftValues); err != nil {
		t.Fatal(err)
	}
	if err = circuit.integerEncoder.Decode(circuit.correctedDelta, deltaValues); err != nil {
		t.Fatal(err)
	}
	wrongControlDistinguished := false
	for wordIndex, pair := range circuit.leaves {
		leftOracle := z2n.Complex128(ringZ.ArithmeticRootSlots(uint64(uint8(pair.Left))))
		delta := uint64(uint8(int16(pair.Right) - int16(pair.Left)))
		corrected, rootErr := ringZ.ToRootSlots(ringZ.BinaryEncode(delta))
		if rootErr != nil {
			t.Fatal(rootErr)
		}
		correctedOracle := z2n.Complex128(corrected)
		wrongOracle := z2n.Complex128(ringZ.ArithmeticRootSlots(delta))
		for slot := 0; slot < signed8RootTreeWordSlots; slot++ {
			index := signed8RootTreeWordSlots*wordIndex + slot
			leftError := cmplxDistance(leftValues[index], leftOracle[slot])
			deltaError := cmplxDistance(deltaValues[index], correctedOracle[slot])
			if leftError > 5e-4 || deltaError > 5e-4 {
				t.Fatalf("word=%d slot=%d public operand root errors left=%g delta=%g exceed 5e-4", wordIndex, slot, leftError, deltaError)
			}
			if cmplxDistance(deltaValues[index], wrongOracle[slot]) > 1e-6 {
				wrongControlDistinguished = true
			}
		}
	}
	if !wrongControlDistinguished {
		t.Fatal("actual corrected-delta plaintext did not distinguish the forbidden no-tau encoding")
	}
	if circuit.correctedDelta.Level() != signed8RootTreeBranchLevel ||
		!circuit.correctedDelta.Scale.Equal(rlwe.NewScale(circuit.params.Q()[signed8RootTreeBranchLevel])) ||
		circuit.left.Level() != signed8RootTreeOutputLevel || !circuit.left.Scale.Equal(circuit.params.DefaultScale()) {
		t.Fatal("actual root-tree public operands do not carry their physical level/scale schedule")
	}
}

func cmplxDistance(left, right complex128) float64 {
	realError, imagError := real(left)-real(right), imag(left)-imag(right)
	return math.Hypot(realError, imagError)
}

func newSigned8RootTreeUnitCircuit(t *testing.T) *Signed8RootTreeCircuit {
	t.Helper()
	params, err := GaoA2BKernelFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	ranges, err := NewSigned8NoOverflowRange(-8, 7, -8, 7)
	if err != nil {
		t.Fatal(err)
	}
	circuit, err := NewSigned8RootTreeCircuit(
		params,
		ckks.NewEncoder(params, signed8RefreshEncoderPrecision),
		ckks.NewEncoder(params, signed8IntegerEncoderPrecision),
		ranges,
		Signed8PackedLeaves{{Left: -128, Right: 127}, {Left: 127, Right: -128}, {Left: -7, Right: 19}, {Left: 42, Right: -99}},
	)
	if err != nil {
		t.Fatal(err)
	}
	return circuit
}

func TestSigned8RootTreeCorrectedDeltaAlgebraExhaustive(t *testing.T) {
	ringZ, err := z2n.New(z2n.Word8)
	if err != nil {
		t.Fatal(err)
	}

	for leftWord := 0; leftWord < 256; leftWord++ {
		for rightWord := 0; rightWord < 256; rightWord++ {
			leaves := Signed8LeafPair{Left: int8(uint8(leftWord)), Right: int8(uint8(rightWord))}
			for branch := uint64(0); branch <= 1; branch++ {
				got, err := signed8RootTreeSelectSlots(ringZ, leaves, branch)
				if err != nil {
					t.Fatalf("left=%d right=%d branch=%d: %v", leaves.Left, leaves.Right, branch, err)
				}
				selected := uint64(uint8(leaves.Left))
				if branch == 1 {
					selected = uint64(uint8(leaves.Right))
				}
				recovered, err := ringZ.RecoverWord(got)
				if err != nil {
					t.Fatalf("left=%d right=%d branch=%d recover: %v", leaves.Left, leaves.Right, branch, err)
				}
				if recovered != selected {
					t.Fatalf("left=%d right=%d branch=%d recovered=%d want=%d", leaves.Left, leaves.Right, branch, recovered, selected)
				}
			}
		}
	}
}

func TestSigned8RootTreeNoTauCorrectionIsARealNegativeControl(t *testing.T) {
	ringZ, err := z2n.New(z2n.Word8)
	if err != nil {
		t.Fatal(err)
	}
	leaves := Signed8LeafPair{Left: -5, Right: 7}
	delta := uint64(uint8(int16(leaves.Right) - int16(leaves.Left)))
	left := ringZ.ArithmeticRootSlots(uint64(uint8(leaves.Left)))
	branch := ringZ.ArithmeticRootSlots(1)
	wrongDelta := ringZ.ArithmeticRootSlots(delta)
	wrong := make([]*bignum.Complex, len(left))
	for slot := range wrong {
		wrong[slot] = addComplex(left[slot], multiplyComplex(branch[slot], wrongDelta[slot]))
	}
	recovered, err := ringZ.RecoverWord(wrong)
	if err != nil {
		t.Fatal(err)
	}
	if recovered == uint64(uint8(leaves.Right)) {
		t.Fatalf("encoding delta as ArithmeticRootSlots unexpectedly selected right leaf: recovered=%d", recovered)
	}
}
