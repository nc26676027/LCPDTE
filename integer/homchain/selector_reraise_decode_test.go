package homchain

import (
	"math"
	"math/big"
	"reflect"
	"testing"

	"github.com/nc26676027/LCPDTE/integer/z2n"

	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
	"github.com/nc26676027/LCPDTE/lattigo/utils/bignum"
)

func TestSelectorReraiseDecodeConstructorProfile(t *testing.T) {
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
	if producer.PublicProfile().Digest() != selectorAcceptedPublicComparatorProfileDigest ||
		producer.OpaqueProfile().Digest() != selectorAcceptedOpaqueComparatorProfileDigest {
		t.Fatal("test producer does not carry the independently accepted comparator profiles")
	}

	circuit, err := NewSelectorReraiseDecodeCircuit(producer)
	if err != nil {
		t.Fatal(err)
	}
	profile := circuit.Profile()
	if profile.Fidelity() != SelectorReraiseDecodeFunctionalNotSecure ||
		profile.WordBits() != z2n.Word8 || profile.Words() != 4 || profile.Slots() != 16 ||
		profile.EncoderPrecision() != 192 || profile.IntegerPrecision() != 256 ||
		profile.ParameterDigest() != producer.parameterDigest || profile.RangeDigest() != ranges.Digest() ||
		profile.ProducerPublicProfileDigest() != selectorAcceptedPublicComparatorProfileDigest ||
		profile.ProducerOpaqueProfileDigest() != selectorAcceptedOpaqueComparatorProfileDigest ||
		profile.ProducerInputBindingDigest() != selectorAcceptedComparatorAdmissionDigest ||
		profile.ProducerParameterDigest() != selectorAcceptedComparatorParameterDigest ||
		profile.ProducerArithmeticOnePayloadDigest() != selectorAcceptedComparatorOnePayloadDigest ||
		profile.SelectorRepresentation() != SelectorArithmeticRootCoefficientsToPeriodicBooleanScalarRepeated ||
		profile.ResultSchema() != selectorReraiseDecodeResultSchema ||
		profile.Digest() == "" {
		t.Fatalf("selector profile is incomplete: %+v", profile)
	}
	if got := profile.ProducerAuditAnchor(); got != (SelectorReraiseDecodeComparatorAuditAnchor{
		PublicProfileDigest:        selectorAcceptedPublicComparatorProfileDigest,
		OpaqueProfileDigest:        selectorAcceptedOpaqueComparatorProfileDigest,
		AdmissionDigest:            selectorAcceptedComparatorAdmissionDigest,
		ParameterDigest:            selectorAcceptedComparatorParameterDigest,
		ArithmeticOnePayloadDigest: selectorAcceptedComparatorOnePayloadDigest,
	}) {
		t.Fatalf("selector comparator audit anchor changed: %+v", got)
	}

	v := profile.NormalV()
	if v.LowName() != V0Normal || v.HighName() != V1Normal || v.LevelQ() != 4 || v.LevelP() != 0 ||
		v.LowBabyStepSize() != 2 || v.HighBabyStepSize() != 2 ||
		!reflect.DeepEqual(v.LowDiagonalIndexes(), []int{0, 1, 2, 3, 13, 14, 15}) ||
		!reflect.DeepEqual(v.HighDiagonalIndexes(), []int{0, 1, 2, 3, 13, 14, 15}) ||
		!reflect.DeepEqual(v.RotationIndexes(), []int{1, 2, 12, 14}) ||
		!reflect.DeepEqual(v.GaloisElements(), []uint64{5, 17, 25, 41}) {
		t.Fatalf("normal V plan differs from the T1 map: %+v", v)
	}

	dft := profile.DFT()
	if dft.EncoderPrecision() != 192 || dft.GeneratorPrecision() != 192 ||
		dft.SlotsToCoeffsRawMatrixDigest() == "" || dft.SlotsToCoeffsExecutionMatrixDigest() == "" ||
		dft.CoeffsToSlotsRawMatrixDigest() == "" || dft.CoeffsToSlotsExecutionMatrixDigest() == "" ||
		dft.CoeffsToSlotsExecutionMatrixDigest() != producer.a2b.profile.SharedCTSExecutionMatrixDigest() ||
		dft.Digest() == "" {
		t.Fatalf("selector DFT profile is incomplete or CTS is not shared: %+v", dft)
	}
	stcRaw, stcExecution := dft.SlotsToCoeffsLiteral(), dft.SlotsToCoeffsExecutionLiteral()
	ctsRaw, ctsExecution := dft.CoeffsToSlotsLiteral(), dft.CoeffsToSlotsExecutionLiteral()
	if stcRaw.LevelQ != 3 || !reflect.DeepEqual(stcRaw.Levels, []int{1, 1}) ||
		stcExecution.LevelQ != 3 || !reflect.DeepEqual(stcExecution.Levels, []int{1, 1}) ||
		ctsRaw.LevelQ != 20 || !reflect.DeepEqual(ctsRaw.Levels, []int{1, 1, 1}) ||
		ctsExecution.LevelQ != 20 || !reflect.DeepEqual(ctsExecution.Levels, []int{1, 1, 1}) {
		t.Fatal("selector DFT level factorization changed")
	}

	wantPeriodic := SelectorReraiseDecodeOperationCounts{
		LinearTransformations: 7, DiagonalPlaintextProducts: 35, NonConjugationRotations: 19,
		Conjugations: 3, KeySwitches: 22, CiphertextAdditionsSubtractions: 34,
		ScalarMultiplicationsPlusMinusI: 2, ExplicitRescales: 10, ScaleDown: 1, ModUp: 1,
		ExponentialPolynomialEvaluations: 1, CiphertextCiphertextProducts: 2, Relinearizations: 2,
		CiphertextPlaintextProducts: 1, PlaintextVectorAdditions: 1,
	}
	if profile.OperationCounts() != wantPeriodic || profile.LogicalPeakLiveCiphertexts() != 8 {
		t.Fatalf("selector periodic runtime-derived ledger changed: %+v", profile.OperationCounts())
	}
	serialized := profile.ExpectedSerializedBytes()
	if !serialized.complete() || serialized.OnlineTotal() != serialized.OnlineInput+serialized.OnlineOutput ||
		serialized.RetainedTraceTotal() != serialized.RetainedNormalVLow+serialized.RetainedNormalVHigh+
			serialized.RetainedSlotsToCoeffs+serialized.RetainedRaisedCoefficients+
			serialized.RetainedCoeffsToSlotsLow+serialized.RetainedCoeffsToSlotsHigh+
			serialized.RetainedExponentialBase+serialized.RetainedPeriodicRootOfUnity {
		t.Fatalf("selector expected serialization ledger is incomplete: %+v", serialized)
	}
	if want := (SelectorReraiseDecodeSerializedBytes{
		OnlineInput: 2942, OnlineOutput: 5054,
		RetainedNormalVLow: 2414, RetainedNormalVHigh: 2414,
		RetainedSlotsToCoeffs: 1358, RetainedRaisedCoefficients: 11390,
		RetainedCoeffsToSlotsLow: 9806, RetainedCoeffsToSlotsHigh: 9806,
		RetainedExponentialBase: 6638, RetainedPeriodicRootOfUnity: 5582,
	}); serialized != want || serialized.OnlineTotal() != 7996 || serialized.RetainedTraceTotal() != 49408 {
		t.Fatalf("selector exact expected serialization ledger=%+v, want %+v", serialized, want)
	}
	if got := circuit.RequiredKeyProfile(); !reflect.DeepEqual(got.All(), []uint64{5, 17, 25, 33, 41, 49, 63}) ||
		!got.RelinearizationRequired() || got.Digest() == "" {
		t.Fatalf("selector key union changed: %+v", got)
	}
	t.Logf("selector profile=%s result-schema=%s", profile.Digest(), profile.ResultSchema())
	periodic := profile.Periodic()
	if periodic.ExponentialDepth() != 6 || periodic.InputLevel() != 17 || periodic.ExponentialLevel() != 11 ||
		periodic.Square0Level() != 10 || periodic.RootLevel() != 9 || periodic.OutputLevel() != 8 ||
		periodic.KernelProfileDigest() == "" || periodic.ExponentialProfileDigest() == "" ||
		periodic.ExponentialArtifactDigest() == "" || periodic.OperandGraphDigest() == "" ||
		periodic.AffineSourceDigest() == "" || periodic.MultiplierPayloadDigest() == "" ||
		periodic.OffsetPayloadDigest() == "" || periodic.RuntimePath() == "" {
		t.Fatalf("periodic profile is incomplete: %+v", periodic)
	}
	states := profile.States()
	wantLevels := []int{4, 4, 4, 3, 3, 2, 1, 0, 20, 19, 18, 17, 17, 17, 11, 10, 9, 9, 8}
	defaultScale, err := NewExactScaleSnapshot(params.DefaultScale())
	if err != nil {
		t.Fatal(err)
	}
	vRawScale, err := NewExactScaleSnapshot(params.DefaultScale().Mul(rlwe.NewScale(params.Q()[4])))
	if err != nil {
		t.Fatal(err)
	}
	rootScale, err := periodic.RootScale().Scale()
	if err != nil {
		t.Fatal(err)
	}
	affineRawScale, err := NewExactScaleSnapshot(rootScale.Mul(rlwe.NewScale(params.Q()[periodic.RootLevel()])))
	if err != nil {
		t.Fatal(err)
	}
	wantScales := make([]ExactScaleSnapshot, len(wantLevels))
	for index := range wantScales {
		wantScales[index] = defaultScale
	}
	wantScales[1], wantScales[2] = vRawScale, vRawScale
	wantScales[14] = periodic.ExponentialScale()
	wantScales[15] = periodic.Square0Scale()
	wantScales[16] = periodic.RootScale()
	wantScales[17] = affineRawScale
	wantScales[18] = periodic.OutputScale()
	if len(states) != len(wantLevels) {
		t.Fatalf("periodic state ledger has %d states, want %d", len(states), len(wantLevels))
	}
	for index := range states {
		if states[index].Level() != wantLevels[index] || !states[index].Scale().Equal(wantScales[index]) {
			t.Fatalf("periodic state %d changed: L%d/%s, want L%d/%s", index,
				states[index].Level(), states[index].Scale().ValueHex(), wantLevels[index], wantScales[index].ValueHex())
		}
	}
	if profile.OperationCounts().IDMSBLUTEvaluations != 0 {
		t.Fatal("periodic selector admitted a full ID/MSB LUT evaluation")
	}
}

func TestSelectorReraiseDecodeAcceptsHonestFullRangeProducerWithoutRetagging(t *testing.T) {
	params, err := GaoA2BKernelFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	ranges, err := NewSigned8NoOverflowRange(-128, 127, 0, 0)
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
	if producer.PublicProfile().Digest() == selectorAcceptedPublicComparatorProfileDigest ||
		producer.OpaqueProfile().Digest() == selectorAcceptedOpaqueComparatorProfileDigest {
		t.Fatal("full-range producer was silently retagged with the narrow audit anchor")
	}

	circuit, err := NewSelectorReraiseDecodeCircuit(producer)
	if err != nil {
		t.Fatalf("honest full-range producer was rejected: %v", err)
	}
	profile := circuit.Profile()
	if profile.RangeDigest() != ranges.Digest() ||
		profile.ProducerPublicProfileDigest() != producer.PublicProfile().Digest() ||
		profile.ProducerOpaqueProfileDigest() != producer.OpaqueProfile().Digest() ||
		profile.ProducerInputBindingDigest() != producer.PublicProfile().InputBindingDigest() {
		t.Fatalf("selector profile did not bind the actual range instance: %+v", profile)
	}
	if profile.ProducerPublicProfileDigest() == profile.ProducerAuditAnchor().PublicProfileDigest ||
		profile.ProducerOpaqueProfileDigest() == profile.ProducerAuditAnchor().OpaqueProfileDigest ||
		profile.ProducerInputBindingDigest() == profile.ProducerAuditAnchor().AdmissionDigest {
		t.Fatal("full-range selector profile collapsed its instance binding into the narrow audit anchor")
	}

	t.Run("narrow anchor cannot replace actual instance", func(t *testing.T) {
		substituted := *circuit
		substituted.graph.circuit = &substituted
		substituted.profile.producerPublicDigest = selectorAcceptedPublicComparatorProfileDigest
		substituted.profile.producerOpaqueDigest = selectorAcceptedOpaqueComparatorProfileDigest
		substituted.profile.producerAdmissionDigest = selectorAcceptedComparatorAdmissionDigest
		substituted.profile.digest = digestSelectorReraiseDecodeProfile(substituted.profile, substituted.keyProfile)
		substituted.graph.profileDigest = substituted.profile.digest
		if err := substituted.validate(); err == nil {
			t.Fatal("narrow audit anchor was accepted as the full-range producer instance")
		}
	})

	t.Run("actual instance cannot replace narrow anchor", func(t *testing.T) {
		substituted := *circuit
		substituted.graph.circuit = &substituted
		substituted.profile.producerAuditAnchor.PublicProfileDigest = producer.PublicProfile().Digest()
		substituted.profile.producerAuditAnchor.OpaqueProfileDigest = producer.OpaqueProfile().Digest()
		substituted.profile.producerAuditAnchor.AdmissionDigest = producer.PublicProfile().InputBindingDigest()
		substituted.profile.digest = digestSelectorReraiseDecodeProfile(substituted.profile, substituted.keyProfile)
		substituted.graph.profileDigest = substituted.profile.digest
		if err := substituted.validate(); err == nil {
			t.Fatal("full-range producer instance was accepted as the narrow audit anchor")
		}
	})

	returned := circuit.Profile()
	returned.normalV.lowDiagonals[0] = 99
	returned.dft.stcRaw.Levels[0] = 99
	returned.states[0].level = 99
	returned.serializedBytes.OnlineInput = 99
	returnedKeys := circuit.RequiredKeyProfile()
	returnedKeys.all[0] = 99
	if circuit.Profile().normalV.lowDiagonals[0] == 99 || circuit.Profile().dft.stcRaw.Levels[0] == 99 ||
		circuit.Profile().states[0].level == 99 || circuit.Profile().serializedBytes.OnlineInput == 99 ||
		circuit.RequiredKeyProfile().all[0] == 99 {
		t.Fatal("selector profile or key accessors alias sealed state")
	}
}

func TestSelectorPeriodicCircuitProfileAndObjectGraphSubstitutionsFailClosed(t *testing.T) {
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
	circuit, err := NewSelectorReraiseDecodeCircuit(producer)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*SelectorReraiseDecodeCircuit)
	}{
		{"periodic kernel profile digest", func(c *SelectorReraiseDecodeCircuit) { c.profile.periodic.kernelProfileDigest = "foreign" }},
		{"periodic operand graph digest", func(c *SelectorReraiseDecodeCircuit) { c.profile.periodic.operandGraphDigest = "foreign" }},
		{"periodic affine source digest", func(c *SelectorReraiseDecodeCircuit) { c.profile.periodic.affineSourceDigest = "foreign" }},
		{"periodic multiplier payload digest", func(c *SelectorReraiseDecodeCircuit) { c.profile.periodic.multiplierPayloadDigest = "foreign" }},
		{"periodic offset payload digest", func(c *SelectorReraiseDecodeCircuit) { c.profile.periodic.offsetPayloadDigest = "foreign" }},
		{"result schema", func(c *SelectorReraiseDecodeCircuit) { c.profile.resultSchema = "foreign" }},
		{"periodic operation count", func(c *SelectorReraiseDecodeCircuit) { c.profile.operationCounts.IDMSBLUTEvaluations = 1 }},
		{"serialized-byte ledger", func(c *SelectorReraiseDecodeCircuit) { c.profile.serializedBytes.OnlineOutput++ }},
		{"periodic state ledger", func(c *SelectorReraiseDecodeCircuit) { c.profile.states[18].level = 7 }},
		{"periodic affine source object", func(c *SelectorReraiseDecodeCircuit) { c.affineSource.digest = "foreign" }},
		{"periodic multiplier object", func(c *SelectorReraiseDecodeCircuit) { c.affineMultiplier = c.affineMultiplier.CopyNew() }},
		{"periodic offset object", func(c *SelectorReraiseDecodeCircuit) { c.affineOffset = c.affineOffset.CopyNew() }},
		{"periodic kernel object", func(c *SelectorReraiseDecodeCircuit) {
			child := *c.kernel
			c.kernel = &child
		}},
		{"normal V Vec pointer", func(c *SelectorReraiseDecodeCircuit) { c.graph.normalVLow = 0 }},
		{"STC factor pointer", func(c *SelectorReraiseDecodeCircuit) { c.graph.stcFactors[0] = 0 }},
		{"CTS factor payload", func(c *SelectorReraiseDecodeCircuit) { c.graph.ctsDigests[0] = "foreign" }},
		{"key union", func(c *SelectorReraiseDecodeCircuit) { c.keyProfile.all[0] = 99 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := *circuit
			changed.profile = cloneSelectorReraiseDecodeProfile(circuit.profile)
			changed.keyProfile = circuit.RequiredKeyProfile()
			changed.graph = circuit.graph
			changed.graph.stcFactors = append([]uintptr(nil), circuit.graph.stcFactors...)
			changed.graph.ctsFactors = append([]uintptr(nil), circuit.graph.ctsFactors...)
			changed.graph.stcDigests = append([]string(nil), circuit.graph.stcDigests...)
			changed.graph.ctsDigests = append([]string(nil), circuit.graph.ctsDigests...)
			changed.graph.circuit = &changed
			test.mutate(&changed)
			changed.profile.digest = digestSelectorReraiseDecodeProfile(changed.profile, changed.keyProfile)
			changed.graph.profileDigest = changed.profile.digest
			if err := changed.validate(); err == nil {
				t.Fatal("selector periodic substitution was accepted")
			}
		})
	}
}

func TestSelectorLinearDUControlIsCorrectlyComposedButFalsifiedByIntegralLift(t *testing.T) {
	algebra, err := newSelectorReraiseDecodeAlgebra()
	if err != nil {
		t.Fatal(err)
	}

	ringZ, err := z2n.NewWithPrecision(z2n.Word8, selectorReraiseDecodeIntegerPrecision)
	if err != nil {
		t.Fatal(err)
	}
	wantD := selectorTestDecoderOracle(t, ringZ)
	selectorTestAssertMatrixClose(t, algebra.decoder.Matrix(), wantD, 1e-70)

	for _, bits := range [][selectorReraiseDecodeWords]uint64{
		{0, 0, 0, 0},
		{1, 1, 1, 1},
		{0, 1, 1, 0},
	} {
		input := selectorTestPackedArithmeticRoots(ringZ, bits)
		got, evalErr := algebra.decoder.EvaluatePlaintext(input)
		if evalErr != nil {
			t.Fatal(evalErr)
		}
		for word, bit := range bits {
			for slot := 0; slot < selectorReraiseDecodeHalfWidth; slot++ {
				selectorTestAssertComplexClose(t, got[word*selectorReraiseDecodeHalfWidth+slot], float64(bit), 0, 1e-35)
			}
		}
	}

	for _, half := range []struct {
		name   string
		normal TransformSpec
		fused  TransformSpec
	}{
		{name: "low", normal: algebra.normalU.Low, fused: algebra.fused.Low},
		{name: "high", normal: algebra.normalU.High, fused: algebra.fused.High},
	} {
		t.Run("D-times-U-"+half.name, func(t *testing.T) {
			want := selectorTestMatrixProduct(t, wantD, half.normal.Matrix())
			selectorTestAssertMatrixClose(t, half.fused.Matrix(), want, 1e-70)

			wrongOrientation := selectorTestMatrixProduct(t, half.normal.Matrix(), wantD)
			if selectorTestMatricesClose(half.fused.Matrix(), wrongOrientation, 1e-35) {
				t.Fatal("fused selector decoder accepted U*D; want left composition D*U")
			}
		})
	}

	// These independently built controls pin all three normalization choices.
	// Each must disagree with the production D on at least one entry.
	tauSlots, err := ringZ.ToRootSlots(ringZ.Tau())
	if err != nil {
		t.Fatal(err)
	}
	noTau := selectorTestConstantRows(tauSlots, false, true)
	noQuarter := selectorTestConstantRows(tauSlots, true, false)
	if selectorTestMatricesClose(algebra.decoder.Matrix(), noTau, 1e-35) {
		t.Fatal("selector decoder omitted tau")
	}
	if selectorTestMatricesClose(algebra.decoder.Matrix(), noQuarter, 1e-35) {
		t.Fatal("selector decoder omitted the 1/4 normalization")
	}

	ordinary, err := NewSpecificationsFromRing(ringZ, selectorReraiseDecodeWords)
	if err != nil {
		t.Fatal(err)
	}
	fusedTInvWrong := selectorTestMatrixProduct(t, wantD, ordinary.UFusedTInvPair().Low.Matrix())
	if selectorTestMatricesClose(algebra.fused.Low.Matrix(), fusedTInvWrong, 1e-35) {
		t.Fatal("selector decoder used fused-tInv U instead of normal U")
	}

	// The old D*U candidate is algebraically composed correctly, but it is not
	// invariant under the integral coefficient lift introduced by CTS. This is
	// the deterministic design falsification that motivated the periodic path.
	liftLow := make([]*bignum.Complex, selectorReraiseDecodeWords*selectorReraiseDecodeHalfWidth)
	liftHigh := make([]*bignum.Complex, len(liftLow))
	for index := range liftLow {
		liftLow[index] = &bignum.Complex{new(big.Float).SetPrec(256), new(big.Float).SetPrec(256)}
		liftHigh[index] = &bignum.Complex{new(big.Float).SetPrec(256), new(big.Float).SetPrec(256)}
	}
	for word := 0; word < selectorReraiseDecodeWords; word++ {
		liftLow[word*selectorReraiseDecodeHalfWidth].Real().SetInt64(1)
	}
	fusedLow, err := algebra.fused.Low.EvaluatePlaintext(liftLow)
	if err != nil {
		t.Fatal(err)
	}
	fusedHigh, err := algebra.fused.High.EvaluatePlaintext(liftHigh)
	if err != nil {
		t.Fatal(err)
	}
	wronglyDecoded := make([]*bignum.Complex, len(fusedLow))
	nonzero := false
	for index := range fusedLow {
		wronglyDecoded[index] = &bignum.Complex{
			new(big.Float).SetPrec(256).Add(fusedLow[index].Real(), fusedHigh[index].Real()),
			new(big.Float).SetPrec(256).Add(fusedLow[index].Imag(), fusedHigh[index].Imag()),
		}
		realValue, _ := wronglyDecoded[index].Real().Float64()
		imaginaryValue, _ := wronglyDecoded[index].Imag().Float64()
		nonzero = nonzero || math.Abs(realValue) > 1e-8 || math.Abs(imaginaryValue) > 1e-8
	}
	if !nonzero {
		t.Fatal("linear D*U unexpectedly removed a nonzero integral CTS lift")
	}
}

func TestSelectorPeriodicBooleanAffinePlaintextAllPatterns(t *testing.T) {
	const precision = uint(256)
	source, err := newSelectorPeriodicAffineSource(precision)
	if err != nil {
		t.Fatal(err)
	}
	if len(source.multiplier) != 16 || len(source.offset) != 16 || source.digest == "" {
		t.Fatalf("periodic affine source is incomplete: multipliers=%d offsets=%d digest=%q", len(source.multiplier), len(source.offset), source.digest)
	}
	var lifts [selectorReraiseDecodeWords * selectorReraiseDecodeHalfWidth]int64
	for index := range lifts {
		// Nonuniform lifts make block/lane aliasing visible while staying well
		// inside the accepted exp46 approximation interval after division by 16.
		lifts[index] = int64(index%13) - 6
	}
	tolerance := new(big.Float).SetPrec(precision).SetInt64(1)
	tolerance.SetMantExp(tolerance, -200)
	for pattern := 0; pattern < 1<<selectorReraiseDecodeWords; pattern++ {
		var bits [selectorReraiseDecodeWords]uint64
		for word := range bits {
			bits[word] = uint64((pattern >> word) & 1)
		}
		decoded, evalErr := evaluateSelectorPeriodicBooleanOracle(bits, lifts, precision)
		if evalErr != nil {
			t.Fatalf("pattern=%04b: %v", pattern, evalErr)
		}
		for word, bit := range bits {
			for slot := 0; slot < selectorReraiseDecodeHalfWidth; slot++ {
				index := word*selectorReraiseDecodeHalfWidth + slot
				realError := new(big.Float).SetPrec(precision).Sub(decoded[index].Real(), new(big.Float).SetPrec(precision).SetUint64(bit))
				realError.Abs(realError)
				imaginaryError := new(big.Float).SetPrec(precision).Abs(decoded[index].Imag())
				if realError.Cmp(tolerance) > 0 || imaginaryError.Cmp(tolerance) > 0 {
					t.Fatalf("pattern=%04b word=%d slot=%d got=(%s,%s), want=%d within 2^-200", pattern, word, slot,
						decoded[index].Real().Text('g', 12), decoded[index].Imag().Text('g', 12), bit)
				}
			}
		}
	}
}

func selectorTestDecoderOracle(t *testing.T, ringZ *z2n.Ring) Matrix {
	t.Helper()
	tauSlots, err := ringZ.ToRootSlots(ringZ.Tau())
	if err != nil {
		t.Fatal(err)
	}
	return selectorTestConstantRows(tauSlots, true, true)
}

func selectorTestConstantRows(tauSlots []*bignum.Complex, includeTau, divideByFour bool) Matrix {
	result := make(Matrix, selectorReraiseDecodeHalfWidth)
	for row := range result {
		result[row] = make([]*bignum.Complex, selectorReraiseDecodeHalfWidth)
		for column := range result[row] {
			value := &bignum.Complex{
				new(big.Float).SetPrec(selectorReraiseDecodeIntegerPrecision),
				new(big.Float).SetPrec(selectorReraiseDecodeIntegerPrecision),
			}
			if includeTau {
				value.Real().Set(tauSlots[column].Real())
				value.Imag().Set(tauSlots[column].Imag())
			} else {
				value.Real().SetInt64(1)
			}
			if divideByFour {
				four := new(big.Float).SetPrec(selectorReraiseDecodeIntegerPrecision).SetInt64(4)
				value.Real().Quo(value.Real(), four)
				value.Imag().Quo(value.Imag(), four)
			}
			result[row][column] = value
		}
	}
	return result
}

func selectorTestPackedArithmeticRoots(ringZ *z2n.Ring, words [selectorReraiseDecodeWords]uint64) []*bignum.Complex {
	result := make([]*bignum.Complex, 0, selectorReraiseDecodeWords*selectorReraiseDecodeHalfWidth)
	for _, word := range words {
		result = append(result, ringZ.ArithmeticRootSlots(word)...)
	}
	return result
}

func selectorTestMatrixProduct(t *testing.T, lhs, rhs Matrix) Matrix {
	t.Helper()
	if len(lhs) == 0 || len(rhs) == 0 || len(lhs[0]) != len(rhs) {
		t.Fatalf("invalid matrix product dimensions %dx%d times %dx%d", len(lhs), len(lhs[0]), len(rhs), len(rhs[0]))
	}
	precision := uint(selectorReraiseDecodeIntegerPrecision)
	result := make(Matrix, len(lhs))
	for row := range lhs {
		result[row] = make([]*bignum.Complex, len(rhs[0]))
		for column := range rhs[0] {
			sum := &bignum.Complex{new(big.Float).SetPrec(precision), new(big.Float).SetPrec(precision)}
			for inner := range rhs {
				term := selectorTestComplexProduct(lhs[row][inner], rhs[inner][column], precision)
				sum.Real().Add(sum.Real(), term.Real())
				sum.Imag().Add(sum.Imag(), term.Imag())
			}
			result[row][column] = sum
		}
	}
	return result
}

func selectorTestComplexProduct(lhs, rhs *bignum.Complex, precision uint) *bignum.Complex {
	ac := new(big.Float).SetPrec(precision).Mul(lhs.Real(), rhs.Real())
	bd := new(big.Float).SetPrec(precision).Mul(lhs.Imag(), rhs.Imag())
	ad := new(big.Float).SetPrec(precision).Mul(lhs.Real(), rhs.Imag())
	bc := new(big.Float).SetPrec(precision).Mul(lhs.Imag(), rhs.Real())
	return &bignum.Complex{
		new(big.Float).SetPrec(precision).Sub(ac, bd),
		new(big.Float).SetPrec(precision).Add(ad, bc),
	}
}

func selectorTestAssertMatrixClose(t *testing.T, got, want Matrix, tolerance float64) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("matrix row count=%d, want %d", len(got), len(want))
	}
	for row := range want {
		if len(got[row]) != len(want[row]) {
			t.Fatalf("matrix row %d width=%d, want %d", row, len(got[row]), len(want[row]))
		}
		for column := range want[row] {
			wr, _ := want[row][column].Real().Float64()
			wi, _ := want[row][column].Imag().Float64()
			selectorTestAssertComplexClose(t, got[row][column], wr, wi, tolerance)
		}
	}
}

func selectorTestMatricesClose(lhs, rhs Matrix, tolerance float64) bool {
	if len(lhs) != len(rhs) {
		return false
	}
	for row := range lhs {
		if len(lhs[row]) != len(rhs[row]) {
			return false
		}
		for column := range lhs[row] {
			lr, _ := lhs[row][column].Real().Float64()
			li, _ := lhs[row][column].Imag().Float64()
			rr, _ := rhs[row][column].Real().Float64()
			ri, _ := rhs[row][column].Imag().Float64()
			if absFloat(lr-rr) > tolerance || absFloat(li-ri) > tolerance {
				return false
			}
		}
	}
	return true
}

func selectorTestAssertComplexClose(t *testing.T, got *bignum.Complex, wantReal, wantImag, tolerance float64) {
	t.Helper()
	gotReal, _ := got.Real().Float64()
	gotImag, _ := got.Imag().Float64()
	if absFloat(gotReal-wantReal) > tolerance || absFloat(gotImag-wantImag) > tolerance {
		t.Fatalf("got %.17g%+.17gi, want %.17g%+.17gi (tol=%g)", gotReal, gotImag, wantReal, wantImag, tolerance)
	}
}

func absFloat(value float64) float64 {
	if value < 0 {
		return -value
	}
	return value
}
