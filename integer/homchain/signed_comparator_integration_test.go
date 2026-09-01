package homchain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/nc26676027/LCPDTE/integer/z2n"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/mod1"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func TestSigned8NoOverflowRangeAcceptedCertificates(t *testing.T) {
	tests := []struct {
		name                       string
		xMin, xMax, tMin, tMax     int64
		wantDifferenceMin, wantMax int64
		frozenDigest               string
	}{
		{name: "full feature against zero", xMin: -128, xMax: 127, tMin: 0, tMax: 0, wantDifferenceMin: -128, wantMax: 127, frozenDigest: "de216af4d5a6e13e71667dc1cbe959b083452d9c49448fd4ea9db4e782ffc215"},
		{name: "symmetric narrow boxes", xMin: -8, xMax: 7, tMin: -8, tMax: 7, wantDifferenceMin: -15, wantMax: 15, frozenDigest: "a8819b509766568b8f68c744363cf90ef9aa6c1a1f2936b7328787228138d9e4"},
		{name: "negative boundary", xMin: -128, xMax: -128, tMin: 0, tMax: 0, wantDifferenceMin: -128, wantMax: -128},
		{name: "positive boundary", xMin: 127, xMax: 127, tMin: 0, tMax: 0, wantDifferenceMin: 127, wantMax: 127},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			certificate, err := NewSigned8NoOverflowRange(test.xMin, test.xMax, test.tMin, test.tMax)
			if err != nil {
				t.Fatal(err)
			}
			if err = validateSigned8NoOverflowRange(certificate); err != nil {
				t.Fatalf("fresh certificate does not self-validate: %v", err)
			}
			if certificate.XMinimum() != test.xMin || certificate.XMaximum() != test.xMax ||
				certificate.ThresholdMinimum() != test.tMin || certificate.ThresholdMaximum() != test.tMax ||
				certificate.DifferenceMinimum() != test.wantDifferenceMin || certificate.DifferenceMaximum() != test.wantMax {
				t.Fatalf("certificate endpoint mismatch: %+v", certificate)
			}
			if certificate.WordBits() != z2n.Word8 || certificate.Signedness() != Signed8TwosComplement ||
				certificate.Predicate() != Signed8GreaterThanOrEqual || certificate.ChildConvention() != Signed8ZeroLTOneGE ||
				certificate.ProofStatus() != Signed8InternallyDerivedEndpointInterval ||
				certificate.OverflowContract() != Signed8SameWidthSubtractionNoOverflow ||
				certificate.DigestSchema() != signed8NoOverflowRangeDigestSchema {
				t.Fatalf("fixed signed comparator metadata changed: %+v", certificate)
			}
			wantDigest := signed8RangeOracleDigest(
				test.xMin, test.xMax, test.tMin, test.tMax,
				test.wantDifferenceMin, test.wantMax,
			)
			if certificate.Digest() != wantDigest {
				t.Fatalf("range digest=%s, want %s", certificate.Digest(), wantDigest)
			}
			if test.frozenDigest != "" && certificate.Digest() != test.frozenDigest {
				t.Fatalf("frozen range digest=%s, want %s", certificate.Digest(), test.frozenDigest)
			}

			second, secondErr := NewSigned8NoOverflowRange(test.xMin, test.xMax, test.tMin, test.tMax)
			if secondErr != nil || second != certificate {
				t.Fatalf("range certificate is not deterministic: second=%+v err=%v", second, secondErr)
			}
		})
	}
}

func TestSigned8NoOverflowRangeExhaustiveSingletonPolicy(t *testing.T) {
	accepted, rejected := 0, 0
	for x := int64(-128); x <= 127; x++ {
		for threshold := int64(-128); threshold <= 127; threshold++ {
			difference := x - threshold
			certificate, err := NewSigned8NoOverflowRange(x, x, threshold, threshold)
			wantAccepted := difference >= -128 && difference <= 127
			if wantAccepted {
				accepted++
				if err != nil {
					t.Fatalf("x=%d threshold=%d difference=%d should be admitted: %v", x, threshold, difference, err)
				}
				if certificate.DifferenceMinimum() != difference || certificate.DifferenceMaximum() != difference {
					t.Fatalf("x=%d threshold=%d: derived singleton difference=%d/%d, want %d",
						x, threshold, certificate.DifferenceMinimum(), certificate.DifferenceMaximum(), difference)
				}
				if err = validateSigned8NoOverflowRange(certificate); err != nil {
					t.Fatalf("x=%d threshold=%d: admitted certificate failed validation: %v", x, threshold, err)
				}
			} else {
				rejected++
				if err == nil {
					t.Fatalf("x=%d threshold=%d difference=%d should fail closed", x, threshold, difference)
				}
			}
		}
	}
	if accepted != 49152 || rejected != 16384 {
		t.Fatalf("unexpected exhaustive singleton partition: accepted=%d rejected=%d", accepted, rejected)
	}
}

func TestSigned8ComparatorIndependentZ256OracleMatchesNoOverflowPolicy(t *testing.T) {
	for x := int64(-128); x <= 127; x++ {
		for threshold := int64(-128); threshold <= 127; threshold++ {
			difference := x - threshold
			if difference < -128 || difference > 127 {
				continue
			}
			var signedWant uint64
			if x >= threshold {
				signedWant = 1
			}
			if got := signed8GEZ256Oracle(x, threshold); got != signedWant {
				t.Fatalf("independent Z_256 oracle x=%d threshold=%d difference=%d: got %d want %d", x, threshold, difference, got, signedWant)
			}
		}
	}
}

func TestSigned8NoOverflowRangeRejectsInvalidAndOverflowingBoxes(t *testing.T) {
	tests := []struct {
		name                   string
		xMin, xMax, tMin, tMax int64
	}{
		{name: "full Cartesian box", xMin: -128, xMax: 127, tMin: -128, tMax: 127},
		{name: "positive overflow witness", xMin: 127, xMax: 127, tMin: -1, tMax: -1},
		{name: "negative overflow witness", xMin: -128, xMax: -128, tMin: 1, tMax: 1},
		{name: "reversed feature", xMin: 1, xMax: 0, tMin: 0, tMax: 0},
		{name: "reversed threshold", xMin: 0, xMax: 0, tMin: 1, tMax: 0},
		{name: "feature lower out of domain", xMin: -129, xMax: 0, tMin: 0, tMax: 0},
		{name: "feature upper out of domain", xMin: 0, xMax: 128, tMin: 0, tMax: 0},
		{name: "threshold lower out of domain", xMin: 0, xMax: 0, tMin: -129, tMax: 0},
		{name: "threshold upper out of domain", xMin: 0, xMax: 0, tMin: 0, tMax: 128},
		{name: "machine extremes cannot wrap", xMin: math.MinInt64, xMax: math.MaxInt64, tMin: math.MinInt64, tMax: math.MaxInt64},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if certificate, err := NewSigned8NoOverflowRange(test.xMin, test.xMax, test.tMin, test.tMax); err == nil {
				t.Fatalf("invalid interval was admitted: %+v", certificate)
			}
		})
	}
}

func TestSigned8NoOverflowRangeFailsClosedOnMetadataOrDigestMutation(t *testing.T) {
	base, err := NewSigned8NoOverflowRange(-8, 7, -8, 7)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := NewSigned8NoOverflowRange(-128, 127, 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	mutations := map[string]func(*Signed8NoOverflowRange){
		"source endpoint":      func(r *Signed8NoOverflowRange) { r.xMin++ },
		"derived endpoint":     func(r *Signed8NoOverflowRange) { r.differenceMax++ },
		"width":                func(r *Signed8NoOverflowRange) { r.wordBits = z2n.Word16 },
		"signedness":           func(r *Signed8NoOverflowRange) { r.signedness = Signed8Signedness("unsigned") },
		"comparator":           func(r *Signed8NoOverflowRange) { r.predicate = Signed8ComparatorPredicate("lt") },
		"child convention":     func(r *Signed8NoOverflowRange) { r.children = Signed8ChildConvention("0=ge,1=lt") },
		"proof contract":       func(r *Signed8NoOverflowRange) { r.proofStatus = Signed8RangeProofStatus("caller_asserted") },
		"overflow contract":    func(r *Signed8NoOverflowRange) { r.overflow = Signed8OverflowContract("wrapping") },
		"empty digest":         func(r *Signed8NoOverflowRange) { r.digest = "" },
		"foreign range digest": func(r *Signed8NoOverflowRange) { r.digest = foreign.Digest() },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			if err := validateSigned8NoOverflowRange(changed); err == nil {
				t.Fatalf("mutated certificate passed validation: %+v", changed)
			}
		})
	}
	if err := validateSigned8NoOverflowRange(Signed8NoOverflowRange{}); err == nil {
		t.Fatal("zero-value range certificate passed validation")
	}
}

func TestSigned8ComparatorAPIIsOpaqueAndInvalidGraphsFailBeforeExecution(t *testing.T) {
	var _ func(int64, int64, int64, int64) (Signed8NoOverflowRange, error) = NewSigned8NoOverflowRange
	var _ func(ckks.Parameters, *ckks.Encoder, *ckks.Encoder, Signed8NoOverflowRange) (*Signed8ComparatorCircuit, error) = NewSigned8ComparatorCircuit
	var _ func(*Signed8ComparatorCircuit, *bootstrapping.Evaluator) (*Signed8ComparatorEvaluator, error) = (*Signed8ComparatorCircuit).BindEvaluator
	var _ func(*Signed8ComparatorCircuit, *rlwe.Ciphertext, ckks.Parameters) (Signed8FeatureInput, error) = (*Signed8ComparatorCircuit).BindFeature
	var _ func(*Signed8ComparatorCircuit, *rlwe.Ciphertext, ckks.Parameters) (Signed8OpaqueThresholdInput, error) = (*Signed8ComparatorCircuit).BindOpaqueThreshold

	for _, object := range []any{
		Signed8NoOverflowRange{}, Signed8FeatureInput{}, Signed8OpaqueThresholdInput{},
		Signed8ComparatorResult{}, Signed8ComparatorTrace{}, Signed8ComparatorCircuit{}, Signed8ComparatorEvaluator{},
	} {
		typeOf := reflect.TypeOf(object)
		for index := 0; index < typeOf.NumField(); index++ {
			if typeOf.Field(index).IsExported() {
				t.Fatalf("%s exposes mutable field %q", typeOf.Name(), typeOf.Field(index).Name)
			}
		}
	}
	for _, typeOf := range []reflect.Type{
		reflect.TypeOf((*Signed8ComparatorCircuit)(nil)),
		reflect.TypeOf((*Signed8ComparatorEvaluator)(nil)),
	} {
		for methodIndex := 0; methodIndex < typeOf.NumMethod(); methodIndex++ {
			method := typeOf.Method(methodIndex)
			for inputIndex := 0; inputIndex < method.Type.NumIn(); inputIndex++ {
				parameter := method.Type.In(inputIndex)
				if parameter == reflect.TypeOf(SignFusionBooleanHalfRole("")) || parameter == reflect.TypeOf(SignFusionBitOrder("")) {
					t.Fatalf("public comparator API %s exposes raw sign-fusion role/order", method.Name)
				}
			}
		}
	}

	ranges, err := NewSigned8NoOverflowRange(-8, 7, -8, 7)
	if err != nil {
		t.Fatal(err)
	}
	if constructed, constructionErr := NewSigned8ComparatorCircuit(ckks.Parameters{}, nil, nil, ranges); constructed != nil || constructionErr == nil {
		t.Fatalf("invalid constructor inputs did not fail closed: circuit=%p err=%v", constructed, constructionErr)
	}

	var nilCircuit *Signed8ComparatorCircuit
	if _, err := nilCircuit.BindEvaluator(nil); err == nil {
		t.Fatal("nil circuit did not fail closed")
	}
	forgedCircuit := &Signed8ComparatorCircuit{ranges: ranges}
	forgedSource := &bootstrapping.Evaluator{}
	if evaluator, bindErr := forgedCircuit.BindEvaluator(forgedSource); evaluator != nil || bindErr == nil {
		t.Fatalf("forged nonnil circuit did not fail closed: evaluator=%p err=%v", evaluator, bindErr)
	}

	var nilEvaluator *Signed8ComparatorEvaluator
	if result, trace, err := nilEvaluator.CompareGEPublicNew(Signed8FeatureInput{}, [4]int64{}); err == nil || !reflect.DeepEqual(result, Signed8ComparatorResult{}) || !signed8TraceIsZero(trace) {
		t.Fatalf("nil public comparator did not fail closed: result=%+v trace=%+v err=%v", result, trace, err)
	}
	if result, trace, err := nilEvaluator.CompareGEOpaqueNew(Signed8FeatureInput{}, Signed8OpaqueThresholdInput{}); err == nil || !reflect.DeepEqual(result, Signed8ComparatorResult{}) || !signed8TraceIsZero(trace) {
		t.Fatalf("nil opaque comparator did not fail closed: result=%+v trace=%+v err=%v", result, trace, err)
	}

	featureCiphertext := &rlwe.Ciphertext{}
	thresholdCiphertext := &rlwe.Ciphertext{}
	feature := Signed8FeatureInput{ciphertext: featureCiphertext, rangeDigest: ranges.Digest(), provenanceDigest: "feature-provenance"}
	threshold := Signed8OpaqueThresholdInput{ciphertext: thresholdCiphertext, rangeDigest: ranges.Digest(), provenanceDigest: "threshold-provenance"}
	featureBefore, thresholdBefore := feature, threshold
	featureCiphertextBefore, thresholdCiphertextBefore := *featureCiphertext, *thresholdCiphertext
	publicThresholds := [4]int64{-8, -1, 0, 7}
	publicThresholdsBefore := publicThresholds
	nonnilEvaluator := &Signed8ComparatorEvaluator{circuit: forgedCircuit, source: forgedSource}

	publicResult, publicTrace, publicErr := nonnilEvaluator.CompareGEPublicNew(feature, publicThresholds)
	if !reflect.DeepEqual(publicResult, Signed8ComparatorResult{}) || !signed8TraceIsZero(publicTrace) || publicErr == nil {
		t.Fatalf("forged nonnil public path did not fail closed: result=%+v trace=%+v err=%v", publicResult, publicTrace, publicErr)
	}
	opaqueResult, opaqueTrace, opaqueErr := nonnilEvaluator.CompareGEOpaqueNew(feature, threshold)
	if !reflect.DeepEqual(opaqueResult, Signed8ComparatorResult{}) || !signed8TraceIsZero(opaqueTrace) || opaqueErr == nil {
		t.Fatalf("forged nonnil opaque path did not fail closed: result=%+v trace=%+v err=%v", opaqueResult, opaqueTrace, opaqueErr)
	}
	if feature != featureBefore || threshold != thresholdBefore || publicThresholds != publicThresholdsBefore ||
		!reflect.DeepEqual(*featureCiphertext, featureCiphertextBefore) || !reflect.DeepEqual(*thresholdCiphertext, thresholdCiphertextBefore) {
		t.Fatal("Phase-A closed execution path mutated a ciphertext or opaque/public input")
	}
}

func TestSigned8ComparatorProfilesSealAcceptedChildrenPrecisionRolesAndArithmeticOne(t *testing.T) {
	params, err := GaoA2BKernelFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	ranges, err := NewSigned8NoOverflowRange(-8, 7, -8, 7)
	if err != nil {
		t.Fatal(err)
	}
	refreshEncoder := ckks.NewEncoder(params, signed8RefreshEncoderPrecision)
	integerEncoder := ckks.NewEncoder(params, signed8IntegerEncoderPrecision)
	circuit, err := NewSigned8ComparatorCircuit(params, refreshEncoder, integerEncoder, ranges)
	if err != nil {
		t.Fatal(err)
	}
	public, opaque := circuit.PublicProfile(), circuit.OpaqueProfile()
	for label, profile := range map[string]Signed8ComparatorProfile{"public": public, "opaque": opaque} {
		if profile.DigestSchema() != signed8ComparatorProfileSchema || profile.Digest() == "" ||
			profile.Fidelity() != Signed8ComparatorLattigoFunctionalComposition || profile.Maturity() != Signed8ComparatorFunctionalNotSecure ||
			profile.WordBits() != z2n.Word8 || profile.Words() != 4 || profile.Slots() != 16 ||
			profile.RefreshEncoderPrecision() != 192 || profile.IntegerEncoderPrecision() != 256 ||
			profile.Predicate() != Signed8GreaterThanOrEqual || profile.ChildConvention() != Signed8ZeroLTOneGE ||
			profile.BindingAssumption() != signed8TrustedAdmissionAssumption || profile.RangeDigest() != ranges.Digest() ||
			profile.ParameterDigest() != signed8AcceptedSignParameterDigest || profile.InputBindingDigest() == "" ||
			profile.A2BProfileDigest() != signed8AcceptedA2BProfileDigest || profile.A2BKeyProfileDigest() == "" ||
			profile.SignParameterDigest() != signed8AcceptedSignParameterDigest ||
			profile.SignSourceDigest() != signed8AcceptedSignSourceDigest ||
			profile.SignCompiledDigest() != signed8AcceptedSignCompiledDigest ||
			profile.SignProfileDigest() != signed8AcceptedSignProfileDigest || profile.ArithmeticOnePayloadDigest() == "" ||
			profile.LevelLedger() != signed8ComparatorLevelLedger || profile.NormalizedInputCertified() ||
			!profile.RequiresRelinearization() || len(profile.RequiredGaloisElements()) == 0 {
			t.Fatalf("%s signed8 profile changed: %+v", label, profile)
		}
		for name, state := range map[string]struct {
			got       Signed8ComparatorStateProfile
			wantLevel int
		}{
			"input": {profile.InputState(), 20}, "difference": {profile.DifferenceState(), 20},
			"high": {profile.HighMSBState(), 5}, "sign": {profile.SignState(), 4}, "output": {profile.OutputState(), 4},
		} {
			if state.got.Level() != state.wantLevel || state.got.Degree() != 1 ||
				state.got.LogDimensions() != params.LogMaxDimensions() || !state.got.Scale().EqualScale(params.DefaultScale()) {
				t.Fatalf("%s %s state changed: %+v", label, name, state.got)
			}
		}
		if profile.SerialA2BOperationCounts() != circuit.a2b.profile.operationCounts ||
			profile.SignOperationCounts() != circuit.sign.profile.operationCounts ||
			profile.KernelOperationCounts() != [2]GaoA2BKernelOperationCounts{{1, 2, 1, 1, 0, 2, 2}, {1, 2, 1, 1, 0, 2, 2}} {
			t.Fatalf("%s nested operation ledger changed", label)
		}
	}
	if public.OperandMode() != Signed8PublicThresholdCTPT || opaque.OperandMode() != Signed8OpaqueThresholdCTCT || public.Digest() == opaque.Digest() {
		t.Fatal("public and opaque comparator profiles are not distinct")
	}
	t.Logf("signed8 profile digests: public=%s opaque=%s binding=%s one=%s keys=%s",
		public.Digest(), opaque.Digest(), public.InputBindingDigest(), public.ArithmeticOnePayloadDigest(), public.A2BKeyProfileDigest())
	for label, pair := range map[string][2]string{
		"public profile":  {public.Digest(), "5075bdf6ee94736fb4dc4755c07f14fdf303f149dab5750440ca030f9f9710bc"},
		"opaque profile":  {opaque.Digest(), "0d62c312fe3084984a350de3dad44ed4ad90bcaa4e8a8370bddc45c7c2e2ee63"},
		"input binding":   {public.InputBindingDigest(), "6815c10bab78ee55ad8c53fdeb30fd665e8cfc38028e8bce4bd384852db9b94b"},
		"arithmetic one":  {public.ArithmeticOnePayloadDigest(), "64b6f5a5fac15062c9a3eb83950da2c2abdbb6f77b3db4eb1a44bff097646592"},
		"A2B key profile": {public.A2BKeyProfileDigest(), "798b57c477bbe8a8ea001e0ad784a44e95d70ec29143d3c3460ecdcf11f5f6a0"},
	} {
		if pair[0] != pair[1] {
			t.Fatalf("frozen signed8 %s digest=%s, want %s", label, pair[0], pair[1])
		}
	}
	if public.WrapperOperationCounts() != (Signed8ComparatorWrapperOperationCounts{CiphertextPlaintextSubtractions: 1, Negations: 1, CiphertextPlaintextVectorAdditions: 1}) ||
		opaque.WrapperOperationCounts() != (Signed8ComparatorWrapperOperationCounts{CiphertextCiphertextSubtractions: 1, Negations: 1, CiphertextPlaintextVectorAdditions: 1}) ||
		public.SetupCounts() != (Signed8ComparatorSetupCounts{CachedArithmeticOneEncodings: 1, PerEvaluationThresholdEncodings: 1, InternalSerialA2BRefreshInvocations: 2}) ||
		opaque.SetupCounts() != (Signed8ComparatorSetupCounts{CachedArithmeticOneEncodings: 1, InternalSerialA2BRefreshInvocations: 2}) ||
		public.WrapperLogicalPeakLiveCiphertexts() != 8 || opaque.WrapperLogicalPeakLiveCiphertexts() != 10 {
		t.Fatal("mode-specific wrapper/setup ledger changed")
	}
	if circuit.arithmeticOne == circuit.arithmeticOneSeal || !circuit.arithmeticOne.Equal(circuit.arithmeticOneSeal) {
		t.Fatal("cached arithmetic one does not have an independent sealed payload copy")
	}
	sealedOneDigest, err := signed8PlaintextDigest(circuit.arithmeticOneSeal)
	if err != nil {
		t.Fatal(err)
	}
	if circuit.arithmeticOneDigest != public.ArithmeticOnePayloadDigest() || sealedOneDigest != circuit.arithmeticOneDigest {
		t.Fatal("cached arithmetic-one seal/digest differs from the profile")
	}

	decoded := make([]complex128, params.MaxSlots())
	if err = integerEncoder.Decode(circuit.arithmeticOne, decoded); err != nil {
		t.Fatal(err)
	}
	ringZ, err := z2n.New(z2n.Word8)
	if err != nil {
		t.Fatal(err)
	}
	want := z2n.Complex128(ringZ.ArithmeticRootSlots(1))
	scalarOneDiffers := false
	for index, got := range decoded {
		if distance := signFusionComplexDistance(got, want[index%4]); distance > 1e-9 {
			t.Fatalf("arithmetic-root one slot %d error %.3g", index, distance)
		}
		if signFusionComplexDistance(got, 1) > 1e-3 {
			scalarOneDiffers = true
		}
	}
	if !scalarOneDiffers {
		t.Fatal("cached complement operand collapsed to scalar CKKS one")
	}
	if _, err = NewSigned8ComparatorCircuit(params, integerEncoder, refreshEncoder, ranges); err == nil {
		t.Fatal("constructor accepted swapped 256-bit refresh and 192-bit integer encoder roles")
	}
	if _, err = NewSigned8ComparatorCircuit(params, nil, integerEncoder, ranges); err == nil {
		t.Fatal("constructor accepted a nil refresh encoder")
	}
	if _, err = NewSigned8ComparatorCircuit(params, refreshEncoder, nil, ranges); err == nil {
		t.Fatal("constructor accepted a nil integer encoder")
	}
	reorderedQ := append([]uint64(nil), params.Q()...)
	reorderedQ[1], reorderedQ[2] = reorderedQ[2], reorderedQ[1]
	reorderedParams, reorderedErr := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN: params.LogN(), Q: reorderedQ, P: append([]uint64(nil), params.P()...), LogDefaultScale: params.LogDefaultScale(),
	})
	if reorderedErr != nil {
		t.Fatal(reorderedErr)
	}
	if params.Equal(&reorderedParams) {
		t.Fatal("same-bit reordered-Q comparator negative unexpectedly equals canonical parameters")
	}
	if _, err = NewSigned8ComparatorCircuit(reorderedParams, ckks.NewEncoder(reorderedParams, 192), ckks.NewEncoder(reorderedParams, 256), ranges); err == nil {
		t.Fatal("constructor accepted a same-bit reordered Q chain")
	}
	if _, err = NewSigned8ComparatorCircuit(params, ckks.NewEncoder(reorderedParams, 192), integerEncoder, ranges); err == nil {
		t.Fatal("constructor accepted a refresh encoder from a reordered Q chain")
	}
	wrongRange := ranges
	wrongRange.digest = "foreign-range"
	if _, err = NewSigned8ComparatorCircuit(params, refreshEncoder, integerEncoder, wrongRange); err == nil {
		t.Fatal("constructor accepted foreign range evidence")
	}
	rotations := public.RequiredGaloisElements()
	rotations[0] = 0
	if circuit.PublicProfile().RequiredGaloisElements()[0] == 0 {
		t.Fatal("profile Galois-element accessor aliases the sealed key schedule")
	}
}

func TestSigned8ComparatorAdmissionOwnsAndSealsCiphertextPayload(t *testing.T) {
	ranges, err := NewSigned8NoOverflowRange(-8, 7, -8, 7)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newSigned8ComparatorFixture(t, ranges)
	original := fixture.encryptSigned(t, [4]int64{-8, -1, 0, 7})
	handle, err := fixture.circuit.BindFeature(original, fixture.params)
	if err != nil {
		t.Fatal(err)
	}
	if handle.ciphertext == original {
		t.Error("feature admission aliases the caller-owned ciphertext")
	}

	admittedBefore := handle.ciphertext.CopyNew()
	original.Scale = rlwe.NewScale(3)
	if !handle.ciphertext.Equal(admittedBefore) {
		t.Error("post-bind caller mutation changed the admitted feature payload")
	}

	tampered := handle
	tampered.ciphertext = admittedBefore.CopyNew()
	tampered.ciphertext.Value[0].Coeffs[0][0]++
	if err = fixture.circuit.validateFeatureHandle(tampered); err == nil {
		t.Fatal("post-bind handle payload tamper retained valid provenance")
	}

	thresholdOriginal := fixture.encryptSigned(t, [4]int64{})
	thresholdHandle, err := fixture.circuit.BindOpaqueThreshold(thresholdOriginal, fixture.params)
	if err != nil {
		t.Fatal(err)
	}
	if thresholdHandle.ciphertext == thresholdOriginal {
		t.Error("opaque-threshold admission aliases the caller-owned ciphertext")
	}
	thresholdAdmittedBefore := thresholdHandle.ciphertext.CopyNew()
	thresholdOriginal.Value[0].Coeffs[0][0]++
	if !thresholdHandle.ciphertext.Equal(thresholdAdmittedBefore) {
		t.Error("post-bind caller mutation changed the admitted opaque-threshold payload")
	}
	thresholdTampered := thresholdHandle
	thresholdTampered.ciphertext = thresholdAdmittedBefore.CopyNew()
	thresholdTampered.ciphertext.Value[0].Coeffs[0][0]++
	if err = fixture.circuit.validateThresholdHandle(thresholdTampered); err == nil {
		t.Fatal("post-bind opaque-threshold payload tamper retained valid provenance")
	}
}

func TestSigned8ComparatorAdmissionRejectsForeignDeclaredOrigins(t *testing.T) {
	ranges, err := NewSigned8NoOverflowRange(-8, 7, -8, 7)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newSigned8ComparatorFixture(t, ranges)
	featureCiphertext := fixture.encryptSigned(t, [4]int64{-8, -1, 0, 7})
	thresholdCiphertext := fixture.encryptSigned(t, [4]int64{})

	differentLogN, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN: fixture.params.LogN() - 1, Q: append([]uint64(nil), fixture.params.Q()...),
		P: append([]uint64(nil), fixture.params.P()...), LogDefaultScale: fixture.params.LogDefaultScale(),
	})
	if err != nil {
		t.Fatal(err)
	}
	reorderedQ := append([]uint64(nil), fixture.params.Q()...)
	reorderedQ[1], reorderedQ[2] = reorderedQ[2], reorderedQ[1]
	reorderedParameters, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN: fixture.params.LogN(), Q: reorderedQ, P: append([]uint64(nil), fixture.params.P()...),
		LogDefaultScale: fixture.params.LogDefaultScale(),
	})
	if err != nil {
		t.Fatal(err)
	}

	for name, declaredSource := range map[string]ckks.Parameters{
		"different LogN": differentLogN,
		"reordered Q":    reorderedParameters,
	} {
		t.Run(name, func(t *testing.T) {
			featureBefore, thresholdBefore := featureCiphertext.CopyNew(), thresholdCiphertext.CopyNew()
			if handle, bindErr := fixture.circuit.BindFeature(featureCiphertext, declaredSource); bindErr == nil || !reflect.DeepEqual(handle, Signed8FeatureInput{}) {
				t.Fatalf("foreign declared feature origin was admitted: handle=%+v err=%v", handle, bindErr)
			}
			if handle, bindErr := fixture.circuit.BindOpaqueThreshold(thresholdCiphertext, declaredSource); bindErr == nil || !reflect.DeepEqual(handle, Signed8OpaqueThresholdInput{}) {
				t.Fatalf("foreign declared threshold origin was admitted: handle=%+v err=%v", handle, bindErr)
			}
			if !featureCiphertext.Equal(featureBefore) || !thresholdCiphertext.Equal(thresholdBefore) {
				t.Fatal("foreign-origin rejection mutated a caller ciphertext")
			}
		})
	}

	foreignLogNCiphertext := ckks.NewCiphertext(differentLogN, 1, signed8InputLevel)
	foreignBefore := foreignLogNCiphertext.CopyNew()
	if handle, bindErr := fixture.circuit.BindFeature(foreignLogNCiphertext, fixture.params); bindErr == nil || !reflect.DeepEqual(handle, Signed8FeatureInput{}) {
		t.Fatalf("different-LogN ciphertext with a canonical declaration bypassed strict state admission: handle=%+v err=%v", handle, bindErr)
	}
	if !foreignLogNCiphertext.Equal(foreignBefore) {
		t.Fatal("strict-state rejection mutated a foreign ciphertext")
	}
}

func TestSigned8ComparatorWallTimeCoversCompleteEntryPaths(t *testing.T) {
	ranges, err := NewSigned8NoOverflowRange(-8, 7, -8, 7)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newSigned8ComparatorFixture(t, ranges)
	featureCiphertext := fixture.encryptSigned(t, [4]int64{-8, -1, 0, 7})
	thresholdCiphertext := fixture.encryptSigned(t, [4]int64{-1, -1, -1, -1})
	feature, err := fixture.circuit.BindFeature(featureCiphertext, fixture.params)
	if err != nil {
		t.Fatal(err)
	}
	threshold, err := fixture.circuit.BindOpaqueThreshold(thresholdCiphertext, fixture.params)
	if err != nil {
		t.Fatal(err)
	}

	publicStarted := time.Now()
	_, publicTrace, err := fixture.evaluator.CompareGEPublicNew(feature, [4]int64{-1, -1, -1, -1})
	publicElapsed := time.Since(publicStarted)
	if err != nil {
		t.Fatal(err)
	}
	assertSigned8WallTimeCoversCall(t, "public", publicElapsed, publicTrace.WallTime())

	opaqueStarted := time.Now()
	_, opaqueTrace, err := fixture.evaluator.CompareGEOpaqueNew(feature, threshold)
	opaqueElapsed := time.Since(opaqueStarted)
	if err != nil {
		t.Fatal(err)
	}
	assertSigned8WallTimeCoversCall(t, "opaque", opaqueElapsed, opaqueTrace.WallTime())
}

func TestSigned8ComparatorPublicZeroAll256(t *testing.T) {
	ranges, err := NewSigned8NoOverflowRange(-128, 127, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newSigned8ComparatorFixture(t, ranges)
	zeroThresholdPlaintext, err := newSigned8WordPlaintext(fixture.params, fixture.refreshEncoder, signed8RefreshEncoderPrecision, signed8InputLevel, [4]uint64{})
	if err != nil {
		t.Fatal(err)
	}
	zeroThresholdDigest, err := signed8PlaintextDigest(zeroThresholdPlaintext)
	if err != nil {
		t.Fatal(err)
	}
	for batch := 0; batch < 64; batch++ {
		var signedWords [4]int64
		for lane := range signedWords {
			signedWords[lane] = int64(int8(uint8(4*batch + lane)))
		}
		featureCiphertext := fixture.encryptSigned(t, signedWords)
		featureBefore := featureCiphertext.CopyNew()
		feature, bindErr := fixture.circuit.BindFeature(featureCiphertext, fixture.params)
		if bindErr != nil {
			t.Fatalf("batch %d bind feature: %v", batch, bindErr)
		}
		result, trace, compareErr := fixture.evaluator.CompareGEPublicNew(feature, [4]int64{})
		if compareErr != nil {
			t.Fatalf("batch %d values=%v: %v", batch, signedWords, compareErr)
		}
		if !featureCiphertext.Equal(featureBefore) {
			t.Fatalf("batch %d public comparison mutated the feature", batch)
		}
		got := fixture.decryptWords(t, result.Ciphertext())
		for lane, value := range signedWords {
			want := signed8GEZ256Oracle(value, 0)
			if got[lane] != want {
				t.Fatalf("batch %d lane %d: [%d >= 0]=%d, got %d", batch, lane, value, want, got[lane])
			}
		}
		assertSigned8ComparatorTrace(t, fixture, trace, Signed8PublicThresholdCTPT)
		if trace.ThresholdOperandDigest() != zeroThresholdDigest {
			t.Fatalf("batch %d public threshold payload digest=%s, want 192-bit encoding %s", batch, trace.ThresholdOperandDigest(), zeroThresholdDigest)
		}
		if result.ProfileDigest() != fixture.circuit.PublicProfile().Digest() || result.RangeDigest() != ranges.Digest() ||
			result.OperandMode() != Signed8PublicThresholdCTPT {
			t.Fatalf("batch %d result provenance changed", batch)
		}
		outputCopy := result.Ciphertext()
		outputCopy.Scale = rlwe.NewScale(3)
		if !fixture.circuit.PublicProfile().OutputState().Scale().EqualScale(result.Ciphertext().Scale) {
			t.Fatalf("batch %d result ciphertext accessor aliases owned output", batch)
		}
	}
}

func TestSigned8ComparatorAllNarrowPairsPublicAndOpaque(t *testing.T) {
	ranges, err := NewSigned8NoOverflowRange(-8, 7, -8, 7)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newSigned8ComparatorFixture(t, ranges)
	pairs := make([][2]int64, 0, 256)
	for feature := int64(-8); feature <= 7; feature++ {
		for threshold := int64(-8); threshold <= 7; threshold++ {
			pairs = append(pairs, [2]int64{feature, threshold})
		}
	}
	for batch := 0; batch < len(pairs)/4; batch++ {
		var features, thresholds [4]int64
		for lane := 0; lane < 4; lane++ {
			features[lane], thresholds[lane] = pairs[4*batch+lane][0], pairs[4*batch+lane][1]
		}
		featureCiphertext := fixture.encryptSigned(t, features)
		thresholdCiphertext := fixture.encryptSigned(t, thresholds)
		featureBefore, thresholdBefore := featureCiphertext.CopyNew(), thresholdCiphertext.CopyNew()
		featureHandle, bindErr := fixture.circuit.BindFeature(featureCiphertext, fixture.params)
		if bindErr != nil {
			t.Fatal(bindErr)
		}
		thresholdHandle, bindErr := fixture.circuit.BindOpaqueThreshold(thresholdCiphertext, fixture.params)
		if bindErr != nil {
			t.Fatal(bindErr)
		}
		publicResult, publicTrace, publicErr := fixture.evaluator.CompareGEPublicNew(featureHandle, thresholds)
		if publicErr != nil {
			t.Fatalf("batch %d public features=%v thresholds=%v: %v", batch, features, thresholds, publicErr)
		}
		opaqueResult, opaqueTrace, opaqueErr := fixture.evaluator.CompareGEOpaqueNew(featureHandle, thresholdHandle)
		if opaqueErr != nil {
			t.Fatalf("batch %d opaque features=%v thresholds=%v: %v", batch, features, thresholds, opaqueErr)
		}
		if !featureCiphertext.Equal(featureBefore) || !thresholdCiphertext.Equal(thresholdBefore) {
			t.Fatalf("batch %d comparison mutated a feature or threshold ciphertext", batch)
		}
		publicWords, opaqueWords := fixture.decryptWords(t, publicResult.Ciphertext()), fixture.decryptWords(t, opaqueResult.Ciphertext())
		for lane := 0; lane < 4; lane++ {
			want := signed8GEZ256Oracle(features[lane], thresholds[lane])
			if publicWords[lane] != want || opaqueWords[lane] != want || publicWords[lane] != opaqueWords[lane] {
				t.Fatalf("batch %d lane %d: [%d >= %d]=%d public=%d opaque=%d",
					batch, lane, features[lane], thresholds[lane], want, publicWords[lane], opaqueWords[lane])
			}
		}
		assertSigned8ComparatorTrace(t, fixture, publicTrace, Signed8PublicThresholdCTPT)
		assertSigned8ComparatorTrace(t, fixture, opaqueTrace, Signed8OpaqueThresholdCTCT)
		if publicTrace.ThresholdOperandDigest() == opaqueTrace.ThresholdOperandDigest() ||
			publicTrace.ProfileDigest() == opaqueTrace.ProfileDigest() {
			t.Fatalf("batch %d public and opaque paths lost operand/profile distinction", batch)
		}
	}
}

func TestSigned8ComparatorRejectsIngressRangeProfileGraphAndKeysBeforeSubtraction(t *testing.T) {
	ranges, err := NewSigned8NoOverflowRange(-8, 7, -8, 7)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newSigned8ComparatorFixture(t, ranges)
	featureCiphertext := fixture.encryptSigned(t, [4]int64{-8, -1, 0, 7})
	thresholdCiphertext := fixture.encryptSigned(t, [4]int64{0, 0, 0, 0})
	feature, err := fixture.circuit.BindFeature(featureCiphertext, fixture.params)
	if err != nil {
		t.Fatal(err)
	}
	threshold, err := fixture.circuit.BindOpaqueThreshold(thresholdCiphertext, fixture.params)
	if err != nil {
		t.Fatal(err)
	}

	assertPublicRejected := func(name string, handle Signed8FeatureInput) {
		t.Helper()
		featureBefore, thresholdBefore := featureCiphertext.CopyNew(), thresholdCiphertext.CopyNew()
		var handleBefore *rlwe.Ciphertext
		if handle.ciphertext != nil {
			handleBefore = cloneSigned8CiphertextForTest(handle.ciphertext)
		}
		oneBefore, oneSealBefore := fixture.circuit.arithmeticOne.CopyNew(), fixture.circuit.arithmeticOneSeal.CopyNew()
		result, trace, evaluationErr := fixture.evaluator.CompareGEPublicNew(handle, [4]int64{})
		if evaluationErr == nil || !reflect.DeepEqual(result, Signed8ComparatorResult{}) || !signed8TraceIsZero(trace) {
			t.Fatalf("%s reached subtraction: result=%+v states=%d counts=%+v err=%v", name, result, len(trace.States()), trace.WrapperOperationCounts(), evaluationErr)
		}
		if !featureCiphertext.Equal(featureBefore) || !thresholdCiphertext.Equal(thresholdBefore) ||
			!signed8CiphertextMatchesTestSnapshot(handle.ciphertext, handleBefore) ||
			!fixture.circuit.arithmeticOne.Equal(oneBefore) || !fixture.circuit.arithmeticOneSeal.Equal(oneSealBefore) {
			t.Fatalf("%s rejection mutated an input", name)
		}
	}
	assertOpaqueRejected := func(name string, featureHandle Signed8FeatureInput, thresholdHandle Signed8OpaqueThresholdInput) {
		t.Helper()
		featureBefore, thresholdBefore := featureCiphertext.CopyNew(), thresholdCiphertext.CopyNew()
		var featureHandleBefore, thresholdHandleBefore *rlwe.Ciphertext
		if featureHandle.ciphertext != nil {
			featureHandleBefore = cloneSigned8CiphertextForTest(featureHandle.ciphertext)
		}
		if thresholdHandle.ciphertext != nil {
			thresholdHandleBefore = cloneSigned8CiphertextForTest(thresholdHandle.ciphertext)
		}
		oneBefore, oneSealBefore := fixture.circuit.arithmeticOne.CopyNew(), fixture.circuit.arithmeticOneSeal.CopyNew()
		result, trace, evaluationErr := fixture.evaluator.CompareGEOpaqueNew(featureHandle, thresholdHandle)
		if evaluationErr == nil || !reflect.DeepEqual(result, Signed8ComparatorResult{}) || !signed8TraceIsZero(trace) {
			t.Fatalf("%s reached subtraction: result=%+v states=%d counts=%+v err=%v", name, result, len(trace.States()), trace.WrapperOperationCounts(), evaluationErr)
		}
		if !featureCiphertext.Equal(featureBefore) || !thresholdCiphertext.Equal(thresholdBefore) ||
			!signed8CiphertextMatchesTestSnapshot(featureHandle.ciphertext, featureHandleBefore) ||
			!signed8CiphertextMatchesTestSnapshot(thresholdHandle.ciphertext, thresholdHandleBefore) ||
			!fixture.circuit.arithmeticOne.Equal(oneBefore) || !fixture.circuit.arithmeticOneSeal.Equal(oneSealBefore) {
			t.Fatalf("%s rejection mutated an input", name)
		}
	}

	badHandles := map[string]func(*Signed8FeatureInput){
		"foreign range digest":      func(h *Signed8FeatureInput) { h.rangeDigest = "foreign" },
		"foreign profile digest":    func(h *Signed8FeatureInput) { h.profileDigest = "foreign" },
		"foreign source parameters": func(h *Signed8FeatureInput) { h.sourceParameterDigest = "foreign" },
		"foreign payload digest":    func(h *Signed8FeatureInput) { h.payloadDigest = "foreign" },
		"foreign provenance":        func(h *Signed8FeatureInput) { h.provenanceDigest = "foreign" },
		"threshold role":            func(h *Signed8FeatureInput) { h.role = signed8ThresholdRole },
		"nil ciphertext":            func(h *Signed8FeatureInput) { h.ciphertext = nil },
	}
	for name, mutate := range badHandles {
		changed := feature
		mutate(&changed)
		assertPublicRejected(name, changed)
	}

	stateMutations := map[string]func(*rlwe.Ciphertext){
		"level":         func(ct *rlwe.Ciphertext) { ct.Resize(ct.Degree(), 19) },
		"numeric scale": func(ct *rlwe.Ciphertext) { ct.Scale = rlwe.NewScale(uint64(1) << 34) },
		"modular scale": func(ct *rlwe.Ciphertext) { ct.Scale.Mod = big.NewInt(257) },
		"scale precision": func(ct *rlwe.Ciphertext) {
			ct.Scale.Value = *new(big.Float).SetPrec(ct.Scale.Value.Prec() + 1).Set(&ct.Scale.Value)
		},
		"scale rounding": func(ct *rlwe.Ciphertext) { ct.Scale.Value.SetMode(big.ToZero) },
		"dimensions":     func(ct *rlwe.Ciphertext) { ct.LogDimensions.Cols-- },
		"degree":         func(ct *rlwe.Ciphertext) { ct.Resize(2, ct.Level()) },
		"batching":       func(ct *rlwe.Ciphertext) { ct.IsBatched = false },
		"NTT":            func(ct *rlwe.Ciphertext) { ct.IsNTT = false },
	}
	for name, mutate := range stateMutations {
		changedCiphertext := featureCiphertext.CopyNew()
		mutate(changedCiphertext)
		changed := feature
		changed.ciphertext = changedCiphertext
		assertPublicRejected("feature "+name, changed)
	}
	featurePayloadTamper := feature
	featurePayloadTamper.ciphertext = feature.ciphertext.CopyNew()
	featurePayloadTamper.ciphertext.Value[0].Coeffs[0][0]++
	assertPublicRejected("feature post-bind coefficient payload tamper", featurePayloadTamper)
	badMetadataCiphertext := featureCiphertext.CopyNew()
	badMetadataCiphertext.MetaData = nil
	badMetadata := feature
	badMetadata.ciphertext = badMetadataCiphertext
	result, trace, metadataErr := fixture.evaluator.CompareGEPublicNew(badMetadata, [4]int64{})
	if metadataErr == nil || !reflect.DeepEqual(result, Signed8ComparatorResult{}) || !signed8TraceIsZero(trace) || badMetadataCiphertext.MetaData != nil {
		t.Fatalf("nil metadata reached subtraction or was mutated: err=%v", metadataErr)
	}
	badThresholdHandles := map[string]func(*Signed8OpaqueThresholdInput){
		"foreign range digest":      func(h *Signed8OpaqueThresholdInput) { h.rangeDigest = "foreign" },
		"foreign profile digest":    func(h *Signed8OpaqueThresholdInput) { h.profileDigest = "foreign" },
		"foreign source parameters": func(h *Signed8OpaqueThresholdInput) { h.sourceParameterDigest = "foreign" },
		"foreign payload digest":    func(h *Signed8OpaqueThresholdInput) { h.payloadDigest = "foreign" },
		"foreign provenance":        func(h *Signed8OpaqueThresholdInput) { h.provenanceDigest = "foreign" },
		"feature role":              func(h *Signed8OpaqueThresholdInput) { h.role = signed8FeatureRole },
		"nil ciphertext":            func(h *Signed8OpaqueThresholdInput) { h.ciphertext = nil },
	}
	for name, mutate := range badThresholdHandles {
		changed := threshold
		mutate(&changed)
		assertOpaqueRejected("opaque "+name, feature, changed)
	}
	for name, mutate := range stateMutations {
		changed := threshold
		changed.ciphertext = threshold.ciphertext.CopyNew()
		mutate(changed.ciphertext)
		assertOpaqueRejected("opaque threshold "+name, feature, changed)
	}
	thresholdPayloadTamper := threshold
	thresholdPayloadTamper.ciphertext = threshold.ciphertext.CopyNew()
	thresholdPayloadTamper.ciphertext.Value[0].Coeffs[0][0]++
	assertOpaqueRejected("opaque threshold post-bind coefficient payload tamper", feature, thresholdPayloadTamper)
	badThresholdMetadata := threshold
	badThresholdMetadata.ciphertext = threshold.ciphertext.CopyNew()
	badThresholdMetadata.ciphertext.MetaData = nil
	assertOpaqueRejected("opaque threshold nil metadata", feature, badThresholdMetadata)

	if result, zeroTrace, thresholdErr := fixture.evaluator.CompareGEPublicNew(feature, [4]int64{-9, 0, 0, 0}); thresholdErr == nil || !reflect.DeepEqual(result, Signed8ComparatorResult{}) || !signed8TraceIsZero(zeroTrace) {
		t.Fatalf("out-of-range public threshold reached subtraction: err=%v", thresholdErr)
	}

	assertCurrentGraphRejected := func(name string) { assertPublicRejected(name, feature) }
	originalPublicDigest := fixture.circuit.publicProfile.digest
	fixture.circuit.publicProfile.digest = "tampered-public-profile"
	assertCurrentGraphRejected("public profile mutation")
	fixture.circuit.publicProfile.digest = originalPublicDigest
	originalOne := fixture.circuit.arithmeticOne
	fixture.circuit.arithmeticOne = originalOne.CopyNew()
	assertCurrentGraphRejected("arithmetic-one pointer replacement")
	fixture.circuit.arithmeticOne = originalOne
	originalOneScale := fixture.circuit.arithmeticOne.Scale
	fixture.circuit.arithmeticOne.Scale = rlwe.NewScale(3)
	assertCurrentGraphRejected("arithmetic-one payload metadata mutation")
	fixture.circuit.arithmeticOne.Scale = originalOneScale
	originalOneSeal := fixture.circuit.arithmeticOneSeal
	fixture.circuit.arithmeticOneSeal = originalOneSeal.CopyNew()
	assertCurrentGraphRejected("arithmetic-one seal pointer replacement")
	fixture.circuit.arithmeticOneSeal = originalOneSeal
	originalSealCoefficient := fixture.circuit.arithmeticOneSeal.Value.Coeffs[0][0]
	fixture.circuit.arithmeticOneSeal.Value.Coeffs[0][0]++
	assertCurrentGraphRejected("arithmetic-one sealed payload mutation")
	fixture.circuit.arithmeticOneSeal.Value.Coeffs[0][0] = originalSealCoefficient
	originalOneDigest := fixture.circuit.arithmeticOneDigest
	fixture.circuit.arithmeticOneDigest = "tampered-one-digest"
	assertCurrentGraphRejected("arithmetic-one cached digest mutation")
	fixture.circuit.arithmeticOneDigest = originalOneDigest
	originalSignRole := fixture.circuit.sign.profile.inputHalfRole
	fixture.circuit.sign.profile.inputHalfRole = SignFusionLowBooleanHalf
	assertCurrentGraphRejected("low-half sign child mutation")
	fixture.circuit.sign.profile.inputHalfRole = originalSignRole
	originalSignOrder := fixture.circuit.sign.profile.inputBitOrder
	fixture.circuit.sign.profile.inputBitOrder = SignFusionMSBFirst
	assertCurrentGraphRejected("MSB-first sign child mutation")
	fixture.circuit.sign.profile.inputBitOrder = originalSignOrder
	originalA2BOrder := fixture.circuit.a2b.profile.bitOrder
	fixture.circuit.a2b.profile.bitOrder = "MSB-first"
	assertCurrentGraphRejected("MSB-first A2B child mutation")
	fixture.circuit.a2b.profile.bitOrder = originalA2BOrder

	keySet := fixture.source.MemEvaluationKeySet
	originalRelinearization := keySet.RelinearizationKey
	keySet.RelinearizationKey = nil
	assertCurrentGraphRejected("deleted relinearization key")
	keySet.RelinearizationKey = originalRelinearization
	foreignSecret := fixture.keyGenerator.GenSecretKeyNew()
	keySet.RelinearizationKey = fixture.keyGenerator.GenRelinearizationKeyNew(foreignSecret)
	assertCurrentGraphRejected("foreign-secret relinearization key")
	keySet.RelinearizationKey = originalRelinearization
	for _, element := range fixture.circuit.PublicProfile().RequiredGaloisElements() {
		original := keySet.GaloisKeys[element]
		keySet.GaloisKeys[element] = nil
		assertCurrentGraphRejected(fmt.Sprintf("deleted Galois key %d", element))
		keySet.GaloisKeys[element] = original
		keySet.GaloisKeys[element] = fixture.keyGenerator.GenGaloisKeyNew(element, fixture.secretKey)
		assertCurrentGraphRejected(fmt.Sprintf("same-element replacement Galois key %d", element))
		keySet.GaloisKeys[element] = original
	}
	elements := fixture.circuit.PublicProfile().RequiredGaloisElements()
	first, second := elements[0], elements[1]
	keySet.GaloisKeys[first], keySet.GaloisKeys[second] = keySet.GaloisKeys[second], keySet.GaloisKeys[first]
	assertCurrentGraphRejected("swapped Galois keys")
	keySet.GaloisKeys[first], keySet.GaloisKeys[second] = keySet.GaloisKeys[second], keySet.GaloisKeys[first]
	originalFirst := keySet.GaloisKeys[first]
	keySet.GaloisKeys[first] = fixture.keyGenerator.GenGaloisKeyNew(first, foreignSecret)
	assertCurrentGraphRejected("foreign-secret Galois key")
	keySet.GaloisKeys[first] = originalFirst
	requiredElements := make(map[uint64]bool, len(elements))
	for _, element := range elements {
		requiredElements[element] = true
	}
	var unexpectedElement uint64
	for rotation := 1; rotation < fixture.params.MaxSlots(); rotation++ {
		candidate := fixture.params.GaloisElementForRotation(rotation)
		if !requiredElements[candidate] {
			unexpectedElement = candidate
			break
		}
	}
	if unexpectedElement == 0 {
		t.Fatal("could not select an unexpected valid Galois element")
	}
	keySet.GaloisKeys[unexpectedElement] = fixture.keyGenerator.GenGaloisKeyNew(unexpectedElement, fixture.secretKey)
	assertCurrentGraphRejected("unexpected extra Galois key")
	delete(keySet.GaloisKeys, unexpectedElement)

	originalSourceKeySet := fixture.source.MemEvaluationKeySet
	fixture.source.MemEvaluationKeySet = rlwe.NewMemEvaluationKeySet(originalRelinearization)
	assertCurrentGraphRejected("source MemEvaluationKeySet replacement")
	fixture.source.MemEvaluationKeySet = originalSourceKeySet
	originalBoundKeySet := fixture.evaluator.keySet
	fixture.evaluator.keySet = rlwe.NewMemEvaluationKeySet(originalRelinearization)
	assertCurrentGraphRejected("bound MemEvaluationKeySet replacement")
	fixture.evaluator.keySet = originalBoundKeySet
	originalExpectedRelinearization := fixture.evaluator.relinearizationKey
	fixture.evaluator.relinearizationKey = fixture.keyGenerator.GenRelinearizationKeyNew(fixture.secretKey)
	assertCurrentGraphRejected("captured relinearization pointer replacement")
	fixture.evaluator.relinearizationKey = originalExpectedRelinearization
	originalExpectedGalois := fixture.evaluator.galoisKeys[first]
	fixture.evaluator.galoisKeys[first] = fixture.keyGenerator.GenGaloisKeyNew(first, fixture.secretKey)
	assertCurrentGraphRejected("captured Galois pointer replacement")
	fixture.evaluator.galoisKeys[first] = originalExpectedGalois
	originalSourceCKKS := fixture.source.Evaluator
	fixture.source.Evaluator = ckks.NewEvaluator(fixture.params, keySet)
	assertCurrentGraphRejected("source CKKS evaluator replacement")
	fixture.source.Evaluator = originalSourceCKKS
	originalSignSource := fixture.evaluator.signSource
	fixture.evaluator.signSource = ckks.NewEvaluator(fixture.params, keySet)
	assertCurrentGraphRejected("sign evaluator graph replacement")
	fixture.evaluator.signSource = originalSignSource
	originalSignKeySet := fixture.evaluator.signSource.EvaluationKeySet
	fixture.evaluator.signSource.EvaluationKeySet = rlwe.NewMemEvaluationKeySet(originalRelinearization)
	assertCurrentGraphRejected("sign evaluator key-set replacement")
	fixture.evaluator.signSource.EvaluationKeySet = originalSignKeySet

	if _, _, err = fixture.evaluator.CompareGEPublicNew(feature, [4]int64{}); err != nil {
		t.Fatalf("restored signed8 graph did not recover: %v", err)
	}
}

func TestSigned8ComparatorEqualityBoundariesDifferenceEndpointsAndBlockIsolation(t *testing.T) {
	fullRange, err := NewSigned8NoOverflowRange(-128, 127, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	full := newSigned8ComparatorFixture(t, fullRange)
	for _, features := range [][4]int64{{-128, -1, 0, 127}, {1, -128, 127, 0}} {
		featureCiphertext := full.encryptSigned(t, features)
		thresholdCiphertext := full.encryptSigned(t, [4]int64{})
		feature, bindErr := full.circuit.BindFeature(featureCiphertext, full.params)
		if bindErr != nil {
			t.Fatal(bindErr)
		}
		threshold, bindErr := full.circuit.BindOpaqueThreshold(thresholdCiphertext, full.params)
		if bindErr != nil {
			t.Fatal(bindErr)
		}
		publicResult, publicTrace, compareErr := full.evaluator.CompareGEPublicNew(feature, [4]int64{})
		if compareErr != nil {
			t.Fatal(compareErr)
		}
		opaqueResult, opaqueTrace, compareErr := full.evaluator.CompareGEOpaqueNew(feature, threshold)
		if compareErr != nil {
			t.Fatal(compareErr)
		}
		publicWords, opaqueWords := full.decryptWords(t, publicResult.Ciphertext()), full.decryptWords(t, opaqueResult.Ciphertext())
		for lane, value := range features {
			want := signed8GEZ256Oracle(value, 0)
			if publicWords[lane] != want || opaqueWords[lane] != want {
				t.Fatalf("difference endpoint fixture lane %d: [%d>=0]=%d public=%d opaque=%d", lane, value, want, publicWords[lane], opaqueWords[lane])
			}
		}
		assertSigned8ComparatorTrace(t, full, publicTrace, Signed8PublicThresholdCTPT)
		assertSigned8ComparatorTrace(t, full, opaqueTrace, Signed8OpaqueThresholdCTCT)
	}

	for _, test := range []struct {
		name   string
		minMax [2]int64
		values [4]int64
	}{
		{name: "negative equality including -128", minMax: [2]int64{-128, -1}, values: [4]int64{-128, -1, -128, -1}},
		{name: "nonnegative equality including 0 and 127", minMax: [2]int64{0, 127}, values: [4]int64{0, 127, 0, 127}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ranges, rangeErr := NewSigned8NoOverflowRange(test.minMax[0], test.minMax[1], test.minMax[0], test.minMax[1])
			if rangeErr != nil {
				t.Fatal(rangeErr)
			}
			fixture := newSigned8ComparatorFixture(t, ranges)
			featureCiphertext, thresholdCiphertext := fixture.encryptSigned(t, test.values), fixture.encryptSigned(t, test.values)
			feature, bindErr := fixture.circuit.BindFeature(featureCiphertext, fixture.params)
			if bindErr != nil {
				t.Fatal(bindErr)
			}
			threshold, bindErr := fixture.circuit.BindOpaqueThreshold(thresholdCiphertext, fixture.params)
			if bindErr != nil {
				t.Fatal(bindErr)
			}
			publicResult, _, publicErr := fixture.evaluator.CompareGEPublicNew(feature, test.values)
			if publicErr != nil {
				t.Fatal(publicErr)
			}
			opaqueResult, _, opaqueErr := fixture.evaluator.CompareGEOpaqueNew(feature, threshold)
			if opaqueErr != nil {
				t.Fatal(opaqueErr)
			}
			if gotPublic, gotOpaque := fixture.decryptWords(t, publicResult.Ciphertext()), fixture.decryptWords(t, opaqueResult.Ciphertext()); gotPublic != [4]uint64{1, 1, 1, 1} || gotOpaque != [4]uint64{1, 1, 1, 1} {
				t.Fatalf("equality must select GE/right child: public=%v opaque=%v", gotPublic, gotOpaque)
			}
		})
	}

	baseFeatures, isolatedFeatures := [4]int64{-1, -1, -1, -1}, [4]int64{-1, 1, -1, -1}
	baseCiphertext, isolatedCiphertext := full.encryptSigned(t, baseFeatures), full.encryptSigned(t, isolatedFeatures)
	baseHandle, err := full.circuit.BindFeature(baseCiphertext, full.params)
	if err != nil {
		t.Fatal(err)
	}
	isolatedHandle, err := full.circuit.BindFeature(isolatedCiphertext, full.params)
	if err != nil {
		t.Fatal(err)
	}
	baseResult, _, err := full.evaluator.CompareGEPublicNew(baseHandle, [4]int64{})
	if err != nil {
		t.Fatal(err)
	}
	isolatedResult, _, err := full.evaluator.CompareGEPublicNew(isolatedHandle, [4]int64{})
	if err != nil {
		t.Fatal(err)
	}
	if baseWords, isolatedWords := full.decryptWords(t, baseResult.Ciphertext()), full.decryptWords(t, isolatedResult.Ciphertext()); baseWords != [4]uint64{0, 0, 0, 0} || isolatedWords != [4]uint64{0, 1, 0, 0} {
		t.Fatalf("one-block feature change leaked across blocks: base=%v isolated=%v", baseWords, isolatedWords)
	}
}

type signed8ComparatorFixture struct {
	params         ckks.Parameters
	refreshEncoder *ckks.Encoder
	integerEncoder *ckks.Encoder
	circuit        *Signed8ComparatorCircuit
	source         *bootstrapping.Evaluator
	evaluator      *Signed8ComparatorEvaluator
	ringZ          *z2n.Ring
	keyGenerator   *rlwe.KeyGenerator
	secretKey      *rlwe.SecretKey
	encryptor      *rlwe.Encryptor
	decryptor      *rlwe.Decryptor
}

func newSigned8ComparatorFixture(t *testing.T, ranges Signed8NoOverflowRange) signed8ComparatorFixture {
	t.Helper()
	params, err := GaoA2BKernelFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	refreshEncoder := ckks.NewEncoder(params, signed8RefreshEncoderPrecision)
	integerEncoder := ckks.NewEncoder(params, signed8IntegerEncoderPrecision)
	circuit, err := NewSigned8ComparatorCircuit(params, refreshEncoder, integerEncoder, ranges)
	if err != nil {
		t.Fatal(err)
	}
	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	keyProfile := circuit.a2b.RequiredKeyProfile()
	evaluationKeys := &bootstrapping.EvaluationKeys{MemEvaluationKeySet: rlwe.NewMemEvaluationKeySet(
		keyGenerator.GenRelinearizationKeyNew(secretKey),
		keyGenerator.GenGaloisKeysNew(keyProfile.All(), secretKey)...,
	)}
	dft := circuit.a2b.refresh.Profile().DFT()
	bootstrapParameters := bootstrapping.Parameters{
		ResidualParameters:      params,
		BootstrappingParameters: params,
		SlotsToCoeffsParameters: dft.SlotsToCoeffsLiteral(),
		CoeffsToSlotsParameters: dft.CoeffsToSlotsLiteral(),
		Mod1ParametersLiteral: mod1.ParametersLiteral{
			LevelQ: dft.CoeffsToSlotsLiteral().LevelQ - 3, LogScale: params.LogDefaultScale(),
			Mod1Type: mod1.SinContinuous, LogMessageRatio: 15, K: 1, Mod1Degree: 3,
		},
		CircuitOrder: bootstrapping.Custom,
	}
	source, err := bootstrapping.NewEvaluator(bootstrapParameters, evaluationKeys)
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := circuit.BindEvaluator(source)
	if err != nil {
		t.Fatal(err)
	}
	ringZ, err := z2n.New(z2n.Word8)
	if err != nil {
		t.Fatal(err)
	}
	return signed8ComparatorFixture{
		params: params, refreshEncoder: refreshEncoder, integerEncoder: integerEncoder,
		circuit: circuit, source: source, evaluator: evaluator, ringZ: ringZ,
		keyGenerator: keyGenerator, secretKey: secretKey,
		encryptor: ckks.NewEncryptor(params, secretKey), decryptor: ckks.NewDecryptor(params, secretKey),
	}
}

func (f signed8ComparatorFixture) encryptSigned(t *testing.T, signedWords [4]int64) *rlwe.Ciphertext {
	t.Helper()
	var residues [4]uint64
	for index, value := range signedWords {
		if value < -128 || value > 127 {
			t.Fatalf("signed test word %d=%d is outside int8", index, value)
		}
		residues[index] = uint64(value) & 0xff
	}
	plaintext, err := newSigned8WordPlaintext(f.params, f.refreshEncoder, signed8RefreshEncoderPrecision, signed8InputLevel, residues)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := f.encryptor.EncryptNew(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	return ciphertext
}

func (f signed8ComparatorFixture) decryptWords(t *testing.T, ciphertext *rlwe.Ciphertext) [4]uint64 {
	t.Helper()
	if ciphertext == nil {
		t.Fatal("nil signed8 comparator output")
	}
	decoded := make([]complex128, ciphertext.Slots())
	if err := f.integerEncoder.Decode(f.decryptor.DecryptNew(ciphertext), decoded); err != nil {
		t.Fatal(err)
	}
	var words [4]uint64
	for lane := range words {
		words[lane] = signFusionRecoverWord(t, f.ringZ, decoded[4*lane:4*(lane+1)])
	}
	return words
}

func assertSigned8ComparatorTrace(t *testing.T, fixture signed8ComparatorFixture, trace Signed8ComparatorTrace, mode Signed8ComparatorOperandMode) {
	t.Helper()
	profile := fixture.circuit.profileForMode(mode)
	if trace.ProfileDigest() != profile.Digest() || trace.RangeDigest() != profile.RangeDigest() || trace.OperandMode() != mode ||
		trace.ThresholdOperandDigest() == "" || trace.ArithmeticOnePayloadDigest() != profile.ArithmeticOnePayloadDigest() ||
		trace.WrapperOperationCounts() != profile.WrapperOperationCounts() || trace.WrapperLogicalPeakLiveCiphertexts() != profile.WrapperLogicalPeakLiveCiphertexts() ||
		trace.WallTime() <= 0 || trace.SerialA2BTrace().ProfileDigest() != profile.A2BProfileDigest() ||
		trace.SignProvenance().ProfileDigest() != profile.SignProfileDigest() {
		t.Fatalf("signed8 trace provenance or ledger changed: %+v", trace)
	}
	preflight := trace.KeyPreflight()
	if !preflight.Checked || !preflight.GraphChecked || !preflight.GraphMatched || !preflight.RelinearizationPresent ||
		!preflight.RelinearizationMatched || !preflight.DenseNoSwitchingMatched || len(preflight.MissingGaloisElements) != 0 ||
		len(preflight.InvalidGaloisElements) != 0 || len(preflight.UnexpectedGaloisElements) != 0 {
		t.Fatalf("signed8 key preflight changed: %+v", preflight)
	}
	wantStages := []Signed8ComparatorStage{Signed8StageFeatureInput}
	wantLevels := []int{20}
	if mode == Signed8OpaqueThresholdCTCT {
		wantStages = append(wantStages, Signed8StageThresholdInput)
		wantLevels = append(wantLevels, 20)
	}
	wantStages = append(wantStages, Signed8StageDifference, Signed8StageHighMSB, Signed8StageArithmeticSign, Signed8StageNegatedSign, Signed8StageGreaterEqual)
	wantLevels = append(wantLevels, 20, 5, 4, 4, 4)
	states := trace.States()
	if len(states) != len(wantStages) {
		t.Fatalf("signed8 trace has %d states, want %d", len(states), len(wantStages))
	}
	for index, state := range states {
		if state.Stage != wantStages[index] || state.Level != wantLevels[index] || state.Degree != 1 ||
			state.LogDimensions != fixture.params.LogMaxDimensions() || !state.Scale.EqualScale(fixture.params.DefaultScale()) {
			t.Fatalf("signed8 state %d changed: %+v", index, state)
		}
	}
	sizes := trace.SerializedBytes()
	if sizes.Feature <= 0 || sizes.ThresholdOperand <= 0 || sizes.Difference <= 0 || sizes.HighMSB <= 0 ||
		sizes.ArithmeticSign <= 0 || sizes.GreaterEqualOutput <= 0 {
		t.Fatalf("signed8 boundary serialization measurement missing: %+v", sizes)
	}
	states[0].Level = -1
	if fixtureState, _ := trace.State(Signed8StageFeatureInput); fixtureState.Level != 20 {
		t.Fatal("signed8 trace state accessor aliases sealed evidence")
	}
	a2bTrace := trace.SerialA2BTrace()
	a2bTrace.states[0].Level = -1
	if trace.SerialA2BTrace().states[0].Level != 20 {
		t.Fatal("signed8 nested A2B trace accessor aliases sealed evidence")
	}
	signTrace := trace.SignProvenance()
	signTrace.states[0].Level = -1
	if trace.SignProvenance().states[0].Level != 5 {
		t.Fatal("signed8 nested sign trace accessor aliases sealed evidence")
	}
}

func signed8TraceIsZero(trace Signed8ComparatorTrace) bool {
	return reflect.DeepEqual(trace, Signed8ComparatorTrace{})
}

func cloneSigned8CiphertextForTest(ciphertext *rlwe.Ciphertext) *rlwe.Ciphertext {
	if ciphertext == nil {
		return nil
	}
	if ciphertext.MetaData != nil {
		return ciphertext.CopyNew()
	}
	// Lattigo's CopyNew dereferences MetaData. Copy through a shallow temporary
	// with empty metadata, then restore nil on the detached deep copy.
	temporary := *ciphertext
	temporary.MetaData = &rlwe.MetaData{}
	clone := temporary.CopyNew()
	clone.MetaData = nil
	return clone
}

func signed8CiphertextMatchesTestSnapshot(ciphertext, snapshot *rlwe.Ciphertext) bool {
	if ciphertext == nil || snapshot == nil {
		return ciphertext == snapshot
	}
	if ciphertext.MetaData == nil || snapshot.MetaData == nil {
		return ciphertext.MetaData == nil && snapshot.MetaData == nil && reflect.DeepEqual(ciphertext.Value, snapshot.Value)
	}
	return ciphertext.Equal(snapshot)
}

func assertSigned8WallTimeCoversCall(t *testing.T, name string, elapsed, recorded time.Duration) {
	t.Helper()
	if recorded <= 0 || recorded > elapsed {
		t.Fatalf("%s wall time=%s is outside observed call duration %s", name, recorded, elapsed)
	}
	// The timer begins at the public method entry. This tight envelope catches
	// validation or public-threshold encoding that is performed before timing.
	if unmeasured := elapsed - recorded; unmeasured > 100*time.Millisecond {
		t.Fatalf("%s wall time omitted %s of entry-path work (elapsed=%s recorded=%s)", name, unmeasured, elapsed, recorded)
	}
}

func signed8RangeOracleDigest(xMin, xMax, tMin, tMax, differenceMin, differenceMax int64) string {
	payload := fmt.Sprintf(
		"%s|x_min=%d|x_max=%d|t_min=%d|t_max=%d|difference_min=%d|difference_max=%d|word_bits=8|signedness=twos_complement|predicate=ge|child_convention=0=lt,1=ge|proof_status=internally_derived_endpoint_interval|overflow_contract=same_width_subtraction_no_overflow",
		signed8NoOverflowRangeDigestSchema, xMin, xMax, tMin, tMax, differenceMin, differenceMax,
	)
	digest := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(digest[:])
}

// signed8GEZ256Oracle is deliberately test-local and independent of production
// comparator and z2n arithmetic helpers. The certified no-overflow policy makes
// the sign bit of the modulo-256 residue difference equal the signed ordering.
func signed8GEZ256Oracle(x, threshold int64) uint64 {
	xResidue, thresholdResidue := uint16(uint8(x)), uint16(uint8(threshold))
	differenceResidue := uint8((xResidue + 256 - thresholdResidue) & 0xff)
	bit7 := (differenceResidue >> 7) & 1
	return uint64(1 - bit7)
}
