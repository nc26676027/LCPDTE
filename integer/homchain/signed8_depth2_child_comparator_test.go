package homchain

import (
	"reflect"
	"testing"

	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
)

func TestSigned8Depth2ChildComparatorConstructorSealsClosedGraph(t *testing.T) {
	prefix := newSigned8Depth2ChildPrefixForTest(t)
	circuit, err := NewSigned8Depth2ChildComparatorCircuit(prefix)
	if err != nil {
		t.Fatal(err)
	}
	if circuit == nil {
		t.Fatal("nil child comparator circuit")
	}

	profile := circuit.Profile()
	prefixProfile := prefix.Profile()
	ingressProfile := circuit.ingress.Profile()
	signProfile := circuit.sign.Profile()
	if profile.Fidelity() != Signed8Depth2ChildFunctionalNotSecure ||
		profile.Predicate() != Signed8GreaterThanOrEqual ||
		profile.ChildConvention() != Signed8ZeroLTOneGE ||
		profile.InputLevel() != 6 || profile.OutputLevel() != 4 ||
		profile.ParameterDigest() != prefixProfile.ParameterDigest() ||
		profile.PrefixProfileDigest() != prefixProfile.Digest() ||
		profile.ProtocolRangeDigest() != prefixProfile.RangeDigest() ||
		profile.TreeDigest() != prefixProfile.TreeDigest() ||
		profile.ScheduleDigest() != prefixProfile.ScheduleDigest() ||
		profile.OperandSourceKind() != Signed8Depth2PrefixL6V1 ||
		profile.IngressProfileDigest() != ingressProfile.Digest() ||
		profile.IngressAdmissionDigest() != ingressProfile.AdmissionDigest() ||
		profile.IngressRangeDigest() != ingressProfile.RangeDigest() ||
		profile.IngressSuffixProfileDigest() != ingressProfile.SuffixProfileDigest() ||
		profile.IngressKeyProfileDigest() != ingressProfile.KeyProfileDigest() ||
		profile.IngressSpecialB0Digest() != ingressProfile.SpecialB0CompiledDigest() ||
		profile.IngressMaskPayloadDigest() != ingressProfile.MaskPayloadDigest() ||
		profile.IngressFirstSTCEncodedPayloadDigest() != ingressProfile.FirstSTCEncodedPayloadDigest() ||
		profile.IngressSharedCTSEncodedPayloadDigest() != ingressProfile.SharedCTSEncodedPayloadDigest() ||
		profile.IngressSecondSTCEncodedPayloadDigest() != ingressProfile.SecondSTCEncodedPayloadDigest() ||
		profile.SignProfileDigest() != signProfile.Digest() ||
		profile.SignSourceDigest() != signProfile.SourceDigest() ||
		profile.SignCompiledDigest() != signProfile.CompiledDigest() ||
		profile.ArithmeticOnePayloadDigest() == "" || profile.Digest() == "" {
		t.Fatalf("child comparator profile is incomplete: %+v", profile)
	}
	wantCounts := Signed8Depth2ChildComparatorOperationCounts{
		CiphertextCiphertextSubtractions: 1,
		IngressInvocations:               1,
		SignFusionInvocations:            1,
		Negations:                        1,
		CiphertextPlaintextVectorAdds:    1,
	}
	if got := profile.OperationCounts(); got != wantCounts || got.Rescales != 0 || got.Rotations != 0 {
		t.Fatalf("wrapper operation ledger=%+v, want %+v", got, wantCounts)
	}
	keys := circuit.RequiredKeyProfile()
	wantKeys := []uint64{5, 17, 25, 33, 41, 49, 63}
	if !equalUint64Slices(keys.All(), wantKeys) || !keys.RelinearizationRequired() ||
		keys.Digest() != ingressProfile.KeyProfileDigest() ||
		!equalUint64Slices(profile.RequiredGaloisElements(), wantKeys) || !profile.RequiresRelinearization() {
		t.Fatalf("child key union changed: all=%v relin=%v digest=%s", keys.All(), keys.RelinearizationRequired(), keys.Digest())
	}
	if _, err = NewSigned8Depth2ChildComparatorCircuit(nil); err == nil {
		t.Fatal("nil prefix admitted")
	}
	states := profile.ExpectedStates()
	states[0].Level = 99
	keysCopy := keys.All()
	keysCopy[0] = 0
	profileKeys := profile.RequiredGaloisElements()
	profileKeys[0] = 0
	if circuit.Profile().ExpectedStates()[0].Level != 6 || circuit.RequiredKeyProfile().All()[0] != 5 ||
		circuit.Profile().RequiredGaloisElements()[0] != 5 {
		t.Fatal("child profile or key accessor aliases sealed data")
	}
	t.Logf("child-profile=%s prefix=%s protocol-range=%s ingress-profile=%s ingress-admission=%s ingress-range=%s ingress-suffix=%s key=%s special=%s mask=%s encoded-first=%s encoded-shared=%s encoded-second=%s sign-profile=%s sign-source=%s sign-compiled=%s one=%s states=%s",
		profile.Digest(), profile.PrefixProfileDigest(), profile.ProtocolRangeDigest(),
		profile.IngressProfileDigest(), profile.IngressAdmissionDigest(), profile.IngressRangeDigest(),
		profile.IngressSuffixProfileDigest(), profile.IngressKeyProfileDigest(), profile.IngressSpecialB0Digest(),
		profile.IngressMaskPayloadDigest(), profile.IngressFirstSTCEncodedPayloadDigest(),
		profile.IngressSharedCTSEncodedPayloadDigest(), profile.IngressSecondSTCEncodedPayloadDigest(),
		profile.SignProfileDigest(), profile.SignSourceDigest(), profile.SignCompiledDigest(),
		profile.ArithmeticOnePayloadDigest(), digestString(digestSigned8Depth2ChildStates(profile.ExpectedStates())))
}

func TestSigned8Depth2ChildComparatorBindOperandsRejectsUnmintedInput(t *testing.T) {
	circuit, err := NewSigned8Depth2ChildComparatorCircuit(newSigned8Depth2ChildPrefixForTest(t))
	if err != nil {
		t.Fatal(err)
	}
	input, err := circuit.BindOperands(Signed8Depth2Operands{})
	if err == nil || !reflect.DeepEqual(input, Signed8Depth2ChildComparatorInput{}) {
		t.Fatalf("unminted operands admitted: input=%+v err=%v", input, err)
	}
}

func TestSigned8Depth2ChildComparatorBindEvaluatorRejectsNilSource(t *testing.T) {
	circuit, err := NewSigned8Depth2ChildComparatorCircuit(newSigned8Depth2ChildPrefixForTest(t))
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := circuit.BindEvaluator(nil)
	if err == nil || evaluator != nil {
		t.Fatalf("nil bootstrap source admitted: evaluator=%p err=%v", evaluator, err)
	}
}

func TestSigned8Depth2ChildComparatorHostOracleExhaustiveRepresentableDifferences(t *testing.T) {
	accepted := 0
	for x := -128; x <= 127; x++ {
		for threshold := -128; threshold <= 127; threshold++ {
			difference := x - threshold
			if difference < -128 || difference > 127 {
				continue
			}
			accepted++
			residue := uint8(int8(difference))
			got := uint64(1 - ((residue >> 7) & 1))
			want := uint64(0)
			if x >= threshold {
				want = 1
			}
			if got != want {
				t.Fatalf("x=%d threshold=%d difference=%d residue=%d: 1-b7=%d, want %d", x, threshold, difference, residue, got, want)
			}
		}
	}
	if accepted != 49152 {
		t.Fatalf("representable int8 subtraction pairs=%d, want 49152", accepted)
	}
}

func newSigned8Depth2ChildPrefixForTest(t *testing.T) *Signed8Depth2SourcePrefixCircuit {
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
	prefix, err := NewSigned8Depth2SourcePrefixCircuit(selector, signed8Depth2TestTree())
	if err != nil {
		t.Fatal(err)
	}
	return prefix
}

func equalUint64Slices(left, right []uint64) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
