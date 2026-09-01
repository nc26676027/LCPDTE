package homchain

import (
	"testing"

	"dt_go/integer/securityparams"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func TestGaoPeriodicBooleanN16L11CircuitSealsRegisteredSchedule(t *testing.T) {
	params, err := securityparams.GaoCompatibleN16Parameters()
	if err != nil {
		t.Fatal(err)
	}
	circuit, err := NewGaoPeriodicBooleanN16L11Circuit(params, ckks.NewEncoder(params, 256))
	if err != nil {
		t.Fatal(err)
	}
	profile := circuit.Profile()
	if profile.Claim() != GaoPeriodicBooleanN16L11SecurityUnverified ||
		profile.InputLevel() != 17 || profile.ExponentialLevel() != 11 ||
		profile.Square0Level() != 10 || profile.RootLevel() != 9 ||
		profile.OutputLevel() != 8 || profile.Slots() != 2048 ||
		profile.ExponentialDegree() != 46 || profile.SquaringRounds() != 2 ||
		profile.AffineSourceDigest() == "" || profile.MultiplierPayloadDigest() == "" ||
		profile.OffsetPayloadDigest() == "" || profile.KernelProfileDigest() == "" ||
		profile.Digest() == "" {
		t.Fatalf("unexpected periodic Boolean N16/L11 profile: %+v", profile)
	}
	if got, want := profile.OperationCounts(), (GaoPeriodicBooleanN16L11OperationCounts{
		ExponentialPolynomialEvaluations: 1,
		CiphertextCiphertextProducts:     2,
		Relinearizations:                 2,
		ExplicitRescales:                 3,
		CiphertextPlaintextProducts:      1,
		PlaintextVectorAdditions:         1,
	}); got != want {
		t.Fatalf("periodic Boolean operation counts=%+v, want %+v", got, want)
	}
	if err = circuit.validate(); err != nil {
		t.Fatal(err)
	}
}

func TestGaoPeriodicBooleanN16L11AffineOracleDecodesBothBits(t *testing.T) {
	source, err := newGaoPeriodicBooleanN16L11AffineSource(256)
	if err != nil {
		t.Fatal(err)
	}
	if len(source.phase) != 2048 || len(source.multiplier) != 2048 || len(source.offset) != 2048 || source.digest == "" {
		t.Fatalf("unexpected affine source shape: phase=%d multiplier=%d offset=%d digest=%q",
			len(source.phase), len(source.multiplier), len(source.offset), source.digest)
	}
	for _, bit := range []uint64{0, 1} {
		decoded, err := evaluateGaoPeriodicBooleanN16L11Oracle(bit, 256)
		if err != nil {
			t.Fatal(err)
		}
		for index, value := range decoded {
			gotReal, _ := value.Real().Float64()
			gotImag, _ := value.Imag().Float64()
			if absFloat64(gotReal-float64(bit)) > 1e-60 || absFloat64(gotImag) > 1e-60 {
				t.Fatalf("bit=%d slot=%d decoded=(%.17g,%.17g)", bit, index, gotReal, gotImag)
			}
		}
	}
}

func absFloat64(value float64) float64 {
	if value < 0 {
		return -value
	}
	return value
}
