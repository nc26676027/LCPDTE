package secureprofile_test

import (
	"testing"

	"dt_go/integer/secureprofile"
	"dt_go/integer/securityparams"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func TestNewGaoN16BindsExactCandidateWithoutPromotingCircuitSecurity(t *testing.T) {
	params, err := securityparams.GaoCompatibleN16Parameters()
	if err != nil {
		t.Fatal(err)
	}
	first, err := secureprofile.NewGaoN16(params)
	if err != nil {
		t.Fatal(err)
	}
	second, err := secureprofile.NewGaoN16(params)
	if err != nil {
		t.Fatal(err)
	}

	if first.Digest() == "" || first.Digest() != second.Digest() {
		t.Fatalf("profile digest is empty or nondeterministic: %q / %q", first.Digest(), second.Digest())
	}
	if first.ParameterDigest() != "c37129e34fb3d726b37412887edf8df1cd6801ba9ab11d02531dddc4f08ea816" {
		t.Fatalf("parameter binary digest drifted: %s", first.ParameterDigest())
	}
	if first.Digest() != "7e4f9308cfd099e9474f496412eb79da5e3a0c1f56625d37a687d067e5e99b89" {
		t.Fatalf("profile digest drifted: %s", first.Digest())
	}
	if first.TupleID() != securityparams.GaoCompatibleTupleID ||
		first.ManifestDigest() != securityparams.GaoCompatibleManifestDigest {
		t.Fatalf("wrong manifest identity: tuple=%q digest=%q", first.TupleID(), first.ManifestDigest())
	}
	if first.Maturity() != secureprofile.ParameterCandidateUnverified {
		t.Fatalf("parameter-only profile was promoted: %q", first.Maturity())
	}
	if first.LogN() != 16 || first.Slots() != 32768 || first.WordBits() != 8 || first.WordCapacity() != 8192 {
		t.Fatalf("wrong packing: LogN=%d slots=%d bits=%d words=%d", first.LogN(), first.Slots(), first.WordBits(), first.WordCapacity())
	}
	if first.LogDefaultScale() != 43 || first.QCount() != 21 || first.PCount() != 7 || first.LogMessageRatio() != 0 {
		t.Fatalf("wrong scale/modulus profile: scale=%d Q=%d P=%d MR=%d", first.LogDefaultScale(), first.QCount(), first.PCount(), first.LogMessageRatio())
	}

	ratio := first.ScaleDownCorrection()
	if ratio.NumeratorDecimal != "8796093022208" || ratio.DenominatorDecimal != "8796090007553" {
		t.Fatalf("wrong exact q0/default-scale correction: %#v", ratio)
	}
	if got := first.ScaleDownCorrectionAbsLog2(); got <= 0 || got >= 1e-6 {
		t.Fatalf("scale correction log2=%g is outside the admitted open interval (0,1e-6)", got)
	}

	topology := first.Topology()
	if topology.RefreshInputLevel != 20 || topology.RefreshOutputLevel != 17 ||
		topology.KernelInputLevel != 17 || topology.KernelOutputLevel != 5 ||
		topology.BooleanToArithmeticOutputLevel != 4 || topology.SelectOutputLevel != 3 {
		t.Fatalf("unexpected secure-port topology: %#v", topology)
	}

	missing := first.MissingEvidence()
	if len(missing) == 0 {
		t.Fatal("parameter-only profile omitted its missing evidence")
	}
	missing[0] = "forged"
	if first.MissingEvidence()[0] == "forged" {
		t.Fatal("MissingEvidence exposed mutable profile state")
	}
	if err = first.ValidateParameters(params); err != nil {
		t.Fatalf("exact parameters failed revalidation: %v", err)
	}
}

func TestNewGaoN16RejectsMaterialParameterDrift(t *testing.T) {
	baseQ := make([]int, 21)
	for i := range baseQ {
		baseQ[i] = 43
	}
	baseP := make([]int, 7)
	for i := range baseP {
		baseP[i] = 50
	}

	tests := []struct {
		name    string
		literal ckks.ParametersLiteral
	}{
		{
			name: "wrong scale",
			literal: ckks.ParametersLiteral{LogN: 16, LogQ: baseQ, LogP: baseP,
				Xs: ring.Ternary{H: 192}, Xe: ring.DiscreteGaussian{Sigma: 3.2, Bound: 19.2},
				RingType: ring.Standard, LogDefaultScale: 42},
		},
		{
			name: "wrong main secret",
			literal: ckks.ParametersLiteral{LogN: 16, LogQ: baseQ, LogP: baseP,
				Xs: ring.Ternary{H: 191}, Xe: ring.DiscreteGaussian{Sigma: 3.2, Bound: 19.2},
				RingType: ring.Standard, LogDefaultScale: 43},
		},
		{
			name: "wrong P inventory",
			literal: ckks.ParametersLiteral{LogN: 16, LogQ: baseQ, LogP: baseP[:6],
				Xs: ring.Ternary{H: 192}, Xe: ring.DiscreteGaussian{Sigma: 3.2, Bound: 19.2},
				RingType: ring.Standard, LogDefaultScale: 43},
		},
		{
			name: "wrong Q inventory",
			literal: ckks.ParametersLiteral{LogN: 16, LogQ: baseQ[:20], LogP: baseP,
				Xs: ring.Ternary{H: 192}, Xe: ring.DiscreteGaussian{Sigma: 3.2, Bound: 19.2},
				RingType: ring.Standard, LogDefaultScale: 43},
		},
		{
			name: "wrong error distribution",
			literal: ckks.ParametersLiteral{LogN: 16, LogQ: baseQ, LogP: baseP,
				Xs: ring.Ternary{H: 192}, Xe: ring.DiscreteGaussian{Sigma: 3.3, Bound: 19.2},
				RingType: ring.Standard, LogDefaultScale: 43},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			params, err := ckks.NewParametersFromLiteral(test.literal)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = secureprofile.NewGaoN16(params); err == nil {
				t.Fatal("drifted parameters were accepted")
			}
		})
	}
}
