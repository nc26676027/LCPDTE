package ckksint

import (
	"testing"
	"time"

	"github.com/nc26676027/LCPDTE/integer/secureeval"
)

func TestGaoFullPackedA2BSetupInfoIncludesClientConstruction(t *testing.T) {
	report := secureeval.GaoFullPackedA2BSetupReport{
		ParameterWallTime:          time.Millisecond,
		KeyGenerationWallTime:      2 * time.Millisecond,
		ServerConstructionWallTime: 3 * time.Millisecond,
		ClientConstructionWallTime: 4 * time.Millisecond,
	}
	got := gaoFullPackedA2BSetupInfo(report)
	if got.ParameterWallTime != time.Millisecond || got.KeyGenerationWallTime != 2*time.Millisecond ||
		got.ServerConstructionWallTime != 3*time.Millisecond || got.ClientConstructionWallTime != 4*time.Millisecond {
		t.Fatalf("public setup timing=%+v", got)
	}
}

func TestGaoFullPackedA2BParameterInfoCopiesNativeProfile(t *testing.T) {
	report := secureeval.GaoFullPackedA2BParameterReport{
		FirstModulusBits:             43,
		ActualFirstQModulusBits:      44,
		QModuli:                      []string{"101", "103"},
		PModuli:                      []string{"107"},
		QModuliBitLengths:            []int{7, 7},
		PModuliBitLengths:            []int{7},
		MainSecretDistribution:       "balanced-sparse-ternary",
		MainSecretHammingWeight:      192,
		EphemeralSecretDistribution:  "balanced-sparse-ternary",
		EphemeralSecretHammingWeight: 32,
		ErrorSampler:                 "lattigo-bounded-discrete-gaussian",
		ErrorSigma:                   3.2,
		ErrorConfiguredBound:         19.2,
		ErrorEffectiveIntegerBound:   19,
		KeySwitchTechnique:           "lattigo-rns-qp-gadget",
		RNSDecompositionComponents:   3,
		BaseTwoDecomposition:         0,
		SecuritySelector:             "external-estimator",
		SecurityEvidence:             "full-packed-profile-not-assessed",
	}

	got := gaoFullPackedA2BParameterInfo(report)
	if got.FirstModulusBits != 43 || got.ActualFirstQModulusBits != 44 ||
		got.MainSecretDistribution != "balanced-sparse-ternary" || got.MainSecretHammingWeight != 192 ||
		got.EphemeralSecretDistribution != "balanced-sparse-ternary" || got.EphemeralSecretHammingWeight != 32 ||
		got.ErrorSampler != "lattigo-bounded-discrete-gaussian" || got.ErrorSigma != 3.2 ||
		got.ErrorConfiguredBound != 19.2 || got.ErrorEffectiveIntegerBound != 19 ||
		got.KeySwitchTechnique != "lattigo-rns-qp-gadget" || got.RNSDecompositionComponents != 3 ||
		got.BaseTwoDecomposition != 0 || got.SecuritySelector != "external-estimator" ||
		got.SecurityEvidence != "full-packed-profile-not-assessed" {
		t.Fatalf("public native parameter profile=%+v", got)
	}
	if len(got.QModuli) != 2 || got.QModuli[0] != "101" || len(got.PModuli) != 1 || got.PModuli[0] != "107" ||
		len(got.QModuliBitLengths) != 2 || got.QModuliBitLengths[0] != 7 ||
		len(got.PModuliBitLengths) != 1 || got.PModuliBitLengths[0] != 7 {
		t.Fatalf("public modulus identity=%+v", got)
	}

	report.QModuli[0] = "mutated"
	report.PModuli[0] = "mutated"
	report.QModuliBitLengths[0] = 0
	report.PModuliBitLengths[0] = 0
	if got.QModuli[0] != "101" || got.PModuli[0] != "107" ||
		got.QModuliBitLengths[0] != 7 || got.PModuliBitLengths[0] != 7 {
		t.Fatal("public modulus identity slices alias the secureeval report")
	}
}
