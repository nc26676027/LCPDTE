package secureeval

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestRouteBApplicationSecurityProfileBindsExactExposureInventory(t *testing.T) {
	profile, err := NewRouteBApplicationSecurityProfile()
	if err != nil {
		t.Fatal(err)
	}
	if err = profile.Validate(); err != nil {
		t.Fatal(err)
	}
	if profile.Decision.Status != RouteBSecurityConditionalPass || profile.Decision.Unconditional128BitClaim ||
		profile.Totals.EvaluationKeys != 41 || profile.Totals.EvaluationKeyRingSamples != 121 ||
		profile.Totals.InputCiphertextRingSamples != 3 || profile.Totals.TotalFreshRingSamples != 124 ||
		profile.Totals.MainSecretRingSamples != 123 || profile.Totals.EphemeralSecretRingSamples != 1 {
		t.Fatalf("application-security decision or totals drifted: decision=%+v totals=%+v", profile.Decision, profile.Totals)
	}
	if len(profile.KeyClasses) != 4 ||
		profile.KeyClasses[0].Class != "galois" || profile.KeyClasses[0].KeyCount != 38 || profile.KeyClasses[0].TotalRingSamples != 114 ||
		profile.KeyClasses[1].Class != "relinearization" || profile.KeyClasses[1].TotalRingSamples != 3 ||
		profile.KeyClasses[2].Class != "dense-to-sparse" || profile.KeyClasses[2].OutputSecret != "ephemeral-h32" || profile.KeyClasses[2].TotalRingSamples != 1 ||
		profile.KeyClasses[3].Class != "sparse-to-dense" || profile.KeyClasses[3].OutputSecret != "main-h192" || profile.KeyClasses[3].TotalRingSamples != 3 {
		t.Fatalf("evaluation-key inventory drifted: %+v", profile.KeyClasses)
	}
	for index, keyClass := range profile.KeyClasses {
		wantBase := []int{1, 1, 1}
		wantRows := 3
		if index == 2 {
			wantBase = []int{1}
			wantRows = 1
		}
		if keyClass.BaseRNSRows != wantRows || !slices.Equal(keyClass.BaseTwoColumns, wantBase) ||
			keyClass.RingSamplesPerKey != wantRows {
			t.Fatalf("key class %d gadget shape drifted: %+v", index, keyClass)
		}
	}
	if len(profile.GaloisElements) != 38 || profile.GaloisElements[0] != 5 || profile.GaloisElements[37] != 131071 {
		t.Fatalf("Galois inventory drifted: %v", profile.GaloisElements)
	}
	if profile.Moduli.FullQ.BitLength != 904 || profile.Moduli.FullQP.BitLength != 1254 ||
		profile.Moduli.Q0P0.BitLength != 93 || profile.Estimator.MainClassicalMinimumBits != "150.672" ||
		profile.Estimator.MainQuantumMinimumBits != "136.740" ||
		profile.Estimator.EphemeralClassicalMinimumBits != "+Infinity" ||
		profile.Estimator.NegativeControlClassicalMinimumBits != "11.680" {
		t.Fatalf("modulus or estimator evidence drifted: moduli=%+v estimator=%+v", profile.Moduli, profile.Estimator)
	}
	if profile.CanonicalJSONSHA256 == "" {
		t.Fatal("application-security profile digest is empty")
	}

	first, err := CanonicalRouteBApplicationSecurityProfileJSON(profile)
	if err != nil {
		t.Fatal(err)
	}
	var decoded RouteBApplicationSecurityProfile
	if err = json.Unmarshal(first, &decoded); err != nil {
		t.Fatal(err)
	}
	second, err := CanonicalRouteBApplicationSecurityProfileJSON(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("application-security profile JSON is not deterministic")
	}
	t.Logf("application-security profile digest=%s", profile.CanonicalJSONSHA256)
}

func TestRouteBApplicationSecurityProfileRejectsSelfConsistentMutations(t *testing.T) {
	base, err := NewRouteBApplicationSecurityProfile()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*RouteBApplicationSecurityProfile)
	}{
		{"galois count", func(value *RouteBApplicationSecurityProfile) { value.KeyClasses[0].KeyCount-- }},
		{"gadget shape", func(value *RouteBApplicationSecurityProfile) { value.KeyClasses[2].BaseRNSRows++ }},
		{"secret role", func(value *RouteBApplicationSecurityProfile) { value.KeyClasses[2].OutputSecret = "main-h192" }},
		{"modulus", func(value *RouteBApplicationSecurityProfile) { value.Moduli.Q0P0.BitLength++ }},
		{"C75 binding", func(value *RouteBApplicationSecurityProfile) {
			value.BoundCircuit.ArtifactSHA256 = value.BoundCircuit.ReportDigest
		}},
		{"estimator minimum", func(value *RouteBApplicationSecurityProfile) { value.Estimator.MainClassicalMinimumBits = "127.999" }},
		{"negative control", func(value *RouteBApplicationSecurityProfile) {
			value.Estimator.NegativeControlClassicalMinimumBits = "128.000"
		}},
		{"assumption", func(value *RouteBApplicationSecurityProfile) {
			value.Assumptions = value.Assumptions[:len(value.Assumptions)-1]
		}},
		{"decision", func(value *RouteBApplicationSecurityProfile) { value.Decision.Status = RouteBSecurityPass }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload, marshalErr := json.Marshal(base)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			var mutated RouteBApplicationSecurityProfile
			if unmarshalErr := json.Unmarshal(payload, &mutated); unmarshalErr != nil {
				t.Fatal(unmarshalErr)
			}
			test.mutate(&mutated)
			mutated.CanonicalJSONSHA256, err = digestRouteBApplicationSecurityProfile(mutated)
			if err != nil {
				t.Fatal(err)
			}
			if err = mutated.Validate(); err == nil {
				t.Fatal("self-consistent foreign application-security profile was accepted")
			}
		})
	}
}
