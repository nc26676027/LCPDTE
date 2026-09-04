package ckksint_test

import (
	"os"
	"testing"

	"github.com/nc26676027/LCPDTE/ckksint"
)

func TestGaoFullPackedA2BPublicAPICompiles(t *testing.T) {
	if ckksint.GaoFullPackedA2BMaxWords != 8192 {
		t.Fatalf("full-packed capacity=%d, want 8192", ckksint.GaoFullPackedA2BMaxWords)
	}
	var _ func() (*ckksint.GaoFullPackedA2BClient, *ckksint.GaoFullPackedA2BServer, ckksint.GaoFullPackedA2BSetupInfo, error) = ckksint.NewGaoFullPackedA2B
	var _ func(*ckksint.GaoFullPackedA2BClient, []uint8) (*ckksint.GaoFullPackedA2BEncryptedInput, ckksint.GaoFullPackedA2BPhaseInfo, error) = (*ckksint.GaoFullPackedA2BClient).EncryptA2B
	var _ func(*ckksint.GaoFullPackedA2BServer, *ckksint.GaoFullPackedA2BEncryptedInput) (*ckksint.GaoFullPackedA2BEncryptedOutput, ckksint.GaoFullPackedA2BPhaseInfo, error) = (*ckksint.GaoFullPackedA2BServer).EvaluateA2B
	var _ func(*ckksint.GaoFullPackedA2BClient, *ckksint.GaoFullPackedA2BEncryptedOutput) ([][8]uint8, ckksint.GaoFullPackedA2BPhaseInfo, error) = (*ckksint.GaoFullPackedA2BClient).DecryptA2B
	var _ func(*ckksint.GaoFullPackedA2BServer) = (*ckksint.GaoFullPackedA2BServer).Close
}

func TestGaoFullPackedA2BEndToEnd(t *testing.T) {
	if os.Getenv("LCPDTE_GAO_FULL_A2B_E2E") != "1" {
		t.Skip("set LCPDTE_GAO_FULL_A2B_E2E=1 to run the N=65536 Gao full-packed A2B session")
	}

	words := make([]uint8, ckksint.GaoFullPackedA2BMaxWords)
	for index := range words {
		words[index] = uint8(index)
	}
	client, server, setup, err := ckksint.NewGaoFullPackedA2B()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if setup.ParameterWallTime <= 0 || setup.KeyGenerationWallTime <= 0 || setup.ServerConstructionWallTime <= 0 ||
		setup.ClientConstructionWallTime <= 0 {
		t.Fatalf("incomplete setup timings: %+v", setup)
	}
	profile := setup.Parameters
	if profile.MainSecretDistribution != "fixed-h-symmetric-sparse-ternary" || profile.MainSecretHammingWeight != 192 ||
		profile.EphemeralSecretDistribution != "fixed-h-symmetric-sparse-ternary" || profile.EphemeralSecretHammingWeight != 32 ||
		profile.ErrorSampler != "lattigo-bounded-discrete-gaussian" || profile.ErrorSigma != 3.19 ||
		profile.ErrorConfiguredBound != 39 || profile.ErrorEffectiveIntegerBound != 39 ||
		profile.KeySwitchTechnique != "lattigo-rns-qp-gadget" || profile.RNSDecompositionComponents != 3 ||
		profile.BaseTwoDecomposition != 0 || profile.SecuritySelector != "external-estimator" ||
		profile.SecurityEvidence != "full-packed-profile-not-assessed" || profile.ActualFirstQModulusBits != 44 ||
		len(profile.QModuli) != profile.QModuliCount || len(profile.QModuliBitLengths) != profile.QModuliCount ||
		len(profile.PModuli) != profile.PModuliCount || len(profile.PModuliBitLengths) != profile.PModuliCount {
		t.Fatalf("incomplete native parameter profile: %+v", profile)
	}

	input, encryption, err := client.EncryptA2B(words)
	if err != nil {
		t.Fatal(err)
	}
	output, evaluation, err := server.EvaluateA2B(input)
	if err != nil {
		t.Fatal(err)
	}
	if evaluation.PreparationWallTime != 0 || evaluation.OnlineWallTime <= 0 ||
		evaluation.WordCount != len(words) {
		t.Fatalf("invalid prepared evaluation report: %+v", evaluation)
	}
	got, decryption, err := client.DecryptA2B(output)
	if err != nil {
		t.Fatal(err)
	}
	if encryption.WordCount != len(words) || decryption.WordCount != len(words) || len(got) != len(words) {
		t.Fatalf("word counts changed: encrypt=%d decrypt=%d decoded=%d", encryption.WordCount, decryption.WordCount, len(got))
	}
	for wordIndex, word := range words {
		for bit := 0; bit < 8; bit++ {
			want := (word >> bit) & 1
			if got[wordIndex][bit] != want {
				t.Fatalf("word %d bit %d=%d, want %d", wordIndex, bit, got[wordIndex][bit], want)
			}
		}
	}
}
