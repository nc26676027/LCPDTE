package ckksint_test

import (
	"os"
	"testing"

	"github.com/nc26676027/LCPDTE/ckksint"
)

func TestCanonicalRouteBA2BPublicAPICompiles(t *testing.T) {
	var _ func() (*ckksint.RouteBA2BClient, *ckksint.RouteBA2BServer, ckksint.RouteBA2BSetupInfo, error) = ckksint.NewCanonicalRouteBA2B
	var _ func(*ckksint.RouteBA2BClient, []uint8) (*ckksint.RouteBA2BEncryptedInput, ckksint.RouteBA2BPhaseInfo, error) = (*ckksint.RouteBA2BClient).EncryptA2B
	var _ func(*ckksint.RouteBA2BServer, *ckksint.RouteBA2BEncryptedInput) (*ckksint.RouteBA2BEncryptedOutput, ckksint.RouteBA2BPhaseInfo, error) = (*ckksint.RouteBA2BServer).EvaluateA2B
	var _ func(*ckksint.RouteBA2BClient, *ckksint.RouteBA2BEncryptedOutput) ([][8]uint8, ckksint.RouteBA2BPhaseInfo, error) = (*ckksint.RouteBA2BClient).DecryptA2B
	var _ func(*ckksint.RouteBA2BServer) = (*ckksint.RouteBA2BServer).Close
}

func TestCanonicalRouteBA2BReusesPreparedEvaluator(t *testing.T) {
	if os.Getenv("LCPDTE_ROUTE_B_A2B_E2E") != "1" {
		t.Skip("set LCPDTE_ROUTE_B_A2B_E2E=1 to run the canonical N=2^16 Route-B A2B session")
	}

	client, server, setup, err := ckksint.NewCanonicalRouteBA2B()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if setup.ParameterArtifactWallTime <= 0 || setup.KeyGenerationWallTime <= 0 || setup.ServerInstallWallTime <= 0 {
		t.Fatalf("incomplete setup timing: %+v", setup)
	}

	words := []uint8{0, 1, 15, 16, 127, 128, 255}
	input, encryption, err := client.EncryptA2B(words)
	if err != nil {
		t.Fatal(err)
	}
	if encryption.Phase != "encrypt" || encryption.WordCount != len(words) || encryption.WallTime <= 0 {
		t.Fatalf("incomplete encryption timing: %+v", encryption)
	}

	firstOutput, firstEvaluation, err := server.EvaluateA2B(input)
	if err != nil {
		t.Fatal(err)
	}
	secondOutput, secondEvaluation, err := server.EvaluateA2B(input)
	if err != nil {
		t.Fatalf("prepared evaluator rejected a second call: %v", err)
	}
	if firstEvaluation.PreparationWallTime <= 0 || firstEvaluation.OnlineWallTime <= 0 ||
		secondEvaluation.PreparationWallTime != 0 || secondEvaluation.OnlineWallTime <= 0 ||
		firstEvaluation.TraceDigest == "" || secondEvaluation.TraceDigest == "" {
		t.Fatalf("invalid prepared timing: first=%+v second=%+v", firstEvaluation, secondEvaluation)
	}

	for run, output := range []*ckksint.RouteBA2BEncryptedOutput{firstOutput, secondOutput} {
		got, decryption, decryptErr := client.DecryptA2B(output)
		if decryptErr != nil {
			t.Fatalf("run %d decrypt: %v", run, decryptErr)
		}
		if decryption.Phase != "decrypt/decode" || decryption.WordCount != len(words) || decryption.WallTime <= 0 {
			t.Fatalf("run %d incomplete decryption timing: %+v", run, decryption)
		}
		if len(got) != len(words) {
			t.Fatalf("run %d decoded words=%d, want %d", run, len(got), len(words))
		}
		for lane, word := range words {
			for bit := 0; bit < 8; bit++ {
				want := uint8((word >> bit) & 1)
				if got[lane][bit] != want {
					t.Fatalf("run %d lane %d bit %d=%d, want %d", run, lane, bit, got[lane][bit], want)
				}
			}
		}
	}
}
