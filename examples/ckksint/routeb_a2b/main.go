package main

import (
	"fmt"
	"os"
	"time"

	"github.com/nc26676027/LCPDTE/ckksint"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "routeb_a2b:", err)
		os.Exit(1)
	}
}

func run() error {
	words := []uint8{0, 1, 2, 15, 16, 127, 128, 255}
	client, server, setup, err := ckksint.NewCanonicalRouteBA2B()
	if err != nil {
		return err
	}
	defer server.Close()

	encrypted, encryption, err := client.EncryptA2B(words)
	if err != nil {
		return err
	}
	evaluated, evaluation, err := server.EvaluateA2B(encrypted)
	if err != nil {
		return err
	}
	bits, decryption, err := client.DecryptA2B(evaluated)
	if err != nil {
		return err
	}

	var mismatches uint64
	for wordIndex, word := range words {
		var reconstructed uint8
		for bit := 0; bit < 8; bit++ {
			reconstructed |= bits[wordIndex][bit] << bit
		}
		if reconstructed != word {
			mismatches++
		}
		fmt.Printf("word[%d]=%3d bits(lsb-first)=%v reconstructed=%3d\n",
			wordIndex, word, bits[wordIndex], reconstructed)
	}

	setupWall := setup.ParameterArtifactWallTime + setup.KeyGenerationWallTime + setup.ServerInstallWallTime
	fmt.Printf("setup=%s preparation=%s online=%s server_call=%s encrypt=%s decrypt=%s\n",
		setupWall.Round(time.Millisecond), evaluation.PreparationWallTime.Round(time.Millisecond),
		evaluation.OnlineWallTime.Round(time.Millisecond), evaluation.WallTime.Round(time.Millisecond),
		encryption.WallTime.Round(time.Millisecond), decryption.WallTime.Round(time.Millisecond))
	fmt.Printf("trace=%s mismatches=%d\n", evaluation.TraceDigest, mismatches)
	if mismatches != 0 {
		return fmt.Errorf("A2B verification failed: mismatch_count=%d", mismatches)
	}
	return nil
}
