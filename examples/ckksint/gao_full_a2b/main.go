package main

import (
	"fmt"
	"os"
	"time"

	"github.com/nc26676027/LCPDTE/ckksint"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gao_full_a2b:", err)
		os.Exit(1)
	}
}

func run() error {
	words := make([]uint8, ckksint.GaoFullPackedA2BMaxWords)
	for index := range words {
		words[index] = uint8(index)
	}

	fmt.Printf("Gao full-packed A2B: N=65536 complex_slots=32768 words=%d output=low4/high4\n", len(words))
	client, server, setup, err := ckksint.NewGaoFullPackedA2B()
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
		for bit := 0; bit < 8; bit++ {
			if bits[wordIndex][bit] != (word>>bit)&1 {
				mismatches++
			}
		}
	}

	setupWall := setup.ParameterWallTime + setup.KeyGenerationWallTime + setup.ServerConstructionWallTime
	throughput := float64(len(words)) / evaluation.OnlineWallTime.Seconds()
	fmt.Printf("setup=%s (parameters=%s keygen=%s server=%s)\n",
		setupWall.Round(time.Millisecond), setup.ParameterWallTime.Round(time.Millisecond),
		setup.KeyGenerationWallTime.Round(time.Millisecond), setup.ServerConstructionWallTime.Round(time.Millisecond))
	fmt.Printf("encrypt=%s online=%s server_call=%s decrypt=%s throughput=%.2f words/s\n",
		encryption.WallTime.Round(time.Millisecond), evaluation.OnlineWallTime.Round(time.Millisecond),
		evaluation.WallTime.Round(time.Millisecond), decryption.WallTime.Round(time.Millisecond), throughput)
	fmt.Printf("trace=%s mismatches=%d\n", evaluation.TraceDigest, mismatches)
	if evaluation.PreparationWallTime != 0 {
		return fmt.Errorf("prepared evaluation reported online preparation %s", evaluation.PreparationWallTime)
	}
	if mismatches != 0 {
		return fmt.Errorf("A2B verification failed: mismatch_count=%d", mismatches)
	}
	return nil
}
