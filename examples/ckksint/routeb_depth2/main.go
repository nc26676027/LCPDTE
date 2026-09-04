// routeb_depth2 runs the complete Gao-compatible Route-B client/server flow.
package main

import (
	"fmt"
	"log"
	"math"

	"github.com/nc26676027/LCPDTE/ckksint"
)

const accuracyTolerance = 5e-4

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	features := [][]int8{
		{-1, -1, 0, 1},
		{-5, -4, -5, -5},
		{3, 2, 2, 3},
	}
	model := ckksint.Depth2Model{
		FeatureIDs: [3]int{0, 1, 2},
		Thresholds: [3]int8{0, -4, 3},
		Leaves:     [4]float64{-1.25, 2.5, -3.75, 5},
	}
	request, err := ckksint.ValidateCanonicalRouteBDepth2Request(features, model)
	if err != nil {
		return err
	}

	client, server, setup, err := ckksint.NewCanonicalRouteBDepth2()
	if err != nil {
		return err
	}
	defer server.Close()

	encrypted, encryption, err := client.EncryptDepth2(features, model)
	if err != nil {
		return err
	}
	evaluated, evaluation, err := server.EvaluateDepth2(encrypted)
	if err != nil {
		return err
	}
	values, decryption, err := client.DecryptDepth2(evaluated)
	if err != nil {
		return err
	}

	want := plaintextDepth2(features, model)
	maxError := 0.0
	mismatches := 0
	for query := range want {
		if !finite(values[query]) || !finite(want[query]) {
			maxError = math.Inf(1)
			mismatches++
			continue
		}
		delta := math.Abs(values[query] - want[query])
		maxError = math.Max(maxError, delta)
		if delta > accuracyTolerance {
			mismatches++
		}
	}
	effectiveThroughput := float64(request.QueryCount) / evaluation.WallTime.Seconds()
	packedThroughput := float64(request.PaddedQueryCount) / evaluation.WallTime.Seconds()

	fmt.Printf("queries=%d padded=%d values=%v\n", request.QueryCount, request.PaddedQueryCount, values)
	fmt.Printf(
		"parameter/artifact=%s keygen=%s server-install=%s encrypt=%s evaluate=%s decrypt/decode=%s\n",
		setup.ParameterArtifactWallTime, setup.KeyGenerationWallTime, setup.ServerInstallWallTime,
		encryption.WallTime, evaluation.WallTime, decryption.WallTime,
	)
	fmt.Printf("effective-query/s=%.6f packed-query/s=%.6f max-error=%.3g mismatches=%d trace=%s\n",
		effectiveThroughput, packedThroughput, maxError, mismatches, evaluation.TraceDigest)
	if mismatches != 0 {
		return fmt.Errorf("Route-B depth2 plaintext verification failed: %d mismatches", mismatches)
	}
	return nil
}

func finite(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0)
}

// plaintextDepth2 is deliberately independent of the encrypted evaluator.
func plaintextDepth2(features [][]int8, model ckksint.Depth2Model) []float64 {
	values := make([]float64, len(features[0]))
	for query := range values {
		root := 0
		if features[model.FeatureIDs[0]][query] >= model.Thresholds[0] {
			root = 1
		}
		childNode := 1 + root
		child := 0
		if features[model.FeatureIDs[childNode]][query] >= model.Thresholds[childNode] {
			child = 1
		}
		values[query] = model.Leaves[2*root+child]
	}
	return values
}
