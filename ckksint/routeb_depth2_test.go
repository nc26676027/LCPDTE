package ckksint_test

import (
	"math"
	"os"
	"strings"
	"testing"

	"github.com/nc26676027/LCPDTE/ckksint"
)

func TestCanonicalRouteBDepth2RequestValidation(t *testing.T) {
	model := routeBDepth2TestModel()
	features := routeBDepth2TestFeatures()

	info, err := ckksint.ValidateCanonicalRouteBDepth2Request(features, model)
	if err != nil {
		t.Fatal(err)
	}
	if info.QueryCount != 4 || info.PaddedQueryCount != 512 || info.FeatureCount != 3 {
		t.Fatalf("request info = %+v", info)
	}

	tests := []struct {
		name     string
		features [][]int8
		model    ckksint.Depth2Model
		contains string
	}{
		{name: "empty batch", features: [][]int8{{}, {}, {}}, model: model, contains: "1..512"},
		{name: "oversized batch", features: [][]int8{
			make([]int8, 513), make([]int8, 513), make([]int8, 513),
		}, model: model, contains: "1..512"},
		{name: "inconsistent feature lengths", features: [][]int8{{-1}, {-5, -4}, {2}}, model: model, contains: "same query count"},
		{name: "missing referenced feature", features: features, model: func() ckksint.Depth2Model {
			value := model
			value.FeatureIDs[2] = 3
			return value
		}(), contains: "requires feature 3"},
		{name: "negative feature id", features: features, model: func() ckksint.Depth2Model {
			value := model
			value.FeatureIDs[0] = -1
			return value
		}(), contains: "feature id"},
		{name: "non-finite leaf", features: features, model: func() ckksint.Depth2Model {
			value := model
			value.Leaves[0] = math.NaN()
			return value
		}(), contains: "leaf"},
		{name: "signed subtraction overflow", features: [][]int8{{-128}, {0}, {0}}, model: ckksint.Depth2Model{
			FeatureIDs: [3]int{0, 1, 2}, Thresholds: [3]int8{127, 0, 0}, Leaves: model.Leaves,
		}, contains: "no-overflow"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ckksint.ValidateCanonicalRouteBDepth2Request(test.features, test.model)
			if err == nil || !strings.Contains(err.Error(), test.contains) {
				t.Fatalf("error = %v, want substring %q", err, test.contains)
			}
		})
	}
}

func TestCanonicalRouteBDepth2PublicAPICompiles(t *testing.T) {
	var _ func() (*ckksint.RouteBDepth2Client, *ckksint.RouteBDepth2Server, ckksint.RouteBDepth2SetupInfo, error) = ckksint.NewCanonicalRouteBDepth2
	var _ func(*ckksint.RouteBDepth2Client, [][]int8, ckksint.Depth2Model) (*ckksint.RouteBDepth2EncryptedInput, ckksint.RouteBDepth2PhaseInfo, error) = (*ckksint.RouteBDepth2Client).EncryptDepth2
	var _ func(*ckksint.RouteBDepth2Server, *ckksint.RouteBDepth2EncryptedInput) (*ckksint.RouteBDepth2EncryptedOutput, ckksint.RouteBDepth2PhaseInfo, error) = (*ckksint.RouteBDepth2Server).EvaluateDepth2
	var _ func(*ckksint.RouteBDepth2Client, *ckksint.RouteBDepth2EncryptedOutput) ([]float64, ckksint.RouteBDepth2PhaseInfo, error) = (*ckksint.RouteBDepth2Client).DecryptDepth2
	var _ func(*ckksint.RouteBDepth2Server) = (*ckksint.RouteBDepth2Server).Close
}

func TestCanonicalRouteBDepth2EndToEnd(t *testing.T) {
	if os.Getenv("LCPDTE_ROUTE_B_E2E") != "1" {
		t.Skip("set LCPDTE_ROUTE_B_E2E=1 to run the canonical N=2^16 Route-B session")
	}

	features := routeBDepth2TestFeatures()
	model := routeBDepth2TestModel()
	if _, err := ckksint.ValidateCanonicalRouteBDepth2Request(features, model); err != nil {
		t.Fatal(err)
	}
	client, server, setup, err := ckksint.NewCanonicalRouteBDepth2()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if setup.ParameterArtifactWallTime <= 0 || setup.KeyGenerationWallTime <= 0 || setup.ServerInstallWallTime <= 0 {
		t.Fatalf("incomplete setup timing: %+v", setup)
	}

	encrypted, encryptInfo, err := client.EncryptDepth2(features, model)
	if err != nil {
		t.Fatal(err)
	}
	evaluated, evaluateInfo, err := server.EvaluateDepth2(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	values, decryptInfo, err := client.DecryptDepth2(evaluated)
	if err != nil {
		t.Fatal(err)
	}
	for _, info := range []ckksint.RouteBDepth2PhaseInfo{encryptInfo, evaluateInfo, decryptInfo} {
		if info.QueryCount != 4 || info.WallTime <= 0 || info.Phase == "" {
			t.Fatalf("incomplete phase timing: %+v", info)
		}
	}
	if evaluateInfo.TraceDigest == "" {
		t.Fatal("evaluation returned an empty trace digest")
	}
	want := []float64{-1.25, 2.5, -3.75, 5}
	if len(values) != len(want) {
		t.Fatalf("decoded length = %d, want %d", len(values), len(want))
	}
	for query := range want {
		if math.IsNaN(values[query]) || math.IsInf(values[query], 0) {
			t.Fatalf("query %d returned non-finite value %v", query, values[query])
		}
		if delta := math.Abs(values[query] - want[query]); delta > 5e-4 {
			t.Fatalf("query %d = %.12g, want %.12g (error %.3g)", query, values[query], want[query], delta)
		}
	}
	if _, _, err := server.EvaluateDepth2(encrypted); err == nil {
		t.Fatal("server accepted a second evaluation")
	}
}

func routeBDepth2TestFeatures() [][]int8 {
	return [][]int8{
		{-1, -1, 0, 1},
		{-5, -4, -5, -5},
		{3, 2, 2, 3},
	}
}

func routeBDepth2TestModel() ckksint.Depth2Model {
	return ckksint.Depth2Model{
		FeatureIDs: [3]int{0, 1, 2},
		Thresholds: [3]int8{0, -4, 3},
		Leaves:     [4]float64{-1.25, 2.5, -3.75, 5},
	}
}
