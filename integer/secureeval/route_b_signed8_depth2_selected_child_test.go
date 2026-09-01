package secureeval

import (
	"math"
	"testing"

	"dt_go/integer/homchain"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func TestRouteBSigned8Depth2SelectedChildModelAndBindingAreClosed(t *testing.T) {
	model, err := NewRouteBSigned8Depth2SelectedChildModel(
		[3]uint32{7, 3, 11}, [3]int64{0, -4, 3}, [4]float64{-1.25, 2.5, -3.75, 5},
	)
	if err != nil {
		t.Fatal(err)
	}
	if model.FeatureIDs() != [3]uint32{7, 3, 11} || model.Thresholds() != [3]int64{0, -4, 3} ||
		model.Leaves() != [4]float64{-1.25, 2.5, -3.75, 5} || model.Digest() == "" {
		t.Fatalf("unexpected selected-child model: %+v", model)
	}
	params, err := canonicalRouteBSigned8RootTreeParameters()
	if err != nil {
		t.Fatal(err)
	}
	newInput := func() *rlwe.Ciphertext {
		value := ckks.NewCiphertext(params, 1, 20)
		value.LogDimensions = ring.Dimensions{Rows: 0, Cols: 11}
		value.Scale = params.DefaultScale()
		return value
	}
	features := map[uint32]*rlwe.Ciphertext{7: newInput(), 3: newInput(), 11: newInput()}
	bound, err := BindRouteBSigned8Depth2SelectedChildFeatures(model, features)
	if err != nil {
		t.Fatal(err)
	}
	if bound.modelDigest != model.Digest() || bound.featureIDs != model.FeatureIDs() || bound.digest == "" {
		t.Fatalf("unexpected selected-child feature binding: %+v", bound)
	}
	features[7].Scale = rlwe.NewScale(1)
	if !bound.features[0].Scale.Equal(params.DefaultScale()) {
		t.Fatal("selected-child binder retained a caller ciphertext alias")
	}
	missing := map[uint32]*rlwe.Ciphertext{7: newInput(), 3: newInput()}
	if got, bindErr := BindRouteBSigned8Depth2SelectedChildFeatures(model, missing); bindErr == nil || got.digest != "" {
		t.Fatal("selected-child binder accepted a missing model feature")
	}
	foreign := model
	foreign.digest = "foreign"
	if got, bindErr := BindRouteBSigned8Depth2SelectedChildFeatures(foreign, map[uint32]*rlwe.Ciphertext{7: newInput(), 3: newInput(), 11: newInput()}); bindErr == nil || got.digest != "" {
		t.Fatal("selected-child binder accepted a self-inconsistent model")
	}
}

func TestRouteBSigned8Depth2SelectedChildOracleCoversPathsAndEquality(t *testing.T) {
	model, err := NewRouteBSigned8Depth2SelectedChildModel(
		[3]uint32{0, 1, 2}, [3]int64{0, -4, 3}, [4]float64{-1.25, 2.5, -3.75, 5},
	)
	if err != nil {
		t.Fatal(err)
	}
	ranges := [3]homchain.Signed8NoOverflowRange{}
	for index, tuple := range [][4]int64{{-128, 127, 0, 0}, {-128, 123, -4, -4}, {-125, 127, 3, 3}} {
		ranges[index], err = homchain.NewSigned8NoOverflowRange(tuple[0], tuple[1], tuple[2], tuple[3])
		if err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		features map[uint32]int64
		leaf     float64
		path     uint8
	}{
		{map[uint32]int64{0: -1, 1: -5, 2: 3}, -1.25, 0},
		{map[uint32]int64{0: -1, 1: -4, 2: 2}, 2.5, 1},
		{map[uint32]int64{0: 0, 1: -5, 2: 2}, -3.75, 2},
		{map[uint32]int64{0: 0, 1: -5, 2: 3}, 5, 3},
	}
	for _, test := range tests {
		leaf, path, root, child, oracleErr := routeBSigned8Depth2SelectedChildOracle(test.features, ranges, model)
		if oracleErr != nil {
			t.Fatal(oracleErr)
		}
		if leaf != test.leaf || path != test.path || path != 2*root+child {
			t.Fatalf("features=%v got leaf/path/root/child=%g/%d/%d/%d", test.features, leaf, path, root, child)
		}
	}
}

func TestRouteBSigned8Depth2SelectedChildBilinearLeafIdentity(t *testing.T) {
	leaves := [4]float64{-1.25, 2.5, -3.75, 5}
	alpha, beta, gamma := routeBSigned8Depth2SelectedChildLeafCoefficients(leaves)
	for root := 0; root <= 1; root++ {
		for child := 0; child <= 1; child++ {
			got := leaves[0] + alpha*float64(root) + beta*float64(child) + gamma*float64(root*child)
			want := leaves[2*root+child]
			if math.Float64bits(got) != math.Float64bits(want) {
				t.Fatalf("root=%d child=%d got %.17g want %.17g", root, child, got, want)
			}
		}
	}
}

func TestRouteBSigned8Depth2SelectedChildPublicAPIAndExactScalePlan(t *testing.T) {
	var _ func(
		*RouteBInstalledEvaluator,
		RouteBSigned8Depth2SelectedChildFeatures,
		[3]homchain.Signed8NoOverflowRange,
		RouteBSigned8Depth2SelectedChildModel,
	) (RouteBSigned8Depth2SelectedChildResult, RouteBFirstOperationReport, RouteBSigned8Depth2SelectedChildReport, error) = (*RouteBInstalledEvaluator).RunSigned8Depth2SelectedChildPublic

	params, err := canonicalRouteBSigned8RootTreeParameters()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := newRouteBSigned8Depth2SelectedChildScalePlan(params)
	if err != nil {
		t.Fatal(err)
	}
	if plan.rootBooleanLevel != 8 || plan.conditionedRootLevel != 7 || plan.selectedChildLevel != 6 ||
		plan.childBooleanLevel != 3 || plan.productLevel != 2 || plan.outputLevel != 1 {
		t.Fatalf("selected-child level schedule changed: %+v", plan)
	}
	if !rbdftEqualScaleExact(plan.conditionedRootScale, rlwe.NewScale(params.Q()[7])) ||
		!rbdftEqualScaleExact(plan.selectedChildScale, params.DefaultScale()) ||
		!rbdftEqualScaleExact(plan.childBooleanScale, params.DefaultScale()) ||
		!plan.terminalOutputScale.Equal(rlwe.NewScale(params.Q()[7])) ||
		plan.terminalOutputScale.Value.Prec() != routeBSigned8RootTreeEncoderPrecision {
		t.Fatalf("selected-child exact-scale endpoints changed: %+v", plan)
	}
	if err = (RouteBSigned8Depth2SelectedChildReport{}).Validate(); err == nil {
		t.Fatal("zero selected-child report validated")
	}
}

func TestRouteBSigned8Depth2SelectedChildCanonicalInputCoversRootDomainPathsAndEqualities(t *testing.T) {
	model, ranges, err := routeBSigned8Depth2SelectedChildCanonicalModelAndRanges()
	if err != nil {
		t.Fatal(err)
	}
	features := routeBSigned8Depth2SelectedChildInputFeatures()
	if len(features[0]) != 512 || len(features[1]) != 512 || len(features[2]) != 512 ||
		routeBSigned8Depth2SelectedChildInputPatternDigest() == "" {
		t.Fatal("canonical selected-child feature shape or digest changed")
	}
	rootCounts := make(map[int64]int, 256)
	var paths [4]uint32
	var rootEquality, leftEquality, rightEquality uint32
	for query := 0; query < 512; query++ {
		rootCounts[features[0][query]]++
		values := map[uint32]int64{0: features[0][query], 1: features[1][query], 2: features[2][query]}
		_, path, root, _, oracleErr := routeBSigned8Depth2SelectedChildOracle(values, ranges, model)
		if oracleErr != nil {
			t.Fatal(oracleErr)
		}
		paths[path]++
		if features[0][query] == 0 {
			rootEquality++
		}
		if root == 0 && features[1][query] == -4 {
			leftEquality++
		}
		if root == 1 && features[2][query] == 3 {
			rightEquality++
		}
	}
	for value := int64(-128); value <= 127; value++ {
		if rootCounts[value] != 2 {
			t.Fatalf("canonical selected-child root value %d count=%d, want 2", value, rootCounts[value])
		}
	}
	if rootEquality != 2 || leftEquality == 0 || rightEquality == 0 ||
		paths[0] == 0 || paths[1] == 0 || paths[2] == 0 || paths[3] == 0 {
		t.Fatalf("canonical selected-child coverage paths=%v equalities=%d/%d/%d", paths, rootEquality, leftEquality, rightEquality)
	}
	for path, want := range [4]uint8{0, 1, 2, 3} {
		values := map[uint32]int64{0: features[0][path], 1: features[1][path], 2: features[2][path]}
		_, got, _, _, oracleErr := routeBSigned8Depth2SelectedChildOracle(values, ranges, model)
		if oracleErr != nil || got != want {
			t.Fatalf("canonical selected-child prefix query %d path=%d error=%v", path, got, oracleErr)
		}
	}
}

func TestRouteBSigned8Depth2SelectedChildRootSignMustBeComplementedToGE(t *testing.T) {
	for difference := int64(-128); difference <= 127; difference++ {
		sign := uint8(0)
		if difference < 0 {
			sign = 1
		}
		ge := uint8(1) - sign
		want := uint8(0)
		if difference >= 0 {
			want = 1
		}
		if ge != want {
			t.Fatalf("difference=%d sign=%d ge=%d want=%d", difference, sign, ge, want)
		}
	}
}
