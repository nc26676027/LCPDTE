package treecompile

import (
	"errors"
	"math"
	"path/filepath"
	"runtime"
	"testing"

	"dt_go/integer/treeplan"
	"dt_go/treeio"
)

func sparseFixture() treeio.RawTree {
	//             n0: x0 < 0
	//             /          \
	//       n1: leaf 10      n2: x1 < 5
	//                         /          \
	//                   n3: leaf 20   n4: leaf 30
	return treeio.RawTree{
		Left:        []int32{1, -1, 3, -1, -1},
		Right:       []int32{2, -1, 4, -1, -1},
		SplitIndex:  []int32{0, -1, 1, -1, -1},
		SplitCond:   []float32{0, 10, 5, 20, 30},
		DefaultLeft: []bool{false, false, false, false, false},
		SplitType:   []uint8{0, 0, 0, 0, 0},
	}
}

func TestCompileTreePadsSparseLeavesAndPreservesMSBOrder(t *testing.T) {
	raw := sparseFixture()
	compiled, err := CompileTree(raw, 2)
	if err != nil {
		t.Fatal(err)
	}
	if compiled.Depth != 2 {
		t.Fatalf("depth=%d, want 2", compiled.Depth)
	}
	if len(compiled.Splits) != 3 || len(compiled.Leaves) != 4 {
		t.Fatalf("unexpected complete shape: splits=%d leaves=%d", len(compiled.Splits), len(compiled.Leaves))
	}
	if math.Float32bits(compiled.Splits[0].Threshold) != math.Float32bits(raw.SplitCond[0]) ||
		math.Float32bits(compiled.Splits[2].Threshold) != math.Float32bits(raw.SplitCond[2]) {
		t.Fatal("source thresholds were numerically rewritten")
	}
	wantLeaves := []float64{10, 10, 20, 30}
	for i := range wantLeaves {
		if compiled.Leaves[i] != wantLeaves[i] {
			t.Fatalf("leaf[%d]=%v, want %v", i, compiled.Leaves[i], wantLeaves[i])
		}
	}

	cases := []struct {
		x         []float32
		wantIndex int
		wantValue float64
	}{
		{[]float32{-1, -100}, 0, 10},
		// The dummy split below the padded left leaf also reads feature 0;
		// both of its leaf positions contain the same source value.
		{[]float32{-1, 100}, 0, 10},
		{[]float32{0, 4}, 2, 20},
		{[]float32{0, 5}, 3, 30},
	}
	for _, tc := range cases {
		index, err := compiled.Route(tc.x)
		if err != nil {
			t.Fatal(err)
		}
		if index != tc.wantIndex {
			t.Fatalf("x=%v leaf index=%d, want %d", tc.x, index, tc.wantIndex)
		}
		got, _ := compiled.Evaluate(tc.x)
		if got != tc.wantValue {
			t.Fatalf("x=%v leaf=%v, want %v", tc.x, got, tc.wantValue)
		}
	}
}

func TestCompileModelUsesCommonForestDepthAndExplicitBaseScore(t *testing.T) {
	shallow := treeio.RawTree{
		Left:        []int32{-1},
		Right:       []int32{-1},
		SplitIndex:  []int32{-1},
		SplitCond:   []float32{2},
		DefaultLeft: []bool{false},
		SplitType:   []uint8{0},
	}
	model := treeio.RawModel{
		BaseScore:  0.25,
		NumFeature: 2,
		TreeInfo:   []int{0, 0},
		Trees:      []treeio.RawTree{shallow, sparseFixture()},
	}
	semantics := ModelSemantics{
		BaseScore: BaseScoreProbability,
		Output:    OutputRawMargin,
	}
	forest, err := CompileModel(model, semantics)
	if err != nil {
		t.Fatal(err)
	}
	if forest.Depth != 2 || len(forest.Trees) != 2 {
		t.Fatalf("forest depth/trees=%d/%d, want 2/2", forest.Depth, len(forest.Trees))
	}
	for i, tree := range forest.Trees {
		if tree.Depth != forest.Depth {
			t.Fatalf("tree %d depth=%d, common depth=%d", i, tree.Depth, forest.Depth)
		}
	}
	if forest.BaseMargin != math.Log(0.25/0.75) {
		t.Fatalf("base margin=%g, want logit(0.25)", forest.BaseMargin)
	}

	x := []float32{0, 4}
	want := math.Log(0.25/0.75) + 2 + 20
	got, err := forest.RawMargin(x)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("raw margin=%g, want %g", got, want)
	}
	pred, err := forest.Predict(x)
	if err != nil {
		t.Fatal(err)
	}
	if pred != got {
		t.Fatalf("raw-output Predict=%g, RawMargin=%g", pred, got)
	}

	probabilityForest, err := CompileModel(model, ModelSemantics{
		BaseScore: BaseScoreProbability,
		Output:    OutputLogisticProbability,
	})
	if err != nil {
		t.Fatal(err)
	}
	probability, err := probabilityForest.Predict(x)
	if err != nil {
		t.Fatal(err)
	}
	if probability != Sigmoid(got) {
		t.Fatalf("probability=%g, want sigmoid(%g)=%g", probability, got, Sigmoid(got))
	}
}

func TestCompileFailsClosedOnUnsupportedSemantics(t *testing.T) {
	t.Run("categorical", func(t *testing.T) {
		raw := sparseFixture()
		raw.SplitType[0] = 1
		if _, err := CompileTree(raw, 2); !errors.Is(err, ErrCategoricalSplit) {
			t.Fatalf("error=%v, want ErrCategoricalSplit", err)
		}
	})

	t.Run("default-left", func(t *testing.T) {
		raw := sparseFixture()
		raw.DefaultLeft[0] = true
		if _, err := CompileTree(raw, 2); !errors.Is(err, ErrDefaultLeft) {
			t.Fatalf("error=%v, want ErrDefaultLeft", err)
		}
	})

	t.Run("missing-input", func(t *testing.T) {
		model := treeio.RawModel{
			BaseScore:  0.5,
			NumFeature: 2,
			TreeInfo:   []int{0},
			Trees:      []treeio.RawTree{sparseFixture()},
		}
		forest, err := CompileModel(model, ModelSemantics{BaseScore: BaseScoreProbability, Output: OutputRawMargin})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := forest.RawMargin([]float32{float32(math.NaN()), 0}); !errors.Is(err, ErrMissingValue) {
			t.Fatalf("error=%v, want ErrMissingValue", err)
		}
	})

	t.Run("implicit-model-semantics", func(t *testing.T) {
		model := treeio.RawModel{BaseScore: 0.5, NumFeature: 1}
		if _, err := CompileModel(model, ModelSemantics{}); !errors.Is(err, ErrModelSemantics) {
			t.Fatalf("error=%v, want ErrModelSemantics", err)
		}
	})
}

func TestCompileModelOutputGroupDomain(t *testing.T) {
	semantics := ModelSemantics{BaseScore: BaseScoreRawMargin, Output: OutputRawMargin}
	for _, groupCount := range []int{0, 1} {
		model := treeio.RawModel{BaseScore: 0, NumFeature: 1, NumOutputGroup: groupCount}
		if _, err := CompileModel(model, semantics); err != nil {
			t.Fatalf("num_output_group=%d rejected: %v", groupCount, err)
		}
	}
	model := treeio.RawModel{BaseScore: 0, NumFeature: 1, NumOutputGroup: -1}
	if _, err := CompileModel(model, semantics); !errors.Is(err, ErrOutputGroup) {
		t.Fatalf("negative output group error=%v, want ErrOutputGroup", err)
	}
}

func TestCompileAndForestRejectAllNonFiniteNumericFields(t *testing.T) {
	for name, value := range map[string]float32{
		"nan":     float32(math.NaN()),
		"pos-inf": float32(math.Inf(1)),
		"neg-inf": float32(math.Inf(-1)),
	} {
		raw := sparseFixture()
		raw.SplitCond[0] = value
		if _, err := CompileTree(raw, 2); !errors.Is(err, ErrMalformedTree) {
			t.Fatalf("%s split error=%v, want ErrMalformedTree", name, err)
		}
		raw = sparseFixture()
		raw.SplitCond[1] = value
		if _, err := CompileTree(raw, 2); !errors.Is(err, ErrMalformedTree) {
			t.Fatalf("%s leaf error=%v, want ErrMalformedTree", name, err)
		}
	}

	forest, err := CompileModel(treeio.RawModel{BaseScore: 0, NumFeature: 1}, ModelSemantics{
		BaseScore: BaseScoreRawMargin,
		Output:    OutputRawMargin,
	})
	if err != nil {
		t.Fatal(err)
	}
	forest.BaseMargin = math.Inf(1)
	if _, err := forest.RawMargin([]float32{0}); !errors.Is(err, ErrNonFiniteValue) {
		t.Fatalf("mutated non-finite forest error=%v, want ErrNonFiniteValue", err)
	}
}

func TestForestRejectsNonFiniteAccumulation(t *testing.T) {
	leafTree := func(value float64) treeplan.BinaryTree[float32, float64] {
		return treeplan.BinaryTree[float32, float64]{Depth: 0, Leaves: []float64{value}}
	}
	semantics := ModelSemantics{BaseScore: BaseScoreRawMargin, Output: OutputRawMargin}

	float64Overflow := Forest{
		NumFeatures:     0,
		Depth:           0,
		SourceBaseScore: 0,
		BaseMargin:      0,
		Semantics:       semantics,
		Trees:           []treeplan.BinaryTree[float32, float64]{leafTree(math.MaxFloat64), leafTree(math.MaxFloat64)},
	}
	if _, err := float64Overflow.RawMargin(nil); !errors.Is(err, ErrNonFiniteValue) {
		t.Fatalf("float64 accumulation error=%v, want ErrNonFiniteValue", err)
	}

	float32Overflow := Forest{
		NumFeatures:     0,
		Depth:           0,
		SourceBaseScore: 0,
		BaseMargin:      0,
		Semantics:       semantics,
		Trees: []treeplan.BinaryTree[float32, float64]{
			leafTree(2 * float64(math.MaxFloat32)),
		},
	}
	if _, err := float32Overflow.RawMarginFloat32(nil); !errors.Is(err, ErrNonFiniteValue) {
		t.Fatalf("float32 accumulation error=%v, want ErrNonFiniteValue", err)
	}

	baseCastOverflow := float32Overflow
	baseCastOverflow.BaseMargin = math.MaxFloat64
	baseCastOverflow.Trees = nil
	if _, err := baseCastOverflow.RawMarginFloat32(nil); !errors.Is(err, ErrNonFiniteValue) {
		t.Fatalf("float32 base cast error=%v, want ErrNonFiniteValue", err)
	}
}

func TestCompileR0EquivalentForEveryFixtureRow(t *testing.T) {
	compiled, err := CompileTree(sparseFixture(), 2)
	if err != nil {
		t.Fatal(err)
	}
	rows := [][]float32{{-1, -100}, {-1, 100}, {0, 4}, {0, 5}, {100, 100}}
	for groupWidth := 1; groupWidth <= 4; groupWidth++ {
		radix, err := treeplan.CompileR0(compiled, groupWidth)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			wantIndex, _ := compiled.Route(row)
			gotIndex, err := radix.Route(row)
			if err != nil {
				t.Fatal(err)
			}
			if gotIndex != wantIndex {
				t.Fatalf("g=%d row=%v index=%d, want %d", groupWidth, row, gotIndex, wantIndex)
			}
			want, _ := compiled.Evaluate(row)
			got, _ := radix.Evaluate(row)
			if math.Float64bits(got) != math.Float64bits(want) {
				t.Fatalf("g=%d row=%v leaf bits=%x, want %x", groupWidth, row, math.Float64bits(got), math.Float64bits(want))
			}
		}
	}
}

func TestCommittedXGBoostRawMarginRegressionAndR0(t *testing.T) {
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(here), "..", ".."))
	dataDir := filepath.Join(repoRoot, "xgbdata")
	if _, err := filepath.Glob(filepath.Join(dataDir, "xgb_model_d*.json")); err != nil {
		t.Fatal(err)
	}

	rows := []int{0, 1, 17, 1024, 32767}
	for _, name := range []string{"d8", "d10", "d12"} {
		bundle, _ := treeio.ParseBundle(dataDir, name)
		forest, err := CompileModel(bundle.Model, ModelSemantics{
			BaseScore: BaseScoreProbability,
			Output:    OutputRawMargin,
		})
		if err != nil {
			t.Fatalf("%s compile: %v", name, err)
		}
		t.Logf("%s: trees=%d common_depth=%d features=%d", name, len(forest.Trees), forest.Depth, forest.NumFeatures)
		sawSigmoidDifference := false
		for _, rowIndex := range rows {
			row := bundle.Input.X[rowIndex*bundle.Input.F : (rowIndex+1)*bundle.Input.F]
			got, err := forest.RawMarginFloat32(row)
			if err != nil {
				t.Fatalf("%s row %d: %v", name, rowIndex, err)
			}
			want := bundle.Pred[rowIndex]
			if math.Float32bits(got) != math.Float32bits(want) {
				t.Fatalf("%s row %d raw margin bits=%08x (%g), pred bits=%08x (%g)", name, rowIndex, math.Float32bits(got), got, math.Float32bits(want), want)
			}
			if math.Float32bits(float32(Sigmoid(float64(got)))) != math.Float32bits(want) {
				sawSigmoidDifference = true
			}

			for treeIndex, binary := range forest.Trees {
				wantIndex, err := binary.Route(row)
				if err != nil {
					t.Fatal(err)
				}
				wantLeaf, _ := binary.Evaluate(row)
				for groupWidth := 1; groupWidth <= 4; groupWidth++ {
					radix, err := treeplan.CompileR0(binary, groupWidth)
					if err != nil {
						t.Fatalf("%s tree %d g=%d: %v", name, treeIndex, groupWidth, err)
					}
					gotIndex, err := radix.Route(row)
					if err != nil {
						t.Fatal(err)
					}
					gotLeaf, _ := radix.Evaluate(row)
					if gotIndex != wantIndex || math.Float64bits(gotLeaf) != math.Float64bits(wantLeaf) {
						t.Fatalf("%s row=%d tree=%d g=%d route mismatch", name, rowIndex, treeIndex, groupWidth)
					}
				}
			}
		}
		if !sawSigmoidDifference {
			t.Fatalf("%s sampled predictions do not distinguish raw margin from sigmoid output", name)
		}
	}
}
