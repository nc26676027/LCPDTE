package treeeval

import (
	"errors"
	"math"
	"math/rand"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"dt_go/integer/treecompile"
	"dt_go/integer/treeplan"
	"dt_go/treeio"
)

func signedTestPolicy(t *testing.T) ComparisonPolicy {
	t.Helper()
	width := strconv.IntSize
	min, max := int64(math.MinInt64), int64(math.MaxInt64)
	if width == 32 {
		min, max = math.MinInt32, math.MaxInt32
	}
	policy, err := NewSignedComparisonPolicy(width, min, max, min, max, ComparatorSignedCorrected, OverflowSignCorrectedExact)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func handTree() treeplan.BinaryTree[float32, float64] {
	return treeplan.BinaryTree[float32, float64]{
		Depth: 2,
		Splits: []treeplan.BinarySplit[float32]{
			{Feature: 0, Threshold: 0},
			{Feature: 1, Threshold: -2},
			{Feature: 1, Threshold: 5},
		},
		Leaves: []float64{10, 11, 20, 30},
	}
}

func opaqueFeatures(values []float32) []PlainValue {
	out := make([]PlainValue, len(values))
	for i, value := range values {
		out[i] = Opaque(float64(value))
	}
	return out
}

func TestOBOHandTreeSemanticsAndExactCounts(t *testing.T) {
	backend := PlainBackend{}
	tree := handTree()
	cases := []struct {
		x    []float32
		want float64
	}{
		{[]float32{-1, -3}, 10},
		{[]float32{-1, -2}, 11},
		{[]float32{0, 4}, 20},
		{[]float32{0, 5}, 30},
	}
	for _, tc := range cases {
		result, err := EvaluateOBO(backend, tree, opaqueFeatures(tc.x), Opaque(1), RealComparisonPolicy())
		if err != nil {
			t.Fatalf("x=%v: %v", tc.x, err)
		}
		if result.Value.Scalar != tc.want || result.Value.Provenance != ValueOpaque {
			t.Fatalf("x=%v output=%+v, want opaque %v", tc.x, result.Value, tc.want)
		}
		if result.Counts.PublicConstants != 2*(1<<tree.Depth)-1 {
			t.Fatalf("x=%v public constants=%d, want %d", tc.x, result.Counts.PublicConstants, 2*(1<<tree.Depth)-1)
		}
		if got, want := result.Counts.TotalBackendCalls(), 10*(1<<tree.Depth)-8-tree.Depth; got != want {
			t.Fatalf("x=%v total backend calls=%d, want %d", tc.x, got, want)
		}
		wantCounts := OperationCounts{
			PublicConstants:          7,
			CTCTMultiplications:      6,
			CTPublicMultiplications:  7,
			Additions:                5,
			Subtractions:             3,
			Comparisons:              2,
			CTCTComparisons:          2,
			PeakLiveStates:           4,
			PeakLivePathStates:       4,
			PeakLiveComparisonStates: 1,
			FinalLiveStates:          4,
		}
		if result.Counts != wantCounts {
			t.Fatalf("x=%v counts:\n got %+v\nwant %+v", tc.x, result.Counts, wantCounts)
		}
	}
}

func TestFullLevelPublicThresholdBaselineCounts(t *testing.T) {
	backend := PlainBackend{}
	tree := handTree()
	result, err := EvaluateFullLevel(backend, tree, opaqueFeatures([]float32{0, 5}), Opaque(1), RealComparisonPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if result.Value.Scalar != 30 || result.Value.Provenance != ValueOpaque {
		t.Fatalf("output=%+v, want opaque 30", result.Value)
	}
	if result.Counts.PublicConstants != 2*(1<<tree.Depth)-1 {
		t.Fatalf("public constants=%d, want %d", result.Counts.PublicConstants, 2*(1<<tree.Depth)-1)
	}
	if got, want := result.Counts.TotalBackendCalls(), 7*(1<<tree.Depth)-5; got != want {
		t.Fatalf("total backend calls=%d, want %d", got, want)
	}
	want := OperationCounts{
		PublicConstants:          7,
		CTCTMultiplications:      3,
		CTPublicMultiplications:  4,
		Additions:                3,
		Subtractions:             3,
		Comparisons:              3,
		CTPublicComparisons:      3,
		PeakLiveStates:           4,
		PeakLivePathStates:       4,
		PeakLiveComparisonStates: 2,
		FinalLiveStates:          4,
	}
	if result.Counts != want {
		t.Fatalf("counts:\n got %+v\nwant %+v", result.Counts, want)
	}
	if result.Counts.Comparisons != (1<<tree.Depth)-1 {
		t.Fatalf("full-level comparisons=%d, want 2^D-1", result.Counts.Comparisons)
	}
}

func TestEqualityRoutesRight(t *testing.T) {
	tree := treeplan.BinaryTree[float32, float64]{
		Depth:  1,
		Splits: []treeplan.BinarySplit[float32]{{Feature: 0, Threshold: 5}},
		Leaves: []float64{-1, 1},
	}
	for name, evaluate := range map[string]func(Backend[PlainValue], treeplan.BinaryTree[float32, float64], []PlainValue, PlainValue, ComparisonPolicy) (Result[PlainValue], error){
		"obo":        EvaluateOBO[float32, float64, PlainValue],
		"full-level": EvaluateFullLevel[float32, float64, PlainValue],
	} {
		result, err := evaluate(PlainBackend{}, tree, []PlainValue{Opaque(5)}, Opaque(1), RealComparisonPolicy())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if result.Value.Scalar != 1 {
			t.Fatalf("%s equality output=%g, want right leaf 1", name, result.Value.Scalar)
		}
	}
}

func TestRandomCompleteTreesMatchPlaintext(t *testing.T) {
	rng := rand.New(rand.NewSource(20260829))
	backend := PlainBackend{}
	for depth := 0; depth <= 6; depth++ {
		tree := treeplan.BinaryTree[int, int]{
			Depth:  depth,
			Splits: make([]treeplan.BinarySplit[int], (1<<depth)-1),
			Leaves: make([]int, 1<<depth),
		}
		for i := range tree.Splits {
			tree.Splits[i] = treeplan.BinarySplit[int]{Feature: rng.Intn(4), Threshold: rng.Intn(21) - 10}
		}
		for i := range tree.Leaves {
			tree.Leaves[i] = rng.Intn(2001) - 1000
		}
		for sample := 0; sample < 100; sample++ {
			x := make([]int, 4)
			values := make([]PlainValue, 4)
			for i := range x {
				x[i] = rng.Intn(31) - 15
				var err error
				values[i], err = OpaqueSigned(int64(x[i]), strconv.IntSize)
				if err != nil {
					t.Fatal(err)
				}
			}
			want, err := tree.Evaluate(x)
			if err != nil {
				t.Fatal(err)
			}
			policy := signedTestPolicy(t)
			obo, err := EvaluateOBO(backend, tree, values, Opaque(1), policy)
			if err != nil {
				t.Fatalf("depth=%d sample=%d OBO: %v", depth, sample, err)
			}
			full, err := EvaluateFullLevel(backend, tree, values, Opaque(1), policy)
			if err != nil {
				t.Fatalf("depth=%d sample=%d full: %v", depth, sample, err)
			}
			if obo.Value.Scalar != float64(want) || full.Value.Scalar != float64(want) {
				t.Fatalf("depth=%d sample=%d outputs OBO/full=%g/%g, want %d", depth, sample, obo.Value.Scalar, full.Value.Scalar, want)
			}
			leaves := 1 << depth
			if obo.Counts.Comparisons != depth || full.Counts.Comparisons != leaves-1 {
				t.Fatalf("depth=%d comparison counts OBO/full=%d/%d", depth, obo.Counts.Comparisons, full.Counts.Comparisons)
			}
			wantOBO := OperationCounts{
				PublicConstants:          2*leaves - 1,
				CTCTMultiplications:      2 * (leaves - 1),
				CTPublicMultiplications:  2*leaves - 1,
				Additions:                3*leaves - 3 - 2*depth,
				Subtractions:             leaves - 1,
				Comparisons:              depth,
				CTCTComparisons:          depth,
				PeakLiveStates:           leaves,
				PeakLivePathStates:       leaves,
				PeakLiveComparisonStates: boolInt(depth > 0),
				FinalLiveStates:          leaves,
			}
			if obo.Counts != wantOBO {
				t.Fatalf("depth=%d OBO counts:\n got %+v\nwant %+v", depth, obo.Counts, wantOBO)
			}
			peakFullComparisons := 0
			if depth > 0 {
				peakFullComparisons = leaves / 2
			}
			wantFull := OperationCounts{
				PublicConstants:          2*leaves - 1,
				CTCTMultiplications:      leaves - 1,
				CTPublicMultiplications:  leaves,
				Additions:                leaves - 1,
				Subtractions:             leaves - 1,
				Comparisons:              leaves - 1,
				CTPublicComparisons:      leaves - 1,
				PeakLiveStates:           leaves,
				PeakLivePathStates:       leaves,
				PeakLiveComparisonStates: peakFullComparisons,
				FinalLiveStates:          leaves,
			}
			if full.Counts != wantFull {
				t.Fatalf("depth=%d full counts:\n got %+v\nwant %+v", depth, full.Counts, wantFull)
			}
		}
	}
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func TestFailsClosedOnInvalidBackendOrValues(t *testing.T) {
	tree := handTree()
	backend := PlainBackend{}

	if _, err := EvaluateOBO[float32, float64, PlainValue](nil, tree, opaqueFeatures([]float32{0, 0}), Opaque(1), RealComparisonPolicy()); !errors.Is(err, ErrInvalidBackend) {
		t.Fatalf("nil backend error=%v, want ErrInvalidBackend", err)
	}
	var typedNil *PlainBackend
	if _, err := EvaluateOBO[float32, float64, PlainValue](typedNil, tree, opaqueFeatures([]float32{0, 0}), Opaque(1), RealComparisonPolicy()); !errors.Is(err, ErrInvalidBackend) {
		t.Fatalf("typed-nil backend error=%v, want ErrInvalidBackend", err)
	}
	if _, err := EvaluateOBO(backend, tree, []PlainValue{Public(0), Opaque(0)}, Opaque(1), RealComparisonPolicy()); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("public query error=%v, want ErrInvalidValue", err)
	}
	if _, err := EvaluateOBO(backend, tree, opaqueFeatures([]float32{0, 0}), Public(1), RealComparisonPolicy()); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("public path one error=%v, want ErrInvalidValue", err)
	}
	if _, err := EvaluateOBO(backend, tree, []PlainValue{Opaque(math.NaN()), Opaque(0)}, Opaque(1), RealComparisonPolicy()); err == nil {
		t.Fatal("NaN opaque feature accepted")
	}

	liar := lyingBackend{PlainBackend: backend}
	if _, err := EvaluateOBO(liar, tree, opaqueFeatures([]float32{0, 0}), Opaque(1), RealComparisonPolicy()); !errors.Is(err, ErrBackendProvenance) {
		t.Fatalf("lying backend error=%v, want ErrBackendProvenance", err)
	}
}

func TestExactIntegerThresholdsAndComparisonPolicies(t *testing.T) {
	backend := PlainBackend{}

	t.Run("uint64-above-float64-exact-range", func(t *testing.T) {
		const threshold = uint64(1<<63 + 1)
		tree := treeplan.BinaryTree[uint64, uint64]{
			Depth:  1,
			Splits: []treeplan.BinarySplit[uint64]{{Feature: 0, Threshold: threshold}},
			Leaves: []uint64{7, 9},
		}
		policy, err := NewUnsignedComparisonPolicy(64, 0, math.MaxUint64, 0, math.MaxUint64, ComparatorUnsignedWidened, OverflowWidenedExact)
		if err != nil {
			t.Fatal(err)
		}
		feature, err := OpaqueUnsigned(threshold, 64)
		if err != nil {
			t.Fatal(err)
		}
		for name, evaluate := range map[string]func(Backend[PlainValue], treeplan.BinaryTree[uint64, uint64], []PlainValue, PlainValue, ComparisonPolicy) (Result[PlainValue], error){
			"obo":        EvaluateOBO[uint64, uint64, PlainValue],
			"full-level": EvaluateFullLevel[uint64, uint64, PlainValue],
		} {
			result, err := evaluate(backend, tree, []PlainValue{feature}, Opaque(1), policy)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			got, ok := result.Value.UnsignedValue()
			if !ok || got != 9 {
				t.Fatalf("%s result=%+v unsigned=%d/%v, want exact 9", name, result.Value, got, ok)
			}
		}
	})

	t.Run("negative-int64", func(t *testing.T) {
		const threshold = int64(-1 << 62)
		tree := treeplan.BinaryTree[int64, int64]{
			Depth:  1,
			Splits: []treeplan.BinarySplit[int64]{{Feature: 0, Threshold: threshold}},
			Leaves: []int64{-7, -9},
		}
		policy, err := NewSignedComparisonPolicy(64, math.MinInt64, math.MaxInt64, math.MinInt64, math.MaxInt64, ComparatorSignedCorrected, OverflowSignCorrectedExact)
		if err != nil {
			t.Fatal(err)
		}
		feature, err := OpaqueSigned(threshold, 64)
		if err != nil {
			t.Fatal(err)
		}
		result, err := EvaluateOBO(backend, tree, []PlainValue{feature}, Opaque(1), policy)
		if err != nil {
			t.Fatal(err)
		}
		got, ok := result.Value.SignedValue()
		if !ok || got != -9 {
			t.Fatalf("result=%+v signed=%d/%v, want exact -9", result.Value, got, ok)
		}
	})

	t.Run("same-bits-different-signedness", func(t *testing.T) {
		unsignedPolicy, err := NewUnsignedComparisonPolicy(8, 0, 255, 0, 255, ComparatorUnsignedBorrow, OverflowBorrowExact)
		if err != nil {
			t.Fatal(err)
		}
		signedPolicy, err := NewSignedComparisonPolicy(8, -128, 127, -128, 127, ComparatorSignedCorrected, OverflowSignCorrectedExact)
		if err != nil {
			t.Fatal(err)
		}
		uFeature, _ := OpaqueUnsigned(0, 8)
		sFeature, _ := OpaqueSigned(0, 8)
		uTree := treeplan.BinaryTree[uint8, int]{Depth: 1, Splits: []treeplan.BinarySplit[uint8]{{Feature: 0, Threshold: 0xff}}, Leaves: []int{0, 1}}
		sTree := treeplan.BinaryTree[int8, int]{Depth: 1, Splits: []treeplan.BinarySplit[int8]{{Feature: 0, Threshold: -1}}, Leaves: []int{0, 1}}
		uResult, err := EvaluateFullLevel(backend, uTree, []PlainValue{uFeature}, Opaque(1), unsignedPolicy)
		if err != nil {
			t.Fatal(err)
		}
		sResult, err := EvaluateFullLevel(backend, sTree, []PlainValue{sFeature}, Opaque(1), signedPolicy)
		if err != nil {
			t.Fatal(err)
		}
		uLeaf, _ := uResult.Value.SignedValue()
		sLeaf, _ := sResult.Value.SignedValue()
		if uLeaf != 0 || sLeaf != 1 {
			t.Fatalf("0 >= bit-pattern ff routed unsigned/signed to %d/%d, want 0/1", uLeaf, sLeaf)
		}
	})

	t.Run("declared-range-enforced", func(t *testing.T) {
		policy, err := NewUnsignedComparisonPolicy(8, 0, 10, 0, 10, ComparatorUnsignedBorrow, OverflowBorrowExact)
		if err != nil {
			t.Fatal(err)
		}
		tree := treeplan.BinaryTree[uint8, uint8]{Depth: 1, Splits: []treeplan.BinarySplit[uint8]{{Feature: 0, Threshold: 5}}, Leaves: []uint8{0, 1}}
		feature, _ := OpaqueUnsigned(11, 8)
		if _, err := EvaluateFullLevel(backend, tree, []PlainValue{feature}, Opaque(1), policy); !errors.Is(err, ErrBackendOperation) {
			t.Fatalf("out-of-contract feature error=%v, want ErrBackendOperation", err)
		}
	})

	t.Run("signed-no-overflow-requires-range-proof", func(t *testing.T) {
		if _, err := NewSignedComparisonPolicy(8, -128, 127, -128, 127, ComparatorSignedNoOverflow, OverflowSignedDifferenceInRange); err == nil {
			t.Fatal("full int8 ranges incorrectly prove subtraction free of overflow")
		}
		if _, err := NewSignedComparisonPolicy(8, -10, 10, -10, 10, ComparatorSignedNoOverflow, OverflowSignedDifferenceInRange); err != nil {
			t.Fatalf("bounded int8 ranges rejected: %v", err)
		}
	})

	t.Run("tree-type-must-match-policy", func(t *testing.T) {
		policy, err := NewUnsignedComparisonPolicy(8, 0, 255, 0, 255, ComparatorUnsignedBorrow, OverflowBorrowExact)
		if err != nil {
			t.Fatal(err)
		}
		tree := treeplan.BinaryTree[int8, int8]{Depth: 1, Splits: []treeplan.BinarySplit[int8]{{Feature: 0, Threshold: -1}}, Leaves: []int8{0, 1}}
		feature, _ := OpaqueSigned(0, 8)
		if _, err := EvaluateOBO(backend, tree, []PlainValue{feature}, Opaque(1), policy); !errors.Is(err, ErrInvalidComparisonPolicy) {
			t.Fatalf("signed tree/unsigned policy error=%v, want ErrInvalidComparisonPolicy", err)
		}
	})
}

type lyingBackend struct{ PlainBackend }

func (b lyingBackend) Mul(a, c PlainValue) (PlainValue, error) {
	value, err := b.PlainBackend.Mul(a, c)
	value.Provenance = ValuePublic
	return value, err
}

func TestCommittedForestsMatchOracleAndR0(t *testing.T) {
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dataDir := filepath.Join(filepath.Clean(filepath.Join(filepath.Dir(here), "..", "..")), "xgbdata")
	backend := PlainBackend{}
	for _, name := range []string{"d8", "d10", "d12"} {
		bundle, _ := treeio.ParseBundle(dataDir, name)
		forest, err := treecompile.CompileModel(bundle.Model, treecompile.ModelSemantics{
			BaseScore: treecompile.BaseScoreProbability,
			Output:    treecompile.OutputRawMargin,
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, rowIndex := range []int{0, 17} {
			row := bundle.Input.X[rowIndex*bundle.Input.F : (rowIndex+1)*bundle.Input.F]
			values := opaqueFeatures(row)
			wantMargin, err := forest.RawMargin(row)
			if err != nil {
				t.Fatal(err)
			}
			gotMargin := forest.BaseMargin
			for treeIndex, binary := range forest.Trees {
				wantLeaf, err := binary.Evaluate(row)
				if err != nil {
					t.Fatal(err)
				}
				obo, err := EvaluateOBO(backend, binary, values, Opaque(1), RealComparisonPolicy())
				if err != nil {
					t.Fatalf("%s row=%d tree=%d OBO: %v", name, rowIndex, treeIndex, err)
				}
				full, err := EvaluateFullLevel(backend, binary, values, Opaque(1), RealComparisonPolicy())
				if err != nil {
					t.Fatalf("%s row=%d tree=%d full: %v", name, rowIndex, treeIndex, err)
				}
				if obo.Value.Scalar != wantLeaf || full.Value.Scalar != wantLeaf {
					t.Fatalf("%s row=%d tree=%d leaves OBO/full=%g/%g, want %g", name, rowIndex, treeIndex, obo.Value.Scalar, full.Value.Scalar, wantLeaf)
				}
				if obo.Counts.CTCTComparisons != binary.Depth || obo.Counts.CTPublicComparisons != 0 {
					t.Fatalf("%s tree=%d OBO comparison provenance=%+v", name, treeIndex, obo.Counts)
				}
				if full.Counts.CTPublicComparisons != (1<<binary.Depth)-1 || full.Counts.CTCTComparisons != 0 {
					t.Fatalf("%s tree=%d full comparison provenance=%+v", name, treeIndex, full.Counts)
				}
				for groupWidth := 1; groupWidth <= 4; groupWidth++ {
					radix, err := treeplan.CompileR0(binary, groupWidth)
					if err != nil {
						t.Fatal(err)
					}
					radixLeaf, err := radix.Evaluate(row)
					if err != nil {
						t.Fatal(err)
					}
					if radixLeaf != obo.Value.Scalar {
						t.Fatalf("%s row=%d tree=%d g=%d radix=%g OBO=%g", name, rowIndex, treeIndex, groupWidth, radixLeaf, obo.Value.Scalar)
					}
				}
				gotMargin += obo.Value.Scalar
			}
			if gotMargin != wantMargin {
				t.Fatalf("%s row=%d OBO forest margin=%g, oracle=%g", name, rowIndex, gotMargin, wantMargin)
			}
		}
	}
}
