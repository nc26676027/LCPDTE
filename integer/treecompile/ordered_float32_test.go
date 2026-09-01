package treecompile

import (
	"errors"
	"math"
	"math/rand"
	"reflect"
	"testing"

	"dt_go/integer/treeplan"
)

func TestOrderedFloat32KeyPreservesFiniteComparisons(t *testing.T) {
	negativeZero := math.Float32frombits(0x80000000)
	positiveZero := math.Float32frombits(0x00000000)
	values := []float32{
		-math.MaxFloat32,
		math.Float32frombits(0xff000000), // a large negative normal
		-1,
		math.Float32frombits(0x80800000), // smallest negative normal
		math.Float32frombits(0x80000001), // smallest negative subnormal
		negativeZero,
		positiveZero,
		math.Float32frombits(0x00000001), // smallest positive subnormal
		math.Float32frombits(0x00800000), // smallest positive normal
		1,
		math.Float32frombits(0x7f000000), // a large positive normal
		math.MaxFloat32,
	}

	keys := make([]uint32, len(values))
	for i, value := range values {
		var err error
		keys[i], err = OrderedFloat32Key(value)
		if err != nil {
			t.Fatalf("value[%d]=%g: %v", i, value, err)
		}
	}

	if keys[5] != keys[6] {
		t.Fatalf("-0 key=%08x, +0 key=%08x; zeros must be canonical", keys[5], keys[6])
	}
	for i, left := range values {
		for j, right := range values {
			if got, want := keys[i] < keys[j], left < right; got != want {
				t.Fatalf("key(%g) < key(%g)=%v, float comparison=%v", left, right, got, want)
			}
			if got, want := keys[i] >= keys[j], left >= right; got != want {
				t.Fatalf("key(%g) >= key(%g)=%v, float comparison=%v", left, right, got, want)
			}
		}
	}
}

func TestOrderedFloat32KeyKnownBoundaryKeys(t *testing.T) {
	cases := []struct {
		name  string
		value float32
		want  uint32
	}{
		{"negative-max", -math.MaxFloat32, 0x00800000},
		{"negative-min-subnormal", math.Float32frombits(0x80000001), 0x7ffffffe},
		{"negative-zero", math.Float32frombits(0x80000000), 0x80000000},
		{"positive-zero", 0, 0x80000000},
		{"positive-min-subnormal", math.Float32frombits(0x00000001), 0x80000001},
		{"positive-max", math.MaxFloat32, 0xff7fffff},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := OrderedFloat32Key(tc.value)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("key=%08x, want %08x", got, tc.want)
			}
		})
	}
}

func TestOrderedFloat32KeyRejectsEveryNonFiniteClass(t *testing.T) {
	values := map[string]float32{
		"positive-infinity": math.Float32frombits(0x7f800000),
		"negative-infinity": math.Float32frombits(0xff800000),
		"quiet-nan":         math.Float32frombits(0x7fc00001),
		"signaling-nan":     math.Float32frombits(0x7f800001),
		"negative-nan":      math.Float32frombits(0xffc00001),
	}
	for name, value := range values {
		t.Run(name, func(t *testing.T) {
			if _, err := OrderedFloat32Key(value); !errors.Is(err, ErrNonFiniteValue) {
				t.Fatalf("error=%v, want ErrNonFiniteValue", err)
			}
		})
	}
}

func TestOrderedFloat32KeyRandomFiniteBitPatterns(t *testing.T) {
	rng := rand.New(rand.NewSource(0x5eedc0de))
	finite := func() float32 {
		for {
			bits := rng.Uint32()
			if bits&0x7f800000 != 0x7f800000 {
				return math.Float32frombits(bits)
			}
		}
	}

	for sample := 0; sample < 100_000; sample++ {
		left, right := finite(), finite()
		leftKey, err := OrderedFloat32Key(left)
		if err != nil {
			t.Fatalf("sample %d left: %v", sample, err)
		}
		rightKey, err := OrderedFloat32Key(right)
		if err != nil {
			t.Fatalf("sample %d right: %v", sample, err)
		}
		if got, want := leftKey < rightKey, left < right; got != want {
			t.Fatalf("sample %d: key(%08x:%g) < key(%08x:%g)=%v, want %v", sample, math.Float32bits(left), left, math.Float32bits(right), right, got, want)
		}
		if got, want := leftKey >= rightKey, left >= right; got != want {
			t.Fatalf("sample %d: key(%08x:%g) >= key(%08x:%g)=%v, want %v", sample, math.Float32bits(left), left, math.Float32bits(right), right, got, want)
		}
		if got, want := leftKey == rightKey, left == right; got != want {
			t.Fatalf("sample %d: key equality=%v, float equality=%v", sample, got, want)
		}
	}
}

func orderedViewFixture() Forest {
	return Forest{
		NumFeatures:     2,
		Depth:           2,
		SourceBaseScore: 0.25,
		BaseMargin:      math.Log(0.25 / 0.75),
		Semantics: ModelSemantics{
			BaseScore: BaseScoreProbability,
			Output:    OutputLogisticProbability,
		},
		Trees: []treeplan.BinaryTree[float32, float64]{
			{
				Depth: 2,
				Splits: []treeplan.BinarySplit[float32]{
					{Feature: 0, Threshold: 0},
					{Feature: 1, Threshold: -1},
					{Feature: 1, Threshold: math.Float32frombits(1)},
				},
				Leaves: []float64{11.25, 12.5, 13.75, 14.125},
			},
			{
				Depth: 2,
				Splits: []treeplan.BinarySplit[float32]{
					{Feature: 1, Threshold: -math.Float32frombits(1)},
					{Feature: 0, Threshold: -math.MaxFloat32},
					{Feature: 0, Threshold: math.MaxFloat32},
				},
				Leaves: []float64{-4, -3, -2, -1},
			},
		},
	}
}

func TestCompileOrderedForestPreservesMetadataAndDoesNotMutateOrAlias(t *testing.T) {
	forest := orderedViewFixture()
	before := orderedViewFixture()

	ordered, err := CompileOrderedForest(forest)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(forest, before) {
		t.Fatal("CompileOrderedForest mutated its source forest")
	}
	if ordered.View != OrderedFloat32R0ComparatorView {
		t.Fatalf("view=%q, want %q", ordered.View, OrderedFloat32R0ComparatorView)
	}
	if ordered.NumFeatures != forest.NumFeatures || ordered.Depth != forest.Depth ||
		math.Float64bits(ordered.SourceBaseScore) != math.Float64bits(forest.SourceBaseScore) ||
		math.Float64bits(ordered.BaseMargin) != math.Float64bits(forest.BaseMargin) ||
		ordered.Semantics != forest.Semantics {
		t.Fatalf("ordered metadata does not preserve source metadata: got %+v, source %+v", ordered, forest)
	}
	if len(ordered.Trees) != len(forest.Trees) {
		t.Fatalf("tree count=%d, want %d", len(ordered.Trees), len(forest.Trees))
	}

	ordered.Trees[0].Splits[0].Threshold++
	ordered.Trees[0].Leaves[0]++
	if !reflect.DeepEqual(forest, before) {
		t.Fatal("mutating the ordered view changed the source forest")
	}
}

func TestCompileOrderedForestPreservesRoutesAndLeaves(t *testing.T) {
	forest := orderedViewFixture()
	ordered, err := CompileOrderedForest(forest)
	if err != nil {
		t.Fatal(err)
	}
	rows := [][]float32{
		{-math.MaxFloat32, -math.MaxFloat32},
		{-2, -2},
		{-2, -1},
		{math.Float32frombits(0x80000000), 0},
		{0, 0},
		{0, math.Float32frombits(1)},
		{math.Float32frombits(1), math.Float32frombits(0x80000001)},
		{math.MaxFloat32, math.MaxFloat32},
	}

	for rowIndex, row := range rows {
		keys := make([]uint32, len(row))
		for i, value := range row {
			keys[i], err = OrderedFloat32Key(value)
			if err != nil {
				t.Fatalf("row %d feature %d: %v", rowIndex, i, err)
			}
		}
		for treeIndex := range forest.Trees {
			wantRoute, err := forest.Trees[treeIndex].Route(row)
			if err != nil {
				t.Fatal(err)
			}
			gotRoute, err := ordered.Trees[treeIndex].Route(keys)
			if err != nil {
				t.Fatal(err)
			}
			if gotRoute != wantRoute {
				t.Fatalf("row %d tree %d route=%d, want %d", rowIndex, treeIndex, gotRoute, wantRoute)
			}
			wantLeaf, err := forest.Trees[treeIndex].Evaluate(row)
			if err != nil {
				t.Fatal(err)
			}
			gotLeaf, err := ordered.Trees[treeIndex].Evaluate(keys)
			if err != nil {
				t.Fatal(err)
			}
			if math.Float64bits(gotLeaf) != math.Float64bits(wantLeaf) {
				t.Fatalf("row %d tree %d leaf bits=%016x, want %016x", rowIndex, treeIndex, math.Float64bits(gotLeaf), math.Float64bits(wantLeaf))
			}
		}
	}
}

func TestCompileOrderedForestValidatesSource(t *testing.T) {
	forest := orderedViewFixture()
	forest.Trees[0].Splits[0].Threshold = float32(math.Inf(1))
	if _, err := CompileOrderedForest(forest); err == nil {
		t.Fatal("non-finite source threshold was accepted")
	}
}
