package dft

import (
	"testing"

	ltcommon "github.com/tuneinsight/lattigo/v6/circuits/ckks/lintrans"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

func TestMatrixConstructionCountersRouteEveryPublicEntryExactlyOnce(t *testing.T) {
	params := explicitPrecisionTestParameters(t)
	literal := explicitPrecisionTestLiteral()
	encoder := ckks.NewEncoder(params)

	tests := []struct {
		name string
		run  func() error
		want [4]uint64
	}{
		{
			name: "default whole",
			run: func() error {
				_, err := NewMatrixFromLiteral(params, literal, encoder)
				return err
			},
			want: [4]uint64{1, 0, 0, 0},
		},
		{
			name: "explicit whole",
			run: func() error {
				_, err := NewMatrixFromLiteralWithGeneratorPrecision(params, literal, encoder, encoder.Prec())
				return err
			},
			want: [4]uint64{0, 1, 0, 0},
		},
		{
			name: "explicit streaming whole",
			run: func() error {
				_, err := NewMatrixFromLiteralWithGeneratorPrecisionStreaming(params, literal, encoder, encoder.Prec())
				return err
			},
			want: [4]uint64{0, 1, 0, 0},
		},
		{
			name: "raw foreach",
			run: func() error {
				count := 0
				err := literal.ForEachMatrixFactor(params.LogN(), encoder.Prec(), func(ltcommon.Diagonals[*bignum.Complex]) error {
					count++
					return nil
				})
				if err == nil && count != literal.Depth(false) {
					t.Fatalf("ForEachMatrixFactor emitted %d factors, want %d", count, literal.Depth(false))
				}
				return err
			},
			want: [4]uint64{0, 0, 1, 0},
		},
		{
			name: "raw all at once",
			run: func() error {
				if got := len(literal.GenMatrices(params.LogN(), encoder.Prec())); got != literal.Depth(false) {
					t.Fatalf("GenMatrices returned %d factors, want %d", got, literal.Depth(false))
				}
				return nil
			},
			want: [4]uint64{0, 0, 1, 0},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before := SnapshotMatrixConstructionCounters()
			if err := test.run(); err != nil {
				t.Fatal(err)
			}
			after := SnapshotMatrixConstructionCounters()
			delta, err := after.Delta(before)
			if err != nil {
				t.Fatal(err)
			}
			got := [4]uint64{
				delta.DefaultWhole(),
				delta.ExplicitWhole(),
				delta.RawNumeric(),
				delta.ObservedStreaming(),
			}
			if got != test.want {
				t.Fatalf("counter delta = %v, want %v", got, test.want)
			}
		})
	}
}

func TestMatrixConstructionCountersIncrementBeforeValidation(t *testing.T) {
	params := explicitPrecisionTestParameters(t)
	literal := explicitPrecisionTestLiteral()

	before := SnapshotMatrixConstructionCounters()
	if _, err := NewMatrixFromLiteralWithGeneratorPrecision(params, literal, nil, params.EncodingPrecision()); err == nil {
		t.Fatal("nil encoder unexpectedly accepted")
	}
	after := SnapshotMatrixConstructionCounters()
	delta, err := after.Delta(before)
	if err != nil {
		t.Fatal(err)
	}
	if got := [4]uint64{delta.DefaultWhole(), delta.ExplicitWhole(), delta.RawNumeric(), delta.ObservedStreaming()}; got != [4]uint64{0, 1, 0, 0} {
		t.Fatalf("failed-entry counter delta = %v, want [0 1 0 0]", got)
	}
}

func TestMatrixConstructionCounterDeltaRejectsNonMonotonicSnapshots(t *testing.T) {
	before := MatrixConstructionCounters{defaultWhole: 2}
	after := MatrixConstructionCounters{defaultWhole: 1}
	if _, err := after.Delta(before); err == nil {
		t.Fatal("non-monotonic snapshots unexpectedly accepted")
	}

	saturated := MatrixConstructionCounters{rawNumeric: maxMatrixConstructionCounter}
	if _, err := saturated.Delta(saturated); err == nil {
		t.Fatal("saturated snapshots unexpectedly accepted")
	}
}
