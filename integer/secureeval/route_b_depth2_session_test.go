package secureeval

import (
	"math"
	"strings"
	"testing"
)

func TestDecodeCanonicalRouteBDepth2Blocks(t *testing.T) {
	tolerance := RouteBSigned8Depth2SelectedChildAccuracyTolerance
	tests := []struct {
		name     string
		values   []complex128
		want     []float64
		contains string
	}{
		{
			name: "valid replicated blocks",
			values: []complex128{
				complex(-1.25, tolerance), complex(-1.25+tolerance, 0), complex(-1.25-tolerance, -tolerance), complex(-1.25, 0),
				complex(5, 0), complex(5, tolerance/2), complex(5-tolerance/2, 0), complex(5+tolerance/2, 0),
			},
			want: []float64{-1.25, 5},
		},
		{
			name: "nan real",
			values: []complex128{
				complex(1, 0), complex(math.NaN(), 0), complex(1, 0), complex(1, 0),
			},
			contains: "query 0 slot 1 real component is non-finite",
		},
		{
			name: "infinite imaginary",
			values: []complex128{
				complex(1, 0), complex(1, math.Inf(1)), complex(1, 0), complex(1, 0),
			},
			contains: "query 0 slot 1 imaginary component is non-finite",
		},
		{
			name: "imaginary residual",
			values: []complex128{
				complex(1, 0), complex(1, tolerance*2), complex(1, 0), complex(1, 0),
			},
			contains: "query 0 slot 1 imaginary residual",
		},
		{
			name: "replica disagreement",
			values: []complex128{
				complex(1, 0), complex(1, 0), complex(1+tolerance*2, 0), complex(1, 0),
			},
			contains: "query 0 slot 2 real replica disagreement",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := decodeCanonicalRouteBDepth2Blocks(test.values, len(test.values)/4)
			if test.contains != "" {
				if err == nil || !strings.Contains(err.Error(), test.contains) {
					t.Fatalf("error = %v, want substring %q", err, test.contains)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(test.want) {
				t.Fatalf("decoded length = %d, want %d", len(got), len(test.want))
			}
			for query := range test.want {
				if got[query] != test.want[query] {
					t.Fatalf("query %d = %g, want %g", query, got[query], test.want[query])
				}
			}
		})
	}
}
