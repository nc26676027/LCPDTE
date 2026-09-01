package ckksint_test

import (
	"math"
	"testing"

	"github.com/nc26676027/LCPDTE/ckksint"
)

func TestDemoFunctional8A2BB2AAndComparisonThroughPublicAPI(t *testing.T) {
	engine, err := ckksint.NewDemoFunctional8(ckksint.Signed8Range{
		FeatureMin: -8, FeatureMax: 7,
		ThresholdMin: -8, ThresholdMax: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	inputWords := [4]int8{-8, -1, 2, 7}
	input, err := engine.Encrypt(inputWords)
	if err != nil {
		t.Fatal(err)
	}

	bits, a2bInfo, err := engine.A2B(input)
	if err != nil {
		t.Fatal(err)
	}
	if a2bInfo.Operation != "A2B" || a2bInfo.ProfileDigest == "" {
		t.Fatalf("incomplete A2B evidence: %+v", a2bInfo)
	}
	gotBits, err := engine.DecryptBits(bits)
	if err != nil {
		t.Fatal(err)
	}
	for lane, word := range inputWords {
		for bit := 0; bit < 8; bit++ {
			want := uint8(word) >> bit & 1
			if gotBits[lane][bit] != want {
				t.Fatalf("lane %d bit %d = %d, want %d", lane, bit, gotBits[lane][bit], want)
			}
		}
	}

	roundTrip, b2aInfo, err := engine.B2A(bits)
	if err != nil {
		t.Fatal(err)
	}
	if b2aInfo.Operation != "B2A" || b2aInfo.ProfileDigest == "" {
		t.Fatalf("incomplete B2A evidence: %+v", b2aInfo)
	}
	if got, err := engine.Decrypt(roundTrip); err != nil {
		t.Fatal(err)
	} else if got != inputWords {
		t.Fatalf("A2B/B2A = %v, want %v", got, inputWords)
	}

	selector, compareInfo, err := engine.CompareGEPublic(input, [4]int8{-8, 0, 3, 6})
	if err != nil {
		t.Fatal(err)
	}
	if compareInfo.Operation != "CompareGEPublic" || compareInfo.ProfileDigest == "" {
		t.Fatalf("incomplete comparison evidence: %+v", compareInfo)
	}
	if got, err := engine.DecryptSelector(selector); err != nil {
		t.Fatal(err)
	} else if want := [4]bool{true, false, false, true}; got != want {
		t.Fatalf("selectors = %v, want %v", got, want)
	}
}

func TestDemoFunctional8Depth2ThroughPublicAPI(t *testing.T) {
	engine, err := ckksint.NewDemoFunctional8(ckksint.Signed8Range{
		FeatureMin: -8, FeatureMax: 7,
		ThresholdMin: -8, ThresholdMax: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	plaintext := [3][4]int8{
		{-1, -1, 1, 1},
		{-5, -4, 0, 0},
		{0, 0, 2, 3},
	}
	features := make([]*ckksint.EncryptedInt8, len(plaintext))
	for index := range plaintext {
		features[index], err = engine.Encrypt(plaintext[index])
		if err != nil {
			t.Fatal(err)
		}
	}
	model := ckksint.Depth2Model{
		FeatureIDs: [3]int{0, 1, 2},
		Thresholds: [3]int8{0, -4, 3},
		Leaves:     [4]float64{-1.25, 2.5, -3.75, 5},
	}
	result, info, err := engine.EvaluateDepth2(features, model)
	if err != nil {
		t.Fatal(err)
	}
	if info.Operation != "EvaluateDepth2" || info.ProfileDigest == "" || info.TraceDigest == "" || info.WallTime <= 0 {
		t.Fatalf("incomplete depth-2 evidence: %+v", info)
	}
	got, err := engine.DecryptReal(result)
	if err != nil {
		t.Fatal(err)
	}
	want := [4]float64{-1.25, 2.5, -3.75, 5}
	for lane := range want {
		if math.Abs(got[lane]-want[lane]) > 1e-3 {
			t.Fatalf("lane %d = %.12g, want %.12g", lane, got[lane], want[lane])
		}
	}
}
