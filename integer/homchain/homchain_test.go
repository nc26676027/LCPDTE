package homchain_test

import (
	"math/big"
	"testing"

	"github.com/nc26676027/LCPDTE/integer/homchain"
	"github.com/nc26676027/LCPDTE/integer/z2n"
	"github.com/nc26676027/LCPDTE/lattigo/utils/bignum"
)

func TestRepeatedRowDiagonalsKeepWordBlocksIsolated(t *testing.T) {
	ringZ, err := z2n.New(z2n.Word8)
	if err != nil {
		t.Fatal(err)
	}
	specs, err := homchain.NewSpecificationsFromRing(ringZ, 4)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := specs.V0.LogDimensions().Rows, 2; got != want {
		t.Fatalf("log rows: got %d, want %d", got, want)
	}
	if got, want := specs.V0.LogDimensions().Cols, 2; got != want {
		t.Fatalf("log columns: got %d, want %d", got, want)
	}

	for diagonalIndex, diagonal := range specs.V0.Diagonals() {
		if got, want := len(diagonal), 16; got != want {
			t.Fatalf("diagonal %d length: got %d, want %d", diagonalIndex, got, want)
		}
		for word := 1; word < 4; word++ {
			for column := 0; column < 4; column++ {
				assertComplexClose(t, diagonal[word*4+column], diagonal[column], 0)
			}
		}
	}

	input := packedRootSlots(ringZ, 1, 7, 31, 127)
	baseline, err := specs.V0.EvaluatePlaintext(input)
	if err != nil {
		t.Fatal(err)
	}
	changed := cloneVector(input)
	for i, value := range ringZ.ArithmeticRootSlots(251) {
		changed[2*4+i] = value
	}
	modified, err := specs.V0.EvaluatePlaintext(changed)
	if err != nil {
		t.Fatal(err)
	}
	for word := 0; word < 4; word++ {
		if word == 2 {
			continue
		}
		for column := 0; column < 4; column++ {
			index := word*4 + column
			assertComplexClose(t, modified[index], baseline[index], 1e-70)
		}
	}
}

func TestTransformSpecOwnsMatrixAndDiagonalProvenance(t *testing.T) {
	ringZ, err := z2n.New(z2n.Word8)
	if err != nil {
		t.Fatal(err)
	}
	matrices, err := homchain.NewMatrixSet(ringZ.Vandermonde(), ringZ.VandermondeInverse())
	if err != nil {
		t.Fatal(err)
	}
	tSlots, err := ringZ.ToRootSlots(ringZ.Tau())
	if err != nil {
		t.Fatal(err)
	}
	tInvSlots, err := ringZ.ToRootSlots(ringZ.TauInverse())
	if err != nil {
		t.Fatal(err)
	}
	specs, err := homchain.NewSpecifications(matrices, 4, tSlots, tInvSlots)
	if err != nil {
		t.Fatal(err)
	}

	wantMatrix := specs.V0.Matrix()
	wantDiagonals := specs.V0.Diagonals()
	wantFusedT := specs.V0FusedT.Matrix()
	wantFusedTInv := specs.U0FusedTInv.Matrix()

	// Mutate every value that has crossed the public boundary: constructor
	// inputs and accessor results. None may alias the trusted spec state.
	matrices.V0[0][0].Real().SetInt64(101)
	tSlots[0].Real().SetInt64(102)
	tInvSlots[0].Real().SetInt64(103)
	exposedMatrix := specs.V0.Matrix()
	exposedMatrix[0][0].Real().SetInt64(104)
	exposedDiagonals := specs.V0.Diagonals()
	exposedDiagonals[0][0].Real().SetInt64(105)
	delete(exposedDiagonals, 1)

	gotMatrix := specs.V0.Matrix()
	for row := range wantMatrix {
		for column := range wantMatrix[row] {
			assertComplexClose(t, gotMatrix[row][column], wantMatrix[row][column], 0)
		}
	}
	gotDiagonals := specs.V0.Diagonals()
	if len(gotDiagonals) != len(wantDiagonals) {
		t.Fatalf("trusted diagonal count changed through public copies: got %d, want %d", len(gotDiagonals), len(wantDiagonals))
	}
	for index, wantDiagonal := range wantDiagonals {
		gotDiagonal, ok := gotDiagonals[index]
		if !ok {
			t.Fatalf("trusted diagonal %d was deleted through a public copy", index)
		}
		for slot := range wantDiagonal {
			assertComplexClose(t, gotDiagonal[slot], wantDiagonal[slot], 0)
		}
	}
	gotFusedT := specs.V0FusedT.Matrix()
	gotFusedTInv := specs.U0FusedTInv.Matrix()
	for row := range wantFusedT {
		for column := range wantFusedT[row] {
			assertComplexClose(t, gotFusedT[row][column], wantFusedT[row][column], 0)
			assertComplexClose(t, gotFusedTInv[row][column], wantFusedTInv[row][column], 0)
		}
	}
}

func TestPlaintextVHalvesThenURecombineRoundTrip(t *testing.T) {
	ringZ, err := z2n.New(z2n.Word8)
	if err != nil {
		t.Fatal(err)
	}
	specs, err := homchain.NewSpecificationsFromRing(ringZ, 4)
	if err != nil {
		t.Fatal(err)
	}

	want := packedRootSlots(ringZ, 0, 1, 173, 255)
	lowRaw, err := specs.V0.EvaluatePlaintext(want)
	if err != nil {
		t.Fatal(err)
	}
	highRaw, err := specs.V1.EvaluatePlaintext(want)
	if err != nil {
		t.Fatal(err)
	}
	low := homchain.ProjectRealPlaintext(lowRaw)
	high := homchain.ProjectRealPlaintext(highRaw)

	lowRoot, err := specs.U0.EvaluatePlaintext(low)
	if err != nil {
		t.Fatal(err)
	}
	highRoot, err := specs.U1.EvaluatePlaintext(high)
	if err != nil {
		t.Fatal(err)
	}
	got, err := homchain.AddPlaintext(lowRoot, highRoot)
	if err != nil {
		t.Fatal(err)
	}

	for i := range want {
		// The published roots carry 128 fractional bits, so the closed-form
		// round trip is expected to be accurate to roughly 1e-38.
		assertComplexClose(t, got[i], want[i], 1e-37)
	}
}

func TestSpecialB0UsesTwiceV0SecondRowAsFirstRow(t *testing.T) {
	ringZ, err := z2n.New(z2n.Word8)
	if err != nil {
		t.Fatal(err)
	}
	specs, err := homchain.NewSpecificationsFromRing(ringZ, 1)
	if err != nil {
		t.Fatal(err)
	}

	normal := specs.V0.Matrix()
	special := specs.V0SpecialB0.Matrix()
	for column := range normal[0] {
		want := scaleComplex(normal[1][column], 2)
		assertComplexClose(t, special[0][column], want, 1e-75)
	}
	for row := 1; row < len(normal); row++ {
		for column := range normal[row] {
			assertComplexClose(t, special[row][column], normal[row][column], 0)
		}
	}
}

func TestFusedTAndTInverseFollowGaoLeftRightDiagonalConvention(t *testing.T) {
	ringZ, err := z2n.New(z2n.Word8)
	if err != nil {
		t.Fatal(err)
	}
	specs, err := homchain.NewSpecificationsFromRing(ringZ, 1)
	if err != nil {
		t.Fatal(err)
	}
	tSlots, err := ringZ.ToRootSlots(ringZ.Tau())
	if err != nil {
		t.Fatal(err)
	}
	tInvSlots, err := ringZ.ToRootSlots(ringZ.TauInverse())
	if err != nil {
		t.Fatal(err)
	}

	u0 := specs.U0.Matrix()
	u0Fused := specs.U0FusedTInv.Matrix()
	v0 := specs.V0.Matrix()
	v0Fused := specs.V0FusedT.Matrix()
	for row := range u0 {
		for column := range u0[row] {
			assertComplexClose(t, u0Fused[row][column], multiplyComplex(tInvSlots[row], u0[row][column]), 1e-75)
		}
	}
	for row := range v0 {
		for column := range v0[row] {
			assertComplexClose(t, v0Fused[row][column], multiplyComplex(v0[row][column], tSlots[column]), 1e-75)
		}
	}
}

func TestSpecificationsRejectNonPowerOfTwoWordCount(t *testing.T) {
	ringZ, err := z2n.New(z2n.Word8)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = homchain.NewSpecificationsFromRing(ringZ, 3); err == nil {
		t.Fatal("NewSpecificationsFromRing(..., 3) succeeded, want a power-of-two error")
	}
}

func packedRootSlots(ringZ *z2n.Ring, words ...uint64) []*bignum.Complex {
	result := make([]*bignum.Complex, 0, len(words)*len(ringZ.Roots()))
	for _, word := range words {
		result = append(result, ringZ.ArithmeticRootSlots(word)...)
	}
	return result
}

func cloneVector(values []*bignum.Complex) []*bignum.Complex {
	result := make([]*bignum.Complex, len(values))
	for i, value := range values {
		result[i] = value.Clone()
	}
	return result
}

func scaleComplex(value *bignum.Complex, factor int64) *bignum.Complex {
	precision := value.Prec()
	return &bignum.Complex{
		newFloat(precision).Mul(value.Real(), newFloat(precision).SetInt64(factor)),
		newFloat(precision).Mul(value.Imag(), newFloat(precision).SetInt64(factor)),
	}
}

func multiplyComplex(lhs, rhs *bignum.Complex) *bignum.Complex {
	precision := lhs.Prec()
	if rhs.Prec() > precision {
		precision = rhs.Prec()
	}
	ac := newFloat(precision).Mul(lhs.Real(), rhs.Real())
	bd := newFloat(precision).Mul(lhs.Imag(), rhs.Imag())
	ad := newFloat(precision).Mul(lhs.Real(), rhs.Imag())
	bc := newFloat(precision).Mul(lhs.Imag(), rhs.Real())
	return &bignum.Complex{
		newFloat(precision).Sub(ac, bd),
		newFloat(precision).Add(ad, bc),
	}
}

func newFloat(precision uint) *big.Float {
	return new(big.Float).SetPrec(precision).SetMode(big.ToNearestEven)
}

func assertComplexClose(t *testing.T, got, want *bignum.Complex, tolerance float64) {
	t.Helper()
	precision := got.Prec()
	if want.Prec() > precision {
		precision = want.Prec()
	}
	realError := newFloat(precision).Sub(got.Real(), want.Real())
	realError.Abs(realError)
	imagError := newFloat(precision).Sub(got.Imag(), want.Imag())
	imagError.Abs(imagError)
	limit := newFloat(precision).SetFloat64(tolerance)
	if realError.Cmp(limit) > 0 || imagError.Cmp(limit) > 0 {
		t.Fatalf("got (%s,%s), want (%s,%s), errors=(%s,%s), tolerance %.3g",
			got.Real().Text('g', 18), got.Imag().Text('g', 18),
			want.Real().Text('g', 18), want.Imag().Text('g', 18),
			realError.Text('g', 6), imagError.Text('g', 6), tolerance)
	}
}
