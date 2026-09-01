package homchain_test

import (
	"math/big"
	"testing"

	"dt_go/integer/homchain"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

func TestGaoSineKernelProfilePinsExactSourceConstants(t *testing.T) {
	profile, err := homchain.NewGaoSineKernelProfile()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := profile.Fidelity(), homchain.GaoSineLattigoAdaptation; got != want {
		t.Fatalf("fidelity: got %q, want %q", got, want)
	}
	if got, want := profile.Maturity(), homchain.GaoSineFunctionalNotSecure; got != want {
		t.Fatalf("maturity: got %q, want %q", got, want)
	}
	if got, want := profile.Precision(), uint(256); got != want {
		t.Fatalf("precision: got %d, want %d", got, want)
	}
	if got, want := profile.InputNormalization(), "x=u/16;u-in-[-16,16];x-in-[-1,1]"; got != want {
		t.Fatalf("input normalization: got %q, want %q", got, want)
	}
	if got, want := profile.SourceSchedule(), (homchain.GaoSineSchedule{PolynomialLevels: 6, DoubleAngleLevels: 3}); got != want {
		t.Fatalf("source schedule: got %+v, want %+v", got, want)
	}
	if got, want := profile.LattigoSchedule(), (homchain.GaoSineSchedule{PolynomialLevels: 6, DoubleAngleLevels: 3}); got != want {
		t.Fatalf("Lattigo schedule: got %+v, want %+v", got, want)
	}
	if got, want := profile.VendoredPolynomialDepthPrediction(), 5; got != want {
		t.Fatalf("vendored simulator prediction: got %d, want %d", got, want)
	}
	if got, want := profile.ScheduleEvidence(), "lattigo-v6.1.1:degree32-chebyshev-ciphertext-trace=6;simEvaluator.PolynomialDepth=5;prediction=falsified"; got != want {
		t.Fatalf("schedule discrepancy evidence: got %q, want %q", got, want)
	}
	if got, want := profile.CoefficientDigest(), "afdbfa756628eff6375a293d2b126c93e99c5d9c28e550285c1658801b9b5fe1"; got != want {
		t.Fatalf("coefficient digest: got %q, want %q", got, want)
	}
	if got, want := profile.RecurrenceDigest(), "c5e7c780f5a51749d68e3d2fef6ed99294eaa00a88c905f1b87034e73e8942a3"; got != want {
		t.Fatalf("recurrence digest: got %q, want %q", got, want)
	}
	coefficients := profile.CoefficientNumerators()
	if got, want := len(coefficients), 33; got != want {
		t.Fatalf("coefficient count: got %d, want %d", got, want)
	}
	if got, want := coefficients[0].String(), "83554883558593341156762503528993204567"; got != want {
		t.Fatalf("c0 numerator: got %s, want %s", got, want)
	}
	coefficients[0].SetInt64(0)
	if got := profile.CoefficientNumerators()[0].String(); got != "83554883558593341156762503528993204567" {
		t.Fatal("mutating a returned numerator changed the immutable profile")
	}
	poly := profile.LattigoPolynomial()
	wantC0 := exactDyadic(t, "83554883558593341156762503528993204567", 129, profile.Precision())
	if poly.Basis != bignum.Chebyshev || poly.Degree() != 32 || poly.Coeffs[0].Real().Cmp(wantC0) != 0 {
		t.Fatalf("Lattigo import did not divide exactly c0 by two once")
	}
}

func TestGaoSineKernelIndependentOracleAndSourceDistinguishingNegatives(t *testing.T) {
	profile, err := homchain.NewGaoSineKernelProfile()
	if err != nil {
		t.Fatal(err)
	}
	prec := profile.Precision()
	x := new(big.Float).SetPrec(prec).SetRat(big.NewRat(1, 64)) // u=0.25
	result, err := homchain.EvaluateGaoSineKernelOracle(profile, x)
	if err != nil {
		t.Fatal(err)
	}
	wantQuarter := mustFloat(t, "0.1591549430918953357688837633725143620345", prec)
	if error := absDifference(result.FixedKernel(), wantQuarter); error.Cmp(pow2Negative(30, prec)) >= 0 {
		t.Fatalf("fixed kernel at u=0.25: error=%s", error.Text('e', 8))
	}
	if result.FinalApproximationError().Cmp(pow2Negative(30, prec)) >= 0 {
		t.Fatalf("fixed-kernel approximation error=%s exceeds 2^-30", result.FinalApproximationError().Text('e', 8))
	}

	// Wrong /16: evaluating x=u instead of x=u/16 gives approximately zero.
	wrongScale, err := homchain.EvaluateGaoSineKernelOracle(profile, new(big.Float).SetPrec(prec).SetRat(big.NewRat(1, 4)))
	if err != nil {
		t.Fatal(err)
	}
	if absDifference(wrongScale.FixedKernel(), result.FixedKernel()).Cmp(mustFloat(t, "0.1", prec)) <= 0 {
		t.Fatal("wrong-/16 negative did not distinguish the source normalization")
	}

	// Missing the third double angle leaves the source-distinguishing ~0.3989 value.
	twoRounds := result.BasePolynomial()
	for i, r := range profile.RecurrenceValues()[:2] {
		twoRounds = doubleAngle(twoRounds, r, prec)
		_ = i
	}
	if absDifference(twoRounds, result.FixedKernel()).Cmp(mustFloat(t, "0.2", prec)) <= 0 {
		t.Fatal("missing-double-angle negative did not diverge")
	}

	// Omitting the sole c0/2 import is catastrophic at x=0 after three rounds.
	zero := new(big.Float).SetPrec(prec)
	missingHalf := explicitChebyshev(profile.SourceCoefficientValues(), zero, prec)
	for _, r := range profile.RecurrenceValues() {
		missingHalf = doubleAngle(missingHalf, r, prec)
	}
	correctZero, err := homchain.EvaluateGaoSineKernelOracle(profile, zero)
	if err != nil {
		t.Fatal(err)
	}
	if absDifference(missingHalf, correctZero.FixedKernel()).Cmp(mustFloat(t, "1", prec)) <= 0 {
		t.Fatal("missing-c0/2 negative did not diverge")
	}

	// Treating Chebyshev coefficients as monomial coefficients fails at a boundary.
	boundary := new(big.Float).SetPrec(prec).SetRat(big.NewRat(63, 64))
	correctBoundary, err := homchain.EvaluateGaoSineKernelOracle(profile, boundary)
	if err != nil {
		t.Fatal(err)
	}
	monomial := explicitMonomial(profile.LattigoCoefficientValues(), boundary, prec)
	for _, r := range profile.RecurrenceValues() {
		monomial = doubleAngle(monomial, r, prec)
	}
	if absDifference(monomial, correctBoundary.FixedKernel()).Cmp(pow2Negative(10, prec)) <= 0 {
		t.Fatal("monomial-basis negative did not distinguish the source basis")
	}
}

func TestGaoSineKernelOracleDenseGridNodesAndBoundaryProbes(t *testing.T) {
	profile, err := homchain.NewGaoSineKernelProfile()
	if err != nil {
		t.Fatal(err)
	}
	prec := profile.Precision()
	points := make([]*big.Float, 0, 220)
	// Exact dense dyadic grid on [-1,1].
	for i := int64(0); i <= 128; i++ {
		points = append(points, new(big.Float).SetPrec(prec).SetRat(big.NewRat(i-64, 64)))
	}
	// The 33 Chebyshev nodes are generated with arbitrary-precision pi/cos.
	for k := int64(0); k < 33; k++ {
		angle := new(big.Float).SetPrec(prec).Mul(
			bignum.Pi(prec),
			new(big.Float).SetPrec(prec).SetRat(big.NewRat(2*k+1, 66)),
		)
		points = append(points, bignum.Cos(angle))
	}
	// Root approaches u=k+-2^-j and extrema u=k+1/4,k+3/4.
	for _, k := range []int64{-15, -7, -1, 0, 1, 7, 15} {
		for _, j := range []uint{8, 16} {
			epsilon := new(big.Rat).SetFrac(big.NewInt(1), new(big.Int).Lsh(big.NewInt(1), j))
			for _, sign := range []int64{-1, 1} {
				u := new(big.Rat).SetInt64(k)
				if sign < 0 {
					u.Sub(u, epsilon)
				} else {
					u.Add(u, epsilon)
				}
				points = append(points, new(big.Float).SetPrec(prec).SetRat(new(big.Rat).Quo(u, big.NewRat(16, 1))))
			}
		}
		for _, quarter := range []int64{1, 3} {
			u := new(big.Rat).Add(new(big.Rat).SetInt64(k), big.NewRat(quarter, 4))
			if u.Cmp(big.NewRat(-16, 1)) >= 0 && u.Cmp(big.NewRat(16, 1)) <= 0 {
				points = append(points, new(big.Float).SetPrec(prec).SetRat(new(big.Rat).Quo(u, big.NewRat(16, 1))))
			}
		}
	}
	for _, boundary := range []*big.Rat{
		big.NewRat(-1, 1), big.NewRat(1, 1), big.NewRat(-63, 64), big.NewRat(63, 64),
	} {
		points = append(points, new(big.Float).SetPrec(prec).SetRat(boundary))
	}

	maxBaseError := new(big.Float).SetPrec(prec)
	maxFinalError := new(big.Float).SetPrec(prec)
	for i, point := range points {
		result, err := homchain.EvaluateGaoSineKernelOracle(profile, point)
		if err != nil {
			t.Fatalf("probe %d (%s): %v", i, point.Text('e', 8), err)
		}
		if result.BaseApproximationError().Cmp(maxBaseError) > 0 {
			maxBaseError.Set(result.BaseApproximationError())
		}
		if result.FinalApproximationError().Cmp(maxFinalError) > 0 {
			maxFinalError.Set(result.FinalApproximationError())
		}
	}
	t.Logf("Gao sine scalar probes=%d max base error=%s max fixed-kernel error=%s",
		len(points), maxBaseError.Text('e', 8), maxFinalError.Text('e', 8))
	if maxFinalError.Cmp(pow2Negative(30, prec)) >= 0 {
		t.Fatalf("max fixed-kernel error=%s exceeds scalar 2^-30 gate", maxFinalError.Text('e', 8))
	}
}

func exactDyadic(t *testing.T, numerator string, denominatorBits uint, prec uint) *big.Float {
	t.Helper()
	n := new(big.Int)
	if _, ok := n.SetString(numerator, 10); !ok {
		t.Fatalf("invalid integer %q", numerator)
	}
	denominator := new(big.Int).Lsh(big.NewInt(1), denominatorBits)
	return new(big.Float).SetPrec(prec).Quo(
		new(big.Float).SetPrec(prec).SetInt(n),
		new(big.Float).SetPrec(prec).SetInt(denominator),
	)
}

func mustFloat(t *testing.T, value string, prec uint) *big.Float {
	t.Helper()
	result, ok := new(big.Float).SetPrec(prec).SetString(value)
	if !ok {
		t.Fatalf("invalid float %q", value)
	}
	return result
}

func pow2Negative(exponent uint, prec uint) *big.Float {
	denominator := new(big.Int).Lsh(big.NewInt(1), exponent)
	return new(big.Float).SetPrec(prec).Quo(
		new(big.Float).SetPrec(prec).SetInt64(1),
		new(big.Float).SetPrec(prec).SetInt(denominator),
	)
}

func absDifference(a, b *big.Float) *big.Float {
	return new(big.Float).Abs(new(big.Float).Sub(a, b))
}

func doubleAngle(value, recurrence *big.Float, prec uint) *big.Float {
	result := new(big.Float).SetPrec(prec).Mul(value, value)
	result.Add(result, result)
	return result.Add(result, recurrence)
}

func explicitChebyshev(coefficients []*big.Float, x *big.Float, prec uint) *big.Float {
	tPrev := new(big.Float).SetPrec(prec).SetInt64(1)
	tCurrent := new(big.Float).SetPrec(prec).Set(x)
	result := new(big.Float).SetPrec(prec).Set(coefficients[0])
	two := new(big.Float).SetPrec(prec).SetInt64(2)
	for i := 1; i < len(coefficients); i++ {
		result.Add(result, new(big.Float).SetPrec(prec).Mul(coefficients[i], tCurrent))
		next := new(big.Float).SetPrec(prec).Mul(two, x)
		next.Mul(next, tCurrent)
		next.Sub(next, tPrev)
		tPrev, tCurrent = tCurrent, next
	}
	return result
}

func explicitMonomial(coefficients []*big.Float, x *big.Float, prec uint) *big.Float {
	result := new(big.Float).SetPrec(prec).Set(coefficients[len(coefficients)-1])
	for i := len(coefficients) - 2; i >= 0; i-- {
		result.Mul(result, x)
		result.Add(result, coefficients[i])
	}
	return result
}
