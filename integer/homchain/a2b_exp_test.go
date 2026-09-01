package homchain_test

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/nc26676027/LCPDTE/integer/homchain"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

const (
	a2bExpArtifactDigest = "a960edc18c4c7dee294d0f452eb3ef377c1d2094dadc0a046f49a68902e36e4d"
	a2bExpImportDigest   = "d33c80bcc033cc0d0305092e50b2ac16bf5aabd19bfe48cbfed05af562001f5d"
	a2bExpProfileDigest  = "9a6d918d7fe8b31673408bc0251d138d07bebddafed15714f7616b4be171c379"
)

func TestGaoA2BExpProfileMatchesFrozenArtifactAndIsImmutable(t *testing.T) {
	profile, err := homchain.NewGaoA2BExpProfile()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := profile.Precision(), uint(256); got != want {
		t.Fatalf("precision: got %d, want %d", got, want)
	}
	if got, want := profile.DenominatorBits(), uint(128); got != want {
		t.Fatalf("denominator bits: got %d, want %d", got, want)
	}
	if got, want := profile.Degree(), 46; got != want {
		t.Fatalf("degree: got %d, want %d", got, want)
	}
	if got, want := profile.Basis(), bignum.Chebyshev; got != want {
		t.Fatalf("basis: got %v, want %v", got, want)
	}
	if got, want := profile.SourceCommit(), "08f1eb87434e7be072cba889270a8400bbffc08e"; got != want {
		t.Fatalf("source commit: got %q, want %q", got, want)
	}
	if got := profile.ArtifactDigest(); got != a2bExpArtifactDigest {
		t.Fatalf("artifact digest: got %s, want %s", got, a2bExpArtifactDigest)
	}
	if got, want := profile.Maturity(), homchain.GaoA2BExpPrerequisiteOnly; got != want {
		t.Fatalf("maturity: got %q, want %q", got, want)
	}
	if got, want := profile.SecurityClaim(), homchain.GaoA2BExpNoSecurityClaim; got != want {
		t.Fatalf("security claim: got %q, want %q", got, want)
	}
	if got, want := profile.InputNormalization(), "x=u/16;u-in-[-16,16];x-in-[-1,1]"; got != want {
		t.Fatalf("normalization: got %q, want %q", got, want)
	}
	if got, want := profile.FreeTermConvention(), "openfhe-ps-c0-over-2;lattigo-import-c0-over-2-once"; got != want {
		t.Fatalf("free-term convention: got %q, want %q", got, want)
	}
	if got, want := profile.BaseTarget(), "exp(i*8*pi*x)"; got != want {
		t.Fatalf("base target: got %q, want %q", got, want)
	}
	if got, want := profile.FinalTarget(), "exp(i*32*pi*x)=exp(i*2*pi*u)"; got != want {
		t.Fatalf("final target: got %q, want %q", got, want)
	}
	if got, want := profile.SquaringRounds(), 2; got != want {
		t.Fatalf("squaring rounds: got %d, want %d", got, want)
	}
	if got := profile.ImportDigest(); got != a2bExpImportDigest {
		t.Fatalf("import digest: got %s, want %s", got, a2bExpImportDigest)
	}
	if got := profile.Digest(); got != a2bExpProfileDigest {
		t.Fatalf("profile digest: got %s, want %s", got, a2bExpProfileDigest)
	}
	t.Logf("Gao A2B exp digests: artifact=%s import=%s profile=%s",
		profile.ArtifactDigest(), profile.ImportDigest(), profile.Digest())

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	artifactPath := filepath.Join(filepath.Dir(thisFile), "..", "..", "research", "phase3_design", "a2b_exp16_degree46.tsv")
	artifact, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatalf("read frozen artifact: %v", err)
	}
	canonicalArtifact := strings.ReplaceAll(string(artifact), "\r\n", "\n")
	if got, want := profile.CanonicalTable(), canonicalArtifact; got != want {
		t.Fatal("compiled profile differs from the frozen artifact")
	}
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(canonicalArtifact))); got != a2bExpArtifactDigest {
		t.Fatalf("canonical LF artifact digest: got %s, want %s", got, a2bExpArtifactDigest)
	}

	realNumerators, imaginaryNumerators := profile.CoefficientNumerators()
	if len(realNumerators) != 47 || len(imaginaryNumerators) != 47 {
		t.Fatalf("coefficient count: got (%d,%d), want (47,47)", len(realNumerators), len(imaginaryNumerators))
	}
	if got, want := realNumerators[0].String(), "76201359508406144086108162329195173168"; got != want {
		t.Fatalf("real c0: got %s, want %s", got, want)
	}
	if got, want := imaginaryNumerators[1].String(), "-75462327482981010929732591801834267864"; got != want {
		t.Fatalf("imaginary c1: got %s, want %s", got, want)
	}
	if got, want := realNumerators[46].String(), "-1494210995158446546673318351371"; got != want {
		t.Fatalf("real c46: got %s, want %s", got, want)
	}

	source := profile.SourceCoefficientValues()
	imported := profile.LattigoCoefficientValues()
	polynomial := profile.LattigoPolynomial()
	if len(source) != 47 || len(imported) != 47 || polynomial.Degree() != 46 || polynomial.Basis != bignum.Chebyshev {
		t.Fatalf("invalid source/import polynomial shape")
	}
	wantSourceC0 := a2bExpExactDyadic(t, realNumerators[0].String(), 128, profile.Precision())
	wantImportedC0 := a2bExpExactDyadic(t, realNumerators[0].String(), 129, profile.Precision())
	if source[0].Real().Cmp(wantSourceC0) != 0 || imported[0].Real().Cmp(wantImportedC0) != 0 ||
		polynomial.Coeffs[0].Real().Cmp(wantImportedC0) != 0 {
		t.Fatal("Lattigo import did not divide exactly c0 by two once")
	}
	for index := range source {
		if source[index].Prec() != profile.Precision() || imported[index].Prec() != profile.Precision() ||
			polynomial.Coeffs[index].Prec() != profile.Precision() {
			t.Fatalf("coefficient %d precision is not 256 bits", index)
		}
		if index > 0 && (source[index].Real().Cmp(imported[index].Real()) != 0 || source[index].Imag().Cmp(imported[index].Imag()) != 0) {
			t.Fatalf("non-free coefficient %d was changed during import", index)
		}
	}
	minusOne := new(big.Float).SetPrec(profile.Precision()).SetInt64(-1)
	one := new(big.Float).SetPrec(profile.Precision()).SetInt64(1)
	if polynomial.Interval.A.Cmp(minusOne) != 0 || polynomial.Interval.B.Cmp(one) != 0 {
		t.Fatalf("polynomial interval is not [-1,1]")
	}

	// Every public numeric view is detached from the immutable profile.
	realNumerators[0].SetInt64(0)
	imaginaryNumerators[1].SetInt64(0)
	source[0].Real().SetInt64(0)
	imported[1].Imag().SetInt64(0)
	polynomial.Coeffs[0].Real().SetInt64(0)
	polynomial.Interval.A.SetInt64(9)
	freshReal, freshImaginary := profile.CoefficientNumerators()
	freshSource := profile.SourceCoefficientValues()
	freshImported := profile.LattigoCoefficientValues()
	freshPolynomial := profile.LattigoPolynomial()
	if freshReal[0].Sign() == 0 || freshImaginary[1].Sign() == 0 || freshSource[0].Real().Sign() == 0 ||
		freshImported[1].Imag().Sign() == 0 || freshPolynomial.Coeffs[0].Real().Sign() == 0 ||
		freshPolynomial.Interval.A.Cmp(minusOne) != 0 {
		t.Fatal("mutating returned data changed the immutable profile")
	}
}

func TestGaoA2BExpIndependentClenshawAndSourceDistinguishingNegatives(t *testing.T) {
	profile, err := homchain.NewGaoA2BExpProfile()
	if err != nil {
		t.Fatal(err)
	}
	prec := profile.Precision()
	x := new(big.Float).SetPrec(prec).SetRat(big.NewRat(1, 64)) // u=1/4
	result, err := homchain.EvaluateGaoA2BExpOracle(profile, x)
	if err != nil {
		t.Fatal(err)
	}
	if result.Precision() != prec {
		t.Fatalf("oracle precision: got %d, want %d", result.Precision(), prec)
	}
	wantFinal := &bignum.Complex{new(big.Float).SetPrec(prec), new(big.Float).SetPrec(prec).SetInt64(1)}
	if errorMagnitude := a2bExpComplexDistance(result.FinalPolynomial(), wantFinal, prec); errorMagnitude.Cmp(a2bExpPow2Negative(26, prec)) >= 0 {
		t.Fatalf("final exp at u=1/4: error=%s", errorMagnitude.Text('e', 8))
	}
	if result.BaseApproximationError().Cmp(a2bExpPow2Negative(28, prec)) >= 0 ||
		result.FinalApproximationError().Cmp(a2bExpPow2Negative(26, prec)) >= 0 {
		t.Fatalf("oracle errors: base=%s final=%s", result.BaseApproximationError().Text('e', 8), result.FinalApproximationError().Text('e', 8))
	}
	baseCopy := result.BasePolynomial()
	targetCopy := result.FinalTargetValue()
	errorCopy := result.FinalApproximationError()
	baseCopy.Real().SetInt64(0)
	targetCopy.Imag().SetInt64(0)
	errorCopy.SetInt64(0)
	if result.BasePolynomial().Real().Sign() == 0 || result.FinalTargetValue().Imag().Sign() == 0 ||
		result.FinalApproximationError().Sign() == 0 {
		t.Fatal("mutating an oracle result view changed the immutable result")
	}

	// A forward Chebyshev recurrence is independent of the production Clenshaw
	// implementation and must agree at arbitrary precision.
	explicit := a2bExpExplicitChebyshev(profile.LattigoCoefficientValues(), x, prec)
	if delta := a2bExpComplexDistance(explicit, result.BasePolynomial(), prec); delta.Cmp(a2bExpPow2Negative(220, prec)) >= 0 {
		t.Fatalf("forward recurrence and Clenshaw disagree: %s", delta.Text('e', 8))
	}
	twoSquares := a2bExpSquare(a2bExpSquare(result.BasePolynomial(), prec), prec)
	if delta := a2bExpComplexDistance(twoSquares, result.FinalPolynomial(), prec); delta.Sign() != 0 {
		t.Fatalf("oracle did not apply exactly two pure squarings: %s", delta.Text('e', 8))
	}

	zero := new(big.Float).SetPrec(prec)
	correctZero, err := homchain.EvaluateGaoA2BExpOracle(profile, zero)
	if err != nil {
		t.Fatal(err)
	}
	noHalf := a2bExpExplicitChebyshev(profile.SourceCoefficientValues(), zero, prec)
	doubleHalfCoefficients := profile.LattigoCoefficientValues()
	doubleHalfCoefficients[0].Real().Quo(doubleHalfCoefficients[0].Real(), new(big.Float).SetPrec(prec).SetInt64(2))
	doubleHalfCoefficients[0].Imag().Quo(doubleHalfCoefficients[0].Imag(), new(big.Float).SetPrec(prec).SetInt64(2))
	doubleHalf := a2bExpExplicitChebyshev(doubleHalfCoefficients, zero, prec)
	if a2bExpComplexDistance(noHalf, correctZero.BasePolynomial(), prec).Cmp(a2bExpMustFloat(t, "0.05", prec)) <= 0 {
		t.Fatal("no-c0/2 negative did not distinguish the OpenFHE free-term convention")
	}
	if a2bExpComplexDistance(doubleHalf, correctZero.BasePolynomial(), prec).Cmp(a2bExpMustFloat(t, "0.05", prec)) <= 0 {
		t.Fatal("double-c0/2 negative did not distinguish the one-time import")
	}
	oneSquare := a2bExpSquare(result.BasePolynomial(), prec)
	if a2bExpComplexDistance(oneSquare, result.FinalPolynomial(), prec).Cmp(a2bExpMustFloat(t, "0.5", prec)) <= 0 {
		t.Fatal("missing-square negative did not diverge")
	}

	// Passing source u directly as a Chebyshev argument is both rejected by the
	// public oracle and numerically catastrophic in an unguarded recurrence.
	unnormalized := new(big.Float).SetPrec(prec).SetRat(big.NewRat(63, 4)) // u=15.75
	if _, err = homchain.EvaluateGaoA2BExpOracle(profile, unnormalized); err == nil {
		t.Fatal("oracle accepted unnormalized u outside [-1,1]")
	}
	exploded := a2bExpExplicitChebyshev(profile.LattigoCoefficientValues(), unnormalized, prec)
	if a2bExpComplexMagnitude(exploded, prec).Cmp(a2bExpMustFloat(t, "1e20", prec)) <= 0 {
		t.Fatal("unnormalized-source negative did not diverge")
	}
	normalized := new(big.Float).SetPrec(prec).SetRat(big.NewRat(63, 64))
	boundary, err := homchain.EvaluateGaoA2BExpOracle(profile, normalized)
	if err != nil || boundary.FinalApproximationError().Cmp(a2bExpPow2Negative(24, prec)) >= 0 {
		t.Fatalf("normalized boundary probe failed: result=%+v err=%v", boundary, err)
	}

	if _, err = homchain.EvaluateGaoA2BExpOracle(profile, nil); err == nil {
		t.Fatal("nil oracle input was accepted")
	}
	if _, err = homchain.EvaluateGaoA2BExpOracle(profile, new(big.Float).SetPrec(128)); err == nil {
		t.Fatal("low-precision oracle input was accepted")
	}
	if _, err = homchain.EvaluateGaoA2BExpOracle(homchain.GaoA2BExpProfile{}, zero); err == nil {
		t.Fatal("zero-value profile was accepted")
	}
}

func TestGaoA2BExpOracleDeterministicGridAndProbes(t *testing.T) {
	profile, err := homchain.NewGaoA2BExpProfile()
	if err != nil {
		t.Fatal(err)
	}
	prec := profile.Precision()
	points := make([]*big.Float, 0, 384)
	for i := int64(0); i <= 256; i++ {
		points = append(points, new(big.Float).SetPrec(prec).SetRat(big.NewRat(i-128, 128)))
	}
	for k := int64(0); k < 47; k++ {
		angle := new(big.Float).SetPrec(prec).Mul(
			bignum.Pi(prec),
			new(big.Float).SetPrec(prec).SetRat(big.NewRat(2*k+1, 94)),
		)
		points = append(points, bignum.Cos(angle))
	}
	for _, u := range []int64{-16, -15, -8, -1, 0, 1, 8, 15, 16} {
		points = append(points, new(big.Float).SetPrec(prec).SetRat(big.NewRat(u, 16)))
		for _, offset := range []*big.Rat{big.NewRat(-1, 256), big.NewRat(1, 256), big.NewRat(1, 4), big.NewRat(3, 4)} {
			probeU := new(big.Rat).Add(new(big.Rat).SetInt64(u), offset)
			if probeU.Cmp(big.NewRat(-16, 1)) >= 0 && probeU.Cmp(big.NewRat(16, 1)) <= 0 {
				points = append(points, new(big.Float).SetPrec(prec).SetRat(new(big.Rat).Quo(probeU, big.NewRat(16, 1))))
			}
		}
	}

	maxBaseError := new(big.Float).SetPrec(prec)
	maxFinalError := new(big.Float).SetPrec(prec)
	for index, point := range points {
		result, err := homchain.EvaluateGaoA2BExpOracle(profile, point)
		if err != nil {
			t.Fatalf("probe %d (%s): %v", index, point.Text('e', 8), err)
		}
		if result.BaseApproximationError().Cmp(maxBaseError) > 0 {
			maxBaseError.Set(result.BaseApproximationError())
		}
		if result.FinalApproximationError().Cmp(maxFinalError) > 0 {
			maxFinalError.Set(result.FinalApproximationError())
		}
	}
	t.Logf("Gao A2B exp scalar probes=%d max base error=%s max final error=%s",
		len(points), maxBaseError.Text('e', 12), maxFinalError.Text('e', 12))
	if maxBaseError.Cmp(a2bExpPow2Negative(28, prec)) >= 0 {
		t.Fatalf("max base error=%s exceeds 2^-28", maxBaseError.Text('e', 12))
	}
	if maxFinalError.Cmp(a2bExpPow2Negative(26, prec)) >= 0 {
		t.Fatalf("max final error=%s exceeds 2^-26", maxFinalError.Text('e', 12))
	}
}

func a2bExpExactDyadic(t *testing.T, numerator string, denominatorBits, precision uint) *big.Float {
	t.Helper()
	value := new(big.Int)
	if _, ok := value.SetString(numerator, 10); !ok {
		t.Fatalf("invalid numerator %q", numerator)
	}
	denominator := new(big.Int).Lsh(big.NewInt(1), denominatorBits)
	return new(big.Float).SetPrec(precision).Quo(
		new(big.Float).SetPrec(precision).SetInt(value),
		new(big.Float).SetPrec(precision).SetInt(denominator),
	)
}

func a2bExpExplicitChebyshev(coefficients []*bignum.Complex, x *big.Float, precision uint) *bignum.Complex {
	tPrev := &bignum.Complex{new(big.Float).SetPrec(precision).SetInt64(1), new(big.Float).SetPrec(precision)}
	tCurrent := &bignum.Complex{new(big.Float).SetPrec(precision).Set(x), new(big.Float).SetPrec(precision)}
	result := coefficients[0].Clone()
	result.SetPrec(precision)
	for index := 1; index < len(coefficients); index++ {
		result.Real().Add(result.Real(), new(big.Float).SetPrec(precision).Mul(coefficients[index].Real(), tCurrent.Real()))
		result.Imag().Add(result.Imag(), new(big.Float).SetPrec(precision).Mul(coefficients[index].Imag(), tCurrent.Real()))
		nextReal := new(big.Float).SetPrec(precision).Mul(x, tCurrent.Real())
		nextReal.Add(nextReal, nextReal)
		nextReal.Sub(nextReal, tPrev.Real())
		tPrev, tCurrent = tCurrent, &bignum.Complex{nextReal, new(big.Float).SetPrec(precision)}
	}
	return result
}

func a2bExpSquare(value *bignum.Complex, precision uint) *bignum.Complex {
	realSquared := new(big.Float).SetPrec(precision).Mul(value.Real(), value.Real())
	imagSquared := new(big.Float).SetPrec(precision).Mul(value.Imag(), value.Imag())
	realPart := new(big.Float).SetPrec(precision).Sub(realSquared, imagSquared)
	imagPart := new(big.Float).SetPrec(precision).Mul(value.Real(), value.Imag())
	imagPart.Add(imagPart, imagPart)
	return &bignum.Complex{realPart, imagPart}
}

func a2bExpComplexDistance(left, right *bignum.Complex, precision uint) *big.Float {
	realDelta := new(big.Float).SetPrec(precision).Sub(left.Real(), right.Real())
	imagDelta := new(big.Float).SetPrec(precision).Sub(left.Imag(), right.Imag())
	realDelta.Mul(realDelta, realDelta)
	imagDelta.Mul(imagDelta, imagDelta)
	return new(big.Float).SetPrec(precision).Sqrt(new(big.Float).SetPrec(precision).Add(realDelta, imagDelta))
}

func a2bExpComplexMagnitude(value *bignum.Complex, precision uint) *big.Float {
	zero := &bignum.Complex{new(big.Float).SetPrec(precision), new(big.Float).SetPrec(precision)}
	return a2bExpComplexDistance(value, zero, precision)
}

func a2bExpPow2Negative(exponent, precision uint) *big.Float {
	denominator := new(big.Int).Lsh(big.NewInt(1), exponent)
	return new(big.Float).SetPrec(precision).Quo(
		new(big.Float).SetPrec(precision).SetInt64(1),
		new(big.Float).SetPrec(precision).SetInt(denominator),
	)
}

func a2bExpMustFloat(t *testing.T, value string, precision uint) *big.Float {
	t.Helper()
	result, ok := new(big.Float).SetPrec(precision).SetString(value)
	if !ok {
		t.Fatalf("invalid float %q", value)
	}
	return result
}
