package homchain_test

import (
	"crypto/sha256"
	"fmt"
	"math"
	"math/cmplx"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"dt_go/integer/homchain"

	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

const a2bLUTCanonicalDigest = "f3aa5c55fa47acd6c5a0f96d362d442948c6b2999d3bd4a6061870d3d21564e3"

func TestGaoA2BLUTProfileMatchesFrozenArtifact(t *testing.T) {
	profile, err := homchain.NewGaoA2BLUTProfile()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := profile.Precision(), uint(256); got != want {
		t.Fatalf("precision: got %d, want %d", got, want)
	}
	if got, want := profile.DenominatorBits(), uint(128); got != want {
		t.Fatalf("denominator bits: got %d, want %d", got, want)
	}
	if got, want := profile.Degree(), 15; got != want {
		t.Fatalf("degree: got %d, want %d", got, want)
	}
	if got := profile.TableDigest(); got != a2bLUTCanonicalDigest {
		t.Fatalf("table digest: got %s, want %s", got, a2bLUTCanonicalDigest)
	}
	if got, want := profile.SourceCommit(), "08f1eb87434e7be072cba889270a8400bbffc08e"; got != want {
		t.Fatalf("source commit: got %s, want %s", got, want)
	}

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	artifactPath := filepath.Join(filepath.Dir(thisFile), "..", "..", "research", "phase3_design", "a2b_lut_p16_order1.tsv")
	artifact, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatalf("read frozen artifact: %v", err)
	}
	canonicalArtifact := strings.ReplaceAll(string(artifact), "\r\n", "\n")
	if got, want := canonicalArtifact, profile.CanonicalTable(); got != want {
		t.Fatalf("frozen artifact differs from compiled profile")
	}
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(canonicalArtifact))); got != a2bLUTCanonicalDigest {
		t.Fatalf("artifact digest: got %s, want %s", got, a2bLUTCanonicalDigest)
	}
}

func TestGaoA2BLUTPolynomialsAreExactAndDetached(t *testing.T) {
	profile, err := homchain.NewGaoA2BLUTProfile()
	if err != nil {
		t.Fatal(err)
	}

	for _, kind := range []homchain.GaoA2BLUTKind{homchain.GaoA2BLUTMSB, homchain.GaoA2BLUTIdentity} {
		polynomial, err := profile.LattigoPolynomial(kind)
		if err != nil {
			t.Fatalf("%s polynomial: %v", kind, err)
		}
		if polynomial.Basis != bignum.Monomial {
			t.Fatalf("%s basis: got %v, want monomial", kind, polynomial.Basis)
		}
		if got, want := polynomial.Degree(), 15; got != want {
			t.Fatalf("%s degree: got %d, want %d", kind, got, want)
		}
		for index, coefficient := range polynomial.Coeffs {
			if coefficient[0].Prec() != profile.Precision() || coefficient[1].Prec() != profile.Precision() {
				t.Fatalf("%s coefficient %d precision: got (%d,%d)", kind, index, coefficient[0].Prec(), coefficient[1].Prec())
			}
		}

		realNumerators, imaginaryNumerators, err := profile.Numerators(kind)
		if err != nil {
			t.Fatalf("%s numerators: %v", kind, err)
		}
		realNumerators[0].SetInt64(0)
		imaginaryNumerators[0].SetInt64(1)
		polynomial.Coeffs[0][0].SetInt64(0)
		polynomial.Coeffs[0][1].SetInt64(1)

		freshReal, freshImaginary, err := profile.Numerators(kind)
		if err != nil {
			t.Fatal(err)
		}
		freshPolynomial, err := profile.LattigoPolynomial(kind)
		if err != nil {
			t.Fatal(err)
		}
		if freshReal[0].Sign() == 0 || freshImaginary[0].Sign() != 0 || freshPolynomial.Coeffs[0][0].Sign() == 0 || freshPolynomial.Coeffs[0][1].Sign() != 0 {
			t.Fatalf("mutating returned %s values changed the immutable profile", kind)
		}
	}

	if _, err := profile.LattigoPolynomial(homchain.GaoA2BLUTKind("unknown")); err == nil {
		t.Fatal("unknown LUT kind was accepted")
	}
}

func TestGaoA2BLUTAllSixteenSourcePoints(t *testing.T) {
	profile, err := homchain.NewGaoA2BLUTProfile()
	if err != nil {
		t.Fatal(err)
	}

	for point := 0; point < 16; point++ {
		gotMSB := evaluateA2BLUTPoint(t, profile, homchain.GaoA2BLUTMSB, point)
		wantMSB := 0.0
		if point != 0 && point <= 8 {
			wantMSB = 1
		}
		if errorMagnitude := math.Abs(gotMSB - wantMSB); errorMagnitude > 1e-14 {
			t.Fatalf("MSB(%d): got %.17g, want %.17g, error %.3g", point, gotMSB, wantMSB, errorMagnitude)
		}

		gotID := evaluateA2BLUTPoint(t, profile, homchain.GaoA2BLUTIdentity, point)
		wantID := 0.0
		if point != 0 {
			wantID = float64(point-16) / 16
		}
		if errorMagnitude := math.Abs(gotID - wantID); errorMagnitude > 1e-14 {
			t.Fatalf("ID(%d): got %.17g, want %.17g, error %.3g", point, gotID, wantID, errorMagnitude)
		}
	}
}

func evaluateA2BLUTPoint(t *testing.T, profile homchain.GaoA2BLUTProfile, kind homchain.GaoA2BLUTKind, point int) float64 {
	t.Helper()
	polynomial, err := profile.LattigoPolynomial(kind)
	if err != nil {
		t.Fatal(err)
	}
	root := cmplx.Exp(complex(0, 2*math.Pi*float64(point)/16))
	power := complex(1, 0)
	value := complex(0, 0)
	for _, coefficient := range polynomial.Coeffs {
		realPart, _ := coefficient[0].Float64()
		imaginaryPart, _ := coefficient[1].Float64()
		value += complex(realPart, imaginaryPart) * power
		power *= root
	}
	// The upstream circuit adds the conjugate after polynomial evaluation.
	return 2 * real(value)
}
