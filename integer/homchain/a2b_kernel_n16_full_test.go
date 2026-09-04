package homchain

import (
	"math"
	"math/big"
	"math/cmplx"
	"testing"

	"github.com/nc26676027/LCPDTE/integer/securityparams"
	ckkspolynomial "github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/polynomial"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/ring"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
)

func TestGaoA2BKernelN16FullPackedProfileMatchesGaoPacking(t *testing.T) {
	params, err := securityparams.GaoOpenFHEFullN16Parameters()
	if err != nil {
		t.Fatal(err)
	}
	encoder := ckks.NewEncoder(params, 256)

	full, err := NewGaoA2BKernelN16FullPackedCircuit(params, encoder)
	if err != nil {
		t.Fatal(err)
	}
	fullProfile := full.Profile()
	if fullProfile.Claim() != GaoA2BKernelN16FullPackedKernelOnlyUnverified ||
		fullProfile.InputLevel() != 17 || fullProfile.BooleanOutputLevel() != 5 ||
		fullProfile.Slots() != 32768 ||
		fullProfile.LogDimensions() != (ring.Dimensions{Rows: 0, Cols: 15}) ||
		fullProfile.OperationalEncoderPrecision() != 256 {
		t.Fatalf("unexpected N16 full-packed Gao kernel profile: %+v", fullProfile)
	}
	if fullProfile.OperandPlan().ExponentialMappedSlots() != 32768 ||
		fullProfile.OperandPlan().LUTMappedSlots() != [2]int{32768, 32768} {
		t.Fatalf("unexpected N16 full-packed Gao operand plan: %+v", fullProfile.OperandPlan())
	}
	if got, want := fullProfile.RuntimePath(), "n16-l15-full-packed-normalized-y;exp46-chebyshev-scalar/evaluate;mulrelin-rescale^2;root16-real-id-plus-i-msb-degree15-scalar/evaluate-once/target-S43;conjugate-split-real-imag"; got != want {
		t.Fatalf("full-packed runtime path=%q, want %q", got, want)
	}
	fullExponential, fullLUTs := full.polynomialEvaluationOperands()
	if _, ok := fullExponential.(ckkspolynomial.Polynomial); !ok {
		t.Fatalf("full-packed exponential operand type=%T, want scalar polynomial", fullExponential)
	}
	if len(fullLUTs) != 1 {
		t.Fatalf("full-packed LUT operands=%d, want one complex-packed ID+i*MSB polynomial", len(fullLUTs))
	}
	packedLUT, ok := fullLUTs[0].(ckkspolynomial.Polynomial)
	if !ok {
		t.Fatalf("full-packed LUT operand type=%T, want scalar polynomial", fullLUTs[0])
	}
	assertGaoA2BKernelN16PackedLUTAtAllRoots(t, packedLUT)

	sparseParams, err := securityparams.GaoCompatibleN16Parameters()
	if err != nil {
		t.Fatal(err)
	}
	sparse, err := NewGaoA2BKernelN16L11Circuit(sparseParams, ckks.NewEncoder(sparseParams, 256))
	if err != nil {
		t.Fatal(err)
	}
	sparseExponential, sparseLUTs := sparse.polynomialEvaluationOperands()
	if _, ok := sparseExponential.(ckkspolynomial.PolynomialVector); !ok {
		t.Fatalf("sparse exponential operand type=%T, want polynomial vector", sparseExponential)
	}
	for i, operand := range sparseLUTs {
		if _, ok := operand.(ckkspolynomial.PolynomialVector); !ok {
			t.Fatalf("sparse LUT operand %d type=%T, want polynomial vector", i, operand)
		}
	}
	sparseProfile := sparse.Profile()
	if got, want := sparseProfile.Digest(), "13ed99b7fc9321ce195a10d9fe297d17ea842b2ba0fd586c305b3a2e7e09e216"; got != want {
		t.Fatalf("frozen N16/L11 profile digest=%s, want %s", got, want)
	}
	if fullProfile.Digest() == "" || fullProfile.Digest() == sparseProfile.Digest() {
		t.Fatalf("full-packed profile digest is not distinct: full=%s sparse=%s", fullProfile.Digest(), sparseProfile.Digest())
	}
	if fullProfile.KeyProfile().Digest() == sparseProfile.KeyProfile().Digest() {
		t.Fatalf("full-packed key profile digest is not distinct: %s", fullProfile.KeyProfile().Digest())
	}
	t.Logf("full-packed profile=%s key-profile=%s", fullProfile.Digest(), fullProfile.KeyProfile().Digest())
}

func TestGaoA2BKernelN16FullPackedDerivedLUTTamperIsRejected(t *testing.T) {
	params, err := securityparams.GaoOpenFHEFullN16Parameters()
	if err != nil {
		t.Fatal(err)
	}
	circuit, err := NewGaoA2BKernelN16FullPackedCircuit(params, ckks.NewEncoder(params, 256))
	if err != nil {
		t.Fatal(err)
	}
	coefficient := circuit.packedLUTOperand.Coeffs[0]
	original := new(big.Float).SetPrec(coefficient.Prec()).Set(coefficient.Real())
	coefficient.Real().Add(coefficient.Real(), new(big.Float).SetPrec(coefficient.Prec()).SetInt64(1))
	if err = circuit.validate(); err == nil {
		t.Fatal("mutated N16 full-packed derived LUT passed circuit validation")
	}
	coefficient.Real().Set(original)
	if err = circuit.validate(); err != nil {
		t.Fatalf("restored N16 full-packed derived LUT did not validate: %v", err)
	}
}

func assertGaoA2BKernelN16PackedLUTAtAllRoots(t *testing.T, polynomial ckkspolynomial.Polynomial) {
	t.Helper()
	for point := 0; point < 16; point++ {
		root := cmplx.Exp(complex(0, 2*math.Pi*float64(point)/16))
		power := complex(1, 0)
		packed := complex(0, 0)
		for _, coefficient := range polynomial.Coeffs {
			packed += coefficient.Complex128() * power
			power *= root
		}
		conjugate := cmplx.Conj(packed)
		gotIdentity := packed + conjugate
		gotMSB := complex(0, -1) * (packed - conjugate)
		wantIdentity := 0.0
		if point != 0 {
			wantIdentity = float64(point-16) / 16
		}
		wantMSB := 0.0
		if point >= 1 && point <= 8 {
			wantMSB = 1
		}
		if math.Abs(real(gotIdentity)-wantIdentity) > 1e-13 || math.Abs(imag(gotIdentity)) > 1e-13 ||
			math.Abs(real(gotMSB)-wantMSB) > 1e-13 || math.Abs(imag(gotMSB)) > 1e-13 {
			t.Fatalf("root %d split: ID=%v want=%g MSB=%v want=%g", point, gotIdentity, wantIdentity, gotMSB, wantMSB)
		}
	}
}

func TestGaoA2BKernelN16PreparedEntryRejectsNilEvaluator(t *testing.T) {
	var evaluator *GaoA2BKernelN16FullPackedEvaluator
	result, err := evaluator.EvaluatePreparedNew(nil)
	if err == nil || result.IDCiphertext() != nil || result.MSBCiphertext() != nil {
		t.Fatalf("nil prepared evaluator: result=%+v err=%v", result, err)
	}
}

func TestGaoA2BKernelN16PreparedMSBEntryRejectsNilEvaluator(t *testing.T) {
	var _ func(*GaoA2BKernelN16FullPackedEvaluator, *rlwe.Ciphertext) (*rlwe.Ciphertext, error) = (*GaoA2BKernelN16FullPackedEvaluator).EvaluatePreparedMSBNew
	var evaluator *GaoA2BKernelN16FullPackedEvaluator
	result, err := evaluator.EvaluatePreparedMSBNew(nil)
	if err == nil || result != nil {
		t.Fatalf("nil prepared MSB evaluator: result=%v err=%v", result, err)
	}
}

func TestGaoA2BKernelN16PreparedOutputsEntryRejectsNilEvaluator(t *testing.T) {
	var _ func(*GaoA2BKernelN16FullPackedEvaluator, *rlwe.Ciphertext) (*rlwe.Ciphertext, *rlwe.Ciphertext, error) = (*GaoA2BKernelN16FullPackedEvaluator).EvaluatePreparedOutputsNew
	var evaluator *GaoA2BKernelN16FullPackedEvaluator
	identity, msb, err := evaluator.EvaluatePreparedOutputsNew(nil)
	if err == nil || identity != nil || msb != nil {
		t.Fatalf("nil prepared-output evaluator: identity=%v msb=%v err=%v", identity, msb, err)
	}
}

func TestNormalizeGaoA2BKernelPolynomialScaleAcceptsOnlyRoundingResidue(t *testing.T) {
	params, err := securityparams.GaoOpenFHEFullN16Parameters()
	if err != nil {
		t.Fatal(err)
	}
	target := params.DefaultScale()
	ciphertext := rlwe.NewCiphertext(params, 1, 0)

	one := new(big.Float).SetPrec(rlwe.ScalePrecision).SetInt64(1)
	delta := new(big.Float).SetPrec(rlwe.ScalePrecision).SetInt64(1)
	delta.SetMantExp(delta, -120)
	ciphertext.Scale = target.Mul(rlwe.NewScale(new(big.Float).SetPrec(rlwe.ScalePrecision).Add(one, delta)))
	if err = normalizeGaoA2BKernelPolynomialScale(ciphertext, target); err != nil {
		t.Fatalf("rounding residue was rejected: %v", err)
	}
	if !ciphertext.Scale.Equal(target) {
		t.Fatalf("normalized scale=%s, want %s", ciphertext.Scale.Value.Text('x', -1), target.Value.Text('x', -1))
	}

	ciphertext.Scale = target.Mul(rlwe.NewScale(2))
	if err = normalizeGaoA2BKernelPolynomialScale(ciphertext, target); err == nil {
		t.Fatal("material scale drift was accepted")
	}
}
