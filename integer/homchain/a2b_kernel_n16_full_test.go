package homchain

import (
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
	if got, want := fullProfile.RuntimePath(), "n16-l15-full-packed-normalized-y;exp46-chebyshev-scalar/evaluate;mulrelin-rescale^2;id-msb-degree15-scalars/evaluate-multi-poly/shared-power-basis/target-S43;conjugate-add^2"; got != want {
		t.Fatalf("full-packed runtime path=%q, want %q", got, want)
	}
	fullExponential, fullLUTs := full.polynomialEvaluationOperands()
	if _, ok := fullExponential.(ckkspolynomial.Polynomial); !ok {
		t.Fatalf("full-packed exponential operand type=%T, want scalar polynomial", fullExponential)
	}
	for i, operand := range fullLUTs {
		if _, ok := operand.(ckkspolynomial.Polynomial); !ok {
			t.Fatalf("full-packed LUT operand %d type=%T, want scalar polynomial", i, operand)
		}
	}

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
