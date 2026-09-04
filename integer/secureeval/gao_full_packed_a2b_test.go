package secureeval

import (
	"math/big"
	"testing"

	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/dft"
	"github.com/nc26676027/LCPDTE/lattigo/ring"
)

func TestGaoN16FullPackedTransportParametersMatchOpenFHE(t *testing.T) {
	parameters, err := newGaoN16FullPackedTransportParameters()
	if err != nil {
		t.Fatal(err)
	}
	if parameters.BootstrappingParameters.LogN() != 16 ||
		parameters.BootstrappingParameters.LogMaxSlots() != 15 ||
		parameters.BootstrappingParameters.MaxSlots() != 32_768 {
		t.Fatalf("ring/slot shape changed: LogN=%d LogSlots=%d slots=%d",
			parameters.BootstrappingParameters.LogN(),
			parameters.BootstrappingParameters.LogMaxSlots(),
			parameters.BootstrappingParameters.MaxSlots())
	}
	if got := len(parameters.BootstrappingParameters.Q()); got != 21 {
		t.Fatalf("Q modulus count=%d, want 21", got)
	}
	if got := parameters.BootstrappingParameters.QBigInt().BitLen(); got != 904 {
		t.Fatalf("Q aggregate bits=%d, want OpenFHE runtime value 904", got)
	}
	if got := len(parameters.BootstrappingParameters.P()); got != 7 {
		t.Fatalf("P modulus count=%d, want 7", got)
	}
	if got := parameters.BootstrappingParameters.PBigInt().BitLen(); got != 350 {
		t.Fatalf("P aggregate bits=%d, want OpenFHE runtime value 350", got)
	}
	if parameters.SlotsToCoeffsParameters.LogSlots != 15 ||
		parameters.SlotsToCoeffsParameters.LevelQ != 2 ||
		parameters.SlotsToCoeffsParameters.LevelP != 6 ||
		parameters.SlotsToCoeffsParameters.Format != dft.SplitRealAndImag ||
		parameters.SlotsToCoeffsParameters.LogBSGSRatio != 2 ||
		!equalInts(parameters.SlotsToCoeffsParameters.Levels, []int{1, 1}) {
		t.Fatalf("STC parameters changed: %+v", parameters.SlotsToCoeffsParameters)
	}
	if parameters.CoeffsToSlotsParameters.LogSlots != 15 ||
		parameters.CoeffsToSlotsParameters.LevelQ != 20 ||
		parameters.CoeffsToSlotsParameters.LevelP != 6 ||
		parameters.CoeffsToSlotsParameters.Format != dft.SplitRealAndImag ||
		parameters.CoeffsToSlotsParameters.LogBSGSRatio != 2 ||
		!equalInts(parameters.CoeffsToSlotsParameters.Levels, []int{1, 1, 1}) {
		t.Fatalf("CTS parameters changed: %+v", parameters.CoeffsToSlotsParameters)
	}
	wantOne := new(big.Float).SetPrec(256).SetInt64(1)
	wantOneSixteenth := new(big.Float).SetPrec(256).SetInt64(1)
	wantOneSixteenth.SetMantExp(wantOneSixteenth, -4)
	if parameters.SlotsToCoeffsParameters.Scaling == nil ||
		parameters.SlotsToCoeffsParameters.Scaling.Cmp(wantOne) != 0 ||
		parameters.CoeffsToSlotsParameters.Scaling == nil ||
		parameters.CoeffsToSlotsParameters.Scaling.Cmp(wantOneSixteenth) != 0 {
		t.Fatalf("DFT scaling changed: STC=%v CTS=%v",
			parameters.SlotsToCoeffsParameters.Scaling,
			parameters.CoeffsToSlotsParameters.Scaling)
	}
	if parameters.EphemeralSecretWeight != 32 || parameters.CircuitOrder != 1 {
		t.Fatalf("encapsulation/order changed: weight=%d order=%d",
			parameters.EphemeralSecretWeight, parameters.CircuitOrder)
	}
	if got := parameters.LogMaxDimensions(); got != (ring.Dimensions{Rows: 0, Cols: 15}) {
		t.Fatalf("max dimensions=%+v, want {Rows:0 Cols:15}", got)
	}
	t.Logf("full-packed DFT Galois elements=%d", len(parameters.GaloisElements(parameters.BootstrappingParameters)))
}

func equalInts(left, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
