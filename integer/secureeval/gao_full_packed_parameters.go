package secureeval

import (
	"fmt"
	"math/big"

	"github.com/nc26676027/LCPDTE/integer/securityparams"
	"github.com/nc26676027/LCPDTE/integer/z2n"
	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/bootstrapping"
	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/dft"
	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/mod1"
)

const (
	gaoFullPackedLogSlots = 15
	gaoFullPackedSlots    = 1 << gaoFullPackedLogSlots
	gaoFullPackedWords    = gaoFullPackedSlots / 4
)

// newGaoN16FullPackedTransportParameters is the Lattigo representation of
// Gao et al.'s full-packed zN=8, zSlots=8192, w=4 A2B transport parameters.
// The small resident Mod1 polynomial is compatibility state; the online A2B
// path evaluates Gao's dedicated exp/LUT kernel instead.
func newGaoN16FullPackedTransportParameters() (bootstrapping.Parameters, error) {
	residual, err := securityparams.GaoOpenFHEFullN16Parameters()
	if err != nil {
		return bootstrapping.Parameters{}, fmt.Errorf("secureeval: construct Gao full-packed residual parameters: %w", err)
	}
	bootstrap, err := securityparams.GaoOpenFHEFullN16Parameters()
	if err != nil {
		return bootstrapping.Parameters{}, fmt.Errorf("secureeval: construct Gao full-packed bootstrap parameters: %w", err)
	}
	if !residual.Equal(&bootstrap) {
		return bootstrapping.Parameters{}, fmt.Errorf("secureeval: Gao full-packed residual and bootstrap parameters differ")
	}

	one := new(big.Float).SetPrec(z2n.DefaultPrecision).SetMode(big.ToNearestEven).SetInt64(1)
	oneSixteenth := new(big.Float).SetPrec(z2n.DefaultPrecision).SetMode(big.ToNearestEven).SetInt64(1)
	oneSixteenth.SetMantExp(oneSixteenth, -4)

	return bootstrapping.Parameters{
		ResidualParameters:      residual,
		BootstrappingParameters: bootstrap,
		SlotsToCoeffsParameters: dft.MatrixLiteral{
			Type: dft.HomomorphicDecode, LogSlots: gaoFullPackedLogSlots,
			LevelQ: 2, LevelP: 6, Levels: []int{1, 1},
			Format: dft.SplitRealAndImag, Scaling: one,
			// OpenFHE dim1=0 and Lattigo use backend-native BSGS planners
			// for the same collapsed FFT factors. Ratio 2 is the faster,
			// lower-residency Lattigo plan measured for this workload.
			BitReversed: false, LogBSGSRatio: 2,
		},
		CoeffsToSlotsParameters: dft.MatrixLiteral{
			Type: dft.HomomorphicEncode, LogSlots: gaoFullPackedLogSlots,
			LevelQ: 20, LevelP: 6, Levels: []int{1, 1, 1},
			Format: dft.SplitRealAndImag, Scaling: oneSixteenth,
			BitReversed: false, LogBSGSRatio: 2,
		},
		Mod1ParametersLiteral: mod1.ParametersLiteral{
			LevelQ: 17, LogScale: 43, Mod1Type: mod1.SinContinuous,
			Scaling: 0, LogMessageRatio: 0, K: 1, Mod1Degree: 3,
			DoubleAngle: 0, Mod1InvDegree: 0,
		},
		EphemeralSecretWeight: 32,
		CircuitOrder:          bootstrapping.DecodeThenModUp,
	}, nil
}
