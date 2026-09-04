package secureeval

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/nc26676027/LCPDTE/integer/securityparams"
	"github.com/nc26676027/LCPDTE/integer/z2n"
	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/bootstrapping"
	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/dft"
	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/mod1"
)

const (
	gaoN16RouteBCKKSParameterDigestHex = "c37129e34fb3d726b37412887edf8df1cd6801ba9ab11d02531dddc4f08ea816"
	// The raw JSON digest is diagnostic. The prepared seal and the eight typed
	// RBAUTH fragments are the authoritative identity because they retain the
	// exact nullable big.Float metadata and CircuitOrder.
	gaoN16RouteBRawDiagnosticDigestHex = "96ae3abc883d62dcd2c1c536728b4c828d077058d877a6488ca685feb8fd2661"
	gaoN16RouteBPreparedDigestHex      = "f5724cc34ecd24a475a82239ff269e3b437602e4c4cfe03b1096ece795e3f7b6"

	gaoN16RouteBRawSTCLiteralDigestHex       = "b6468918cbd2c3f8ca76d22cb000bfe0c970c4d1932bbb9bcc27b03baa5fdcbb"
	gaoN16RouteBRawSTCScalingDigestHex       = "ca2fd7688b462df6336d04bdbf0e324723e490fc7afa7808822df3e10a7681ff"
	gaoN16RouteBEffectiveSTCLiteralDigestHex = "85ee70d5fd49463fcd46ed37f5ab9ccc511e766bf5e73adbf60ea019dd3b8655"
	gaoN16RouteBEffectiveSTCScalingDigestHex = "58b7bebf46c178efaf34a42a723ebfa05ad770a948ed8efa607b7161871650d0"
	gaoN16RouteBRawCTSLiteralDigestHex       = "b97fff2a1a6c730a827dd18200038af9c3e13c1b2db556dd2e75cd45bd40d3c7"
	gaoN16RouteBRawCTSScalingDigestHex       = "2280bfc7e749da1ebfb2d673e165cde835daa0dd3c2a512cb0689eb583484c6a"
	gaoN16RouteBEffectiveCTSLiteralDigestHex = "527bec38d2a4582d9d40592ec0b529fdbeadbadfb99bcd8872952a47db1cdb6e"
	gaoN16RouteBEffectiveCTSScalingDigestHex = "db13c608527e9be98ce64dd5614cfff68b35f28c976e49dec8abdfae9a7f7840"
)

// newGaoN16RouteBTransportParameters creates the sole project-owned raw
// Route-B transport configuration. Its degree-3 SinContinuous polynomial is
// a resident compatibility object and is not an executable Gao kernel.
func newGaoN16RouteBTransportParameters() (bootstrapping.Parameters, error) {
	residual, err := securityparams.GaoCompatibleN16Parameters()
	if err != nil {
		return bootstrapping.Parameters{}, fmt.Errorf("secureeval: construct Route-B residual parameters: %w", err)
	}
	bootstrap, err := securityparams.GaoCompatibleN16Parameters()
	if err != nil {
		return bootstrapping.Parameters{}, fmt.Errorf("secureeval: construct Route-B bootstrap parameters: %w", err)
	}
	if err = validateGaoN16RouteBCKKSParameterIdentity(residual); err != nil {
		return bootstrapping.Parameters{}, err
	}
	if err = validateGaoN16RouteBCKKSParameterIdentity(bootstrap); err != nil {
		return bootstrapping.Parameters{}, err
	}
	if !residual.Equal(&bootstrap) {
		return bootstrapping.Parameters{}, fmt.Errorf("secureeval: Route-B residual and bootstrap parameter values differ")
	}

	one := new(big.Float).SetPrec(z2n.DefaultPrecision).SetMode(big.ToNearestEven).SetInt64(1)
	oneSixteenth := new(big.Float).SetPrec(z2n.DefaultPrecision).SetMode(big.ToNearestEven).SetInt64(1)
	oneSixteenth.SetMantExp(oneSixteenth, -4)

	raw := bootstrapping.Parameters{
		ResidualParameters:      residual,
		BootstrappingParameters: bootstrap,
		SlotsToCoeffsParameters: dft.MatrixLiteral{
			Type: dft.HomomorphicDecode, LogSlots: 11, LevelQ: 18, LevelP: 6,
			Levels: []int{1, 1}, Format: dft.SplitRealAndImag, Scaling: one,
			BitReversed: false, LogBSGSRatio: 0,
		},
		CoeffsToSlotsParameters: dft.MatrixLiteral{
			Type: dft.HomomorphicEncode, LogSlots: 11, LevelQ: 20, LevelP: 6,
			Levels: []int{1, 1, 1}, Format: dft.SplitRealAndImag, Scaling: oneSixteenth,
			BitReversed: false, LogBSGSRatio: 0,
		},
		Mod1ParametersLiteral: mod1.ParametersLiteral{
			LevelQ: 17, LogScale: 43, Mod1Type: mod1.SinContinuous, Scaling: 0,
			LogMessageRatio: 0, K: 1, Mod1Degree: 3, DoubleAngle: 0, Mod1InvDegree: 0,
		},
		IterationsParameters:  nil,
		EphemeralSecretWeight: 32,
		CircuitOrder:          bootstrapping.DecodeThenModUp,
	}
	if err = validateGaoN16RouteBRawDiagnosticIdentity(raw); err != nil {
		return bootstrapping.Parameters{}, err
	}
	return raw, nil
}

// prepareGaoN16RouteBTransportParameters is pure. The live Authority must call
// it only after current L11 capacity admission; this helper itself does not
// mint capacity, lineage, a permit, an encoder or an artifact.
func prepareGaoN16RouteBTransportParameters() (bootstrapping.PreparedParameters, RBAUTHTransformDigests, error) {
	raw, err := newGaoN16RouteBTransportParameters()
	if err != nil {
		return bootstrapping.PreparedParameters{}, RBAUTHTransformDigests{}, err
	}
	return prepareGaoN16RouteBTransportParametersFromRaw(raw)
}

func prepareGaoN16RouteBTransportParametersFromRaw(raw bootstrapping.Parameters) (bootstrapping.PreparedParameters, RBAUTHTransformDigests, error) {
	if err := validateGaoN16RouteBRawDiagnosticIdentity(raw); err != nil {
		return bootstrapping.PreparedParameters{}, RBAUTHTransformDigests{}, err
	}
	before, err := raw.MarshalBinary()
	if err != nil {
		return bootstrapping.PreparedParameters{}, RBAUTHTransformDigests{}, fmt.Errorf("secureeval: marshal stored Route-B raw parameters before preparation: %w", err)
	}
	prepared, err := bootstrapping.PrepareParameters(raw)
	if err != nil {
		return bootstrapping.PreparedParameters{}, RBAUTHTransformDigests{}, fmt.Errorf("secureeval: prepare canonical Route-B transport parameters: %w", err)
	}
	if err = prepared.Verify(); err != nil {
		return bootstrapping.PreparedParameters{}, RBAUTHTransformDigests{}, fmt.Errorf("secureeval: verify canonical Route-B prepared parameters: %w", err)
	}
	if err = validateGaoN16RouteBPreparedIdentity(prepared); err != nil {
		return bootstrapping.PreparedParameters{}, RBAUTHTransformDigests{}, err
	}
	transforms, err := deriveGaoN16RouteBTransformIdentities(prepared)
	if err != nil {
		return bootstrapping.PreparedParameters{}, RBAUTHTransformDigests{}, err
	}
	if err = validateGaoN16RouteBTransformIdentitySet(transforms); err != nil {
		return bootstrapping.PreparedParameters{}, RBAUTHTransformDigests{}, err
	}
	after, err := raw.MarshalBinary()
	if err != nil {
		return bootstrapping.PreparedParameters{}, RBAUTHTransformDigests{}, fmt.Errorf("secureeval: marshal stored Route-B raw parameters after preparation: %w", err)
	}
	if !bytes.Equal(before, after) {
		return bootstrapping.PreparedParameters{}, RBAUTHTransformDigests{}, fmt.Errorf("secureeval: stored Route-B raw parameters changed during preparation")
	}
	return prepared, transforms, nil
}

func validateGaoN16RouteBRawDiagnosticIdentity(raw bootstrapping.Parameters) error {
	payload, err := raw.MarshalBinary()
	if err != nil {
		return fmt.Errorf("secureeval: marshal canonical Route-B raw parameters: %w", err)
	}
	digest := sha256.Sum256(payload)
	if hex.EncodeToString(digest[:]) != gaoN16RouteBRawDiagnosticDigestHex {
		return fmt.Errorf("secureeval: canonical Route-B raw diagnostic identity changed")
	}
	return nil
}

func validateGaoN16RouteBPreparedIdentity(prepared bootstrapping.PreparedParameters) error {
	if err := prepared.Verify(); err != nil {
		return fmt.Errorf("secureeval: verify canonical Route-B prepared parameters: %w", err)
	}
	digest := prepared.Digest()
	if hex.EncodeToString(digest[:]) != gaoN16RouteBPreparedDigestHex {
		return fmt.Errorf("secureeval: canonical Route-B prepared identity changed")
	}
	return nil
}

func validateGaoN16RouteBTransformIdentitySet(value RBAUTHTransformDigests) error {
	expected := [...]string{
		gaoN16RouteBRawSTCLiteralDigestHex,
		gaoN16RouteBRawSTCScalingDigestHex,
		gaoN16RouteBEffectiveSTCLiteralDigestHex,
		gaoN16RouteBEffectiveSTCScalingDigestHex,
		gaoN16RouteBRawCTSLiteralDigestHex,
		gaoN16RouteBRawCTSScalingDigestHex,
		gaoN16RouteBEffectiveCTSLiteralDigestHex,
		gaoN16RouteBEffectiveCTSScalingDigestHex,
	}
	for index, digest := range transformDigestSlice(value) {
		if hex.EncodeToString(digest[:]) != expected[index] {
			return fmt.Errorf("secureeval: canonical Route-B transform identity %d changed", index)
		}
	}
	return nil
}

func validateGaoN16RouteBCKKSParameterIdentity(parameters interface{ MarshalBinary() ([]byte, error) }) error {
	payload, err := parameters.MarshalBinary()
	if err != nil {
		return fmt.Errorf("secureeval: marshal Route-B CKKS parameters: %w", err)
	}
	digest := sha256.Sum256(payload)
	if hex.EncodeToString(digest[:]) != gaoN16RouteBCKKSParameterDigestHex {
		return fmt.Errorf("secureeval: Route-B CKKS parameter identity changed")
	}
	return nil
}

func deriveGaoN16RouteBTransformIdentities(prepared bootstrapping.PreparedParameters) (RBAUTHTransformDigests, error) {
	if err := prepared.Verify(); err != nil {
		return RBAUTHTransformDigests{}, fmt.Errorf("secureeval: cannot identify invalid prepared Route-B parameters: %w", err)
	}
	raw := prepared.RawParameters()
	effective := prepared.EffectiveParameters()

	rawSTCLiteral, rawSTCScaling, err := deriveGaoN16RouteBTransformIdentity(
		RBAUTHRoleSTC, RBAUTHPhaseRaw, raw.SlotsToCoeffsParameters)
	if err != nil {
		return RBAUTHTransformDigests{}, err
	}
	effectiveSTCLiteral, effectiveSTCScaling, err := deriveGaoN16RouteBTransformIdentity(
		RBAUTHRoleSTC, RBAUTHPhaseEffective, effective.SlotsToCoeffsParameters)
	if err != nil {
		return RBAUTHTransformDigests{}, err
	}
	rawCTSLiteral, rawCTSScaling, err := deriveGaoN16RouteBTransformIdentity(
		RBAUTHRoleCTS, RBAUTHPhaseRaw, raw.CoeffsToSlotsParameters)
	if err != nil {
		return RBAUTHTransformDigests{}, err
	}
	effectiveCTSLiteral, effectiveCTSScaling, err := deriveGaoN16RouteBTransformIdentity(
		RBAUTHRoleCTS, RBAUTHPhaseEffective, effective.CoeffsToSlotsParameters)
	if err != nil {
		return RBAUTHTransformDigests{}, err
	}

	return RBAUTHTransformDigests{
		RawSTCLiteralDigest: rawSTCLiteral, RawSTCScalingDigest: rawSTCScaling,
		EffectiveSTCLiteralDigest: effectiveSTCLiteral, EffectiveSTCScalingDigest: effectiveSTCScaling,
		RawCTSLiteralDigest: rawCTSLiteral, RawCTSScalingDigest: rawCTSScaling,
		EffectiveCTSLiteralDigest: effectiveCTSLiteral, EffectiveCTSScalingDigest: effectiveCTSScaling,
	}, nil
}

func deriveGaoN16RouteBTransformIdentity(role, phase byte, literal dft.MatrixLiteral) (RBAUTHDigest, RBAUTHDigest, error) {
	typeValue, err := checkedGaoN16RouteBByte("DFT type", int(literal.Type))
	if err != nil {
		return RBAUTHDigest{}, RBAUTHDigest{}, err
	}
	logSlots, err := checkedGaoN16RouteBInt32("DFT LogSlots", literal.LogSlots)
	if err != nil {
		return RBAUTHDigest{}, RBAUTHDigest{}, err
	}
	levelQ, err := checkedGaoN16RouteBInt32("DFT LevelQ", literal.LevelQ)
	if err != nil {
		return RBAUTHDigest{}, RBAUTHDigest{}, err
	}
	levelP, err := checkedGaoN16RouteBInt32("DFT LevelP", literal.LevelP)
	if err != nil {
		return RBAUTHDigest{}, RBAUTHDigest{}, err
	}
	format, err := checkedGaoN16RouteBByte("DFT format", int(literal.Format))
	if err != nil {
		return RBAUTHDigest{}, RBAUTHDigest{}, err
	}
	logBSGSRatio, err := checkedGaoN16RouteBInt32("DFT LogBSGSRatio", literal.LogBSGSRatio)
	if err != nil {
		return RBAUTHDigest{}, RBAUTHDigest{}, err
	}
	levels := make([]int32, len(literal.Levels))
	for index, level := range literal.Levels {
		levels[index], err = checkedGaoN16RouteBInt32("DFT factor level", level)
		if err != nil {
			return RBAUTHDigest{}, RBAUTHDigest{}, err
		}
	}
	literalDigest, err := RBAUTHLiteralIdentity(RBAUTHMatrixLiteralIdentity{
		Role: role, Phase: phase, Type: typeValue, LogSlots: logSlots,
		LevelQ: levelQ, LevelP: levelP, Levels: levels,
		Format: format, BitReversed: literal.BitReversed,
		LogBSGSRatio: logBSGSRatio,
	})
	if err != nil {
		return RBAUTHDigest{}, RBAUTHDigest{}, fmt.Errorf("secureeval: identify Route-B DFT literal: %w", err)
	}
	scaling, err := NewRBAUTHNullableBigFloat(literal.Scaling)
	if err != nil {
		return RBAUTHDigest{}, RBAUTHDigest{}, fmt.Errorf("secureeval: identify Route-B DFT scaling: %w", err)
	}
	scalingDigest, err := RBAUTHScalingIdentity(role, phase, scaling)
	if err != nil {
		return RBAUTHDigest{}, RBAUTHDigest{}, fmt.Errorf("secureeval: digest Route-B DFT scaling: %w", err)
	}
	return literalDigest, scalingDigest, nil
}

func checkedGaoN16RouteBInt32(name string, value int) (int32, error) {
	converted := int32(value)
	if int(converted) != value {
		return 0, fmt.Errorf("secureeval: Route-B %s exceeds int32", name)
	}
	return converted, nil
}

func checkedGaoN16RouteBByte(name string, value int) (byte, error) {
	converted := byte(value)
	if int(converted) != value {
		return 0, fmt.Errorf("secureeval: Route-B %s exceeds byte", name)
	}
	return converted, nil
}
