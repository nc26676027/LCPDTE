package homchain

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"sort"
	"strings"

	ckksdft "github.com/tuneinsight/lattigo/v6/circuits/ckks/dft"
	ltcommon "github.com/tuneinsight/lattigo/v6/circuits/ckks/lintrans"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

// RawFullSlotDFTConfig fixes the factorization and levels for the coefficient
// bridge used by A2A-I. The sum of each Levels slice is the number of
// factorized matrices (and ciphertext levels) used to cover the LogSlots FFT
// layers; it must not exceed LogSlots.
type RawFullSlotDFTConfig struct {
	SlotsToCoeffsLevelQ int
	SlotsToCoeffsLevels []int
	CoeffsToSlotsLevelQ int
	CoeffsToSlotsLevels []int
	LevelP              int
	LogBSGSRatio        int
}

// RawFullSlotDFT owns a dense, full-slot DFT/IDFT pair whose literal scaling
// is exactly one. It is deliberately separate from the matrices initialized
// by Lattigo's bootstrapping evaluator, which fold EvalMod-specific scaling
// factors into their literals. The construction encoder's precision is bound
// into the value so source-specific circuits can reject a mismatched profile.
type RawFullSlotDFT struct {
	params             ckks.Parameters
	encoderPrecision   uint
	generatorPrecision uint
	matrixSourceDigest string
	logSlots           int
	slotsToCoeffs      ckksdft.Matrix
	coeffsToSlots      ckksdft.Matrix
	stcOutputLevel     int
	ctsOutputLevel     int
}

// NewRawFullSlotDFT constructs the raw dense DFT bridge. SplitRealAndImag is
// required because dense Gao Z-To-C produces two real coefficient halves.
func NewRawFullSlotDFT(params ckks.Parameters, encoder *ckks.Encoder, config RawFullSlotDFTConfig) (RawFullSlotDFT, error) {
	if encoder == nil {
		return RawFullSlotDFT{}, fmt.Errorf("homchain: nil raw DFT encoder")
	}
	encoderParameters := encoder.GetParameters()
	if !params.Equal(&encoderParameters) {
		return RawFullSlotDFT{}, fmt.Errorf("homchain: raw DFT encoder parameters do not match the requested parameters")
	}
	if config.LevelP < 0 || config.LevelP > params.MaxLevelP() {
		return RawFullSlotDFT{}, fmt.Errorf("homchain: raw DFT LevelP %d outside [0,%d]", config.LevelP, params.MaxLevelP())
	}

	logSlots := params.LogMaxSlots()
	stcOutput, err := validateRawDFTLevels(
		"Slots-To-Coeffs", logSlots, config.SlotsToCoeffsLevelQ,
		config.SlotsToCoeffsLevels, params,
	)
	if err != nil {
		return RawFullSlotDFT{}, err
	}
	ctsOutput, err := validateRawDFTLevels(
		"Coeffs-To-Slots", logSlots, config.CoeffsToSlotsLevelQ,
		config.CoeffsToSlotsLevels, params,
	)
	if err != nil {
		return RawFullSlotDFT{}, err
	}

	newScalingOne := func() *big.Float {
		return new(big.Float).SetPrec(encoder.Prec()).SetInt64(1)
	}
	stcLiteral := ckksdft.MatrixLiteral{
		Type: ckksdft.HomomorphicDecode, Format: ckksdft.SplitRealAndImag,
		LogSlots: logSlots, LevelQ: config.SlotsToCoeffsLevelQ, LevelP: config.LevelP,
		Levels:  append([]int(nil), config.SlotsToCoeffsLevels...),
		Scaling: newScalingOne(), LogBSGSRatio: config.LogBSGSRatio,
	}
	ctsLiteral := ckksdft.MatrixLiteral{
		Type: ckksdft.HomomorphicEncode, Format: ckksdft.SplitRealAndImag,
		LogSlots: logSlots, LevelQ: config.CoeffsToSlotsLevelQ, LevelP: config.LevelP,
		Levels:  append([]int(nil), config.CoeffsToSlotsLevels...),
		Scaling: newScalingOne(), LogBSGSRatio: config.LogBSGSRatio,
	}

	stc, stcSourceDigest, err := newDFTMatrixFromLiteralAtPrecision(params, stcLiteral, encoder)
	if err != nil {
		return RawFullSlotDFT{}, fmt.Errorf("homchain: encode raw Slots-To-Coeffs DFT: %w", err)
	}
	cts, ctsSourceDigest, err := newDFTMatrixFromLiteralAtPrecision(params, ctsLiteral, encoder)
	if err != nil {
		return RawFullSlotDFT{}, fmt.Errorf("homchain: encode raw Coeffs-To-Slots DFT: %w", err)
	}
	matrixSourceDigest := sha256.Sum256([]byte(fmt.Sprintf(
		"raw-full-slot-dft-matrix-payload-v1|stc=%s|cts=%s",
		stcSourceDigest, ctsSourceDigest,
	)))

	return RawFullSlotDFT{
		params: params, encoderPrecision: encoder.Prec(), generatorPrecision: encoder.Prec(),
		matrixSourceDigest: fmt.Sprintf("%x", matrixSourceDigest),
		logSlots:           logSlots, slotsToCoeffs: stc, coeffsToSlots: cts,
		stcOutputLevel: stcOutput, ctsOutputLevel: ctsOutput,
	}, nil
}

// GeneratorPrecision is the precision used to generate the DFT roots and
// factor matrices. It is intentionally separate from EncoderPrecision: the
// stock Lattigo constructor generates matrices at params.EncodingPrecision(),
// even when the supplied encoder uses a higher precision.
func (d RawFullSlotDFT) GeneratorPrecision() uint { return d.generatorPrecision }

// MatrixSourceDigest identifies the exact high-precision diagonal vectors
// supplied to the encoder for both directions of the raw DFT bridge.
func (d RawFullSlotDFT) MatrixSourceDigest() string { return d.matrixSourceDigest }

// SlotsToCoeffsLiteral returns a detached copy suitable for key generation or
// bootstrapping metadata. Its Scaling value remains the literal one, not a
// bootstrap-initialized derivative.
func (d RawFullSlotDFT) SlotsToCoeffsLiteral() ckksdft.MatrixLiteral {
	return cloneDFTLiteral(d.slotsToCoeffs.MatrixLiteral)
}

// CoeffsToSlotsLiteral returns a detached raw inverse-DFT literal.
func (d RawFullSlotDFT) CoeffsToSlotsLiteral() ckksdft.MatrixLiteral {
	return cloneDFTLiteral(d.coeffsToSlots.MatrixLiteral)
}

// SlotsToCoeffsOutputLevel is the exact level after the configured raw DFT.
func (d RawFullSlotDFT) SlotsToCoeffsOutputLevel() int { return d.stcOutputLevel }

// CoeffsToSlotsOutputLevel is the exact level after the configured raw IDFT.
func (d RawFullSlotDFT) CoeffsToSlotsOutputLevel() int { return d.ctsOutputLevel }

func validateRawDFTLevels(name string, logSlots, levelQ int, levels []int, params ckks.Parameters) (int, error) {
	if levelQ < 0 || levelQ > params.MaxLevel() {
		return 0, fmt.Errorf("homchain: raw %s LevelQ %d outside [0,%d]", name, levelQ, params.MaxLevel())
	}
	if len(levels) == 0 {
		return 0, fmt.Errorf("homchain: raw %s has no factorization levels", name)
	}
	sum := 0
	for i, depth := range levels {
		if depth <= 0 {
			return 0, fmt.Errorf("homchain: raw %s factorization level %d is %d, want positive", name, i, depth)
		}
		sum += depth
	}
	if sum > logSlots {
		return 0, fmt.Errorf("homchain: raw %s uses %d matrix factors, maximum is LogSlots=%d", name, sum, logSlots)
	}
	output := levelQ - sum*params.LevelsConsumedPerRescaling()
	if output < 0 {
		return 0, fmt.Errorf("homchain: raw %s output level %d is negative", name, output)
	}
	return output, nil
}

func cloneDFTLiteral(input ckksdft.MatrixLiteral) ckksdft.MatrixLiteral {
	result := input
	result.Levels = append([]int(nil), input.Levels...)
	if input.Scaling != nil {
		result.Scaling = new(big.Float).SetPrec(input.Scaling.Prec()).Set(input.Scaling)
	}
	return result
}

// newDFTMatrixFromLiteralAtPrecision mirrors Lattigo's DFT constructor while
// fixing the matrix-generator precision to the operational encoder precision.
// Keeping this adapter local avoids changing the semantics of unrelated
// vendored Lattigo callers.
func newDFTMatrixFromLiteralAtPrecision(params ckks.Parameters, literal ckksdft.MatrixLiteral, encoder *ckks.Encoder) (ckksdft.Matrix, string, error) {
	logDimensionsCols := literal.LogSlots
	if maxLogSlots := params.LogMaxDimensions().Cols; logDimensionsCols < maxLogSlots && literal.Format == ckksdft.RepackImagAsReal {
		logDimensionsCols++
	}

	generatorPrecision := encoder.Prec()
	plainMatrices := literal.GenMatrices(params.LogN(), generatorPrecision)
	sourceDigest := digestDFTMatrixNumericPayload(literal, plainMatrices)
	matrices := make([]ltcommon.LinearTransformation, 0, len(plainMatrices))
	nbModuliPerRescale := params.LevelsConsumedPerRescaling()
	level := literal.LevelQ
	index := 0
	for i := range literal.Levels {
		scale := rlwe.NewScale(params.Q()[level])
		for j := 1; j < nbModuliPerRescale; j++ {
			scale = scale.Mul(rlwe.NewScale(params.Q()[level-j]))
		}
		if literal.Levels[i] > 1 {
			inverseDepth := new(big.Float).SetPrec(scale.Value.Prec()).SetInt64(1)
			inverseDepth.Quo(inverseDepth, new(big.Float).SetPrec(scale.Value.Prec()).SetInt64(int64(literal.Levels[i])))
			scale.Value = *bignum.Pow(&scale.Value, inverseDepth)
		}
		for j := 0; j < literal.Levels[i]; j++ {
			parameters := ltcommon.Parameters{
				DiagonalsIndexList:        plainMatrices[index].DiagonalsIndexList(),
				LevelQ:                    literal.LevelQ,
				LevelP:                    literal.LevelP,
				Scale:                     scale,
				LogDimensions:             ring.Dimensions{Rows: 0, Cols: logDimensionsCols},
				LogBabyStepGiantStepRatio: literal.LogBSGSRatio,
			}
			matrix := ltcommon.NewTransformation(params, parameters)
			if err := ltcommon.Encode(encoder, plainMatrices[index], matrix); err != nil {
				return ckksdft.Matrix{}, "", fmt.Errorf("encode DFT factor %d: %w", index, err)
			}
			matrices = append(matrices, matrix)
			index++
		}
		level -= nbModuliPerRescale
	}
	if index != len(plainMatrices) {
		return ckksdft.Matrix{}, "", fmt.Errorf("encoded %d DFT factors, generated %d", index, len(plainMatrices))
	}
	return ckksdft.Matrix{MatrixLiteral: literal, Matrices: matrices}, sourceDigest, nil
}

// digestDFTMatrixNumericPayload deliberately excludes declared precision,
// big.Float precision/mode metadata, and encoder identity. A 53-vs-192 test
// using this witness can pass only when the generated numerical diagonals differ.
func digestDFTMatrixNumericPayload(literal ckksdft.MatrixLiteral, matrices []ltcommon.Diagonals[*bignum.Complex]) string {
	var canonical strings.Builder
	fmt.Fprintf(&canonical,
		"dft-matrix-numeric-payload-v1|type=%d|format=%d|log-slots=%d|level-q=%d|level-p=%d|levels=%v|bsgs=%d|bit-reversed=%t|",
		literal.Type, literal.Format, literal.LogSlots, literal.LevelQ, literal.LevelP,
		literal.Levels, literal.LogBSGSRatio, literal.BitReversed,
	)
	if literal.Scaling == nil {
		canonical.WriteString("scaling=nil|")
	} else {
		fmt.Fprintf(&canonical, "scaling=%s|", literal.Scaling.Text('x', -1))
	}
	for factorIndex, diagonals := range matrices {
		indexes := diagonals.DiagonalsIndexList()
		sort.Ints(indexes)
		fmt.Fprintf(&canonical, "factor=%d;", factorIndex)
		for _, diagonalIndex := range indexes {
			fmt.Fprintf(&canonical, "diag=%d:", diagonalIndex)
			for _, value := range diagonals[diagonalIndex] {
				fmt.Fprintf(&canonical, "%s,%s;", value.Real().Text('x', -1), value.Imag().Text('x', -1))
			}
		}
	}
	digest := sha256.Sum256([]byte(canonical.String()))
	return fmt.Sprintf("%x", digest)
}
