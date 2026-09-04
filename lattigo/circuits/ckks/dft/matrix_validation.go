// Modified by the LCPDTE project for local module integration and, where applicable,
// runtime instrumentation. See lattigo/NOTICE for attribution and modification details.

package dft

import (
	"fmt"
	"math/big"
	"slices"

	ltcommon "github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/lintrans"
	commonlintrans "github.com/nc26676027/LCPDTE/lattigo/circuits/common/lintrans"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
	"github.com/nc26676027/LCPDTE/lattigo/utils/bignum"
)

// ValidateAgainst performs pure structural validation against params and the
// exact expected literal. It never constructs numeric or encoded factors and
// therefore does not increment any DFT construction counter.
//
// A bare Matrix does not carry generator/encoder precision, a parameter-chain
// digest or the canonical encoded-payload digest. Those identities remain the
// responsibility of the observed artifact seal; this method intentionally
// makes no claim beyond literal, schedule, metadata, topology and Q/P/N shape.
func (m Matrix) ValidateAgainst(params ckks.Parameters, expected MatrixLiteral) error {
	if err := validateExpectedDFTMatrixLiteral(params, expected); err != nil {
		return err
	}
	if !equalDFTMatrixLiteral(m.MatrixLiteral, expected) {
		return fmt.Errorf("dft: Matrix literal differs from the expected literal")
	}
	factorCount := expected.Depth(false)
	if len(m.Matrices) != factorCount {
		return fmt.Errorf("dft: Matrix factor count is %d, want %d", len(m.Matrices), factorCount)
	}
	plan, err := newDFTMatrixValidationPlan(params, expected)
	if err != nil {
		return err
	}
	for factorIndex, transformation := range m.Matrices {
		if err := validateDFTMatrixTransformation(params, expected, factorIndex, transformation, plan); err != nil {
			return err
		}
	}
	return nil
}

type dftMatrixValidationPlan struct {
	topologies []map[int]bool
	scales     []rlwe.Scale
	logCols    int
	cols       int
}

func newDFTMatrixValidationPlan(params ckks.Parameters, expected MatrixLiteral) (dftMatrixValidationPlan, error) {
	factorCount := expected.Depth(false)
	topologies := expected.computeBootstrappingDFTIndexMap(params.LogN())
	if len(topologies) != factorCount {
		return dftMatrixValidationPlan{}, fmt.Errorf("dft: expected topology factor count is %d, want %d", len(topologies), factorCount)
	}
	scales, err := expectedDFTMatrixScales(params, expected)
	if err != nil {
		return dftMatrixValidationPlan{}, err
	}
	logCols := expected.LogSlots
	if expected.Format == RepackImagAsReal && logCols < params.LogMaxDimensions().Cols {
		logCols++
	}
	return dftMatrixValidationPlan{topologies: topologies, scales: scales, logCols: logCols, cols: 1 << logCols}, nil
}

func validateDFTMatrixTransformation(params ckks.Parameters, expected MatrixLiteral, factorIndex int, transformation ltcommon.LinearTransformation, plan dftMatrixValidationPlan) error {
	if factorIndex < 0 || factorIndex >= len(plan.topologies) || factorIndex >= len(plan.scales) {
		return fmt.Errorf("dft: factor index %d is outside the validation plan", factorIndex)
	}
	if transformation.MetaData == nil {
		return fmt.Errorf("dft: factor %d metadata is nil", factorIndex)
	}
	topologyKeys := make([]int, 0, len(plan.topologies[factorIndex]))
	for key := range plan.topologies[factorIndex] {
		topologyKeys = append(topologyKeys, key)
	}
	slices.Sort(topologyKeys)
	wantN1, wantVecKeys := expectedDFTMatrixVecKeys(topologyKeys, plan.cols, expected.LogBSGSRatio)
	gotVecKeys := make([]int, 0, len(transformation.Vec))
	for key := range transformation.Vec {
		gotVecKeys = append(gotVecKeys, key)
	}
	slices.Sort(gotVecKeys)
	if transformation.LevelQ != expected.LevelQ || transformation.LevelP != expected.LevelP ||
		transformation.LogBabyStepGiantStepRatio != expected.LogBSGSRatio || transformation.N1 != wantN1 ||
		!slices.Equal(gotVecKeys, wantVecKeys) {
		return fmt.Errorf("dft: factor %d level, BSGS or sorted Vec topology changed", factorIndex)
	}
	metadata := transformation.MetaData
	if metadata.LogDimensions.Rows != 0 || metadata.LogDimensions.Cols != plan.logCols ||
		!metadata.IsBatched || metadata.IsBitReversed || !metadata.IsNTT || !metadata.IsMontgomery ||
		!equalRLWEScaleExact(metadata.Scale, plan.scales[factorIndex]) {
		return fmt.Errorf("dft: factor %d scale, dimensions or flags changed", factorIndex)
	}
	for _, key := range gotVecKeys {
		poly := transformation.Vec[key]
		if err := validateDFTMatrixPolyShape(params, expected.LevelQ, expected.LevelP, poly.Q.Coeffs, poly.P.Coeffs, poly.BinarySize()); err != nil {
			return fmt.Errorf("dft: factor %d diagonal %d: %w", factorIndex, key, err)
		}
	}
	return nil
}

func validateExpectedDFTMatrixLiteral(params ckks.Parameters, literal MatrixLiteral) error {
	if literal.Type != HomomorphicEncode && literal.Type != HomomorphicDecode {
		return fmt.Errorf("dft: expected literal has invalid type %d", literal.Type)
	}
	if literal.Format < Standard || literal.Format > RepackImagAsReal {
		return fmt.Errorf("dft: expected literal has invalid format %d", literal.Format)
	}
	if literal.LogSlots <= 0 || literal.LogSlots > params.LogMaxDimensions().Cols {
		return fmt.Errorf("dft: expected literal LogSlots is out of range")
	}
	if literal.LevelQ < 0 || literal.LevelQ > params.MaxLevelQ() ||
		literal.LevelP < -1 || literal.LevelP > params.MaxLevelP() {
		return fmt.Errorf("dft: expected literal Q/P level is out of range")
	}
	if literal.Levels == nil || len(literal.Levels) == 0 {
		return fmt.Errorf("dft: expected literal Levels is nil or empty")
	}
	depth := 0
	for _, groupDepth := range literal.Levels {
		if groupDepth <= 0 || groupDepth > literal.LogSlots-depth {
			return fmt.Errorf("dft: expected literal contains an invalid level group")
		}
		depth += groupDepth
	}
	if depth == 0 {
		return fmt.Errorf("dft: expected literal factorization depth is invalid")
	}
	logCols := literal.LogSlots
	if literal.Format == RepackImagAsReal && logCols < params.LogMaxDimensions().Cols {
		logCols++
	}
	if literal.LogBSGSRatio > logCols {
		return fmt.Errorf("dft: expected literal BSGS ratio exceeds its dimensions")
	}
	if literal.Scaling != nil && (literal.Scaling.Prec() == 0 || literal.Scaling.Prec() > observedStreamingRequiredPrecision ||
		literal.Scaling.IsInf() || literal.Scaling.Mode() > big.ToPositiveInf) {
		return fmt.Errorf("dft: expected literal scaling is non-finite or outside 1..256 bits")
	}
	_, err := expectedDFTMatrixScales(params, literal)
	return err
}

func expectedDFTMatrixScales(params ckks.Parameters, literal MatrixLiteral) ([]rlwe.Scale, error) {
	consumed := params.LevelsConsumedPerRescaling()
	if consumed <= 0 {
		return nil, fmt.Errorf("dft: invalid levels-consumed-per-rescaling value %d", consumed)
	}
	level := literal.LevelQ
	result := make([]rlwe.Scale, 0, literal.Depth(false))
	for groupIndex, groupDepth := range literal.Levels {
		if level < 0 || level-consumed+1 < 0 || level > params.MaxLevelQ() {
			return nil, fmt.Errorf("dft: expected literal scale group %d exceeds the Q chain", groupIndex)
		}
		scale := rlwe.NewScale(params.Q()[level])
		for offset := 1; offset < consumed; offset++ {
			scale = scale.Mul(rlwe.NewScale(params.Q()[level-offset]))
		}
		if groupDepth > 1 {
			exponent := new(big.Float).SetPrec(scale.Value.Prec()).SetInt64(1)
			exponent.Quo(exponent, new(big.Float).SetPrec(scale.Value.Prec()).SetInt64(int64(groupDepth)))
			scale.Value = *bignum.Pow(&scale.Value, exponent)
		}
		for factor := 0; factor < groupDepth; factor++ {
			result = append(result, scale)
		}
		level -= consumed
	}
	return result, nil
}

func expectedDFTMatrixVecKeys(diagonalKeys []int, cols, logBSGSRatio int) (n1 int, keys []int) {
	if logBSGSRatio < 0 {
		keys = make([]int, len(diagonalKeys))
		for index, key := range diagonalKeys {
			keys[index] = key & (cols - 1)
		}
		slices.Sort(keys)
		return 0, slices.Compact(keys)
	}
	n1 = commonlintrans.FindBestBSGSRatio(diagonalKeys, cols, logBSGSRatio)
	index, _, _ := commonlintrans.BSGSIndex(diagonalKeys, cols, n1)
	seen := make(map[int]struct{}, len(diagonalKeys))
	for giantStep, babySteps := range index {
		for _, babyStep := range babySteps {
			seen[giantStep+babyStep] = struct{}{}
		}
	}
	keys = make([]int, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return n1, keys
}

func validateDFTMatrixPolyShape(params ckks.Parameters, levelQ, levelP int, q, p [][]uint64, binarySize int) error {
	if len(q) != levelQ+1 || len(p) != levelP+1 {
		return fmt.Errorf("Q/P limb count is %d/%d, want %d/%d", len(q), len(p), levelQ+1, levelP+1)
	}
	for index, coefficients := range q {
		if len(coefficients) != params.N() {
			return fmt.Errorf("Q limb %d coefficient count is %d, want %d", index, len(coefficients), params.N())
		}
	}
	for index, coefficients := range p {
		if len(coefficients) != params.N() {
			return fmt.Errorf("P limb %d coefficient count is %d, want %d", index, len(coefficients), params.N())
		}
	}
	wantRingSize := func(level int) int {
		if level < 0 {
			return 8
		}
		return 8 + (level+1)*(8+8*params.N())
	}
	if want := wantRingSize(levelQ) + wantRingSize(levelP); binarySize != want {
		return fmt.Errorf("binary size is %d, want %d", binarySize, want)
	}
	return nil
}

func equalDFTMatrixLiteral(left, right MatrixLiteral) bool {
	if left.Type != right.Type || left.LogSlots != right.LogSlots || left.LevelQ != right.LevelQ ||
		left.LevelP != right.LevelP || left.Format != right.Format || left.BitReversed != right.BitReversed ||
		left.LogBSGSRatio != right.LogBSGSRatio || (left.Levels == nil) != (right.Levels == nil) ||
		!slices.Equal(left.Levels, right.Levels) || !equalBigFloatExact(left.Scaling, right.Scaling) {
		return false
	}
	return true
}

func equalRLWEScaleExact(left, right rlwe.Scale) bool {
	if (left.Mod == nil) != (right.Mod == nil) || !equalBigFloatExact(&left.Value, &right.Value) {
		return false
	}
	return left.Mod == nil || left.Mod.Cmp(right.Mod) == 0
}

func equalBigFloatExact(left, right *big.Float) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Prec() == right.Prec() && left.Mode() == right.Mode() && left.Acc() == right.Acc() &&
		left.Signbit() == right.Signbit() && left.IsInf() == right.IsInf() && left.Cmp(right) == 0
}
