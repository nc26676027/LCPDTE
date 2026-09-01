package treecompile

import (
	"fmt"
	"math"

	"github.com/nc26676027/LCPDTE/integer/treeplan"
	"github.com/nc26676027/LCPDTE/treeio"
)

type BaseScoreEncoding string

const (
	// BaseScoreProbability means the serialized base score is a probability and
	// is converted to a raw margin with logit(p).
	BaseScoreProbability BaseScoreEncoding = "probability_logit"
	// BaseScoreRawMargin means the serialized value is already an additive margin.
	BaseScoreRawMargin BaseScoreEncoding = "raw_margin"
)

type OutputTransform string

const (
	OutputRawMargin           OutputTransform = "raw_margin"
	OutputLogisticProbability OutputTransform = "logistic_probability"
)

// ModelSemantics is required because treeio.RawModel currently discards the
// XGBoost objective. The compiler therefore refuses to guess how BaseScore or
// the final tree sum should be interpreted.
type ModelSemantics struct {
	BaseScore BaseScoreEncoding `json:"base_score_encoding"`
	Output    OutputTransform   `json:"output_transform"`
}

// Forest is a complete, common-depth numeric forest. Trees remain in source
// order, which fixes deterministic accumulation order for the plaintext oracle.
type Forest struct {
	NumFeatures     int                                     `json:"num_features"`
	Depth           int                                     `json:"depth"`
	SourceBaseScore float64                                 `json:"source_base_score"`
	BaseMargin      float64                                 `json:"base_margin"`
	Semantics       ModelSemantics                          `json:"semantics"`
	Trees           []treeplan.BinaryTree[float32, float64] `json:"trees"`
}

// CompileModel validates single-output aggregation, computes a common maximum
// depth, and pads every source tree to that depth.
func CompileModel(raw treeio.RawModel, semantics ModelSemantics) (Forest, error) {
	if raw.NumFeature < 0 {
		return Forest{}, fmt.Errorf("%w: negative feature count %d", ErrMalformedTree, raw.NumFeature)
	}
	if semantics.BaseScore != BaseScoreProbability && semantics.BaseScore != BaseScoreRawMargin {
		return Forest{}, fmt.Errorf("%w: unknown base-score encoding %q", ErrModelSemantics, semantics.BaseScore)
	}
	if semantics.Output != OutputRawMargin && semantics.Output != OutputLogisticProbability {
		return Forest{}, fmt.Errorf("%w: unknown output transform %q", ErrModelSemantics, semantics.Output)
	}
	if raw.NumOutputGroup < 0 || raw.NumOutputGroup > 1 {
		return Forest{}, fmt.Errorf("%w: num_output_group=%d", ErrOutputGroup, raw.NumOutputGroup)
	}
	if len(raw.TreeInfo) != 0 && len(raw.TreeInfo) != len(raw.Trees) {
		return Forest{}, fmt.Errorf("%w: tree_info length=%d, tree count=%d", ErrOutputGroup, len(raw.TreeInfo), len(raw.Trees))
	}
	for i, group := range raw.TreeInfo {
		if group != 0 {
			return Forest{}, fmt.Errorf("%w: tree %d belongs to output group %d", ErrOutputGroup, i, group)
		}
	}

	baseMargin := raw.BaseScore
	switch semantics.BaseScore {
	case BaseScoreProbability:
		if !(raw.BaseScore > 0 && raw.BaseScore < 1) || math.IsNaN(raw.BaseScore) {
			return Forest{}, fmt.Errorf("%w: probability base score must be in (0,1), got %g", ErrModelSemantics, raw.BaseScore)
		}
		baseMargin = math.Log(raw.BaseScore / (1 - raw.BaseScore))
	case BaseScoreRawMargin:
		if math.IsNaN(raw.BaseScore) || math.IsInf(raw.BaseScore, 0) {
			return Forest{}, fmt.Errorf("%w: raw base margin is non-finite", ErrModelSemantics)
		}
	}

	commonDepth := 0
	for i, rawTree := range raw.Trees {
		analysis, err := analyzeRawTree(rawTree, raw.NumFeature)
		if err != nil {
			return Forest{}, fmt.Errorf("tree %d: %w", i, err)
		}
		if analysis.maxDepth > commonDepth {
			commonDepth = analysis.maxDepth
		}
	}

	forest := Forest{
		NumFeatures:     raw.NumFeature,
		Depth:           commonDepth,
		SourceBaseScore: raw.BaseScore,
		BaseMargin:      baseMargin,
		Semantics:       semantics,
		Trees:           make([]treeplan.BinaryTree[float32, float64], len(raw.Trees)),
	}
	for i, rawTree := range raw.Trees {
		compiled, err := CompileTreeAtDepth(rawTree, raw.NumFeature, commonDepth)
		if err != nil {
			return Forest{}, fmt.Errorf("tree %d: %w", i, err)
		}
		forest.Trees[i] = compiled
	}
	return forest, nil
}

// Validate checks the exported forest snapshot before evaluation. This catches
// non-finite or structurally inconsistent mutations after CompileModel.
func (f Forest) Validate() error {
	if f.NumFeatures < 0 {
		return fmt.Errorf("%w: negative feature count %d", ErrMalformedTree, f.NumFeatures)
	}
	if f.Depth < 0 || f.Depth > MaxMaterializedDepth {
		return fmt.Errorf("%w: invalid common depth %d", ErrMalformedTree, f.Depth)
	}
	if math.IsNaN(f.SourceBaseScore) || math.IsInf(f.SourceBaseScore, 0) {
		return fmt.Errorf("%w: source base score is non-finite", ErrNonFiniteValue)
	}
	if math.IsNaN(f.BaseMargin) || math.IsInf(f.BaseMargin, 0) {
		return fmt.Errorf("%w: base margin is non-finite", ErrNonFiniteValue)
	}
	if f.Semantics.BaseScore != BaseScoreProbability && f.Semantics.BaseScore != BaseScoreRawMargin {
		return fmt.Errorf("%w: unknown base-score encoding %q", ErrModelSemantics, f.Semantics.BaseScore)
	}
	if f.Semantics.Output != OutputRawMargin && f.Semantics.Output != OutputLogisticProbability {
		return fmt.Errorf("%w: unknown output transform %q", ErrModelSemantics, f.Semantics.Output)
	}
	for i, tree := range f.Trees {
		if tree.Depth != f.Depth {
			return fmt.Errorf("%w: tree %d depth=%d, common depth=%d", ErrMalformedTree, i, tree.Depth, f.Depth)
		}
		if err := tree.Validate(); err != nil {
			return fmt.Errorf("%w: tree %d: %v", ErrMalformedTree, i, err)
		}
		for j, split := range tree.Splits {
			if split.Feature >= f.NumFeatures {
				return fmt.Errorf("%w: tree %d split %d feature=%d, feature count=%d", ErrMalformedTree, i, j, split.Feature, f.NumFeatures)
			}
		}
	}
	return nil
}

func (f Forest) validateFeatures(features []float32) error {
	if len(features) != f.NumFeatures {
		return fmt.Errorf("feature count=%d, want %d", len(features), f.NumFeatures)
	}
	for i, value := range features {
		if math.IsNaN(float64(value)) {
			return fmt.Errorf("%w: feature %d", ErrMissingValue, i)
		}
		if math.IsInf(float64(value), 0) {
			return fmt.Errorf("%w: feature %d", ErrNonFiniteValue, i)
		}
	}
	return nil
}

// RawMargin is the independent float64 plaintext oracle used by CKKS-facing
// code. It adds the converted base margin and leaf values in source tree order.
func (f Forest) RawMargin(features []float32) (float64, error) {
	if err := f.Validate(); err != nil {
		return 0, err
	}
	if err := f.validateFeatures(features); err != nil {
		return 0, err
	}
	sum := f.BaseMargin
	for i, tree := range f.Trees {
		leaf, err := tree.Evaluate(features)
		if err != nil {
			return 0, fmt.Errorf("tree %d: %w", i, err)
		}
		sum += leaf
		if math.IsNaN(sum) || math.IsInf(sum, 0) {
			return 0, fmt.Errorf("%w: float64 margin became non-finite after tree %d", ErrNonFiniteValue, i)
		}
	}
	return sum, nil
}

// RawMarginFloat32 mirrors the repository's XGBoost fixture oracle: the base
// margin and each float32-stored leaf are accumulated sequentially in float32.
// It exists for bit-level regression against pred_*.bin; HE accuracy should be
// assessed against RawMargin's float64 value with a declared tolerance.
func (f Forest) RawMarginFloat32(features []float32) (float32, error) {
	if err := f.Validate(); err != nil {
		return 0, err
	}
	if err := f.validateFeatures(features); err != nil {
		return 0, err
	}
	sum := float32(f.BaseMargin)
	if math.IsNaN(float64(sum)) || math.IsInf(float64(sum), 0) {
		return 0, fmt.Errorf("%w: base margin is not representable as finite float32", ErrNonFiniteValue)
	}
	for i, tree := range f.Trees {
		leaf, err := tree.Evaluate(features)
		if err != nil {
			return 0, fmt.Errorf("tree %d: %w", i, err)
		}
		sum += float32(leaf)
		if math.IsNaN(float64(sum)) || math.IsInf(float64(sum), 0) {
			return 0, fmt.Errorf("%w: float32 margin became non-finite after tree %d", ErrNonFiniteValue, i)
		}
	}
	return sum, nil
}

// Predict applies the explicitly registered output transform.
func (f Forest) Predict(features []float32) (float64, error) {
	margin, err := f.RawMargin(features)
	if err != nil {
		return 0, err
	}
	switch f.Semantics.Output {
	case OutputRawMargin:
		return margin, nil
	case OutputLogisticProbability:
		return Sigmoid(margin), nil
	default:
		return 0, fmt.Errorf("%w: unknown output transform %q", ErrModelSemantics, f.Semantics.Output)
	}
}

// PredictRows evaluates row-major input without importing the encryption path.
func (f Forest) PredictRows(input treeio.RawInput) ([]float64, error) {
	if input.N < 0 || input.F != f.NumFeatures || len(input.X) != input.N*input.F {
		return nil, fmt.Errorf("input shape N=%d F=%d len=%d, want F=%d and len=N*F", input.N, input.F, len(input.X), f.NumFeatures)
	}
	out := make([]float64, input.N)
	for row := 0; row < input.N; row++ {
		value, err := f.Predict(input.X[row*input.F : (row+1)*input.F])
		if err != nil {
			return nil, fmt.Errorf("row %d: %w", row, err)
		}
		out[row] = value
	}
	return out, nil
}

// Sigmoid is numerically stable for both positive and negative raw margins.
func Sigmoid(margin float64) float64 {
	if margin >= 0 {
		return 1 / (1 + math.Exp(-margin))
	}
	e := math.Exp(margin)
	return e / (1 + e)
}
