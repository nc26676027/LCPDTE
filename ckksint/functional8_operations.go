package ckksint

import (
	"fmt"
	"math"

	"github.com/nc26676027/LCPDTE/integer/homchain"
	"github.com/nc26676027/LCPDTE/integer/treeplan"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
)

// A2B converts four arithmetic int8 words to encrypted LSB-first bits.
func (f *Functional8) A2B(input *EncryptedInt8) (*Boolean8, EvaluationInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.ownsInt(input, true); err != nil {
		return nil, EvaluationInfo{}, err
	}
	result, trace, err := f.a2bEvaluator.EvaluateNew(input.ciphertext)
	if err != nil {
		return nil, EvaluationInfo{}, fmt.Errorf("ckksint: functional8 A2B: %w", err)
	}
	return &Boolean8{low: result.LowMSB(), high: result.HighMSB(), owner: f.token}, EvaluationInfo{
		Operation: "A2B", ProfileDigest: trace.ProfileDigest(), StageCount: len(trace.States()),
	}, nil
}

// B2A converts encrypted bits back to four arithmetic int8 words.
func (f *Functional8) B2A(input *Boolean8) (*EncryptedInt8, EvaluationInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.ownsBoolean(input); err != nil {
		return nil, EvaluationInfo{}, err
	}
	low, err := f.b2aCircuit.BindLow(input.low)
	if err != nil {
		return nil, EvaluationInfo{}, fmt.Errorf("ckksint: bind B2A low half: %w", err)
	}
	high, err := f.b2aCircuit.BindHigh(input.high)
	if err != nil {
		return nil, EvaluationInfo{}, fmt.Errorf("ckksint: bind B2A high half: %w", err)
	}
	bound, err := f.b2aCircuit.BindInput(low, high)
	if err != nil {
		return nil, EvaluationInfo{}, fmt.Errorf("ckksint: bind B2A input: %w", err)
	}
	result, err := f.b2aEvaluator.EvaluateNew(bound)
	if err != nil {
		return nil, EvaluationInfo{}, fmt.Errorf("ckksint: functional8 B2A: %w", err)
	}
	provenance := result.Provenance()
	return &EncryptedInt8{
			ciphertext: result.Ciphertext(), owner: f.token, kind: functional8Converted,
		}, EvaluationInfo{
			Operation: "B2A", ProfileDigest: provenance.ProfileDigest(), StageCount: len(provenance.States()),
		}, nil
}

// CompareGEPublic returns encrypted selectors for input[lane] >= threshold[lane].
func (f *Functional8) CompareGEPublic(input *EncryptedInt8, thresholds [Functional8Lanes]int8) (*Selector8, EvaluationInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.ownsInt(input, true); err != nil {
		return nil, EvaluationInfo{}, err
	}
	if !input.comparisonAdmissible {
		return nil, EvaluationInfo{}, fmt.Errorf(
			"ckksint: comparison input was encrypted outside the certified feature range [%d,%d]",
			f.ranges.FeatureMin, f.ranges.FeatureMax,
		)
	}
	var public [Functional8Lanes]int64
	for lane, threshold := range thresholds {
		if threshold < f.ranges.ThresholdMin || threshold > f.ranges.ThresholdMax {
			return nil, EvaluationInfo{}, fmt.Errorf(
				"ckksint: threshold lane %d=%d lies outside certified [%d,%d]",
				lane, threshold, f.ranges.ThresholdMin, f.ranges.ThresholdMax,
			)
		}
		public[lane] = int64(threshold)
	}
	feature, err := f.comparatorCircuit.BindFeature(input.ciphertext, f.params)
	if err != nil {
		return nil, EvaluationInfo{}, fmt.Errorf("ckksint: bind comparison feature: %w", err)
	}
	result, trace, err := f.comparatorEvaluator.CompareGEPublicNew(feature, public)
	if err != nil {
		return nil, EvaluationInfo{}, fmt.Errorf("ckksint: signed8 public comparison: %w", err)
	}
	return &Selector8{ciphertext: result.Ciphertext(), owner: f.token}, EvaluationInfo{
		Operation: "CompareGEPublic", ProfileDigest: trace.ProfileDigest(),
		StageCount: len(trace.States()), WallTime: trace.WallTime(),
	}, nil
}

// EvaluateDepth2 evaluates a public depth-2 model with encrypted features. The
// circuit selects only the root-referenced child before the second comparison.
func (f *Functional8) EvaluateDepth2(features []*EncryptedInt8, model Depth2Model) (*EncryptedReal8, EvaluationInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.ready(); err != nil {
		return nil, EvaluationInfo{}, err
	}
	tree, err := f.depth2Tree(model)
	if err != nil {
		return nil, EvaluationInfo{}, err
	}
	ciphertexts := make([]*rlwe.Ciphertext, len(features))
	checked := make(map[int]bool, len(model.FeatureIDs))
	for node, featureID := range model.FeatureIDs {
		if featureID < 0 || featureID >= len(features) {
			return nil, EvaluationInfo{}, fmt.Errorf(
				"ckksint: depth2 node %d requires feature %d, got %d features", node, featureID, len(features),
			)
		}
		if checked[featureID] {
			continue
		}
		if err := f.ownsInt(features[featureID], true); err != nil {
			return nil, EvaluationInfo{}, fmt.Errorf("ckksint: depth2 feature %d: %w", featureID, err)
		}
		if !features[featureID].comparisonAdmissible {
			return nil, EvaluationInfo{}, fmt.Errorf(
				"ckksint: depth2 feature %d was encrypted outside certified range [%d,%d]",
				featureID, f.ranges.FeatureMin, f.ranges.FeatureMax,
			)
		}
		ciphertexts[featureID] = features[featureID].ciphertext
		checked[featureID] = true
	}
	circuit, err := homchain.NewSigned8Depth2SelectedChildCircuit(f.comparatorCircuit, tree)
	if err != nil {
		return nil, EvaluationInfo{}, fmt.Errorf("ckksint: construct depth2 selected-child circuit: %w", err)
	}
	evaluator, err := circuit.BindEvaluator(f.source)
	if err != nil {
		return nil, EvaluationInfo{}, fmt.Errorf("ckksint: bind depth2 selected-child evaluator: %w", err)
	}
	input, err := circuit.BindCiphertexts(ciphertexts, f.params)
	if err != nil {
		return nil, EvaluationInfo{}, fmt.Errorf("ckksint: bind depth2 features: %w", err)
	}
	result, trace, err := evaluator.EvaluatePublicNew(input)
	if err != nil {
		return nil, EvaluationInfo{}, fmt.Errorf("ckksint: evaluate depth2 selected child: %w", err)
	}
	return &EncryptedReal8{ciphertext: result.Ciphertext(), owner: f.token}, EvaluationInfo{
		Operation: "EvaluateDepth2", ProfileDigest: trace.ProfileDigest(), TraceDigest: trace.Digest(),
		StageCount: 5, WallTime: trace.WallTime(),
	}, nil
}

func (f *Functional8) depth2Tree(model Depth2Model) (treeplan.BinaryTree[int8, float64], error) {
	for node, threshold := range model.Thresholds {
		if threshold < f.ranges.ThresholdMin || threshold > f.ranges.ThresholdMax {
			return treeplan.BinaryTree[int8, float64]{}, fmt.Errorf(
				"ckksint: depth2 threshold %d=%d lies outside certified [%d,%d]",
				node, threshold, f.ranges.ThresholdMin, f.ranges.ThresholdMax,
			)
		}
	}
	for index, leaf := range model.Leaves {
		if math.IsNaN(leaf) || math.IsInf(leaf, 0) {
			return treeplan.BinaryTree[int8, float64]{}, fmt.Errorf("ckksint: depth2 leaf %d is not finite", index)
		}
	}
	tree := treeplan.BinaryTree[int8, float64]{
		Depth: 2,
		Splits: []treeplan.BinarySplit[int8]{
			{Feature: model.FeatureIDs[0], Threshold: model.Thresholds[0]},
			{Feature: model.FeatureIDs[1], Threshold: model.Thresholds[1]},
			{Feature: model.FeatureIDs[2], Threshold: model.Thresholds[2]},
		},
		Leaves: append([]float64(nil), model.Leaves[:]...),
	}
	if err := tree.Validate(); err != nil {
		return treeplan.BinaryTree[int8, float64]{}, fmt.Errorf("ckksint: invalid depth2 model: %w", err)
	}
	return tree, nil
}
