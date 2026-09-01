package secureeval

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"

	"github.com/nc26676027/LCPDTE/integer/homchain"
	"github.com/nc26676027/LCPDTE/integer/z2n"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

const (
	routeBSigned8Depth2SelectedChildModelSchema   = "lcpdte-route-b-signed8-depth2-selected-child-model-v1"
	routeBSigned8Depth2SelectedChildBindingSchema = "lcpdte-route-b-signed8-depth2-selected-child-feature-binding-v1"
	routeBSigned8Depth2SelectedChildMaxLeaf       = float64(1 << 20)
)

// RouteBSigned8Depth2SelectedChildModel is the immutable public depth-2
// binary tree. Node order is root/left/right and leaf order is 00/01/10/11.
type RouteBSigned8Depth2SelectedChildModel struct {
	featureIDs [3]uint32
	thresholds [3]int64
	leaves     [4]float64
	digest     string
}

func NewRouteBSigned8Depth2SelectedChildModel(
	featureIDs [3]uint32,
	thresholds [3]int64,
	leaves [4]float64,
) (RouteBSigned8Depth2SelectedChildModel, error) {
	for index, threshold := range thresholds {
		if threshold < -128 || threshold > 127 {
			return RouteBSigned8Depth2SelectedChildModel{}, lineagef(
				"selected-child threshold %d at node %d is outside [-128,127]", threshold, index,
			)
		}
	}
	for index, leaf := range leaves {
		if math.IsNaN(leaf) || math.IsInf(leaf, 0) || math.Abs(leaf) > routeBSigned8Depth2SelectedChildMaxLeaf {
			return RouteBSigned8Depth2SelectedChildModel{}, lineagef(
				"selected-child leaf %d is non-finite or exceeds the registered magnitude bound", index,
			)
		}
	}
	alpha, beta, gamma := routeBSigned8Depth2SelectedChildLeafCoefficients(leaves)
	for _, value := range []float64{alpha, beta, gamma} {
		if math.IsNaN(value) || math.IsInf(value, 0) || math.Abs(value) > 4*routeBSigned8Depth2SelectedChildMaxLeaf {
			return RouteBSigned8Depth2SelectedChildModel{}, lineagef("selected-child bilinear leaf coefficient exceeds its bound")
		}
	}
	model := RouteBSigned8Depth2SelectedChildModel{featureIDs: featureIDs, thresholds: thresholds, leaves: leaves}
	model.digest = digestRouteBSigned8Depth2SelectedChildModel(model)
	return model, nil
}

func (m RouteBSigned8Depth2SelectedChildModel) FeatureIDs() [3]uint32 { return m.featureIDs }
func (m RouteBSigned8Depth2SelectedChildModel) Thresholds() [3]int64  { return m.thresholds }
func (m RouteBSigned8Depth2SelectedChildModel) Leaves() [4]float64    { return m.leaves }
func (m RouteBSigned8Depth2SelectedChildModel) Digest() string        { return m.digest }

func validateRouteBSigned8Depth2SelectedChildModel(model RouteBSigned8Depth2SelectedChildModel) error {
	expected, err := NewRouteBSigned8Depth2SelectedChildModel(model.featureIDs, model.thresholds, model.leaves)
	if err != nil {
		return err
	}
	if model.digest == "" || model.digest != expected.digest || model.featureIDs != expected.featureIDs ||
		model.thresholds != expected.thresholds {
		return lineagef("selected-child model identity changed")
	}
	for index := range model.leaves {
		if math.Float64bits(model.leaves[index]) != math.Float64bits(expected.leaves[index]) {
			return lineagef("selected-child model leaf identity changed")
		}
	}
	return nil
}

func digestRouteBSigned8Depth2SelectedChildModel(model RouteBSigned8Depth2SelectedChildModel) string {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(routeBSigned8Depth2SelectedChildModelSchema + "\x00"))
	var record [8]byte
	for _, featureID := range model.featureIDs {
		binary.LittleEndian.PutUint32(record[:4], featureID)
		_, _ = hasher.Write(record[:4])
	}
	for _, threshold := range model.thresholds {
		binary.LittleEndian.PutUint64(record[:], uint64(threshold))
		_, _ = hasher.Write(record[:])
	}
	for _, leaf := range model.leaves {
		binary.LittleEndian.PutUint64(record[:], math.Float64bits(leaf))
		_, _ = hasher.Write(record[:])
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

type RouteBSigned8Depth2SelectedChildFeatures struct {
	features       [3]*rlwe.Ciphertext
	featureIDs     [3]uint32
	payloadDigests [3]string
	modelDigest    string
	digest         string
}

// BindRouteBSigned8Depth2SelectedChildFeatures derives the three node-role
// operands from the immutable model and takes defensive ciphertext copies.
func BindRouteBSigned8Depth2SelectedChildFeatures(
	model RouteBSigned8Depth2SelectedChildModel,
	featureVector map[uint32]*rlwe.Ciphertext,
) (RouteBSigned8Depth2SelectedChildFeatures, error) {
	if err := validateRouteBSigned8Depth2SelectedChildModel(model); err != nil {
		return RouteBSigned8Depth2SelectedChildFeatures{}, err
	}
	if featureVector == nil {
		return RouteBSigned8Depth2SelectedChildFeatures{}, lineagef("selected-child feature vector is nil")
	}
	params, err := canonicalRouteBSigned8RootTreeParameters()
	if err != nil {
		return RouteBSigned8Depth2SelectedChildFeatures{}, err
	}
	bound := RouteBSigned8Depth2SelectedChildFeatures{featureIDs: model.featureIDs, modelDigest: model.digest}
	for role, featureID := range model.featureIDs {
		value := featureVector[featureID]
		if err = requireRouteBSigned8Depth2SelectedChildFeatureState(fmt.Sprintf("feature %d", featureID), value, params); err != nil {
			return RouteBSigned8Depth2SelectedChildFeatures{}, err
		}
		bound.features[role] = value.CopyNew()
		if bound.payloadDigests[role], err = routeBSigned8RootTreeCiphertextDigest(bound.features[role]); err != nil {
			return RouteBSigned8Depth2SelectedChildFeatures{}, err
		}
	}
	bound.digest = digestRouteBSigned8Depth2SelectedChildFeatures(bound)
	return bound, nil
}

func validateRouteBSigned8Depth2SelectedChildFeatures(
	model RouteBSigned8Depth2SelectedChildModel,
	input RouteBSigned8Depth2SelectedChildFeatures,
) error {
	if err := validateRouteBSigned8Depth2SelectedChildModel(model); err != nil {
		return err
	}
	params, err := canonicalRouteBSigned8RootTreeParameters()
	if err != nil {
		return err
	}
	if input.modelDigest != model.digest || input.featureIDs != model.featureIDs || input.digest == "" {
		return lineagef("selected-child feature binding model identity changed")
	}
	for index, feature := range input.features {
		if err = requireRouteBSigned8Depth2SelectedChildFeatureState("bound feature", feature, params); err != nil {
			return err
		}
		digest, digestErr := routeBSigned8RootTreeCiphertextDigest(feature)
		if digestErr != nil || digest != input.payloadDigests[index] {
			return lineagef("selected-child bound feature payload changed")
		}
	}
	if input.digest != digestRouteBSigned8Depth2SelectedChildFeatures(input) {
		return lineagef("selected-child feature binding digest changed")
	}
	return nil
}

func requireRouteBSigned8Depth2SelectedChildFeatureState(name string, value *rlwe.Ciphertext, params ckks.Parameters) error {
	if value == nil || value.MetaData == nil || value.Level() != 20 || value.Degree() != 1 ||
		value.LogN() != 16 || value.LogDimensions != (ring.Dimensions{Rows: 0, Cols: 11}) ||
		!value.IsBatched || !value.IsNTT || !value.Scale.Equal(params.DefaultScale()) {
		return lineagef("selected-child %s is not canonical L20/degree1/N16/L11/default-scale", name)
	}
	return nil
}

func digestRouteBSigned8Depth2SelectedChildFeatures(input RouteBSigned8Depth2SelectedChildFeatures) string {
	hasher := sha256.New()
	_, _ = fmt.Fprintf(hasher, "%s|model=%s|ids=%v|payloads=%v",
		routeBSigned8Depth2SelectedChildBindingSchema, input.modelDigest, input.featureIDs, input.payloadDigests)
	return hex.EncodeToString(hasher.Sum(nil))
}

func validateRouteBSigned8Depth2SelectedChildRanges(
	ranges [3]homchain.Signed8NoOverflowRange,
	model RouteBSigned8Depth2SelectedChildModel,
) error {
	if err := validateRouteBSigned8Depth2SelectedChildModel(model); err != nil {
		return err
	}
	for index, admitted := range ranges {
		reconstructed, err := homchain.NewSigned8NoOverflowRange(
			admitted.XMinimum(), admitted.XMaximum(), admitted.ThresholdMinimum(), admitted.ThresholdMaximum(),
		)
		if err != nil {
			return fmt.Errorf("secureeval: reconstruct selected-child node %d range: %w", index, err)
		}
		if admitted.Digest() == "" || admitted.Digest() != reconstructed.Digest() ||
			admitted.WordBits() != z2n.Word8 || admitted.Signedness() != homchain.Signed8TwosComplement ||
			admitted.Predicate() != homchain.Signed8GreaterThanOrEqual ||
			admitted.ChildConvention() != homchain.Signed8ZeroLTOneGE ||
			admitted.ProofStatus() != homchain.Signed8InternallyDerivedEndpointInterval ||
			admitted.OverflowContract() != homchain.Signed8SameWidthSubtractionNoOverflow ||
			admitted.ThresholdMinimum() != model.thresholds[index] || admitted.ThresholdMaximum() != model.thresholds[index] {
			return lineagef("selected-child node %d range certificate changed", index)
		}
	}
	return nil
}

func routeBSigned8Depth2SelectedChildOracle(
	features map[uint32]int64,
	ranges [3]homchain.Signed8NoOverflowRange,
	model RouteBSigned8Depth2SelectedChildModel,
) (leaf float64, path, rootBranch, childBranch uint8, err error) {
	if err = validateRouteBSigned8Depth2SelectedChildRanges(ranges, model); err != nil {
		return
	}
	values := [3]int64{}
	for role, featureID := range model.featureIDs {
		value, present := features[featureID]
		if !present {
			err = lineagef("selected-child oracle feature %d is absent", featureID)
			return
		}
		if value < ranges[role].XMinimum() || value > ranges[role].XMaximum() {
			err = lineagef("selected-child oracle feature %d lies outside node %d range", featureID, role)
			return
		}
		values[role] = value
	}
	if values[0] >= model.thresholds[0] {
		rootBranch = 1
	}
	childRole := 1 + int(rootBranch)
	if values[childRole] >= model.thresholds[childRole] {
		childBranch = 1
	}
	path = 2*rootBranch + childBranch
	leaf = model.leaves[path]
	return
}

func routeBSigned8Depth2SelectedChildLeafCoefficients(leaves [4]float64) (alpha, beta, gamma float64) {
	alpha = leaves[2] - leaves[0]
	beta = leaves[1] - leaves[0]
	gamma = leaves[3] - leaves[2] - leaves[1] + leaves[0]
	return
}
