package secureeval

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"

	"github.com/nc26676027/LCPDTE/integer/homchain"
	"github.com/nc26676027/LCPDTE/integer/z2n"
)

const (
	routeBSigned8Depth2NodeBatchModelSchema      = "lcpdte-route-b-signed8-depth2-node-batch-model-v1"
	routeBSigned8Depth2NodeBatchWords            = 512
	routeBSigned8Depth2NodeBatchSlots            = 2048
	routeBSigned8Depth2NodeBatchQueries          = 170
	routeBSigned8Depth2NodeBatchWordsPerQuery    = 3
	routeBSigned8Depth2NodeBatchPaddingWords     = 2
	routeBSigned8Depth2NodeBatchMaxLeafMagnitude = float64(1 << 20)
)

// RouteBSigned8Depth2NodeBatchModel is the immutable public model for the
// first secure-parameter depth-2 node-batched slice. Threshold order is
// root/left/right and leaf order is l00/l01/l10/l11.
type RouteBSigned8Depth2NodeBatchModel struct {
	thresholds [3]int64
	leaves     [4]float64
	digest     string
}

func NewRouteBSigned8Depth2NodeBatchModel(
	thresholds [3]int64,
	leaves [4]float64,
) (RouteBSigned8Depth2NodeBatchModel, error) {
	for index, threshold := range thresholds {
		if threshold < -128 || threshold > 127 {
			return RouteBSigned8Depth2NodeBatchModel{}, lineagef("signed8 depth-2 threshold %d at node %d is outside [-128,127]", threshold, index)
		}
	}
	for index, leaf := range leaves {
		if math.IsNaN(leaf) || math.IsInf(leaf, 0) || math.Abs(leaf) > routeBSigned8Depth2NodeBatchMaxLeafMagnitude {
			return RouteBSigned8Depth2NodeBatchModel{}, lineagef("signed8 depth-2 leaf %d is non-finite or exceeds the registered magnitude bound", index)
		}
	}
	for _, pair := range [][2]int{{1, 0}, {2, 0}, {3, 2}} {
		delta := leaves[pair[0]] - leaves[pair[1]]
		if math.IsNaN(delta) || math.IsInf(delta, 0) || math.Abs(delta) > 2*routeBSigned8Depth2NodeBatchMaxLeafMagnitude {
			return RouteBSigned8Depth2NodeBatchModel{}, lineagef("signed8 depth-2 leaf delta is non-finite or exceeds the registered magnitude bound")
		}
	}
	model := RouteBSigned8Depth2NodeBatchModel{thresholds: thresholds, leaves: leaves}
	model.digest = digestRouteBSigned8Depth2NodeBatchModel(model)
	return model, nil
}

func (model RouteBSigned8Depth2NodeBatchModel) Thresholds() [3]int64 { return model.thresholds }
func (model RouteBSigned8Depth2NodeBatchModel) Leaves() [4]float64   { return model.leaves }
func (model RouteBSigned8Depth2NodeBatchModel) Digest() string       { return model.digest }

func validateRouteBSigned8Depth2NodeBatchModel(model RouteBSigned8Depth2NodeBatchModel) error {
	expected, err := NewRouteBSigned8Depth2NodeBatchModel(model.thresholds, model.leaves)
	if err != nil {
		return err
	}
	if model.digest == "" || model.digest != expected.digest || model.thresholds != expected.thresholds {
		return lineagef("signed8 depth-2 node-batch model identity changed")
	}
	for index := range model.leaves {
		if math.Float64bits(model.leaves[index]) != math.Float64bits(expected.leaves[index]) {
			return lineagef("signed8 depth-2 node-batch leaf identity changed")
		}
	}
	return nil
}

func digestRouteBSigned8Depth2NodeBatchModel(model RouteBSigned8Depth2NodeBatchModel) string {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(routeBSigned8Depth2NodeBatchModelSchema + "\x00"))
	var record [8]byte
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

func validateRouteBSigned8Depth2NodeBatchInputs(
	ranges [3]homchain.Signed8NoOverflowRange,
	model RouteBSigned8Depth2NodeBatchModel,
) error {
	if err := validateRouteBSigned8Depth2NodeBatchModel(model); err != nil {
		return err
	}
	for index, admitted := range ranges {
		reconstructed, err := homchain.NewSigned8NoOverflowRange(
			admitted.XMinimum(), admitted.XMaximum(), admitted.ThresholdMinimum(), admitted.ThresholdMaximum(),
		)
		if err != nil {
			return fmt.Errorf("secureeval: reconstruct signed8 depth-2 node %d range: %w", index, err)
		}
		if admitted.Digest() == "" || admitted.Digest() != reconstructed.Digest() ||
			admitted.WordBits() != z2n.Word8 || admitted.Signedness() != homchain.Signed8TwosComplement ||
			admitted.Predicate() != homchain.Signed8GreaterThanOrEqual ||
			admitted.ChildConvention() != homchain.Signed8ZeroLTOneGE ||
			admitted.ProofStatus() != homchain.Signed8InternallyDerivedEndpointInterval ||
			admitted.OverflowContract() != homchain.Signed8SameWidthSubtractionNoOverflow ||
			admitted.DifferenceMinimum() != reconstructed.DifferenceMinimum() ||
			admitted.DifferenceMaximum() != reconstructed.DifferenceMaximum() {
			return lineagef("signed8 depth-2 node %d range certificate changed", index)
		}
		if admitted.ThresholdMinimum() != model.thresholds[index] || admitted.ThresholdMaximum() != model.thresholds[index] {
			return lineagef("signed8 depth-2 node %d threshold is not fixed by its range certificate", index)
		}
	}
	return nil
}

func routeBSigned8Depth2NodeBatchOracle(
	features [3]int64,
	ranges [3]homchain.Signed8NoOverflowRange,
	model RouteBSigned8Depth2NodeBatchModel,
) (leaf float64, path uint8, branches [3]uint8, err error) {
	if err = validateRouteBSigned8Depth2NodeBatchInputs(ranges, model); err != nil {
		return 0, 0, branches, err
	}
	for index, feature := range features {
		if feature < ranges[index].XMinimum() || feature > ranges[index].XMaximum() {
			return 0, 0, branches, lineagef("signed8 depth-2 feature %d at node %d lies outside the admitted interval", feature, index)
		}
		if feature >= model.thresholds[index] {
			branches[index] = 1
		}
	}
	path = 2 * branches[0]
	if branches[0] == 0 {
		path += branches[1]
	} else {
		path += branches[2]
	}
	return model.leaves[path], path, branches, nil
}

// routeBSigned8Depth2NodeBatchAlignOracle models role masking followed by
// Lattigo rotations +4 and +8: output[i] receives input[i+rotation].
func routeBSigned8Depth2NodeBatchAlignOracle(ge []float64) (root, left, right []float64, err error) {
	if len(ge) != routeBSigned8Depth2NodeBatchSlots {
		return nil, nil, nil, lineagef("signed8 depth-2 alignment input has %d slots, want %d", len(ge), routeBSigned8Depth2NodeBatchSlots)
	}
	root = make([]float64, len(ge))
	left = make([]float64, len(ge))
	right = make([]float64, len(ge))
	for query := 0; query < routeBSigned8Depth2NodeBatchQueries; query++ {
		rootWord := routeBSigned8Depth2NodeBatchWordsPerQuery * query
		for slot := 0; slot < 4; slot++ {
			target := 4*rootWord + slot
			root[target] = ge[target]
			left[target] = ge[target+4]
			right[target] = ge[target+8]
		}
	}
	return root, left, right, nil
}
