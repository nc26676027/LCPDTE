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
	routeBSigned8RootTreeModelSchema      = "lcpdte-route-b-signed8-root-tree-model-v1"
	routeBSigned8RootTreeMaxLeafMagnitude = float64(1 << 20)
)

// RouteBSigned8RootTreeModel is the immutable public model for the first
// source-scheduled Route-B tree slice.
type RouteBSigned8RootTreeModel struct {
	threshold int64
	leftLeaf  float64
	rightLeaf float64
	digest    string
}

// NewRouteBSigned8RootTreeModel admits one signed-int8 public threshold and
// two bounded finite real leaves.
func NewRouteBSigned8RootTreeModel(threshold int64, leftLeaf, rightLeaf float64) (RouteBSigned8RootTreeModel, error) {
	if threshold < -128 || threshold > 127 {
		return RouteBSigned8RootTreeModel{}, lineagef("signed8 root threshold %d is outside [-128,127]", threshold)
	}
	for name, value := range map[string]float64{"left": leftLeaf, "right": rightLeaf} {
		if math.IsNaN(value) || math.IsInf(value, 0) || math.Abs(value) > routeBSigned8RootTreeMaxLeafMagnitude {
			return RouteBSigned8RootTreeModel{}, lineagef("signed8 root %s leaf is non-finite or exceeds the registered magnitude bound", name)
		}
	}
	delta := rightLeaf - leftLeaf
	if math.IsNaN(delta) || math.IsInf(delta, 0) || math.Abs(delta) > 2*routeBSigned8RootTreeMaxLeafMagnitude {
		return RouteBSigned8RootTreeModel{}, lineagef("signed8 root leaf delta is non-finite or exceeds the registered magnitude bound")
	}
	model := RouteBSigned8RootTreeModel{threshold: threshold, leftLeaf: leftLeaf, rightLeaf: rightLeaf}
	model.digest = digestRouteBSigned8RootTreeModel(model)
	return model, nil
}

func (model RouteBSigned8RootTreeModel) Threshold() int64  { return model.threshold }
func (model RouteBSigned8RootTreeModel) LeftLeaf() float64 { return model.leftLeaf }
func (model RouteBSigned8RootTreeModel) RightLeaf() float64 {
	return model.rightLeaf
}
func (model RouteBSigned8RootTreeModel) Digest() string { return model.digest }

func validateRouteBSigned8RootTreeModel(model RouteBSigned8RootTreeModel) error {
	expected, err := NewRouteBSigned8RootTreeModel(model.threshold, model.leftLeaf, model.rightLeaf)
	if err != nil {
		return err
	}
	if model.digest == "" || model.digest != expected.digest ||
		math.Float64bits(model.leftLeaf) != math.Float64bits(expected.leftLeaf) ||
		math.Float64bits(model.rightLeaf) != math.Float64bits(expected.rightLeaf) {
		return lineagef("signed8 root model identity changed")
	}
	return nil
}

func digestRouteBSigned8RootTreeModel(model RouteBSigned8RootTreeModel) string {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(routeBSigned8RootTreeModelSchema + "\x00"))
	var record [24]byte
	binary.LittleEndian.PutUint64(record[0:8], uint64(model.threshold))
	binary.LittleEndian.PutUint64(record[8:16], math.Float64bits(model.leftLeaf))
	binary.LittleEndian.PutUint64(record[16:24], math.Float64bits(model.rightLeaf))
	_, _ = hasher.Write(record[:])
	return hex.EncodeToString(hasher.Sum(nil))
}

func validateRouteBSigned8RootTreeInputs(ranges homchain.Signed8NoOverflowRange, model RouteBSigned8RootTreeModel) error {
	if err := validateRouteBSigned8RootTreeModel(model); err != nil {
		return err
	}
	reconstructed, err := homchain.NewSigned8NoOverflowRange(
		ranges.XMinimum(), ranges.XMaximum(), ranges.ThresholdMinimum(), ranges.ThresholdMaximum(),
	)
	if err != nil {
		return fmt.Errorf("secureeval: reconstruct signed8 root no-overflow range: %w", err)
	}
	if ranges.Digest() == "" || ranges.Digest() != reconstructed.Digest() ||
		ranges.WordBits() != z2n.Word8 || ranges.Signedness() != homchain.Signed8TwosComplement ||
		ranges.Predicate() != homchain.Signed8GreaterThanOrEqual ||
		ranges.ChildConvention() != homchain.Signed8ZeroLTOneGE ||
		ranges.ProofStatus() != homchain.Signed8InternallyDerivedEndpointInterval ||
		ranges.OverflowContract() != homchain.Signed8SameWidthSubtractionNoOverflow ||
		ranges.DifferenceMinimum() != reconstructed.DifferenceMinimum() ||
		ranges.DifferenceMaximum() != reconstructed.DifferenceMaximum() {
		return lineagef("signed8 root range certificate changed")
	}
	if ranges.ThresholdMinimum() != model.threshold || ranges.ThresholdMaximum() != model.threshold {
		return lineagef("signed8 root public threshold is not the single value fixed by the range certificate")
	}
	return nil
}

func routeBSigned8RootTreeOracle(
	value int64,
	ranges homchain.Signed8NoOverflowRange,
	model RouteBSigned8RootTreeModel,
) (leaf float64, branch int, err error) {
	if err = validateRouteBSigned8RootTreeInputs(ranges, model); err != nil {
		return 0, 0, err
	}
	if value < ranges.XMinimum() || value > ranges.XMaximum() {
		return 0, 0, lineagef("signed8 root oracle input %d lies outside the admitted feature interval", value)
	}
	if value >= model.threshold {
		return model.rightLeaf, 1, nil
	}
	return model.leftLeaf, 0, nil
}

func routeBSigned8BroadcastOracle(input [4]float64) [4]float64 {
	return [4]float64{input[3], input[3], input[3], input[3]}
}
