package secureeval

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math"

	"dt_go/integer/homchain"
)

const (
	routeBSigned8Radix4ModelSchema         = "lcpdte-route-b-signed8-radix4-model-v1"
	routeBSigned8Radix4InputSchema         = "lcpdte-route-b-signed8-radix4-input-v1"
	routeBSigned8Radix4Words               = 512
	routeBSigned8Radix4Slots               = 2048
	routeBSigned8Radix4Queries             = 170
	routeBSigned8Radix4WordsPerQuery       = 3
	routeBSigned8Radix4PaddingWords        = 2
	routeBSigned8Radix4ExpectedInputDigest = "d7d9335e7d4f74921b835191dddf3fc7c62b4af59721d5c6287456ff9c1775f7"
	routeBSigned8Radix4ExpectedModelDigest = "7f10d686835d5e1c351a6641956cf259e8f23d445e7b5e819e93822064ab9c2d"
	routeBSigned8Radix4ExpectedProofDigest = "8b0f5a894f5dee94afd061395a4b70282f628e751b7ddaaea7b0e7259dbd937e"
)

type RouteBSigned8Radix4Model struct {
	thresholds [3]int64
	leaves     [4]float64
	digest     string
}

func NewRouteBSigned8Radix4Model(thresholds [3]int64, leaves [4]float64) (RouteBSigned8Radix4Model, error) {
	for index, threshold := range thresholds {
		if threshold < -128 || threshold > 127 {
			return RouteBSigned8Radix4Model{}, lineagef("signed8 radix-4 threshold %d at index %d is outside [-128,127]", threshold, index)
		}
		if index > 0 && thresholds[index-1] >= threshold {
			return RouteBSigned8Radix4Model{}, lineagef("signed8 radix-4 thresholds are not strictly increasing")
		}
	}
	for index, leaf := range leaves {
		if math.IsNaN(leaf) || math.IsInf(leaf, 0) || math.Abs(leaf) > routeBSigned8Depth2NodeBatchMaxLeafMagnitude {
			return RouteBSigned8Radix4Model{}, lineagef("signed8 radix-4 leaf %d is non-finite or exceeds the magnitude bound", index)
		}
		if index > 0 {
			delta := leaf - leaves[index-1]
			if math.IsNaN(delta) || math.IsInf(delta, 0) || math.Abs(delta) > 2*routeBSigned8Depth2NodeBatchMaxLeafMagnitude {
				return RouteBSigned8Radix4Model{}, lineagef("signed8 radix-4 leaf delta is non-finite or exceeds the magnitude bound")
			}
		}
	}
	model := RouteBSigned8Radix4Model{thresholds: thresholds, leaves: leaves}
	model.digest = digestRouteBSigned8Radix4Model(model)
	return model, nil
}

func (model RouteBSigned8Radix4Model) Thresholds() [3]int64 { return model.thresholds }
func (model RouteBSigned8Radix4Model) Leaves() [4]float64   { return model.leaves }
func (model RouteBSigned8Radix4Model) Digest() string       { return model.digest }

func validateRouteBSigned8Radix4Model(model RouteBSigned8Radix4Model) error {
	expected, err := NewRouteBSigned8Radix4Model(model.thresholds, model.leaves)
	if err != nil {
		return err
	}
	if model.digest == "" || model.digest != expected.digest || model.thresholds != expected.thresholds {
		return lineagef("signed8 radix-4 model identity changed")
	}
	for index := range model.leaves {
		if math.Float64bits(model.leaves[index]) != math.Float64bits(expected.leaves[index]) {
			return lineagef("signed8 radix-4 leaf identity changed")
		}
	}
	return nil
}

func digestRouteBSigned8Radix4Model(model RouteBSigned8Radix4Model) string {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(routeBSigned8Radix4ModelSchema + "\x00"))
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

func validateRouteBSigned8Radix4Inputs(ranges [3]homchain.Signed8NoOverflowRange, model RouteBSigned8Radix4Model) error {
	if err := validateRouteBSigned8Radix4Model(model); err != nil {
		return err
	}
	for index, admitted := range ranges {
		reconstructed, err := homchain.NewSigned8NoOverflowRange(
			admitted.XMinimum(), admitted.XMaximum(), admitted.ThresholdMinimum(), admitted.ThresholdMaximum(),
		)
		if err != nil {
			return err
		}
		if admitted.Digest() == "" || admitted.Digest() != reconstructed.Digest() ||
			admitted.ThresholdMinimum() != model.thresholds[index] || admitted.ThresholdMaximum() != model.thresholds[index] ||
			admitted.XMinimum() != -96 || admitted.XMaximum() != 95 {
			return lineagef("signed8 radix-4 range %d differs from the fixed model/domain certificate", index)
		}
	}
	return nil
}

func routeBSigned8Radix4Oracle(
	feature int64,
	ranges [3]homchain.Signed8NoOverflowRange,
	model RouteBSigned8Radix4Model,
) (leaf float64, path uint8, predicates [3]uint8, err error) {
	if err = validateRouteBSigned8Radix4Inputs(ranges, model); err != nil {
		return 0, 0, predicates, err
	}
	if feature < -96 || feature > 95 {
		return 0, 0, predicates, lineagef("signed8 radix-4 feature lies outside [-96,95]")
	}
	for index, threshold := range model.thresholds {
		if feature >= threshold {
			predicates[index] = 1
			path++
		}
	}
	if predicates[0] < predicates[1] || predicates[1] < predicates[2] || path > 3 {
		return 0, 0, predicates, lineagef("signed8 radix-4 unary predicate code is invalid")
	}
	return model.leaves[path], path, predicates, nil
}

func routeBSigned8Radix4CanonicalModelsAndRanges() (
	model RouteBSigned8Radix4Model,
	ranges [3]homchain.Signed8NoOverflowRange,
	binaryModel RouteBSigned8Depth2NodeBatchModel,
	binaryRanges [3]homchain.Signed8NoOverflowRange,
	err error,
) {
	model, err = NewRouteBSigned8Radix4Model([3]int64{-32, 0, 32}, [4]float64{-3.25, -0.75, 2.5, 5.125})
	if err != nil {
		return
	}
	for index, threshold := range model.thresholds {
		ranges[index], err = homchain.NewSigned8NoOverflowRange(-96, 95, threshold, threshold)
		if err != nil {
			return
		}
	}
	binaryModel, err = NewRouteBSigned8Depth2NodeBatchModel(
		[3]int64{model.thresholds[1], model.thresholds[0], model.thresholds[2]}, model.leaves,
	)
	if err != nil {
		return
	}
	binaryRanges = [3]homchain.Signed8NoOverflowRange{ranges[1], ranges[0], ranges[2]}
	return
}

func routeBSigned8Radix4InputValues() []int64 {
	values := make([]int64, routeBSigned8Radix4Queries)
	for index := range values {
		values[index] = -96 + int64((37*index)%192)
	}
	copy(values, []int64{-96, -32, -31, -1, 0, 1, 31, 32, 33, 95})
	return values
}

func routeBSigned8Radix4InputWords() []int64 {
	words := make([]int64, 0, routeBSigned8Radix4Words)
	for _, value := range routeBSigned8Radix4InputValues() {
		words = append(words, value, value, value)
	}
	for len(words) < routeBSigned8Radix4Words {
		words = append(words, 0)
	}
	return words
}

func routeBSigned8Radix4InputPatternDigest() string {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(routeBSigned8Radix4InputSchema + "\x00"))
	var record [16]byte
	for index, value := range routeBSigned8Radix4InputWords() {
		binary.LittleEndian.PutUint64(record[0:8], uint64(index))
		binary.LittleEndian.PutUint64(record[8:16], uint64(value))
		_, _ = hasher.Write(record[:])
	}
	return hex.EncodeToString(hasher.Sum(nil))
}
