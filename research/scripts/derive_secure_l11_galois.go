// Command derive_secure_l11_galois prints the exact reduced-packing DFT,
// Trace and conjugation key union without generating any HE key or DFT matrix.
package main

import (
	"fmt"
	"sort"

	"github.com/nc26676027/LCPDTE/integer/securityparams"
	ckksdft "github.com/tuneinsight/lattigo/v6/circuits/ckks/dft"
)

func main() {
	params, err := securityparams.GaoCompatibleN16Parameters()
	if err != nil {
		panic(err)
	}
	for _, format := range []ckksdft.Format{ckksdft.SplitRealAndImag, ckksdft.RepackImagAsReal} {
		for _, ratio := range []int{0, 1, 2} {
			stc := ckksdft.MatrixLiteral{
				Type: ckksdft.HomomorphicDecode, Format: format, LogSlots: 11,
				LevelQ: 18, LevelP: 6, Levels: []int{1, 1}, LogBSGSRatio: ratio,
			}
			cts := ckksdft.MatrixLiteral{
				Type: ckksdft.HomomorphicEncode, Format: format, LogSlots: 11,
				LevelQ: 20, LevelP: 6, Levels: []int{1, 1, 1}, LogBSGSRatio: ratio,
			}
			groups := [][]uint64{
				stc.GaloisElements(params), cts.GaloisElements(params),
				params.GaloisElementsForTrace(11),
				{params.GaloisElementForComplexConjugation()},
			}
			union := uniqueSorted(groups...)
			fmt.Printf("format=%d ratio=%d stc=%d cts=%d trace=%d union=%d\n",
				format, ratio, len(uniqueSorted(groups[0])), len(uniqueSorted(groups[1])),
				len(uniqueSorted(groups[2])), len(union))
			if len(union) == 38 {
				fmt.Printf("stc elements=%v\n", uniqueSorted(groups[0]))
				fmt.Printf("cts elements=%v\n", uniqueSorted(groups[1]))
				fmt.Printf("trace elements=%v\n", uniqueSorted(groups[2]))
				fmt.Printf("conjugation=%v\n", groups[3])
				fmt.Printf("union elements=%v\n", union)
				fmt.Printf("union rotations=%v\n", rotationsForElements(params.N(), union))
			}
		}
	}
}

func uniqueSorted(groups ...[]uint64) []uint64 {
	set := map[uint64]struct{}{}
	for _, group := range groups {
		for _, element := range group {
			if element != 1 {
				set[element] = struct{}{}
			}
		}
	}
	result := make([]uint64, 0, len(set))
	for element := range set {
		result = append(result, element)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func rotationsForElements(ringDegree int, elements []uint64) []int {
	modulus := uint64(2 * ringDegree)
	rotationByElement := make(map[uint64]int, ringDegree/2)
	value := uint64(1)
	for rotation := 0; rotation < ringDegree/2; rotation++ {
		rotationByElement[value] = rotation
		value = value * 5 % modulus
	}
	result := make([]int, len(elements))
	for index, element := range elements {
		if rotation, ok := rotationByElement[element]; ok {
			result[index] = rotation
		} else {
			result[index] = -1 // conjugation is outside the rotation subgroup.
		}
	}
	return result
}
