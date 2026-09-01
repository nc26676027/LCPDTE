// depth2 demonstrates the complete source-faithful selected-child tree path.
// It is an acceptance example, not a production-security configuration.
package main

import (
	"fmt"
	"log"

	"github.com/nc26676027/LCPDTE/ckksint"
)

func main() {
	engine, err := ckksint.NewDemoFunctional8(ckksint.Signed8Range{
		FeatureMin: -8, FeatureMax: 7,
		ThresholdMin: -8, ThresholdMax: 7,
	})
	check(err)

	plaintext := [3][4]int8{
		{-1, -1, 1, 1},
		{-5, -4, 0, 0},
		{0, 0, 2, 3},
	}
	features := make([]*ckksint.EncryptedInt8, len(plaintext))
	for index := range plaintext {
		features[index], err = engine.Encrypt(plaintext[index])
		check(err)
	}
	model := ckksint.Depth2Model{
		FeatureIDs: [3]int{0, 1, 2},
		Thresholds: [3]int8{0, -4, 3},
		Leaves:     [4]float64{-1.25, 2.5, -3.75, 5},
	}
	result, info, err := engine.EvaluateDepth2(features, model)
	check(err)
	decoded, err := engine.DecryptReal(result)
	check(err)

	fmt.Println("security boundary: DemoOnly (functional example; not secure)")
	fmt.Printf("depth-2 leaves: %v\n", decoded)
	fmt.Printf("profile=%s trace=%s wall=%s\n", info.ProfileDigest, info.TraceDigest, info.WallTime)
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
