// conversion demonstrates the fixed four-lane A2B/B2A and signed comparison
// circuit. Its LogN=5 parameters are functional-only.
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

	words := [4]int8{-8, -1, 2, 7}
	encrypted, err := engine.Encrypt(words)
	check(err)
	bits, a2bInfo, err := engine.A2B(encrypted)
	check(err)
	decodedBits, err := engine.DecryptBits(bits)
	check(err)
	roundTrip, b2aInfo, err := engine.B2A(bits)
	check(err)
	decodedWords, err := engine.Decrypt(roundTrip)
	check(err)
	selectors, compareInfo, err := engine.CompareGEPublic(encrypted, [4]int8{-8, 0, 3, 6})
	check(err)
	decodedSelectors, err := engine.DecryptSelector(selectors)
	check(err)

	fmt.Println("security boundary: DemoOnly (functional example; not secure)")
	fmt.Printf("input:       %v\n", words)
	fmt.Printf("LSB bits:    %v\n", decodedBits)
	fmt.Printf("B2A result:  %v\n", decodedWords)
	fmt.Printf(">= selector: %v\n", decodedSelectors)
	fmt.Printf("profiles: A2B=%s B2A=%s compare=%s\n",
		a2bInfo.ProfileDigest, b2aInfo.ProfileDigest, compareInfo.ProfileDigest)
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
