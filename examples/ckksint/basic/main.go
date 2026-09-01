// basic demonstrates packed modular arithmetic through the supported ckksint
// facade. The parameter tuple is deliberately small and functional-only.
package main

import (
	"fmt"
	"log"

	"github.com/nc26676027/LCPDTE/ckksint"
)

func main() {
	ctx, err := ckksint.NewDemo(ckksint.DemoParameters{
		WordBits:   ckksint.Word8,
		Signedness: ckksint.Unsigned,
	})
	check(err)

	lhs, err := ctx.Encrypt([]uint64{250, 10, 3, 8})
	check(err)
	rhs, err := ctx.Encrypt([]uint64{10, 3, 7, 8})
	check(err)
	sum, err := ctx.Add(lhs, rhs)
	check(err)
	product, err := ctx.Mul(lhs, rhs)
	check(err)

	decodedSum, err := ctx.Decrypt(sum)
	check(err)
	decodedProduct, err := ctx.Decrypt(product)
	check(err)

	fmt.Println("security boundary: DemoOnly (functional example; not secure)")
	fmt.Printf("(lhs + rhs) mod 256 = %v\n", decodedSum)
	fmt.Printf("(lhs * rhs) mod 256 = %v\n", decodedProduct)
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
