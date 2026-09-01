package ckksint_test

import (
	"reflect"
	"testing"

	"github.com/nc26676027/LCPDTE/ckksint"
)

func TestDemoContextArithmeticThroughPublicAPI(t *testing.T) {
	ctx, err := ckksint.NewDemo(ckksint.DemoParameters{
		WordBits:   ckksint.Word8,
		Signedness: ckksint.Unsigned,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := ctx.Parameters().SecurityBoundary; got != ckksint.DemoOnly {
		t.Fatalf("security boundary = %v, want DemoOnly", got)
	}

	lhs, err := ctx.Encrypt([]uint64{250, 10, 3, 8})
	if err != nil {
		t.Fatal(err)
	}
	rhs, err := ctx.Encrypt([]uint64{10, 3, 7, 8})
	if err != nil {
		t.Fatal(err)
	}

	sum, err := ctx.Add(lhs, rhs)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ctx.Decrypt(sum); err != nil {
		t.Fatal(err)
	} else if want := []uint64{4, 13, 10, 16}; !reflect.DeepEqual(got, want) {
		t.Fatalf("sum = %v, want %v", got, want)
	}

	difference, err := ctx.Sub(lhs, rhs)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ctx.Decrypt(difference); err != nil {
		t.Fatal(err)
	} else if want := []uint64{240, 7, 252, 0}; !reflect.DeepEqual(got, want) {
		t.Fatalf("difference = %v, want %v", got, want)
	}

	product, err := ctx.Mul(lhs, rhs)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ctx.Decrypt(product); err != nil {
		t.Fatal(err)
	} else if want := []uint64{196, 30, 21, 64}; !reflect.DeepEqual(got, want) {
		t.Fatalf("product = %v, want %v", got, want)
	}
}

func TestContextRejectsValuesFromAnotherContext(t *testing.T) {
	parameters := ckksint.DemoParameters{WordBits: ckksint.Word8, Signedness: ckksint.Unsigned}
	first, err := ckksint.NewDemo(parameters)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ckksint.NewDemo(parameters)
	if err != nil {
		t.Fatal(err)
	}
	left, err := first.Encrypt([]uint64{1})
	if err != nil {
		t.Fatal(err)
	}
	right, err := second.Encrypt([]uint64{1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = first.Add(left, right); err == nil {
		t.Fatal("cross-context operands were accepted")
	}
}

func TestSignedShortAndLattigoInteropThroughPublicAPI(t *testing.T) {
	ctx, err := ckksint.NewDemo(ckksint.DemoParameters{
		WordBits:   ckksint.Word8,
		Signedness: ckksint.TwosComplement,
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := ctx.EncryptSigned([]int64{-128, -1, 0, 127})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ctx.DecryptSigned(signed); err != nil {
		t.Fatal(err)
	} else if want := []int64{-128, -1, 0, 127}; !reflect.DeepEqual(got, want) {
		t.Fatalf("signed round trip = %v, want %v", got, want)
	}

	detached := signed.LattigoCiphertext()
	imported, err := ctx.ImportCiphertext(detached, signed.WordCount())
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ctx.DecryptSigned(imported); err != nil {
		t.Fatal(err)
	} else if want := []int64{-128, -1, 0, 127}; !reflect.DeepEqual(got, want) {
		t.Fatalf("imported round trip = %v, want %v", got, want)
	}

	arithmetic, err := ctx.Encrypt([]uint64{3, 5, 7, 9})
	if err != nil {
		t.Fatal(err)
	}
	short, err := ctx.EncryptShort([]uint64{4, 3, 2, 1})
	if err != nil {
		t.Fatal(err)
	}
	product, err := ctx.MulShort(arithmetic, short)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ctx.Decrypt(product); err != nil {
		t.Fatal(err)
	} else if want := []uint64{12, 15, 14, 9}; !reflect.DeepEqual(got, want) {
		t.Fatalf("short product = %v, want %v", got, want)
	}
}
