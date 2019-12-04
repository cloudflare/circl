// +build gofuzz

// How to run the fuzzer:
//  $ go get github.com/dvyukov/go-fuzz
//  $ go-fuzz-build -libfuzzer -func FuzzReduction -o lib.a
//  $ clang -fsanitize=fuzzer lib.a -o fu.exe
//  $ ./fu.exe
package fp448

import (
	"fmt"
	"math/big"
	"unsafe"

	"github.com/cloudflare/circl/internal/conv"
)

// FuzzReduction is a fuzzer target for red64 function, which reduces t
// (112 bits) to a number t' (56 bits) congruent modulo p448.
func FuzzReduction(data []byte) int {
	if len(data) != 2*Size {
		return -1
	}
	var got, want Elt

	var lo = *(*elt64)(unsafe.Pointer(&data[0*Size]))
	var hi = *(*elt64)(unsafe.Pointer(&data[1*Size]))
	red64(&lo, &hi)
	got = *(*Elt)(unsafe.Pointer(&lo))

	t := conv.BytesLe2BigInt(data[:2*Size])

	two448 := big.NewInt(1)
	two448.Lsh(two448, 448) // 2^448
	mask448 := big.NewInt(1)
	mask448.Sub(two448, mask448) // 2^448-1
	two224plus1 := big.NewInt(1)
	two224plus1.Lsh(two224plus1, 224)
	two224plus1.Add(two224plus1, big.NewInt(1)) // 2^224+1

	var loBig, hiBig big.Int
	for t.Cmp(two448) >= 0 {
		loBig.And(t, mask448)
		hiBig.Rsh(t, 448)
		t.Mul(&hiBig, two224plus1)
		t.Add(t, &loBig)
	}
	conv.BigInt2BytesLe(want[:], t)

	if got != want {
		fmt.Printf("in:   %v\n", conv.BytesLe2BigInt(data[:2*Size]))
		fmt.Printf("got:  %v\n", got)
		fmt.Printf("want: %v\n", want)
		panic("error found")
	}
	return 1
}
