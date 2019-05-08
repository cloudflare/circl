package p384

import (
	"fmt"
	"github.com/cloudflare/circl/utils/cpu"
	"math/big"
)

var hasBMI2 = cpu.X86.HasBMI2

type fp384 [6]big.Word

func (e *fp384) Set(f *fp384) {
	e[0] = f[0]
	e[1] = f[1]
	e[2] = f[2]
	e[3] = f[3]
	e[4] = f[4]
	e[5] = f[5]
}

func (e *fp384) Int() *big.Int {
	return new(big.Int).SetBits(e[:])
}

func (e *fp384) String() string {
	return fmt.Sprintf("%16.16x%16.16x%16.16x%16.16x%16.16x%16.16x", e[5], e[4], e[3], e[2], e[1], e[0])
}

func (e *fp384) Invert(f *fp384) {
	bits := [6]uint64{0xfffffffd, 0xffffffff00000000, 0xfffffffffffffffe, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff}

	sum, power := &fp384{}, &fp384{}
	sum.Set(&rN1)
	power.Set(f)

	for word := 0; word < 6; word++ {
		for bit := uint(0); bit < 64; bit++ {
			if (bits[word]>>bit)&1 == 1 {
				fp384Mul(sum, sum, power)
			}
			fp384Mul(power, power, power)
		}
	}

	fp384Mul(sum, sum, &r3)
	e.Set(sum)
}

func montEncode(c, a *fp384) { fp384Mul(c, a, &r2) }
func montDecode(c, a *fp384) { fp384Mul(c, a, &fp384{1}) }

// go:noescape
func fp384Neg(c, a *fp384)

//go:noescape
func fp384Add(c, a, b *fp384)

//go:noescape
func fp384Sub(c, a, b *fp384)

//go:noescape
func fp384Mul(c, a, b *fp384)
