package csidh

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
)

var (
	// Number of iterations
	numIter = 10
	// Modulus
	modulus, _ = new(big.Int).SetString(fp2S(p), 16)
	// Zero in fp
	zeroFp512 = fp{}
	// One in fp
	oneFp512 = fp{1, 0, 0, 0, 0, 0, 0, 0}
	// file with KAT vectors
	katFile = "testdata/csidh_testvectors.json"
)

// Converts dst to Montgomery if "toMont==true" or from Montgomery domain otherwise.
func toMont(dst *big.Int, toMont bool) {
	var bigP, bigR big.Int

	intSetU64(&bigP, p[:])
	bigR.SetUint64(1)
	bigR.Lsh(&bigR, 512)

	if !toMont {
		bigR.ModInverse(&bigR, &bigP)
	}
	dst.Mul(dst, &bigR)
	dst.Mod(dst, &bigP)
}

func fp2S(v fp) string {
	var str string
	for i := 0; i < 8; i++ {
		str = fmt.Sprintf("%016x", v[i]) + str
	}
	return str
}

// zeroize fp.
func zero(v *fp) {
	for i := range *v {
		v[i] = 0
	}
}

// returns random value in a range (0,p).
func randomFp() (u fp) {
	_ = binary.Read(rand.Reader, binary.LittleEndian, &u)
	return
}

// return x==y for fp.
func eqFp(l, r *fp) bool {
	for idx := range l {
		if l[idx] != r[idx] {
			return false
		}
	}
	return true
}

// return x==y for point.
func ceqpoint(l, r *point) bool {
	return eqFp(&l.x, &r.x) && eqFp(&l.z, &r.z)
}

// Converts src to big.Int. Function assumes that src is a slice of uint64
// values encoded in little-endian byte order.
func intSetU64(dst *big.Int, src []uint64) {
	var tmp big.Int

	dst.SetUint64(0)
	for i := range src {
		tmp.SetUint64(src[i])
		tmp.Lsh(&tmp, uint(i*64))
		dst.Add(dst, &tmp)
	}
}

// Converts src to an array of uint64 values encoded in little-endian
// byte order.
func intGetU64(src *big.Int) []uint64 {
	var tmp, mod big.Int
	dst := make([]uint64, (src.BitLen()/64)+1)

	u64 := uint64(0)
	u64--
	mod.SetUint64(u64)
	for i := 0; i < (src.BitLen()/64)+1; i++ {
		tmp.Set(src)
		tmp.Rsh(&tmp, uint(i)*64)
		tmp.And(&tmp, &mod)
		dst[i] = tmp.Uint64()
	}
	return dst
}

// Returns projective coordinate X of normalized EC 'point' (point.x / point.z).
func toNormX(point *point) big.Int {
	var bigP, bigDnt, bigDor big.Int

	intSetU64(&bigP, p[:])
	intSetU64(&bigDnt, point.x[:])
	intSetU64(&bigDor, point.z[:])

	bigDor.ModInverse(&bigDor, &bigP)
	bigDnt.Mul(&bigDnt, &bigDor)
	bigDnt.Mod(&bigDnt, &bigP)
	return bigDnt
}

// Converts string to fp element in Montgomery domain of cSIDH-512.
func toFp(num string) fp {
	var tmp big.Int
	var ok bool
	var ret fp

	_, ok = tmp.SetString(num, 0)
	if !ok {
		panic("Can't parse a number")
	}
	toMont(&tmp, true)
	copy(ret[:], intGetU64(&tmp))
	return ret
}
