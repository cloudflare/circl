// Code generated from ./templates/vector.go.tmpl. DO NOT EDIT.

package fp64

import (
	"encoding/binary"
	"io"
	"math/bits"

	"github.com/cloudflare/circl/internal/conv"
	"github.com/cloudflare/circl/internal/sha3"
	"github.com/cloudflare/circl/math"
	"golang.org/x/crypto/cryptobyte"
)

type Vec []Fp

func (v Vec) Size() uint { return Size * uint(len(v)) }

func (v Vec) AddAssign(x Vec) {
	mustSameLen(v, x)
	for i := range v {
		v[i].AddAssign(&x[i])
	}
}

func (v Vec) SubAssign(x Vec) {
	mustSameLen(v, x)
	for i := range v {
		v[i].SubAssign(&x[i])
	}
}

func (v Vec) ScalarMul(x *Fp) {
	for i := range v {
		v[i].MulAssign(x)
	}
}

func (v Vec) DotProduct(x Vec) (out Fp) {
	mustSameLen(v, x)
	var t Fp
	for i := range v {
		t.Mul(&v[i], &x[i])
		out.AddAssign(&t)
	}
	return
}

func bitRev(x uint, numBits uint) uint {
	return bits.Reverse(x) >> (bits.UintSize - numBits)
}

func (v Vec) NTT(values Vec, n uint)    { v.doNTT(values, n, false) }
func (v Vec) InvNTT(values Vec, n uint) { v.doNTT(values, n, true) }
func (v Vec) doNTT(values Vec, n uint, isInvNTT bool) {
	valuesLen := uint(len(values))
	_, logN := math.NextPow2(n)

	for i := range v {
		j := bitRev(uint(i), logN)
		if j < valuesLen {
			v[i] = values[j]
		}
	}

	var t, w, wn, iwn Fp
	r := &wn
	if isInvNTT {
		r = &iwn
		iwn.SetOne()
	}

	for l := uint(1); l <= logN; l++ {
		y := uint(1) << (l - 1)
		chunk := uint(1) << (logN - l)

		for j := range chunk {
			x := j << l
			u := v[x]
			v[x+0].Add(&u, &v[x+y])
			v[x+y].Sub(&u, &v[x+y])
		}

		w.SetOne()
		wn.SetRootOfUnityTwoN(l)
		iwn.MulAssign(&wn)
		for i := uint(1); i < y; i++ {
			w.MulAssign(r)
			for j := range chunk {
				x := (j << l) + i
				u := v[x]
				t.Mul(&w, &v[x+y])
				v[x+0].Add(&u, &t)
				v[x+y].Sub(&u, &t)
			}
		}
	}
}

func (v Vec) SplitBits(n uint64) error {
	if bits.Len64(n) > len(v) {
		return ErrNumberTooLarge
	}

	clear(v)
	for i := range v {
		if (n>>i)&0x1 == 1 {
			v[i].SetOne()
		}
	}

	return nil
}

func (v Vec) JoinBits() Fp {
	var two Fp
	_ = two.SetUint64(2)
	return Poly(v).Evaluate(&two)
}

func (v Vec) Random(rnd io.Reader) error {
	var b [Size]byte
	var ok bool
forVec:
	for i := range v {
		for range maxNumTries {
			_, err := rnd.Read(b[:])
			if err != nil {
				return err
			}

			v[i], ok = isInRange(&b)
			if ok {
				v[i].toMont()
				continue forVec
			}
		}
		return ErrMaxNumTries
	}

	return nil
}

func (v Vec) RandomSHA3(s *sha3.State) error {
	for i := range v {
		err := v[i].RandomSHA3(s)
		if err != nil {
			return err
		}
	}

	return nil
}

func (v Vec) RandomSHA3Bytes(out []byte, s *sha3.State) error {
	var b [Size]byte
	var ok bool

forVec:
	for i := range v {
		for range maxNumTries {
			_, err := s.Read(b[:])
			if err != nil {
				return err
			}

			v[i], ok = isInRange(&b)
			if ok {
				out = append(out, b[:]...)
				v[i].toMont()
				continue forVec
			}
		}

		return ErrMaxNumTries
	}
	return nil
}

func (v Vec) MarshalBinary() ([]byte, error) {
	return conv.MarshalBinaryLen(v, v.Size())
}

func (v Vec) UnmarshalBinary(b []byte) error {
	return conv.UnmarshalBinary(v, b)
}

func (v Vec) Marshal(b *cryptobyte.Builder) error {
	for i := range v {
		v[i].Marshal(b)
	}
	return nil
}

func (v Vec) Unmarshal(s *cryptobyte.String) bool {
	for i := range v {
		if !v[i].Unmarshal(s) {
			return false
		}
	}
	return true
}

func isInRange(b *[Size]byte) (out [1]uint64, ok bool) {
	out[0] = binary.LittleEndian.Uint64(b[:8])
	ok = out[0] < orderP0
	return
}

func mustSameLen[T ~[]E, E any](x, y T) {
	if len(x) != len(y) {
		panic(ErrMatchLen)
	}
}

func mustSumLen[T ~[]E, E any](z, x, y T) {
	if len(z) != len(x)+len(y)-1 {
		panic(ErrMatchLen)
	}
}
