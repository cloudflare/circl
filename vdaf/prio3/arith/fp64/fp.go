// Code generated from ./templates/field.go.tmpl. DO NOT EDIT.

package fp64

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"

	"github.com/cloudflare/circl/internal/conv"
	"github.com/cloudflare/circl/internal/sha3"
	"golang.org/x/crypto/cryptobyte"
)

// Size is the length in bytes of an Fp64 element.
const Size = 8

// Fp represents a prime field element as a positive integer less than Order.
type Fp [1]uint64

func (z Fp) String() string                  { x := z.fromMont(); return conv.Uint64Le2Hex(x[:]) }
func (z Fp) Size() uint                      { return Size }
func (z Fp) OrderRootUnity() uint            { return numRootsUnity }
func (z *Fp) AddAssign(x *Fp)                { fiatFpAdd(z, z, x) }
func (z *Fp) SubAssign(x *Fp)                { fiatFpSub(z, z, x) }
func (z *Fp) MulAssign(x *Fp)                { fiatFpMul(z, z, x) }
func (z *Fp) Add(x, y *Fp)                   { fiatFpAdd(z, x, y) }
func (z *Fp) Sub(x, y *Fp)                   { fiatFpSub(z, x, y) }
func (z *Fp) Mul(x, y *Fp)                   { fiatFpMul(z, x, y) }
func (z *Fp) Sqr(x *Fp)                      { fiatFpSquare(z, x) }
func (z *Fp) IsZero() bool                   { return ctEqual(z, &Fp{}) }
func (z *Fp) IsOne() bool                    { return ctEqual(z, &rootOfUnityTwoN[0]) }
func (z *Fp) IsEqual(x *Fp) bool             { return ctEqual(z, x) }
func (z *Fp) SetOne()                        { *z = rootOfUnityTwoN[0] }
func (z *Fp) toMont()                        { fiatFpMul(z, z, &rSquare) }
func (z *Fp) fromMont() (out Fp)             { fiatFpMul(&out, z, &Fp{1}); return }
func (z *Fp) MarshalBinary() ([]byte, error) { return conv.MarshalBinaryLen(z, Size) }
func (z *Fp) UnmarshalBinary(b []byte) error { return conv.UnmarshalBinary(z, b) }
func (z *Fp) Marshal(b *cryptobyte.Builder) error {
	var x [Size]byte
	for i, zi := range z.fromMont() {
		binary.LittleEndian.PutUint64(x[8*i:], zi)
	}
	b.AddBytes(x[:])
	return nil
}

func (z *Fp) Unmarshal(s *cryptobyte.String) bool {
	var b [Size]byte
	if s.CopyBytes(b[:]) {
		n, ok := isInRange(&b)
		if ok {
			*z = n
			z.toMont()
			return true
		}
	}
	return false
}

func (z *Fp) Random(r io.Reader) error {
	var b [Size]byte
	var ok bool
	for range maxNumTries {
		_, err := r.Read(b[:])
		if err != nil {
			return err
		}

		*z, ok = isInRange(&b)
		if ok {
			z.toMont()
			return nil
		}
	}

	return ErrMaxNumTries
}

func (z *Fp) RandomSHA3(s *sha3.State) error {
	var b [Size]byte
	var ok bool
	for range maxNumTries {
		_, err := s.Read(b[:])
		if err != nil {
			return err
		}

		*z, ok = isInRange(&b)
		if ok {
			z.toMont()
			return nil
		}
	}

	return ErrMaxNumTries
}

func (z *Fp) InvUint64(x uint64) {
	if 0 < x && x <= numInverseInt {
		*z = inverseInt[x-1]
	} else {
		err := z.SetUint64(x)
		if err != nil {
			panic(ErrFieldEltDecode)
		}
		z.Inv(z)
	}
}

func (z *Fp) InvTwoN(n uint) {
	z.SetOne()
	for range n {
		z.Mul(z, &half)
	}
}

func (z *Fp) SetUint64(n uint64) error {
	if n >= orderP0 {
		return ErrFieldEltDecode
	}
	*z = Fp{n}
	z.toMont()
	return nil
}

func (z *Fp) GetUint64() (uint64, error) {
	x := z.fromMont()
	return x[0], nil
}

func (z *Fp) SetRootOfUnityTwoN(n uint) {
	if n > numRootsUnity {
		panic(ErrRootsOfUnity)
	}
	*z = rootOfUnityTwoN[n]
}

func (z Fp) Order() []byte {
	var x [Size]byte
	binary.Write(bytes.NewBuffer(x[:0]), binary.BigEndian, []uint64{orderP0})
	return x[:]
}

func (z *Fp) sqri(x *Fp, n uint) {
	z.Sqr(x)
	for range n - 1 {
		z.Sqr(z)
	}
}

func fiatFpCmovznzU64(z *uint64, b, x, y uint64) { *z = (x &^ (-b)) | (y & (-b)) }

func ctEqual(x, y *Fp) bool {
	var v uint64
	for i := 0; i < len(*x); i++ {
		v |= (*x)[i] ^ (*y)[i]
	}
	v32 := uint32(v>>32) | uint32(v)
	return subtle.ConstantTimeEq(int32(v32), 0) == 1
}

const (
	// order is the order of the Fp64 field.
	orderP0 = uint64(0xffffffff00000001)
	// numRootsUnity is ..
	numRootsUnity = 32
	// numInverseIntFp64 is the number of precomputed inverses.
	numInverseInt = 8
	// maxNumTries is the maximum tries for rejection sampling.
	maxNumTries = 10
)

var (
	// rSquare is R^2 mod Fp64Order, where R=2^64 (little-endian).
	rSquare = Fp{0xfffffffe00000001}
	// half is 1/2 mod Order.
	half = Fp{0x8000000000000000}
	// rootOfUnityTwoN are the (principal) roots of unity that generate
	// a multiplicative group of order 2^n.
	// i.e., rootOfUnityTwoN[i] generates a group of order 2^i.
	// Thus, by definition,
	// - rootOfUnityTwoN[0] = One
	// - rootOfUnityTwoN[numRoots] = Generator
	// Constants are encoded in Montgomery domain (little-endian).
	rootOfUnityTwoN = [numRootsUnity + 1]Fp{
		{0x00000000ffffffff},
		{0xfffffffe00000002},
		{0xfffffffeffff0001},
		{0xfeffffff01000001},
		{0x0000000010000000},
		{0xffffbfff00000001},
		{0xfffffffeffffff81},
		{0x07fffffffffff800},
		{0xe60ca9645a7a425e},
		{0x5c411f4d8ab91088},
		{0x8bfed970d671fbb7},
		{0x1da1c8cedc0a82b1},
		{0x959dfcb4779eb1b1},
		{0x35d17996b4e99746},
		{0x10bba1e10e56548b},
		{0x2306baaae6467556},
		{0xbf79450ceba724c2},
		{0xaa3d8a0ca9f1cf0a},
		{0x05f9beab78de26d9},
		{0x8caa33007781b093},
		{0x5e93e76c70b1e9c6},
		{0x32322652d8cb2ab7},
		{0xe67246b3ce63a09e},
		{0x36fbc989de66dc62},
		{0xc307e16fb62a525e},
		{0x6ecfefd745751a91},
		{0x78d6e28499e74d1f},
		{0x915a171c5dce5b0b},
		{0x004a4484a6b1267b},
		{0xa46d26647bea105f},
		{0xb86a0843c8fa27b2},
		{0x5588e6586a6c9a32},
		{0xda58878b0d514e98},
	}
	// inverseInt has the inverse of the first `numInverseInt` integers.
	inverseInt = [numInverseInt]Fp{
		{0x00000000ffffffff},
		{0x8000000000000000},
		{0x0000000055555555},
		{0x4000000000000000},
		{0x0000000033333333},
		{0x7fffffffaaaaaaab},
		{0x6db6db6d6db6db6e},
		{0x2000000000000000},
	}
)

var (
	ErrMatchLen       = errors.New("inputs mismatched length")
	ErrFieldEltDecode = errors.New("incorrect field element value")
	ErrNumberTooLarge = errors.New("number of bits is not enough to represent the number")
	ErrMaxNumTries    = errors.New("random rejection sampling reached maximum number of tries")
	ErrRootsOfUnity   = errors.New("Fp has no roots of unity of order larger than 2^32")
)
