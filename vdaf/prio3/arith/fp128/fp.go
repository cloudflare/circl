// Code generated from ./templates/field.go.tmpl. DO NOT EDIT.

package fp128

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

// Size is the length in bytes of an Fp128 element.
const Size = 16

// Fp represents a prime field element as a positive integer less than Order.
type Fp [2]uint64

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
	*z = Fp{n}
	z.toMont()
	return nil
}

func (z *Fp) GetUint64() (uint64, error) {
	x := z.fromMont()
	if x[1] != 0 {
		return 0, ErrNumberTooLarge
	}
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
	binary.Write(bytes.NewBuffer(x[:0]), binary.BigEndian, []uint64{orderP1, orderP0})
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
	// order is the order of the Fp128 field.
	orderP1 = uint64(0xffffffffffffffe4)
	orderP0 = uint64(0x1)
	// numRootsUnity is ..
	numRootsUnity = 66
	// numInverseIntFp128 is the number of precomputed inverses.
	numInverseInt = 8
	// maxNumTries is the maximum tries for rejection sampling.
	maxNumTries = 10
)

var (
	// rSquare is R^2 mod Fp128Order, where R=2^128 (little-endian).
	rSquare = Fp{0xfffffffffffffcf1, 0x0000000000005587}
	// half is 1/2 mod Order.
	half = Fp{0x0000000000000000, 0x8000000000000000}
	// rootOfUnityTwoN are the (principal) roots of unity that generate
	// a multiplicative group of order 2^n.
	// i.e., rootOfUnityTwoN[i] generates a group of order 2^i.
	// Thus, by definition,
	// - rootOfUnityTwoN[0] = One
	// - rootOfUnityTwoN[numRoots] = Generator
	// Constants are encoded in Montgomery domain (little-endian).
	rootOfUnityTwoN = [numRootsUnity + 1]Fp{
		{0xffffffffffffffff, 0x000000000000001b},
		{0x0000000000000002, 0xffffffffffffffc8},
		{0x8ff94ea745b7d9d6, 0x6171e408747992c7},
		{0x1323bb095fba9556, 0x7f2a4e6655e5a49c},
		{0xd1c455956aafabfc, 0x3d661493c5e89442},
		{0x416d53fbcdfcc65c, 0x5c159e1cffd5eca0},
		{0x1428d15e766f5f3e, 0x960d5c8696ec3aa3},
		{0x8f0cef59f8c23f3e, 0xcce83f596bb28730},
		{0x432d8d01ae187081, 0x12b496afe629224c},
		{0x0edc26fa686e3d3b, 0xc2026e57b1554ea9},
		{0x79663ccecfe8c86c, 0xf38c95d1e57405ea},
		{0xfecc377cf0f47a9f, 0x2b486d42d73283bd},
		{0x0ab1068497116540, 0x70866815dbf52bac},
		{0x2d9420dc5196c01a, 0x852c9b234b09c7df},
		{0x1a491a6cf3399115, 0xca4b831e2e621692},
		{0xb99152aabeebd757, 0xb7fbf514f82e2269},
		{0xb8da2f851dfd594a, 0x597c0e93a246d640},
		{0xf2888c210ef9f1c4, 0x97f929a5d52ab886},
		{0xe6a0ccbc956fc7fb, 0xfa4748aea960d0eb},
		{0xe53d6d96e1ec92a0, 0xc24ed95c3c013bcc},
		{0x6cc6e9129e1679c0, 0x6f825f88648b270c},
		{0x2c4d04cc40a2bd04, 0x17c2af4df9629e3d},
		{0x843747925bd7da8e, 0xdcd8c9979b888e8a},
		{0x4a1b1730d0aa77a0, 0x391696912d85b368},
		{0x68fb2b7e053e9500, 0x8ab5e54096ca012c},
		{0x1ccc0958442d4cd2, 0x819909091849c5c1},
		{0x25e9f8eeb3a11b26, 0x741eb9f6cfde0f02},
		{0x57b7921d9d4d0d66, 0x681f358ffad3a90d},
		{0x9bd3b6be3602bfe2, 0x294e31a63bbd8bb1},
		{0xe36811a2b6dd2f4d, 0x402946e8dcc86185},
		{0x468354d0ce6f4f42, 0xdc3971476a49c161},
		{0xd42c20d91e16ba3b, 0x16849c909ba2920d},
		{0x488a61cbe76f8796, 0xe0312b455090dc3d},
		{0x34d592b2d95461c7, 0x69ff23c4ae8a9ae2},
		{0xab1c9df91252cfb0, 0x3a71deec98434255},
		{0x1c5f61d837a9ff92, 0x4ec0bbb14b4943fc},
		{0x2550c6695de272ea, 0x4e7f5d927ad2bb46},
		{0x786b6c965e58be0d, 0xfbb47d3729647361},
		{0xbbfba318618fff40, 0x58938d40e16fc273},
		{0x0c8b4baee9a2907f, 0x2b0dddcff641c0c4},
		{0xf0d881f5c07b45fc, 0x33044b6b9af79104},
		{0x530f1c8d85c53b49, 0x7277db26e889f0c0},
		{0xefe24ff8e3caacf0, 0xd39b9320d2172567},
		{0xee7e1fbb71e9b04c, 0x105d0de0eba9ed48},
		{0x743424fea03af69b, 0xff50f6975f58d667},
		{0x1e55f4c8165fa615, 0x60d0d6428bc526f6},
		{0xf89e2f45fe30a628, 0xd35040e25d621120},
		{0x93a9b9bfa0ba47e5, 0xa14eda13d2c9f218},
		{0x7184aca1f5b7d796, 0x3067d899e53ae149},
		{0x48c135bbd45c9f78, 0x0231ec7261c6fe5e},
		{0xace311a714d11f45, 0x985458a22fc7b74f},
		{0xebd8c0f65c3941c7, 0x9253e8d60d138145},
		{0xa22ef3d3cf82d6ff, 0xf616691696239dad},
		{0xeb43ea48a880c558, 0x4c33bc414d65c622},
		{0xb02ca157db2f5773, 0x0ca75daa548fab25},
		{0x2e2d3b5d3d7fd880, 0xe709ce35344480a0},
		{0x04febe6d0fed06db, 0x82de81148eada3d0},
		{0xc549b2f670e7fe80, 0xef7c7c796a560813},
		{0x420d567cfa7dd71d, 0xd10bc78478e67eba},
		{0xd4e1bfae0eae0e5d, 0x69c02ae2b2189664},
		{0xee5aab9df23ad495, 0xe7fa9150bd2dd0bb},
		{0xdbe38168360cebac, 0x612d7349f49997ad},
		{0x9e4fc0f4006111e3, 0x54879fe858345e92},
		{0x3c5dd0cda73814c2, 0x1a29ef0cd721372e},
		{0x8b45f6e90b16542d, 0xd9b5db39af523ffb},
		{0x336824df50a3e9de, 0x1f70898af1701972},
		{0xf0111fb98c6b9875, 0x50f8f7f554db309c},
	}
	// inverseInt has the inverse of the first `numInverseInt` integers.
	inverseInt = [numInverseInt]Fp{
		{0xffffffffffffffff, 0x000000000000001b},
		{0x0000000000000000, 0x8000000000000000},
		{0x5555555555555555, 0x0000000000000009},
		{0x0000000000000000, 0x4000000000000000},
		{0xcccccccccccccccd, 0x6666666666666660},
		{0xaaaaaaaaaaaaaaab, 0x7ffffffffffffff6},
		{0xdb6db6db6db6db6e, 0x6db6db6db6db6dae},
		{0x0000000000000000, 0x2000000000000000},
	}
)

var (
	ErrMatchLen       = errors.New("inputs mismatched length")
	ErrFieldEltDecode = errors.New("incorrect field element value")
	ErrNumberTooLarge = errors.New("number of bits is not enough to represent the number")
	ErrMaxNumTries    = errors.New("random rejection sampling reached maximum number of tries")
	ErrRootsOfUnity   = errors.New("Fp has no roots of unity of order larger than 2^66")
)
