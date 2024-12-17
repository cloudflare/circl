package arith

import (
	"crypto/rand"
	"io"
	"slices"
	"testing"

	"github.com/cloudflare/circl/internal/sha3"
	"github.com/cloudflare/circl/internal/test"
)

func testVec[V Vec[V, E], E EltTest, F Fp[E]](t *testing.T) {
	t.Run("marshal", marshalVec[V, E, F])
	t.Run("bitRepresentation", bitRepresentation[V, E, F])
	t.Run("random", random[V, E, F])
}

func marshalVec[V Vec[V, E], E EltTest, F Fp[E]](t *testing.T) {
	const N = 4
	x := NewVec[V](N)
	y := NewVec[V](N)
	for i := 0; i < testTimes; i++ {
		mustRead(t, x)
		s, err := x.MarshalBinary()
		test.CheckNoErr(t, err, "MarshalBinary failed")
		test.CheckOk(uint(len(s)) == x.Size(), "wrong byte length", t)

		err = y.UnmarshalBinary(s)
		test.CheckNoErr(t, err, "UnmarshalBinary failed")
		if !slices.Equal(x, y) {
			test.ReportError(t, x, y)
		}

		// check for invalid size
		err = y.UnmarshalBinary(s[1:])
		test.CheckIsErr(t, err, "UnmarshalBinary should failed")
	}
}

func bitRepresentation[V Vec[V, E], E Elt, F Fp[E]](t *testing.T) {
	N := uint64(0x0F)
	eightBits := NewVec[V](8)
	err := eightBits.SplitBits(N)
	test.CheckNoErr(t, err, "failed to split number in bits")

	for i := range eightBits {
		if i < 4 {
			test.CheckOk(F(&eightBits[i]).IsOne(), "vector element should be one", t)
		} else {
			test.CheckOk(F(&eightBits[i]).IsZero(), "vector element should be zero", t)
		}
	}

	num := eightBits.JoinBits()
	test.CheckNoErr(t, err, "JoinBits failed")

	got, err := F(&num).GetUint64()
	test.CheckNoErr(t, err, "failed to recover uint64")

	want := N
	if got != want {
		test.ReportError(t, got, want, eightBits, num)
	}

	fourBits := NewVec[V](4)
	err = fourBits.SplitBits(0xFF)
	test.CheckIsErr(t, err, "SplitBits should return an error")
}

func random[V Vec[V, E], E EltTest, F Fp[E]](t *testing.T) {
	r := sha3.NewShake128()
	v := NewVec[V](4)
	err := v.Random(io.LimitReader(&r, 0))
	test.CheckIsErr(t, err, "generating random vector should failed")

	r.Reset()
	got := NewVec[V](4)
	err = got.Random(&r)
	test.CheckNoErr(t, err, "Random failed")

	r.Reset()
	want := NewVec[V](4)
	err = want.RandomSHA3(&r)
	test.CheckNoErr(t, err, "RandomSHA3 failed")

	if !slices.Equal(got, want) {
		test.ReportError(t, got, want)
	}
}

func benchmarkVec[V Vec[V, E], E Elt, F Fp[E]](b *testing.B) {
	const N = 1024
	k := F(new(E))
	x := NewVec[V](N)
	z := NewVec[V](N)

	mustRead(b, k)
	mustRead(b, x)
	mustRead(b, z)

	const Bits = uint64(0x0F)
	eightBits := NewVec[V](8)
	_ = eightBits.SplitBits(Bits)
	buf, _ := x.MarshalBinary()

	b.Run("MarshalBinary", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = z.MarshalBinary()
		}
	})
	b.Run("UnmarshalBinary", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = z.UnmarshalBinary(buf)
		}
	})
	b.Run("Random", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = z.Random(rand.Reader)
		}
	})
	b.Run("RandomSHA3", func(b *testing.B) {
		r := sha3.NewShake128()
		for i := 0; i < b.N; i++ {
			_ = z.RandomSHA3(&r)
		}
	})
	b.Run("AddAssign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			z.AddAssign(x)
		}
	})
	b.Run("SubAssign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			z.SubAssign(x)
		}
	})
	b.Run("ScalarMul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			z.ScalarMul(k)
		}
	})
	b.Run("DotProduct", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			z.DotProduct(x)
		}
	})
	b.Run("SplitBits", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = eightBits.SplitBits(Bits)
		}
	})
	b.Run("JoinBits", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = eightBits.JoinBits()
		}
	})
}
