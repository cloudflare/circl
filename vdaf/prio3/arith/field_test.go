package arith

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"slices"
	"testing"

	"github.com/cloudflare/circl/internal/sha3"
	"github.com/cloudflare/circl/internal/test"
	"golang.org/x/crypto/cryptobyte"
)

type EltTest interface {
	comparable
	fmt.Stringer
	OrderRootUnity() uint
	Order() []byte
}

const testTimes = 1 << 10

func testFp[E EltTest, F Fp[E]](t *testing.T) {
	t.Run("randomNum", randomNum[E, F])
	t.Run("noAlias", noAlias[E, F])
	t.Run("addSub", addSub[E, F])
	t.Run("mulInv", mulInv[E, F])
	t.Run("invTwoN", invTwoN[E, F])
	t.Run("expInv", expInv[E, F])
	t.Run("mulSqr", mulSqr[E, F])
	t.Run("marshal", marshal[E, F])
	t.Run("rootsUnity", rootsUnityTwoN[E, F])
	t.Run("stringer", stringer[E, F])
}

func mustRead[T interface{ Random(io.Reader) error }](t testing.TB, x T) {
	err := x.Random(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
}

func randomNum[E Elt, F Fp[E]](t *testing.T) {
	err := F(new(E)).Random(io.LimitReader(rand.Reader, 0))
	test.CheckIsErr(t, err, "random should fail")

	r := sha3.NewShake128()
	r.Reset()
	got := F(new(E))
	err = got.Random(&r)
	test.CheckNoErr(t, err, "Random failed")

	r.Reset()
	want := F(new(E))
	err = want.RandomSHA3(&r)
	test.CheckNoErr(t, err, "RandomSHA3 failed")

	if !got.IsEqual(want) {
		test.ReportError(t, got, want)
	}
}

func noAlias[E Elt, F Fp[E]](t *testing.T) {
	x := F(new(E))
	mustRead(t, x)
	y := *x
	var got F = &y
	got.Sqr(got)
	z := *x
	want := F(&z)
	want.Mul(want, want)

	if !got.IsEqual(want) {
		test.ReportError(t, got, want, x)
	}
}

func addSub[E Elt, F Fp[E]](t *testing.T) {
	got := F(new(E))
	want := F(new(E))
	x := F(new(E))
	y := F(new(E))
	for i := 0; i < testTimes; i++ {
		mustRead(t, x)
		mustRead(t, y)

		// 2x = (x + y) + x - y
		//    = (x - y) + x + y
		got.Add(x, y)
		got.AddAssign(x)
		got.SubAssign(y)
		want.Sub(x, y)
		want.AddAssign(x)
		want.AddAssign(y)

		if !got.IsEqual(want) {
			test.ReportError(t, got, want, x, y)
		}
	}
}

func mulInv[E Elt, F Fp[E]](t *testing.T) {
	x := F(new(E))
	y := F(new(E))
	z := F(new(E))
	for i := 0; i < testTimes; i++ {
		mustRead(t, x)
		mustRead(t, y)

		// x*y*x^1 = y
		z.Inv(x)
		z.Mul(z, y)
		z.Mul(z, x)
		got := z
		want := y
		if !got.IsEqual(want) {
			test.ReportError(t, got, want, x, y)
		}
	}
}

func invTwoN[E Elt, F Fp[E]](t *testing.T) {
	got := F(new(E))
	want := F(new(E))
	for i := 0; i < 64; i++ {
		pow2 := uint64(1) << i

		got.InvTwoN(uint(i))

		err := want.SetUint64(pow2)
		test.CheckNoErr(t, err, "setuint64 failed")
		want.Inv(want)

		if !got.IsEqual(want) {
			test.ReportError(t, got, want, i)
		}
	}
}

func expInv[E Elt, F Fp[E]](t *testing.T) {
	got := F(new(E))
	want := F(new(E))
	x := F(new(E))
	for i := 0; i < testTimes; i++ {
		mustRead(t, x)

		// (1/x) * x = 1
		got.Inv(x)
		got.MulAssign(x)
		want.SetOne()
		if !got.IsEqual(want) {
			test.ReportError(t, got, want, x)
		}
	}

	for i := uint64(0); i < 8; i++ {
		got.InvUint64(i)
		_ = want.SetUint64(i)
		want.Inv(want)

		if !got.IsEqual(want) {
			test.ReportError(t, got, want, i)
		}
	}
}

func mulSqr[E Elt, F Fp[E]](t *testing.T) {
	x := F(new(E))
	y := F(new(E))
	l0 := F(new(E))
	l1 := F(new(E))
	r0 := F(new(E))
	r1 := F(new(E))
	for i := 0; i < testTimes; i++ {
		mustRead(t, x)
		mustRead(t, y)

		// (x+y)(x-y) = (x^2-y^2)
		l0.Add(x, y)
		l1.Sub(x, y)
		l0.Mul(l0, l1)
		r0.Sqr(x)
		r1.Sqr(y)
		r0.Sub(r0, r1)
		got := l0
		want := r0
		if !got.IsEqual(want) {
			test.ReportError(t, got, want, x, y)
		}
	}
}

func rootsUnityTwoN[E EltTest, F Fp[E]](t *testing.T) {
	w := F(new(E))
	x := F(new(E))

	w.SetRootOfUnityTwoN(0)
	test.CheckOk(w.IsOne(), "incorrect order of the root of unity", t)

	order := (*w).OrderRootUnity()
	for i := uint(1); i <= order; i++ {
		w.SetRootOfUnityTwoN(i)

		x.Sqr(w)
		for range i - 1 {
			test.CheckOk(!x.IsOne(), "incorrect order of the root of unity", t)
			x.Sqr(x)
		}

		test.CheckOk(x.IsOne(), "incorrect order of the root of unity", t)
	}
}

func marshal[E EltTest, F Fp[E]](t *testing.T) {
	x := F(new(E))
	y := F(new(E))
	for i := 0; i < testTimes; i++ {
		mustRead(t, x)
		s, err := x.MarshalBinary()
		test.CheckNoErr(t, err, "MarshalBinary failed")
		test.CheckOk(uint(len(s)) == x.Size(), "wrong byte length", t)

		err = y.UnmarshalBinary(s)
		test.CheckNoErr(t, err, "UnmarshalBinary failed")
		if !x.IsEqual(y) {
			test.ReportError(t, x, y)
		}
		// check for invalid size
		err = y.UnmarshalBinary(s[1:])
		test.CheckIsErr(t, err, "UnmarshalBinary should failed")

		// check for invalid element
		order := (*x).Order()
		slices.Reverse(order)
		err = y.UnmarshalBinary(order)
		test.CheckIsErr(t, err, "UnmarshalBinary should failed")
	}
}

func stringer[E EltTest, F Fp[E]](t *testing.T) {
	minusOne := F(new(E))
	minusOne.SetOne()
	minusOne.Sub(new(E), minusOne)
	got := (*minusOne).String()

	fpOrder := new(big.Int).SetBytes((*minusOne).Order())
	pMinusOne := new(big.Int).Sub(fpOrder, big.NewInt(1))
	want := "0x" + pMinusOne.Text(16)

	if got != want {
		test.ReportError(t, got, want)
	}
}

func benchmarkFp[E EltTest, F Fp[E]](b *testing.B) {
	x := F(new(E))
	y := F(new(E))
	z := F(new(E))
	mustRead(b, x)
	mustRead(b, y)
	mustRead(b, z)

	b.Run("Marshal", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			var builder cryptobyte.Builder
			_ = z.Marshal(&builder)
		}
	})
	b.Run("MarshalBinary", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = z.MarshalBinary()
		}
	})
	b.Run("Unmarshal", func(b *testing.B) {
		buf := make([]byte, z.Size())
		for i := 0; i < b.N; i++ {
			s := cryptobyte.String(buf)
			_ = z.Unmarshal(&s)
		}
	})
	b.Run("UnmarshalBinary", func(b *testing.B) {
		buf := make([]byte, z.Size())
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
	b.Run("Add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			z.Add(x, y)
		}
	})
	b.Run("Sub", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			z.Sub(x, y)
		}
	})
	b.Run("Mul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			z.Mul(x, y)
		}
	})
	b.Run("Sqr", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			z.Sqr(x)
		}
	})
	b.Run("InvUint64", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			z.InvUint64(5)
		}
	})
	b.Run("InvTwoN", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			z.InvTwoN(16)
		}
	})
	b.Run("Inv", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			z.Inv(x)
		}
	})
}
