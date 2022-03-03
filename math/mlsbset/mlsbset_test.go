package mlsbset_test

import (
	"crypto/rand"
	"errors"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/internal/conv"
	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/math/mlsbset"
)

func TestExp(t *testing.T) {
	T := uint(126)
	for v := uint(1); v <= 5; v++ {
		for w := uint(2); w <= 5; w++ {
			m, err := mlsbset.New(T, v, w)
			if err != nil {
				test.ReportError(t, err, nil)
			}
			testExp(t, m)
		}
	}
}

func testExp(t *testing.T, m mlsbset.Encoder) {
	const testTimes = 1 << 8
	params := m.GetParams()
	TBytes := (params.T + 7) / 8
	topBits := (byte(1) << (params.T % 8)) - 1
	k := make([]byte, TBytes)
	for i := 0; i < testTimes; i++ {
		_, _ = rand.Read(k)
		k[0] |= 1
		k[TBytes-1] &= topBits

		c, err := m.Encode(k)
		if err != nil {
			test.ReportError(t, err, nil)
		}

		g := zzAdd{m.GetParams()}
		a := c.Exp(g)

		got := a.(*big.Int)
		want := conv.BytesLe2BigInt(k)
		if got.Cmp(want) != 0 {
			test.ReportError(t, got, want, m)
		}
	}
}

type zzAdd struct{ set mlsbset.Params }

func (zzAdd) Identity() mlsbset.EltG { return big.NewInt(0) }
func (zzAdd) NewEltP() mlsbset.EltP  { return new(big.Int) }
func (zzAdd) Sqr(x mlsbset.EltG) {
	a := x.(*big.Int)
	a.Add(a, a)
}

func (zzAdd) Mul(x mlsbset.EltG, y mlsbset.EltP) {
	a := x.(*big.Int)
	b := y.(*big.Int)
	a.Add(a, b)
}

func (z zzAdd) ExtendedEltP() mlsbset.EltP {
	a := big.NewInt(1)
	a.Lsh(a, z.set.W*z.set.D)
	return a
}

func (z zzAdd) Lookup(x mlsbset.EltP, idTable uint, sgnElt int32, idElt int32) {
	a := x.(*big.Int)
	a.SetInt64(1)
	a.Lsh(a, z.set.E*idTable) // 2^(e*v)
	sum := big.NewInt(0)
	for i := int(z.set.W - 2); i >= 0; i-- {
		ui := big.NewInt(int64((idElt >> uint(i)) & 0x1))
		sum.Add(sum, ui)
		sum.Lsh(sum, z.set.D)
	}
	sum.Add(sum, big.NewInt(1))
	a.Mul(a, sum)
	if sgnElt == -1 {
		a.Neg(a)
	}
}

func TestEncodeErr(t *testing.T) {
	t.Run("mArgs", func(t *testing.T) {
		_, got := mlsbset.New(0, 0, 0)
		want := errors.New("t>1, v>=1, w>=2")
		if got.Error() != want.Error() {
			test.ReportError(t, got, want)
		}
	})
	t.Run("kOdd", func(t *testing.T) {
		m, _ := mlsbset.New(16, 2, 2)
		k := make([]byte, 2)
		_, got := m.Encode(k)
		want := errors.New("k must be odd")
		if got.Error() != want.Error() {
			test.ReportError(t, got, want)
		}
	})
	t.Run("kBig", func(t *testing.T) {
		m, _ := mlsbset.New(16, 2, 2)
		k := make([]byte, 4)
		_, got := m.Encode(k)
		want := errors.New("k too big")
		if got.Error() != want.Error() {
			test.ReportError(t, got, want)
		}
	})
	t.Run("kEmpty", func(t *testing.T) {
		m, _ := mlsbset.New(16, 2, 2)
		k := []byte{}
		_, got := m.Encode(k)
		want := errors.New("empty slice")
		if got.Error() != want.Error() {
			test.ReportError(t, got, want)
		}
	})
}

func BenchmarkEncode(b *testing.B) {
	t, v, w := uint(256), uint(2), uint(3)
	m, _ := mlsbset.New(t, v, w)
	params := m.GetParams()
	TBytes := (params.T + 7) / 8
	topBits := (byte(1) << (params.T % 8)) - 1

	k := make([]byte, TBytes)
	_, _ = rand.Read(k)
	k[0] |= 1
	k[TBytes-1] &= topBits

	c, _ := m.Encode(k)
	g := zzAdd{params}

	b.Run("Encode", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = m.Encode(k)
		}
	})
	b.Run("Exp", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			c.Exp(g)
		}
	})
}
