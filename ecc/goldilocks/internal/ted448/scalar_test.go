package ted448_test

import (
	"bytes"
	"crypto/rand"
	"encoding"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/ecc/goldilocks/internal/ted448"
	"github.com/cloudflare/circl/internal/conv"
	"github.com/cloudflare/circl/internal/test"
	fp "github.com/cloudflare/circl/math/fp448"
)

var bigOrder, _ = new(big.Int).SetString("3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3", 16)

func rndScalar(t testing.TB) *ted448.Scalar {
	var buf [ted448.ScalarSize]byte
	_, err := rand.Read(buf[:])
	if err != nil {
		t.Fatal(err)
	}
	var s ted448.Scalar
	s.FromBytesLE(buf[:])
	return &s
}

func toBig(s *ted448.Scalar) *big.Int {
	return new(big.Int).SetBytes(s.ToBytesBE())
}

func TestReduceModOrder(t *testing.T) {
	const max = 3*fp.Size - 1
	var b [max]byte
	_, _ = rand.Read(b[:])
	var z ted448.Scalar
	for i := 0; i < max; i++ {
		x := b[0:i]
		bigX := conv.BytesLe2BigInt(x)

		z.FromBytesLE(x)
		got := toBig(&z)
		got.Mod(got, bigOrder)

		want := bigX.Mod(bigX, bigOrder)

		if got.Cmp(want) != 0 {
			test.ReportError(t, got, want, x, i)
		}
	}
}

func testOp(t *testing.T,
	f func(z, x, y *ted448.Scalar),
	g func(z, x, y *big.Int),
) {
	t.Helper()
	const testTimes = 1 << 8
	want := new(big.Int)
	var z ted448.Scalar
	for i := 0; i < testTimes; i++ {
		x := rndScalar(t)
		y := rndScalar(t)
		bigX := toBig(x)
		bigY := toBig(y)

		f(&z, x, y)
		got := toBig(&z)

		g(want, bigX, bigY)
		want.Mod(want, bigOrder)
		if got.Cmp(want) != 0 {
			test.ReportError(t, got.Text(16), want.Text(16), x, y)
		}
	}
}

type canMarshal interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

func testMarshal(t *testing.T, x, y canMarshal, name string) {
	t.Helper()

	wantBytes, err := x.MarshalBinary()
	test.CheckNoErr(t, err, "error on marshaling "+name)

	err = y.UnmarshalBinary(wantBytes)
	test.CheckNoErr(t, err, "error on unmarshaling "+name)

	gotBytes, err := x.MarshalBinary()
	test.CheckNoErr(t, err, "error on marshaling "+name)

	if !bytes.Equal(gotBytes, wantBytes) {
		test.ReportError(t, gotBytes, wantBytes)
	}

	b, _ := x.MarshalBinary()
	err = y.UnmarshalBinary(b[:0])
	test.CheckIsErr(t, err, "should trigger unmarshal error")

	order := bigOrder.Bytes()
	err = y.UnmarshalBinary(order)
	test.CheckIsErr(t, err, "should trigger unmarshal error")

	order[0] += 1
	err = y.UnmarshalBinary(order[:])
	test.CheckIsErr(t, err, "should trigger unmarshal error")

	order[0] -= 2
	err = y.UnmarshalBinary(order[:])
	test.CheckNoErr(t, err, "should not trigger unmarshal error")
}

func testFromBytes(t *testing.T) {
	const testTimes = 1 << 8
	var got, want ted448.Scalar
	for i := 0; i < testTimes; i++ {
		x := rndScalar(t)

		got.FromBytesLE(x.ToBytesLE())
		want.FromBytesBE(x.ToBytesBE())

		if got != want {
			test.ReportError(t, got, want, x)
		}

		s := x.String()
		got1, ok := new(big.Int).SetString(s, 0)
		want1 := toBig(x)

		if !ok || got1.Cmp(want1) != 0 {
			test.ReportError(t, got1, want1, x)
		}
	}
}

func TestScalar(t *testing.T) {
	t.Run("Add", func(t *testing.T) {
		testOp(t,
			func(z, x, y *ted448.Scalar) { z.Add(x, y) },
			func(z, x, y *big.Int) { z.Add(x, y) })
	})
	t.Run("Sub", func(t *testing.T) {
		testOp(t,
			func(z, x, y *ted448.Scalar) { z.Sub(x, y) },
			func(z, x, y *big.Int) { z.Sub(x, y) })
	})
	t.Run("Mul", func(t *testing.T) {
		testOp(t,
			func(z, x, y *ted448.Scalar) { z.Mul(x, y) },
			func(z, x, y *big.Int) { z.Mul(x, y) })
	})
	t.Run("Neg", func(t *testing.T) {
		testOp(t,
			func(z, x, y *ted448.Scalar) { z.Neg(x) },
			func(z, x, y *big.Int) { z.Neg(x) })
	})
	t.Run("Inv", func(t *testing.T) {
		testOp(t,
			func(z, x, y *ted448.Scalar) { z.Inv(x) },
			func(z, x, y *big.Int) { z.ModInverse(x, bigOrder) })
	})
	t.Run("Marshal", func(t *testing.T) {
		testMarshal(t, rndScalar(t), new(ted448.Scalar), "scalar")
	})
	t.Run("FromBytes", testFromBytes)
}
