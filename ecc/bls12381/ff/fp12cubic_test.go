package ff

import (
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func TestFP12CubicAdd(t *testing.T) {
	const testTimes = 1 << 8
	for i := 0; i < testTimes; i++ {
		var xalt, yalt, zalt Fp12Cubic
		var z, zcmp Fp12
		x := randomFp12(t)
		y := randomFp12(t)
		xalt.FromFp12(x)
		yalt.FromFp12(y)
		zalt.Add(&xalt, &yalt)
		z.Add(x, y)
		zcmp.FromFp12Alt(&zalt)
		if z.IsEqual(&zcmp) == 0 {
			test.ReportError(t, z, zcmp, x, y)
		}
	}
}

func TestFP12CubicMul(t *testing.T) {
	const testTimes = 1 << 8
	for i := 0; i < testTimes; i++ {
		var xalt, yalt, zalt Fp12Cubic
		var z, zcmp Fp12
		x := randomFp12(t)
		y := randomFp12(t)
		xalt.FromFp12(x)
		yalt.FromFp12(y)
		zalt.Mul(&xalt, &yalt)
		z.Mul(x, y)
		zcmp.FromFp12Alt(&zalt)
		if z.IsEqual(&zcmp) == 0 {
			test.ReportError(t, z, zcmp, x, y)
		}
	}
}

func TestFP12AltSqr(t *testing.T) {
	const testTimes = 1 << 8
	for i := 0; i < testTimes; i++ {
		var xalt, zalt Fp12Cubic
		var z, zcmp Fp12
		x := randomFp12(t)
		xalt.FromFp12(x)
		zalt.Sqr(&xalt)
		z.Sqr(x)
		zcmp.FromFp12Alt(&zalt)
		if z.IsEqual(&zcmp) == 0 {
			test.ReportError(t, z, zcmp, x)
		}
	}
}

func TestFP12CubicLine(t *testing.T) {
	const testTimes = 1 << 8
	for i := 0; i < testTimes; i++ {
		var x, y, z, zcmp Fp12Cubic
		var yline LineValue
		xnorm := randomFp12(t)
		x.FromFp12(xnorm)

		yline[0] = *randomFp2(t)
		yline[1] = *randomFp2(t)
		yline[2] = *randomFp2(t)

		y[0][0] = yline[0]
		y[0][1] = yline[2]
		y[2][0] = yline[1]

		zcmp.Mul(&x, &y)
		z.MulLine(&x, &yline)
		if z.IsEqual(&zcmp) == 0 {
			test.ReportError(t, z, zcmp, x)
		}
	}
}
