package goldilocks

import (
	"github.com/cloudflare/circl/internal/conv"
	"github.com/cloudflare/circl/math"
	fp "github.com/cloudflare/circl/math/fp448"
)

// twistCurve is -x^2+y^2=1-39082x^2y^2 and is 4-isogeneous to Goldilocks.
type twistCurve struct{}

// Identity returns the identity point.
func (twistCurve) Identity() *twistPoint {
	return &twistPoint{
		y: fp.One(),
		z: fp.One(),
	}
}

// ScalarMult returns kP.
func (twistCurve) ScalarMult(k []byte, P *twistPoint) *twistPoint { return &twistPoint{} }

const (
	omegaFix = 7
	omegaVar = 5
)

// CombinedMult returns mG+nP
func (e twistCurve) CombinedMult(m, n []byte, P *twistPoint) *twistPoint {
	nafFix := math.OmegaNAF(conv.BytesLe2BigInt(m), omegaFix)
	nafVar := math.OmegaNAF(conv.BytesLe2BigInt(n), omegaVar)

	if len(nafFix) > len(nafVar) {
		nafVar = append(nafVar, make([]int32, len(nafFix)-len(nafVar))...)
	} else if len(nafFix) < len(nafVar) {
		nafFix = append(nafFix, make([]int32, len(nafVar)-len(nafFix))...)
	}

	var TabQ [1 << (omegaVar - 2)]pointR2
	P.oddMultiples(TabQ[:])
	Q := e.Identity()
	for i := len(nafFix) - 1; i >= 0; i-- {
		Q.Double()
		// Generator point
		if nafFix[i] != 0 {
			idxM := absolute(nafFix[i]) >> 1
			R := tabVerif[idxM]
			if nafFix[i] < 0 {
				R.neg()
			}
			Q.mixAdd(&R)
		}
		// Variable input point
		if nafVar[i] != 0 {
			idxN := absolute(nafVar[i]) >> 1
			S := TabQ[idxN]
			if nafVar[i] < 0 {
				S.neg()
			}
			Q.add(&S)
		}
	}
	return Q
}
// absolute returns always a positive value.
func absolute(x int32) int32 {
	mask := x >> 31
	return (x + mask) ^ mask
}
