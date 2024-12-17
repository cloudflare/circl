// Code generated from ./templates/field_test.go.tmpl. DO NOT EDIT.

package arith

import (
	"testing"

	"github.com/cloudflare/circl/vdaf/prio3/arith/fp64"
)

func TestFp64(t *testing.T) {
	t.Run("Fp", testFp[fp64.Fp])
	t.Run("Vec", testVec[fp64.Vec])
	t.Run("Poly", testPoly[fp64.Poly, fp64.Vec])
}

func BenchmarkFp64(b *testing.B) {
	b.Run("Fp", benchmarkFp[fp64.Fp])
	b.Run("Vec", benchmarkVec[fp64.Vec])
	b.Run("Poly", benchmarkPoly[fp64.Poly, fp64.Vec])
}
