// Code generated from ./templates/field_test.go.tmpl. DO NOT EDIT.

package arith

import (
	"testing"

	"github.com/cloudflare/circl/vdaf/prio3/arith/fp128"
)

func TestFp128(t *testing.T) {
	t.Run("Fp", testFp[fp128.Fp])
	t.Run("Vec", testVec[fp128.Vec])
	t.Run("Poly", testPoly[fp128.Poly, fp128.Vec])
}

func BenchmarkFp128(b *testing.B) {
	b.Run("Fp", benchmarkFp[fp128.Fp])
	b.Run("Vec", benchmarkVec[fp128.Vec])
	b.Run("Poly", benchmarkPoly[fp128.Poly, fp128.Vec])
}
