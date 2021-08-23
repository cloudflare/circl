//go:build !amd64 || purego
// +build !amd64 purego

package fourq

import "crypto/subtle"

func fqCmov(c, a *Fq, b int) {
	subtle.ConstantTimeCopy(b, c[0][:], a[0][:])
	subtle.ConstantTimeCopy(b, c[1][:], a[1][:])
}
func fqAdd(c, a, b *Fq) { fqAddGeneric(c, a, b) }
func fqSub(c, a, b *Fq) { fqSubGeneric(c, a, b) }
func fqMul(c, a, b *Fq) { fqMulGeneric(c, a, b) }
func fqSqr(c, a *Fq)    { fqSqrGeneric(c, a) }
