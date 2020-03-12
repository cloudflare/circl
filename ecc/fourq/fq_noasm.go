// +build !amd64 purego

package fourq

func fqCmov(c, a *Fq, b int) { fqCmovGeneric(c, a, b) }
func fqAdd(c, a, b *Fq)      { fqAddGeneric(c, a, b) }
func fqSub(c, a, b *Fq)      { fqSubGeneric(c, a, b) }
func fqMul(c, a, b *Fq)      { fqMulGeneric(c, a, b) }
func fqSqr(c, a *Fq)         { fqSqrGeneric(c, a) }
