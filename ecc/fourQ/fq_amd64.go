// +build amd64,go1.12

package fourQ

//go:noescape
func fqCmov(c, a *Fq, b int)

//go:noescape
func fqAdd(c, a, b *Fq)

//go:noescape
func fqSub(c, a, b *Fq)

//go:noescape
func fqMul(c, a, b *Fq)

//go:noescape
func fqSqr(c, a *Fq)
