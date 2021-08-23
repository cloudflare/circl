//go:build amd64 && !purego
// +build amd64,!purego

package fourq

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
