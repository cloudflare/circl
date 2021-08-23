//go:build !amd64 || purego
// +build !amd64 purego

package fourq

func fpMod(c *Fp)       { fpModGeneric(c) }
func fpAdd(c, a, b *Fp) { fpAddGeneric(c, a, b) }
func fpSub(c, a, b *Fp) { fpSubGeneric(c, a, b) }
func fpMul(c, a, b *Fp) { fpMulGeneric(c, a, b) }
func fpSqr(c, a *Fp)    { fpSqrGeneric(c, a) }
func fpHlf(c, a *Fp)    { fpHlfGeneric(c, a) }
