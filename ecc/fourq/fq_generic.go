package fourq

import "crypto/subtle"

func fqCmovGeneric(c, a *Fq, b int) {
	subtle.ConstantTimeCopy(b, c[0][:], a[0][:])
	subtle.ConstantTimeCopy(b, c[1][:], a[1][:])
}

func fqAddGeneric(c, a, b *Fq) {
	fpAdd(&c[0], &a[0], &b[0])
	fpAdd(&c[1], &a[1], &b[1])
}

func fqSubGeneric(c, a, b *Fq) {
	fpSub(&c[0], &a[0], &b[0])
	fpSub(&c[1], &a[1], &b[1])
}

func fqMulGeneric(c, a, b *Fq) {
	var a0b0, a0b1, a1b0, a1b1 Fp
	fpMul(&a0b0, &a[0], &b[0])
	fpMul(&a0b1, &a[0], &b[1])
	fpMul(&a1b0, &a[1], &b[0])
	fpMul(&a1b1, &a[1], &b[1])
	fpSub(&c[0], &a0b0, &a1b1)
	fpAdd(&c[1], &a0b1, &a1b0)
}

func fqSqrGeneric(c, a *Fq) {
	var aa0, a01, aa1 Fp
	fpSqr(&aa0, &a[0])
	fpMul(&a01, &a[0], &a[1])
	fpSqr(&aa1, &a[1])
	fpSub(&c[0], &aa0, &aa1)
	fpAdd(&c[1], &a01, &a01)
}
