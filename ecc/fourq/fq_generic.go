package fourq

func fqAddGeneric(c, a, b *Fq) {
	fpAddGeneric(&c[0], &a[0], &b[0])
	fpAddGeneric(&c[1], &a[1], &b[1])
}

func fqSubGeneric(c, a, b *Fq) {
	fpSubGeneric(&c[0], &a[0], &b[0])
	fpSubGeneric(&c[1], &a[1], &b[1])
}

func fqMulGeneric(c, a, b *Fq) {
	var a0b0, a0b1, a1b0, a1b1 Fp
	fpMulGeneric(&a0b0, &a[0], &b[0])
	fpMulGeneric(&a0b1, &a[0], &b[1])
	fpMulGeneric(&a1b0, &a[1], &b[0])
	fpMulGeneric(&a1b1, &a[1], &b[1])
	fpSubGeneric(&c[0], &a0b0, &a1b1)
	fpAddGeneric(&c[1], &a0b1, &a1b0)
}

func fqSqrGeneric(c, a *Fq) {
	var aa0, a01, aa1 Fp
	fpSqrGeneric(&aa0, &a[0])
	fpMulGeneric(&a01, &a[0], &a[1])
	fpSqrGeneric(&aa1, &a[1])
	fpSubGeneric(&c[0], &aa0, &aa1)
	fpAddGeneric(&c[1], &a01, &a01)
}
