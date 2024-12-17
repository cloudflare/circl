package fp128

func (z *Fp) Inv(x *Fp) {
	// Addition chain found using mmcloughlin/addchain: v0.4.0
	// (McLoughlin, 2021). https://doi.org/10.5281/zenodo.4758226
	var t, t0, t1, t2 Fp
	t.Sqr(x)
	t.Mul(x, &t)
	t.Sqr(&t)
	t0.Mul(x, &t)
	t.Sqr(&t0)
	t1.sqri(&t, 3)
	t.Mul(&t, &t1)
	t.Mul(x, &t)
	t1.sqri(&t, 3)
	t2.sqri(&t1, 7)
	t1.Mul(&t1, &t2)
	t2.sqri(&t1, 14)
	t1.Mul(&t1, &t2)
	t2.sqri(&t1, 28)
	t1.Mul(&t1, &t2)
	t0.Mul(&t0, &t1)
	t1.sqri(&t0, 62)
	t0.Mul(&t0, &t1)
	t0.sqri(&t0, 7)
	z.Mul(&t, &t0)
}
