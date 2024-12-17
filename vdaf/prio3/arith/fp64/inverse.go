package fp64

func (z *Fp) Inv(x *Fp) {
	// Addition chain found using mmcloughlin/addchain: v0.4.0
	// (McLoughlin, 2021). https://doi.org/10.5281/zenodo.4758226
	var t, t0, t1 Fp
	t.Sqr(x)
	t.Mul(x, &t)
	t.Sqr(&t)
	t.Mul(x, &t)
	t0.sqri(&t, 3)
	t0.Mul(&t, &t0)
	t1.Sqr(&t0)
	t.Mul(x, &t1)
	t1.sqri(&t1, 5)
	t0.Mul(&t0, &t1)
	t1.sqri(&t0, 12)
	t0.Mul(&t0, &t1)
	t0.sqri(&t0, 7)
	t.Mul(&t, &t0)
	t0.sqri(&t, 32)
	t.Mul(&t, &t0)
	t.Sqr(&t)
	z.Mul(x, &t)
}
