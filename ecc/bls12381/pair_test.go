package bls12381

import (
	"crypto/rand"
	"fmt"
	"slices"
	"testing"

	"github.com/cloudflare/circl/ecc/bls12381/ff"
	"github.com/cloudflare/circl/internal/test"
)

func TestProdPair(t *testing.T) {
	const testTimes = 1 << 5
	const N = 3

	listG1 := [N]*G1{}
	listG2 := [N]*G2{}
	listSc := [N]*Scalar{}
	var ePQn, got Gt

	for i := 0; i < testTimes; i++ {
		got.SetIdentity()
		for j := 0; j < N; j++ {
			listG1[j] = randomG1(t)
			listG2[j] = randomG2(t)
			listSc[j] = randomScalar(t)

			ePQ := Pair(listG1[j], listG2[j])
			ePQn.Exp(ePQ, listSc[j])
			got.Mul(&got, &ePQn)
		}

		want := ProdPair(listG1[:], listG2[:], listSc[:])

		if !got.IsEqual(want) {
			test.ReportError(t, got, want)
		}
	}
}

func TestProdPairFrac(t *testing.T) {
	const testTimes = 1 << 5
	const N = 5

	listG1 := [N]*G1{}
	listG2 := [N]*G2{}
	listSc := [N]*Scalar{}
	listSigns := [N]int{}
	var ePQn, got Gt
	var coins [1]byte
	for i := 0; i < testTimes; i++ {
		got.SetIdentity()
		for j := 0; j < N; j++ {
			listG1[j] = randomG1(t)
			listG2[j] = randomG2(t)
			listSc[j] = &Scalar{}
			_, err := rand.Read(coins[:])
			test.CheckNoErr(t, err, "random reading failed")

			switch coins[0] & 1 {
			case 0:
				listSc[j].SetOne()
				listSc[j].Neg()
				listSigns[j] = -1

			case 1:
				listSc[j].SetOne()
				listSigns[j] = 1
			}

			ePQ := Pair(listG1[j], listG2[j])
			ePQn.Exp(ePQ, listSc[j])
			got.Mul(&got, &ePQn)
		}

		want := ProdPairFrac(listG1[:], listG2[:], listSigns[:])

		if !got.IsEqual(want) {
			test.ReportError(t, got, want)
		}
	}
}

func TestInputs(t *testing.T) {
	t.Run("Pair", func(t *testing.T) {
		P := *randomG1(t)
		Q := *randomG2(t)
		oldP := P
		oldQ := Q
		_ = Pair(&P, &Q)
		test.CheckOk(P == oldP, "the point P was overwritten", t)
		test.CheckOk(Q == oldQ, "the point Q was overwritten", t)
	})

	t.Run("ProdPair", func(t *testing.T) {
		P0, P1 := *randomG1(t), *randomG1(t)
		Q0, Q1 := *randomG2(t), *randomG2(t)
		n0, n1 := *randomScalar(t), *randomScalar(t)

		oldP0, oldP1 := P0, P1
		oldQ0, oldQ1 := Q0, Q1
		oldn0, oldn1 := n0, n1

		_ = ProdPair([]*G1{&P0, &P1}, []*G2{&Q0, &Q1}, []*Scalar{&n0, &n1})

		test.CheckOk(P0 == oldP0, "the point P0 was overwritten", t)
		test.CheckOk(P1 == oldP1, "the point P1 was overwritten", t)
		test.CheckOk(Q0 == oldQ0, "the point Q0 was overwritten", t)
		test.CheckOk(Q1 == oldQ1, "the point Q1 was overwritten", t)
		test.CheckOk(n0 == oldn0, "the scalar n0 was overwritten", t)
		test.CheckOk(n1 == oldn1, "the scalar n1 was overwritten", t)
	})

	t.Run("ProdPairFrac", func(t *testing.T) {
		P0, P1 := *randomG1(t), *randomG1(t)
		Q0, Q1 := *randomG2(t), *randomG2(t)

		oldP0, oldP1 := P0, P1
		oldQ0, oldQ1 := Q0, Q1

		_ = ProdPairFrac([]*G1{&P0, &P1}, []*G2{&Q0, &Q1}, []int{1, -1})

		test.CheckOk(P0 == oldP0, "the point P0 was overwritten", t)
		test.CheckOk(P1 == oldP1, "the point P1 was overwritten", t)
		test.CheckOk(Q0 == oldQ0, "the point Q0 was overwritten", t)
		test.CheckOk(Q1 == oldQ1, "the point Q1 was overwritten", t)
	})
}

func TestPairBilinear(t *testing.T) {
	testTimes := 1 << 5
	for i := 0; i < testTimes; i++ {
		g1 := G1Generator()
		g2 := G2Generator()
		a := randomScalar(t)
		b := randomScalar(t)

		ab := &Scalar{}
		ab.Mul(a, b)
		p := &G1{}
		q := &G2{}
		p.ScalarMult(a, g1)
		q.ScalarMult(b, g2)
		lhs := Pair(p, q)
		tmp := Pair(g1, g2)
		rhs := &Gt{}
		rhs.Exp(tmp, ab)
		if !lhs.IsEqual(rhs) {
			test.ReportError(t, lhs, rhs)
		}
	}
}

func TestPairIdentity(t *testing.T) {
	g1id := &G1{}
	g2id := &G2{}
	g1 := G1Generator()
	g2 := G2Generator()
	g1id.SetIdentity()
	g2id.SetIdentity()
	one := &Gt{}
	one.SetIdentity()
	ans := Pair(g1id, g2)
	if !ans.IsEqual(one) {
		test.ReportError(t, ans, one)
	}
	ans = Pair(g1, g2id)
	if !ans.IsEqual(one) {
		test.ReportError(t, ans, one)
	}
	ans = Pair(g1id, g2id)
	if !ans.IsEqual(one) {
		test.ReportError(t, ans, one)
	}
}

func TestProdPairIdentity(t *testing.T) {
	g1id := &G1{}
	g2id := &G2{}
	g1 := G1Generator()
	g2 := G2Generator()
	g1id.SetIdentity()
	g2id.SetIdentity()

	listExp := []*Scalar{new(Scalar), new(Scalar)}
	for i := range listExp {
		err := listExp[i].Random(rand.Reader)
		test.CheckNoErr(t, err, "random reading failed")
	}

	cases := []struct {
		g1 []*G1
		g2 []*G2
	}{
		{[]*G1{g1, g1id}, []*G2{g2, g2}},
		{[]*G1{g1, g1}, []*G2{g2, g2id}},
		{[]*G1{g1, g1id}, []*G2{g2, g2id}},
	}

	var e, want Gt
	for i, c := range cases {
		got := ProdPair(c.g1, c.g2, listExp)

		want.SetIdentity()
		for i := range len(c.g1) {
			e.Exp(Pair(c.g1[i], c.g2[i]), listExp[i])
			want.Mul(&want, &e)
		}

		if !got.IsEqual(&want) {
			test.ReportError(t, got, want, i, listExp)
		}
	}
}

func TestProdPairFracIdentity(t *testing.T) {
	g1id := &G1{}
	g2id := &G2{}
	g1 := G1Generator()
	g2 := G2Generator()
	g1id.SetIdentity()
	g2id.SetIdentity()

	listSign := []int{1, -1}

	cases := []struct {
		g1 []*G1
		g2 []*G2
	}{
		{[]*G1{g1id, g1}, []*G2{g2, g2}},
		{[]*G1{g1, g1id}, []*G2{g2, g2}},
		{[]*G1{g1, g1}, []*G2{g2, g2id}},
		{[]*G1{g1, g1}, []*G2{g2id, g2}},
		{[]*G1{g1, g1id}, []*G2{g2, g2id}},
		{[]*G1{g1id, g1}, []*G2{g2id, g2}},
		{[]*G1{g1id, g1id}, []*G2{g2id, g2id}},
	}

	var want Gt
	for i, c := range cases {
		got := ProdPairFrac(c.g1, c.g2, listSign)

		want.SetIdentity()
		for i := range len(c.g1) {
			e := Pair(c.g1[i], c.g2[i])
			if listSign[i] == -1 { //#nosec G602 -- listSign length matches c.g1
				e.Inv(e)
			}
			want.Mul(&want, e)
		}

		if !got.IsEqual(&want) {
			test.ReportError(t, got, want, i, listSign)
		}
	}
}

func TestAffinize(t *testing.T) {
	cmp := func(x, y G1) (b int) {
		if !x.IsEqual(&y) {
			return 1
		}
		return
	}

	const SIZE = 10
	x := make([]*G1, SIZE)
	for i := range x {
		if i%3 == 1 {
			x[i] = new(G1)
			x[i].SetIdentity()
		} else {
			x[i] = randomG1(t)
		}
	}

	got := affinize(x)
	want := make([]G1, SIZE)
	for i := range want {
		want[i] = *x[i]
		want[i].toAffine()
	}

	if slices.CompareFunc(got, want, cmp) != 0 {
		test.ReportError(t, got, want, x)
	}
}

func BenchmarkMiller(b *testing.B) {
	g1 := G1Generator()
	g2 := G2Generator()
	mi := new(ff.Fp12)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		miller(mi, g1, g2)
	}
}

func BenchmarkFinalExpo(b *testing.B) {
	g1 := G1Generator()
	g2 := G2Generator()
	mi := new(ff.Fp12)
	miller(mi, g1, g2)
	c := &ff.Cyclo6{}
	u := &ff.URoot{}
	g := &Gt{}

	ff.EasyExponentiation(c, mi)

	b.Run("EasyExp", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ff.EasyExponentiation(c, mi)
		}
	})
	b.Run("HardExp", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ff.HardExponentiation(u, c)
		}
	})
	b.Run("FinalExp", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			finalExp(g, mi)
		}
	})
}

func BenchmarkPair(b *testing.B) {
	g1 := G1Generator()
	g2 := G2Generator()

	const N = 3
	listG1 := [N]*G1{}
	listG2 := [N]*G2{}
	listExp := [N]*Scalar{}
	for i := 0; i < N; i++ {
		listG1[i] = new(G1)
		*listG1[i] = *g1
		listG2[i] = new(G2)
		*listG2[i] = *g2
		listExp[i] = randomScalar(b)
	}

	b.Run("Pair", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Pair(g1, g2)
		}
	})
	b.Run(fmt.Sprintf("ProdPair%v", N), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ProdPair(listG1[:], listG2[:], listExp[:])
		}
	})
}
