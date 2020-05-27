package csidh

import "math/bits"

// mul576 implements schoolbook multiplication of
// 64x512-bit integer. Returns result modulo 2^512.
// r = m1*m2.
func mul512Generic(r, m1 *fp, m2 uint64) {
	var c, h, l uint64

	c, r[0] = bits.Mul64(m2, m1[0])

	h, l = bits.Mul64(m2, m1[1])
	r[1], c = bits.Add64(l, c, 0)
	c = h + c

	h, l = bits.Mul64(m2, m1[2])
	r[2], c = bits.Add64(l, c, 0)
	c = h + c

	h, l = bits.Mul64(m2, m1[3])
	r[3], c = bits.Add64(l, c, 0)
	c = h + c

	h, l = bits.Mul64(m2, m1[4])
	r[4], c = bits.Add64(l, c, 0)
	c = h + c

	h, l = bits.Mul64(m2, m1[5])
	r[5], c = bits.Add64(l, c, 0)
	c = h + c

	h, l = bits.Mul64(m2, m1[6])
	r[6], c = bits.Add64(l, c, 0)
	c = h + c

	_, l = bits.Mul64(m2, m1[7])
	r[7], _ = bits.Add64(l, c, 0)
}

// mul576 implements schoolbook multiplication of
// 64x512-bit integer. Returns 576-bit result of
// multiplication.
// r = m1*m2.
func mul576Generic(r *[9]uint64, m1 *fp, m2 uint64) {
	var c, h, l uint64

	c, r[0] = bits.Mul64(m2, m1[0])

	h, l = bits.Mul64(m2, m1[1])
	r[1], c = bits.Add64(l, c, 0)
	c = h + c

	h, l = bits.Mul64(m2, m1[2])
	r[2], c = bits.Add64(l, c, 0)
	c = h + c

	h, l = bits.Mul64(m2, m1[3])
	r[3], c = bits.Add64(l, c, 0)
	c = h + c

	h, l = bits.Mul64(m2, m1[4])
	r[4], c = bits.Add64(l, c, 0)
	c = h + c

	h, l = bits.Mul64(m2, m1[5])
	r[5], c = bits.Add64(l, c, 0)
	c = h + c

	h, l = bits.Mul64(m2, m1[6])
	r[6], c = bits.Add64(l, c, 0)
	c = h + c

	h, l = bits.Mul64(m2, m1[7])
	r[7], c = bits.Add64(l, c, 0)
	r[8], c = bits.Add64(h, c, 0)
	r[8] += c
}

// cswap512 implements constant time swap operation.
// If choice = 0, leave x,y unchanged. If choice = 1, set x,y = y,x.
// If choice is neither 0 nor 1 then behaviour is undefined.
func cswap512Generic(x, y *fp, choice uint8) {
	var tmp uint64
	mask64 := 0 - uint64(choice)

	for i := 0; i < numWords; i++ {
		tmp = mask64 & (x[i] ^ y[i])
		x[i] = tmp ^ x[i]
		y[i] = tmp ^ y[i]
	}
}

// mulRdc performs montgomery multiplication r = x * y mod P.
// Returned result r is already reduced and in Montgomery domain.
func mulRdcGeneric(r, x, y *fp) {
	var t fp
	var c uint64

	mulGeneric(r, x, y)

	// if p <= r < 2p then r = r-p
	t[0], c = bits.Sub64(r[0], p[0], 0)
	t[1], c = bits.Sub64(r[1], p[1], c)
	t[2], c = bits.Sub64(r[2], p[2], c)
	t[3], c = bits.Sub64(r[3], p[3], c)
	t[4], c = bits.Sub64(r[4], p[4], c)
	t[5], c = bits.Sub64(r[5], p[5], c)
	t[6], c = bits.Sub64(r[6], p[6], c)
	t[7], c = bits.Sub64(r[7], p[7], c)

	w := 0 - c
	r[0] = ctPick64(w, r[0], t[0])
	r[1] = ctPick64(w, r[1], t[1])
	r[2] = ctPick64(w, r[2], t[2])
	r[3] = ctPick64(w, r[3], t[3])
	r[4] = ctPick64(w, r[4], t[4])
	r[5] = ctPick64(w, r[5], t[5])
	r[6] = ctPick64(w, r[6], t[6])
	r[7] = ctPick64(w, r[7], t[7])
}

func mulGeneric(r, x, y *fp) {
	var s fp // keeps intermediate results
	var t1, t2 [9]uint64
	var c, q uint64

	for i := 0; i < numWords-1; i++ {
		q = ((x[i] * y[0]) + s[0]) * pNegInv[0]
		mul576Generic(&t1, &p, q)
		mul576Generic(&t2, y, x[i])

		// x[i]*y + q_i*p
		t1[0], c = bits.Add64(t1[0], t2[0], 0)
		t1[1], c = bits.Add64(t1[1], t2[1], c)
		t1[2], c = bits.Add64(t1[2], t2[2], c)
		t1[3], c = bits.Add64(t1[3], t2[3], c)
		t1[4], c = bits.Add64(t1[4], t2[4], c)
		t1[5], c = bits.Add64(t1[5], t2[5], c)
		t1[6], c = bits.Add64(t1[6], t2[6], c)
		t1[7], c = bits.Add64(t1[7], t2[7], c)
		t1[8], _ = bits.Add64(t1[8], t2[8], c)

		// s = (s + x[i]*y + q_i * p) / R
		_, c = bits.Add64(t1[0], s[0], 0)
		s[0], c = bits.Add64(t1[1], s[1], c)
		s[1], c = bits.Add64(t1[2], s[2], c)
		s[2], c = bits.Add64(t1[3], s[3], c)
		s[3], c = bits.Add64(t1[4], s[4], c)
		s[4], c = bits.Add64(t1[5], s[5], c)
		s[5], c = bits.Add64(t1[6], s[6], c)
		s[6], c = bits.Add64(t1[7], s[7], c)
		s[7], _ = bits.Add64(t1[8], 0, c)
	}

	// last iteration stores result in r
	q = ((x[numWords-1] * y[0]) + s[0]) * pNegInv[0]
	mul576Generic(&t1, &p, q)
	mul576Generic(&t2, y, x[numWords-1])

	t1[0], c = bits.Add64(t1[0], t2[0], c)
	t1[1], c = bits.Add64(t1[1], t2[1], c)
	t1[2], c = bits.Add64(t1[2], t2[2], c)
	t1[3], c = bits.Add64(t1[3], t2[3], c)
	t1[4], c = bits.Add64(t1[4], t2[4], c)
	t1[5], c = bits.Add64(t1[5], t2[5], c)
	t1[6], c = bits.Add64(t1[6], t2[6], c)
	t1[7], c = bits.Add64(t1[7], t2[7], c)
	t1[8], _ = bits.Add64(t1[8], t2[8], c)

	_, c = bits.Add64(t1[0], s[0], 0)
	r[0], c = bits.Add64(t1[1], s[1], c)
	r[1], c = bits.Add64(t1[2], s[2], c)
	r[2], c = bits.Add64(t1[3], s[3], c)
	r[3], c = bits.Add64(t1[4], s[4], c)
	r[4], c = bits.Add64(t1[5], s[5], c)
	r[5], c = bits.Add64(t1[6], s[6], c)
	r[6], c = bits.Add64(t1[7], s[7], c)
	r[7], _ = bits.Add64(t1[8], 0, c)
}
