// +build amd64,!noasm

package csidh

import "math/bits"

//go:noescape
func mul512(a, b *fp, c uint64)

//go:noescape
func mul576(a *[9]uint64, b *fp, c uint64)

//go:noescape
func cswap512(x, y *fp, choice uint8)

//go:noescape
func mulBmiAsm(res, x, y *fp)

// mulRdc performs montgomery multiplication r = x * y mod P.
// Returned result r is already reduced and in Montgomery domain.
func mulRdc(r, x, y *fp) {
	var t fp
	var c uint64

	if hasADXandBMI2 {
		mulBmiAsm(r, x, y)
	} else {
		mulGeneric(r, x, y)
	}

	// if p <= r < 2p then r = r-p
	t[0], c = bits.Sub64(r[0], p[0], 0)
	t[1], c = bits.Sub64(r[1], p[1], c)
	t[2], c = bits.Sub64(r[2], p[2], c)
	t[3], c = bits.Sub64(r[3], p[3], c)
	t[4], c = bits.Sub64(r[4], p[4], c)
	t[5], c = bits.Sub64(r[5], p[5], c)
	t[6], c = bits.Sub64(r[6], p[6], c)
	t[7], c = bits.Sub64(r[7], p[7], c)

	var w = 0 - c
	r[0] = ctPick64(w, r[0], t[0])
	r[1] = ctPick64(w, r[1], t[1])
	r[2] = ctPick64(w, r[2], t[2])
	r[3] = ctPick64(w, r[3], t[3])
	r[4] = ctPick64(w, r[4], t[4])
	r[5] = ctPick64(w, r[5], t[5])
	r[6] = ctPick64(w, r[6], t[6])
	r[7] = ctPick64(w, r[7], t[7])
}
