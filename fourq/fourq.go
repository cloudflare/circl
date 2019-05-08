// Package fourq implements FourQ, a high-speed elliptic curve at the 128-bit
// security level.
//
// https://eprint.iacr.org/2015/565.pdf
package fourq

func multByCofactor(pt *point) {
	temp := (&point{}).Set(pt)
	feMul(&temp.t, &temp.t, d)

	pDbl(pt)
	pMixedAdd(pt, temp)
	pDbl(pt)
	pDbl(pt)
	pDbl(pt)
	pDbl(pt)
	pMixedAdd(pt, temp)
	pDbl(pt)
	pDbl(pt)
	pDbl(pt)
}

func scalarBaseMult(k []byte) *point {
	if len(k) > 32 {
		return nil
	}
	K := make([]byte, 32)
	copy(K[32-len(k):], k)

	sum := newPoint()

	for i := 0; i < 4; i++ {
		for bit := uint(0); bit < 8; bit++ {
			var idx byte
			for block := 0; block < 8; block++ {
				idx = 2*idx + ((K[4*block+i] >> (7 - bit)) & 1)
			}

			pDbl(sum)
			if idx != 0 {
				pMixedAdd(sum, generatorBase[idx])
			}
		}
	}

	return sum
}

func scalarMult(pt *point, k []byte, clearCofactor bool) *point {
	if clearCofactor {
		multByCofactor(pt)
		pt.MakeAffine()
	}
	feMul(&pt.t, &pt.t, d)

	sum := newPoint()

	for _, byte := range k {
		for bit := 0; bit < 8; bit++ {
			pDbl(sum)
			if byte&0x80 == 0x080 {
				pMixedAdd(sum, pt)
			}
			byte <<= 1
		}
	}

	return sum
}

// IsOnCurve returns true if pt represents a compressed point on the curve
// (including the identity point and points in a non-prime order subgroup) and
// false otherwise.
func IsOnCurve(pt [32]byte) bool {
	_, ok := newPoint().SetBytes(pt)
	return ok
}

// IsOnCurveU returns true if pt represents an uncompressed point on the curve.
func IsOnCurveU(pt [64]byte) bool {
	_, ok := newPoint().SetBytesU(pt)
	return ok
}

// ScalarBaseMult returns the generator multiplied by scalar k, compressed. k's
// slice should be 32 bytes long or shorter (or the function will return nil and
// false).
func ScalarBaseMult(k []byte) ([32]byte, bool) {
	pt := scalarBaseMult(k)
	if pt == nil {
		return [32]byte{}, false
	}
	return pt.Bytes(), true
}

// ScalarBaseMultU returns the generator multiplied by scalar k, uncompressed.
func ScalarBaseMultU(k []byte) ([64]byte, bool) {
	pt := scalarBaseMult(k)
	if pt == nil {
		return [64]byte{}, false
	}
	return pt.BytesU(), true
}

// ScalarMult returns the compressed point multiplied by scalar k. The function
// returns false if pt does not represent a point on the curve, of if the output
// is the identity point. When clearCofactor=true, it additionally returns false
// when pt is not in the prime-order subgroup.
func ScalarMult(pt [32]byte, k []byte, clearCofactor bool) ([32]byte, bool) {
	in, ok := (&point{}).SetBytes(pt)
	if !ok {
		return [32]byte{}, false
	}

	out := scalarMult(in, k, clearCofactor).Bytes()
	return out, out != [32]byte{1}
}

// ScalarMultU returns the uncompressed point multiplied by scalar k.
func ScalarMultU(pt [64]byte, k []byte, clearCofactor bool) ([64]byte, bool) {
	in, ok := (&point{}).SetBytesU(pt)
	if !ok {
		return [64]byte{}, false
	}

	out := scalarMult(in, k, clearCofactor).BytesU()
	return out, out != uncompressedIdentity
}
