package csidh

import (
	"io"
)

// 511-bit number representing prime field element GF(p)
type fp [numWords]uint64

// Represents projective point on elliptic curve E over GF(p)
type point struct {
	x fp
	z fp
}

// Curve coefficients
type coeff struct {
	a fp
	c fp
}

type fpRngGen struct {
	// working buffer needed to avoid memory allocation
	wbuf [64]byte
}

// Defines operations on public key
type PublicKey struct {
	fpRngGen
	// Montgomery coefficient A from GF(p) of the elliptic curve
	// y^2 = x^3 + Ax^2 + x.
	a fp
}

// Defines operations on private key
type PrivateKey struct {
	fpRngGen
	// private key is a set of integers randomly
	// each sampled from a range [-5, 5].
	e [PrivateKeySize]int8
}

// randFp generates random element from Fp.
func (s *fpRngGen) randFp(v *fp, rng io.Reader) {
	mask := uint64(1<<(pbits%limbBitSize)) - 1
	for {
		*v = fp{}
		_, err := io.ReadFull(rng, s.wbuf[:])
		if err != nil {
			panic("Can't read random number")
		}

		for i := 0; i < len(s.wbuf); i++ {
			j := i / limbByteSize
			k := uint(i % 8)
			v[j] |= uint64(s.wbuf[i]) << (8 * k)
		}

		v[len(v)-1] &= mask
		if isLess(v, &p) {
			return
		}
	}
}

// cofactorMul helper implements batch cofactor multiplication as described
// in the ia.cr/2018/383 (algo. 3). Returns tuple of two booleans, first indicates
// if function has finished successfully. In case first return value is true,
// second return value indicates if curve represented by coffactor 'a' is
// supersingular.
// Implementation uses divide-and-conquer strategy and recursion in order to
// speed up calculation of Q_i = [(p+1)/l_i] * P.
// Implementation is not constant time, but it operates on public data only.
func cofactorMul(p *point, a *coeff, halfL, halfR int, order *fp) (bool, bool) {
	var Q point
	var r1, d1, r2, d2 bool
	if (halfR - halfL) == 1 {
		// base case
		if !p.z.isZero() {
			tmp := fp{primes[halfL]}
			xMul(p, p, a, &tmp)

			if !p.z.isZero() {
				// order does not divide p+1 -> ordinary curve
				return true, false
			}

			mul512(order, order, primes[halfL])
			if isLess(&fourSqrtP, order) {
				// order > 4*sqrt(p) -> supersingular curve
				return true, true
			}
		}
		return false, false
	}

	// perform another recursive step
	mid := halfL + ((halfR - halfL + 1) / 2)
	mulL, mulR := fp{1}, fp{1}
	// compute u = primes_1 * ... * primes_m
	for i := halfL; i < mid; i++ {
		mul512(&mulR, &mulR, primes[i])
	}
	// compute v = primes_m+1 * ... * primes_n
	for i := mid; i < halfR; i++ {
		mul512(&mulL, &mulL, primes[i])
	}

	// calculate Q_i
	xMul(&Q, p, a, &mulR)
	xMul(p, p, a, &mulL)

	d1, r1 = cofactorMul(&Q, a, mid, halfR, order)
	d2, r2 = cofactorMul(p, a, halfL, mid, order)
	return d1 || d2, r1 || r2
}

// groupAction evaluates group action of prv.e on a Montgomery
// curve represented by coefficient pub.A.
// This is implementation of algorithm 2 from ia.cr/2018/383.
func groupAction(pub *PublicKey, prv *PrivateKey, rng io.Reader) {
	var k [2]fp
	var e [2][primeCount]uint8
	done := [2]bool{false, false}
	A := coeff{a: pub.a, c: one}

	k[0][0] = 4
	k[1][0] = 4

	for i, v := range primes {
		t := (prv.e[uint(i)>>1] << ((uint(i) % 2) * 4)) >> 4
		if t > 0 {
			e[0][i] = uint8(t)
			e[1][i] = 0
			mul512(&k[1], &k[1], v)
		} else if t < 0 {
			e[1][i] = uint8(-t)
			e[0][i] = 0
			mul512(&k[0], &k[0], v)
		} else {
			e[0][i] = 0
			e[1][i] = 0
			mul512(&k[0], &k[0], v)
			mul512(&k[1], &k[1], v)
		}
	}

	for {
		var P point
		var rhs fp
		prv.randFp(&P.x, rng)
		P.z = one
		montEval(&rhs, &A.a, &P.x)
		sign := rhs.isNonQuadRes()

		if done[sign] {
			continue
		}

		xMul(&P, &P, &A, &k[sign])
		done[sign] = true

		for i, v := range primes {
			if e[sign][i] != 0 {
				cof := fp{1}
				var K point

				for j := i + 1; j < len(primes); j++ {
					if e[sign][j] != 0 {
						mul512(&cof, &cof, primes[j])
					}
				}

				xMul(&K, &P, &A, &cof)
				if !K.z.isZero() {
					xIso(&P, &A, &K, v)
					e[sign][i] = e[sign][i] - 1
					if e[sign][i] == 0 {
						mul512(&k[sign], &k[sign], primes[i])
					}
				}
			}
			done[sign] = done[sign] && (e[sign][i] == 0)
		}

		modExpRdc512(&A.c, &A.c, &pMin1)
		mulRdc(&A.a, &A.a, &A.c)
		A.c = one

		if done[0] && done[1] {
			break
		}
	}
	pub.a = A.a
}

// PrivateKey operations

func (c *PrivateKey) Import(key []byte) bool {
	if len(key) < len(c.e) {
		return false
	}
	for i, v := range key {
		c.e[i] = int8(v)
	}
	return true
}

func (c PrivateKey) Export(out []byte) bool {
	if len(out) < len(c.e) {
		return false
	}
	for i, v := range c.e {
		out[i] = byte(v)
	}
	return true
}

func GeneratePrivateKey(key *PrivateKey, rng io.Reader) error {
	for i := range key.e {
		key.e[i] = 0
	}

	for i := 0; i < len(primes); {
		_, err := io.ReadFull(rng, key.wbuf[:])
		if err != nil {
			return err
		}

		for j := range key.wbuf {
			if int8(key.wbuf[j]) <= expMax && int8(key.wbuf[j]) >= -expMax {
				key.e[i>>1] |= int8((key.wbuf[j] & 0xF) << uint((i%2)*4))
				i = i + 1
				if i == len(primes) {
					break
				}
			}
		}
	}
	return nil
}

// Public key operations

// reset removes key material from PublicKey.
func (c *PublicKey) reset() {
	for i := range c.a {
		c.a[i] = 0
	}
}

// Assumes key is in Montgomery domain.
func (c *PublicKey) Import(key []byte) bool {
	if len(key) != numWords*limbByteSize {
		return false
	}
	for i := 0; i < len(key); i++ {
		j := i / limbByteSize
		k := uint64(i % 8)
		c.a[j] |= uint64(key[i]) << (8 * k)
	}
	return true
}

// Assumes key is exported as encoded in Montgomery domain.
func (c *PublicKey) Export(out []byte) bool {
	if len(out) != numWords*limbByteSize {
		return false
	}
	for i := 0; i < len(out); i++ {
		j := i / limbByteSize
		k := uint64(i % 8)
		out[i] = byte(c.a[j] >> (8 * k))
	}
	return true
}

func GeneratePublicKey(pub *PublicKey, prv *PrivateKey, rng io.Reader) {
	pub.reset()
	groupAction(pub, prv, rng)
}

// Validate returns true if 'pub' is a valid cSIDH public key,
// otherwise false.
// More precisely, the function verifies that curve
//
//	y^2 = x^3 + pub.a * x^2 + x
//
// is supersingular.
func Validate(pub *PublicKey, rng io.Reader) bool {
	// Check if in range
	if !isLess(&pub.a, &p) {
		return false
	}

	// Check if pub represents a smooth Montgomery curve.
	if pub.a.equal(&two) || pub.a.equal(&twoNeg) {
		return false
	}

	// Check if pub represents a supersingular curve.
	for {
		var P point
		A := point{pub.a, one}

		// Randomly chosen P must have big enough order to check
		// supersingularity. Probability of random P having big
		// enough order is very high, as proven by W.Castryck et
		// al. (ia.cr/2018/383, ch 5)
		pub.randFp(&P.x, rng)
		P.z = one

		xDbl(&P, &P, &A)
		xDbl(&P, &P, &A)

		done, res := cofactorMul(&P, &coeff{A.x, A.z}, 0, len(primes), &fp{1})
		if done {
			return res
		}
	}
}

// DeriveSecret computes a cSIDH shared secret. If successful, returns true
// and fills 'out' with shared secret. Function returns false in case 'pub' is invalid.
// More precisely, shared secret is a Montgomery coefficient A of a secret
// curve y^2 = x^3 + Ax^2 + x, computed by applying action of a prv.e
// on a curve represented by pub.a.
func DeriveSecret(out *[64]byte, pub *PublicKey, prv *PrivateKey, rng io.Reader) bool {
	if !Validate(pub, rng) {
		return false
	}
	groupAction(pub, prv, rng)
	pub.Export(out[:])
	return true
}
