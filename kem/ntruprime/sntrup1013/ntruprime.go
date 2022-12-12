// Code generated from sntrup.templ.go. DO NOT EDIT.

// Package sntrup1013 implements the IND-CCA2 secure key encapsulation mechanism
// sntrup1013 as submitted to round 3 of the NIST PQC competition and
// described in
//
// https://ntruprime.cr.yp.to/nist/ntruprime-20201007.pdf
package sntrup1013

import (
	"bytes"
	cryptoRand "crypto/rand"
	"crypto/sha512"

	"github.com/cloudflare/circl/internal/nist"
	"github.com/cloudflare/circl/kem/ntruprime/internal"
	"github.com/cloudflare/circl/pke/ntruprime/kem"
	ntrup "github.com/cloudflare/circl/pke/ntruprime/sntrup1013"
)

type (
	small  int8
	Fq     int16
	Inputs [p]small
)

const (
	p            = ntrup.P
	q            = ntrup.Q
	q12          = ((q - 1) / 2)
	roundedBytes = ntrup.RoundedBytes
	rqBytes      = ntrup.RqBytes
	w            = ntrup.W

	hashBytes = 32

	smallBytes = ((p + 3) / 4)

	inputsBytes      = smallBytes
	ciphertextsBytes = roundedBytes
	secretKeysBytes  = (2 * smallBytes)
	publicKeysBytes  = rqBytes

	confirmBytes = 32
)

const (
	// Size of the established shared key.
	SharedKeySize = ntrup.SharedKeySize

	// Size of the encapsulated shared key.
	CiphertextSize = ntrup.CiphertextSize

	// Size of a packed public key.
	PublicKeySize = ntrup.PublicKeySize

	// Size of a packed private key.
	PrivateKeySize = ntrup.PrivateKeySize
)

// Arithmetic operations over GF(3)

// A polynomial of R has all of its coefficients in (-1,0,1)
// F3 is always represented as -1,0,1
// so ZZ_fromF3 is a no-op

// x must not be close to top int16
func f3Freeze(x int16) small {
	return small(internal.Int32_mod_uint14(int32(x)+1, 3)) - 1
}

// Arithmetic operations over GF(q)

/* always represented as -q12...q12 */
/* so ZZ_fromFq is a no-op */

/* x must not be close to top int32 */
func fqFreeze(x int32) Fq {
	return Fq(internal.Int32_mod_uint14(x+q12, q) - q12)
}

// Calculates reciprocal of Fq
func fqRecip(a1 Fq) Fq {
	var i int = 1
	ai := a1

	for i < (q - 2) {
		ai = fqFreeze(int32(a1) * int32(ai))
		i += 1
	}
	return ai
}

// Returns 0 if the weight w is equal to r
// otherwise returns -1
func weightwMask(r []small) int {
	var weight int = 0

	for i := 0; i < p; i++ {
		weight += int(r[i]) & 1
	}

	// returns -1 if non zero
	// otherwise returns 0 if weight==w
	return internal.Int16_nonzero_mask(int16(weight - w))

}

/* R3_fromR(R_fromRq(r)) */
func r3FromRq(r []Fq) []small {
	out := make([]small, p)
	for i := 0; i < p; i++ {
		out[i] = small(f3Freeze(int16(r[i])))
	}
	return out
}

// h = f*g in the ring R3
func r3Mult(f []small, g []small) (h []small) {
	h = make([]small, p)
	fg := make([]small, p+p-1)
	var result small
	var i, j int

	for i = 0; i < p; i++ {
		result = 0
		for j = 0; j <= i; j++ {
			result = f3Freeze(int16(result + f[j]*g[i-j]))
		}
		fg[i] = result
	}

	for i = p; i < p+p-1; i++ {
		result = 0
		for j = i - p + 1; j < p; j++ {
			result = f3Freeze(int16(result + f[j]*g[i-j]))
		}
		fg[i] = result
	}

	for i = p + p - 2; i >= p; i-- {
		fg[i-p] = f3Freeze(int16(fg[i-p] + fg[i]))
		fg[i-p+1] = f3Freeze(int16(fg[i-p+1] + fg[i]))
	}

	for i = 0; i < p; i++ {
		h[i] = fg[i]
	}

	return h

}

// Calculates the reciprocal of R3 polynomials
// Returns 0 if recip succeeded; else -1
func r3Recip(in []small) ([]small, int) {
	out := make([]small, p)
	f := make([]small, p+1)
	g := make([]small, p+1)
	v := make([]small, p+1)
	r := make([]small, p+1)

	var sign int

	r[0] = 1
	f[0] = 1

	f[p-1] = -1
	f[p] = -1

	for i := 0; i < p; i++ {
		g[p-1-i] = in[i]
	}

	g[p] = 0

	delta := 1

	for loop := 0; loop < 2*p-1; loop++ {
		for i := p; i > 0; i-- {
			v[i] = v[i-1]
		}
		v[0] = 0

		sign = int(-g[0] * f[0])
		var swap int = int(internal.Int16_negative_mask(int16(-delta)) & internal.Int16_nonzero_mask(int16(g[0])))
		delta ^= swap & int(delta^-delta)
		delta += 1

		for i := 0; i < p+1; i++ {
			t := swap & int(f[i]^g[i])
			f[i] ^= small(t)
			g[i] ^= small(t)
			t = swap & int(v[i]^r[i])
			v[i] ^= small(t)
			r[i] ^= small(t)
		}
		for i := 0; i < p+1; i++ {
			g[i] = f3Freeze(int16(int(g[i]) + sign*int(f[i])))
		}

		for i := 0; i < p+1; i++ {
			r[i] = f3Freeze(int16(int(r[i]) + sign*int(v[i])))
		}

		for i := 0; i < p; i++ {
			g[i] = g[i+1]
		}

		g[p] = 0

	}
	sign = int(f[0])

	for i := 0; i < p; i++ {

		out[i] = small(sign * int(v[p-1-i]))
	}

	return out, internal.Int16_nonzero_mask(int16(delta))

}

// Polynomials mod q

// h = f*g in the ring Rq */
func rqMultSmall(f []Fq, g []small) (h []Fq) {
	h = make([]Fq, p)
	fg := make([]Fq, p+p-1)
	var result Fq

	for i := 0; i < p; i++ {
		result = 0
		for j := 0; j <= i; j++ {
			result = fqFreeze(int32(result) + int32(f[j])*(int32)(g[i-j]))
		}
		fg[i] = result
	}

	for i := p; i < p+p-1; i++ {
		result = 0
		for j := i - p + 1; j < p; j++ {
			result = fqFreeze(int32(result) + int32(f[j])*(int32)(g[i-j]))
		}
		fg[i] = result
	}

	for i := p + p - 2; i >= p; i-- {
		fg[i-p] = fqFreeze(int32(fg[i-p] + fg[i]))
		fg[i-p+1] = fqFreeze(int32(fg[i-p+1] + fg[i]))

	}

	for i := 0; i < p; i++ {
		h[i] = fg[i]
	}
	return h
}

// h = 3f in Rq
func rqMult3(f []Fq) (h []Fq) {
	h = make([]Fq, p)
	for i := 0; i < p; i++ {
		h[i] = fqFreeze(int32(3 * f[i]))
	}
	return h
}

// Returns 0 if recip succeeded; else -1
// out = 1/(3*in) in Rq
func rqRecip3(in []small) ([]Fq, int) {
	out := make([]Fq, p)
	f := make([]Fq, p+1)
	g := make([]Fq, p+1)
	v := make([]Fq, p+1)
	r := make([]Fq, p+1)

	var swap, t int
	var f0, g0 int32

	r[0] = fqRecip(3)
	f[0] = 1
	f[p-1] = -1
	f[p] = -1

	for i := 0; i < p; i++ {
		g[p-1-i] = Fq(in[i])
	}
	g[p] = 0

	delta := 1

	for loop := 0; loop < 2*p-1; loop++ {
		for i := p; i > 0; i-- {
			v[i] = v[i-1]
		}
		v[0] = 0

		swap = internal.Int16_negative_mask(int16(-delta)) & internal.Int16_nonzero_mask(int16(g[0]))
		delta ^= swap & (delta ^ -delta)
		delta += 1

		for i := 0; i < p+1; i++ {
			t = swap & int(f[i]^g[i])
			f[i] ^= Fq(t)
			g[i] ^= Fq(t)
			t = swap & int(v[i]^r[i])
			v[i] ^= Fq(t)
			r[i] ^= Fq(t)
		}

		f0 = int32(f[0])
		g0 = int32(g[0])

		for i := 0; i < p+1; i++ {
			g[i] = fqFreeze(f0*int32(g[i]) - g0*int32(f[i]))
		}
		for i := 0; i < p+1; i++ {
			r[i] = fqFreeze(f0*int32(r[i]) - g0*int32(v[i]))
		}

		for i := 0; i < p; i++ {
			g[i] = g[i+1]
		}
		g[p] = 0
	}

	scale := Fq(fqRecip(f[0]))
	for i := 0; i < p; i++ {
		out[i] = fqFreeze(int32(scale) * (int32)(v[p-1-i]))
	}

	return out, internal.Int16_nonzero_mask(int16(delta))

}

// Rounding all coefficients of a polynomial to the nearest multiple of 3
// Rounded polynomials mod q
func round(a []Fq) []Fq {
	out := make([]Fq, p)
	for i := 0; i < p; i++ {
		out[i] = a[i] - Fq(f3Freeze(int16(a[i])))
	}
	return out
}

// Returns (min(x, y), max(x, y)), executes in constant time
func minmax(x, y *uint32) {
	var xi uint32 = *x
	var yi uint32 = *y
	var xy uint32 = xi ^ yi
	var c uint32 = yi - xi
	c ^= xy & (c ^ yi ^ 0x80000000)
	c >>= 31
	c = -c
	c &= xy
	*x = xi ^ c
	*y = yi ^ c
}

// Sorts the array of unsigned integers
func cryptoSortUint32(x []uint32, n int) {
	if n < 2 {
		return
	}
	top := 1

	for top < n-top {
		top += top
	}

	for p := top; p > 0; p >>= 1 {
		for i := 0; i < n-p; i++ {
			if i&p == 0 {
				minmax(&x[i], &x[i+p])
			}
		}
		for q := top; q > p; q >>= 1 {
			for i := 0; i < n-q; i++ {
				if i&p == 0 {
					minmax(&x[i+p], &x[i+q])
				}
			}
		}
	}
}

// Sorting to generate short polynomial
func shortFromList(in []int32) []small {
	out := make([]small, p)
	L := make([]uint32, p)

	var neg2, neg3 int = -2, -3

	for i := 0; i < w; i++ {
		L[i] = uint32(in[i]) & uint32((neg2))
	}

	for i := w; i < p; i++ {
		L[i] = (uint32(in[i]) & uint32((neg3))) | 1
	}

	cryptoSortUint32(L, p)

	for i := 0; i < p; i++ {
		out[i] = small((L[i] & 3) - 1)
	}
	return out
}

//  Underlying hash function

// The input byte array, in, is prepended by the byte b
// and its SHA-512 hash is calculated
// Only the first 32 bytes of the hash are returned
// e.g., b = 0 means out = Hash0(in)
func hashPrefix(out []byte, b int, in []byte, inlen int) {
	x := make([]byte, inlen+1)
	h := make([]byte, 64)

	x[0] = byte(b)
	copy(x[1:], in)

	hash := sha512.New()
	hash.Write([]byte(x))
	h = hash.Sum(nil)

	copy(out, h[:32])

}

// Higher level randomness
// Returns a random unsigned integer
// A generator can be passed for deterministic number generation
func urandom32(gen *nist.DRBG) uint32 {

	c := make([]byte, 4)
	var out [4]uint32

	if gen != nil {
		gen.Fill(c)
	} else {
		cryptoRand.Read(c)

	}

	out[0] = uint32(c[0])
	out[1] = uint32(c[1]) << 8
	out[2] = uint32(c[2]) << 16
	out[3] = uint32(c[3]) << 24
	return out[0] + out[1] + out[2] + out[3]
}

// Generates a random short polynomial
func shortRandom(gen *nist.DRBG) []small {

	L := make([]uint32, p)

	for i := 0; i < p; i++ {
		L[i] = urandom32(gen)
	}

	// Converts uint32 array to int32 array
	L_int32 := make([]int32, p)
	for i := 0; i < len(L); i++ {
		L_int32[i] = int32(L[i])
	}
	out := shortFromList(L_int32)

	return out

}

// Generates a random list of small
func smallRandom(gen *nist.DRBG) []small {

	out := make([]small, p)
	for i := 0; i < p; i++ {
		out[i] = small(((urandom32(gen)&0x3fffffff)*3)>>30) - 1
	}
	return out
}

// Streamlined NTRU Prime Core

// h,(f,ginv) = keyGen()
func keyGen(gen *nist.DRBG) (h []Fq, f []small, ginv []small) {
	g := make([]small, p)
	var err int
	for {
		g = smallRandom(gen)
		ginv, err = r3Recip(g)
		if err == 0 {
			break
		}

	}

	f = shortRandom(gen)

	finv, _ := rqRecip3(f) /* always works */
	h = rqMultSmall(finv, g)
	return h, f, ginv
}

// c = encrypt(r,h)
func encrypt(r []small, h []Fq) []Fq {

	hr := rqMultSmall(h, r)
	c := round(hr)

	return c

}

// r = decrypt(c,(f,ginv))
func decrypt(c []Fq, f []small, ginv []small) []small {
	r := make([]small, p)
	cf := make([]Fq, p)

	cf = rqMultSmall(c, f)
	cf3 := rqMult3(cf)
	e := r3FromRq(cf3)
	ev := r3Mult(e, ginv)

	mask := weightwMask(ev) /* 0 if weight w, else -1 */
	for i := 0; i < w; i++ {
		r[i] = ((ev[i] ^ 1) & small(^mask)) ^ 1
	}

	for i := w; i < p; i++ {
		r[i] = ev[i] & small(^mask)
	}
	return r

}

// Encoding small polynomials (including short polynomials)

// Transform polynomial in R to bytes
// these are the only functions that rely on p mod 4 = 1 */
func smallEncode(s []byte, f []small) {
	var x small
	var index int = 0
	for i := 0; i < p/4; i++ {
		x = f[index] + 1
		index++

		x += (f[index] + 1) << 2
		index++
		x += (f[index] + 1) << 4
		index++
		x += (f[index] + 1) << 6
		index++

		s[0] = byte(x)
		s = s[1:]
	}
	x = f[index] + 1

	s[0] = byte(x)
}

// Transform bytes into polynomial in R
func smallDecode(f []small, s []byte) {
	var index int = 0
	var x byte

	for i := 0; i < p/4; i++ {
		x = s[0]
		s = s[1:]

		f[index] = ((small)(x & 3)) - 1
		x >>= 2
		index++
		f[index] = ((small)(x & 3)) - 1
		x >>= 2
		index++
		f[index] = ((small)(x & 3)) - 1
		x >>= 2
		index++
		f[index] = ((small)(x & 3)) - 1
		index++
	}
	x = s[0]
	f[index] = ((small)(x & 3)) - 1
}

// Encoding general polynomials

// Transform polynomials in R/q to bytes
func rqEncode(s []byte, r []Fq) {
	R := make([]uint16, p)
	M := make([]uint16, p)

	for i := 0; i < p; i++ {
		R[i] = uint16(r[i] + q12)
		M[i] = q
	}
	internal.Encode(s, R, M, p)
}

// Transform polynomials in R/q from bytes
func rqDecode(r []Fq, s []byte) {
	R := make([]uint16, p)
	M := make([]uint16, p)

	for i := 0; i < p; i++ {
		M[i] = q
	}
	internal.Decode(R, s, M, p)
	for i := 0; i < p; i++ {
		r[i] = ((Fq)(R[i])) - q12
	}

}

// Encoding rounded polynomials

// Transform rounded polynomials to bytes
func roundedEncode(s []byte, r []Fq) {

	R := make([]uint16, p)
	M := make([]uint16, p)

	for i := 0; i < p; i++ {
		R[i] = uint16((int32((r[i])+q12) * 10923) >> 15)
		M[i] = (q + 2) / 3
	}
	internal.Encode(s, R, M, p)
}

// Transform bytes to rounded polynomials
func roundedDecode(r []Fq, s []byte) {
	R := make([]uint16, p)
	M := make([]uint16, p)

	for i := 0; i < p; i++ {
		M[i] = (q + 2) / 3
	}
	internal.Decode(R, s, M, p)
	for i := 0; i < p; i++ {
		r[i] = Fq(R[i]*3 - q12)
	}

}

// Streamlined NTRU Prime Core plus encoding

// Generates public key and private key
// pk,sk = zKeyGen()
func zKeyGen(pk []byte, sk []byte, gen *nist.DRBG) {

	h, f, v := keyGen(gen)

	rqEncode(pk, h)
	smallEncode(sk, f)
	sk = sk[smallBytes:]
	smallEncode(sk, v)

}

// C = zEncrypt(r,pk)
func zEncrypt(C []byte, r Inputs, pk []byte) {
	h := make([]Fq, p)
	rqDecode(h, pk)
	c := encrypt(r[:], h)
	roundedEncode(C, c)
}

// r = zDecrypt(C,sk)
func zDecrypt(r *Inputs, C []byte, sk []byte) {
	f := make([]small, p)
	v := make([]small, p)
	c := make([]Fq, p)

	smallDecode(f, sk)
	sk = sk[smallBytes:]
	smallDecode(v, sk)
	roundedDecode(c, C)

	copy(r[:], decrypt(c, f, v))
}

// Confirmation hash

// h = hashConfirm(r,pk,cache); cache is Hash4(pk)
func hashConfirm(h []byte, r []byte, pk []byte, cache []byte) {
	x := make([]byte, hashBytes*2)

	hashPrefix(x, 3, r, inputsBytes)

	copy(x[hashBytes:], cache[:hashBytes])

	hashPrefix(h, 2, x, len(x))

}

// Session-key hash

// k = hashSession(b,y,z)
func hashSession(k []byte, b int, y []byte, z []byte) {
	x := make([]byte, hashBytes+ciphertextsBytes+confirmBytes)

	hashPrefix(x, 3, y, inputsBytes)

	copy(x[hashBytes:], z[:ciphertextsBytes+confirmBytes])

	hashPrefix(k, b, x, len(x))

}

//  Streamlined NTRU Prime

// pk,sk = kemKeyGen()
func kemKeyGen(pk []byte, sk []byte, gen *nist.DRBG) {
	zKeyGen(pk, sk, gen)
	sk = sk[secretKeysBytes:]

	copy(sk, pk)
	sk = sk[publicKeysBytes:]

	if gen != nil {
		gen.Fill(sk[:inputsBytes])

	} else {
		cryptoRand.Read(sk[:inputsBytes])
	}
	sk = sk[inputsBytes:]
	hashPrefix(sk, 4, pk, publicKeysBytes)

}

// c,r_enc = hide(r,pk,cache); cache is Hash4(pk)
func hide(c []byte, r_enc []byte, r Inputs, pk []byte, cache []byte) {
	smallEncode(r_enc, r[:])
	zEncrypt(c, r, pk)
	c = c[ciphertextsBytes:]
	hashConfirm(c, r_enc, pk, cache)

}

// Takes as input a public key
// Returns ciphertext and shared key
// c,k = encap(pk)
func (pub PublicKey) EncapsulateTo(c []byte, k []byte, gen *nist.DRBG) {
	if len(c) != CiphertextSize {
		panic("ct must be of length CiphertextSize")
	}
	if len(k) != SharedKeySize {
		panic("ss must be of length SharedKeySize")
	}

	pk := pub.pk[:]

	var r Inputs
	r_enc := make([]byte, inputsBytes)
	cache := make([]byte, hashBytes)

	hashPrefix(cache, 4, pk, publicKeysBytes)
	copy(r[:], shortRandom(gen))
	hide(c, r_enc, r, pk, cache)
	hashSession(k, 1, r_enc, c)

}

// Returns 0 if matching ciphertext+confirm, else -1
func ciphertexts_diff_mask(c []byte, c2 []byte) int {
	var differentbits uint16 = 0
	var len int = ciphertextsBytes + confirmBytes

	for i := 0; i < len; i++ {
		differentbits |= uint16((c[i]) ^ (c2[i]))
	}
	return int((1 & ((differentbits - 1) >> 8)) - 1)

}

// Returns shared key from ciphertext and private key
// k = decap(c,sk)
func (priv *PrivateKey) DecapsulateTo(k []byte, c []byte) {
	if len(c) != CiphertextSize {
		panic("ct must be of length CiphertextSize")
	}

	if len(k) != SharedKeySize {
		panic("ss must be of length SharedKeySize")
	}

	sk := priv.sk[:]

	pk := sk[secretKeysBytes:]
	rho := pk[publicKeysBytes:]
	cache := rho[inputsBytes:]
	var r Inputs

	r_enc := make([]byte, inputsBytes)
	cnew := make([]byte, ciphertextsBytes+confirmBytes)

	zDecrypt(&r, c, sk)
	hide(cnew, r_enc, r, pk, cache)
	var mask int = ciphertexts_diff_mask(c, cnew)

	for i := 0; i < inputsBytes; i++ {
		r_enc[i] ^= byte(mask & int(r_enc[i]^rho[i]))
	}
	hashSession(k, 1+mask, r_enc, c)
}

// The structure of the private key is given by the following segments:
// The secret key, the public key, entropy and the hash of the public key
type PrivateKey struct {
	sk [PrivateKeySize]byte
}

type PublicKey struct {
	pk [PublicKeySize]byte
}

type scheme struct{}

var sch kem.Scheme = &scheme{}

// Scheme returns a KEM interface.
func Scheme() kem.Scheme { return sch }

func (*scheme) Name() string        { return "sntrup1013" }
func (*scheme) PublicKeySize() int  { return PublicKeySize }
func (*scheme) PrivateKeySize() int { return PrivateKeySize }
func (*scheme) SharedKeySize() int  { return SharedKeySize }
func (*scheme) CiphertextSize() int { return CiphertextSize }

func (sk *PrivateKey) Scheme() kem.Scheme { return sch }
func (pk *PublicKey) Scheme() kem.Scheme  { return sch }

func (sk *PrivateKey) MarshalBinary() ([]byte, error) {
	var ret [PrivateKeySize]byte
	copy(ret[:], sk.sk[:])
	return ret[:], nil
}

func (sk *PrivateKey) Equal(other kem.PrivateKey) bool {
	oth, ok := other.(*PrivateKey)
	if !ok {
		return false
	}
	return bytes.Equal(sk.sk[:], oth.sk[:])
}

func (pk *PublicKey) Equal(other kem.PublicKey) bool {
	oth, ok := other.(*PublicKey)
	if !ok {
		return false
	}
	return bytes.Equal(pk.pk[:], oth.pk[:])
}

func (sk *PrivateKey) Public() kem.PublicKey {
	var pk [PublicKeySize]byte
	skey, _ := sk.MarshalBinary()
	ppk := skey[secretKeysBytes : secretKeysBytes+publicKeysBytes]
	copy(pk[:], ppk[:])
	return &PublicKey{pk: pk}
}

func (pk *PublicKey) MarshalBinary() ([]byte, error) {
	var ret [PublicKeySize]byte
	copy(ret[:], pk.pk[:])
	return ret[:], nil
}

func (*scheme) GenerateKeyPair() (kem.PublicKey, kem.PrivateKey, error) {
	var pk [PublicKeySize]byte
	var sk [PrivateKeySize]byte
	kemKeyGen(pk[:], sk[:], nil)

	return &PublicKey{pk: pk}, &PrivateKey{sk: sk}, nil

}

func (*scheme) DeriveKeyPairFromGen(gen *nist.DRBG) (kem.PublicKey, kem.PrivateKey) {
	var pk [PublicKeySize]byte
	var sk [PrivateKeySize]byte

	kemKeyGen(pk[:], sk[:], gen)

	return &PublicKey{pk: pk}, &PrivateKey{sk: sk}
}

func (*scheme) Encapsulate(pk kem.PublicKey) (ct, ss []byte, err error) {
	ct = make([]byte, CiphertextSize)
	ss = make([]byte, SharedKeySize)

	pub, ok := pk.(*PublicKey)
	if !ok {
		return nil, nil, kem.ErrTypeMismatch
	}

	pub.EncapsulateTo(ct, ss, nil)

	return ct, ss, nil

}

func (*scheme) EncapsulateDeterministicallyFromGen(pk kem.PublicKey, gen *nist.DRBG) (ct, ss []byte, err error) {

	if gen == nil {
		panic("A nist DRBG must be provided")
	}

	ct = make([]byte, CiphertextSize)
	ss = make([]byte, SharedKeySize)

	pub, ok := pk.(*PublicKey)
	if !ok {
		return nil, nil, kem.ErrTypeMismatch
	}

	pub.EncapsulateTo(ct, ss, gen)

	return ct, ss, nil
}

func (*scheme) Decapsulate(sk kem.PrivateKey, ct []byte) ([]byte, error) {
	ssk, ok := sk.(*PrivateKey)
	if !ok {
		return nil, kem.ErrTypeMismatch
	}

	if len(ct) != CiphertextSize {
		return nil, kem.ErrCiphertextSize
	}
	ss := [SharedKeySize]byte{}

	ssk.DecapsulateTo(ss[:], ct)

	return ss[:], nil
}

func (*scheme) UnmarshalBinaryPublicKey(buf []byte) (kem.PublicKey, error) {
	if len(buf) != PublicKeySize {
		return nil, kem.ErrPubKeySize
	}
	pk := [PublicKeySize]byte{}
	copy(pk[:], buf)
	return &PublicKey{pk: pk}, nil
}

func (*scheme) UnmarshalBinaryPrivateKey(buf []byte) (kem.PrivateKey, error) {
	if len(buf) != PrivateKeySize {
		return nil, kem.ErrPrivKeySize
	}
	sk := [PrivateKeySize]byte{}
	copy(sk[:], buf)
	return &PrivateKey{sk: sk}, nil
}
