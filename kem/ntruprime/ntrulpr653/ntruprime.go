// Code generated from ntrulpr.templ.go. DO NOT EDIT.

// Package ntrulpr653 implements the IND-CCA2 secure key encapsulation mechanism
// ntrulpr653 as submitted to round 3 of the NIST PQC competition and
// described in
//
// https://ntruprime.cr.yp.to/nist/ntruprime-20201007.pdf
package ntrulpr653

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	cryptoRand "crypto/rand"
	"crypto/sha512"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/ntruprime/internal"
	ntrup "github.com/cloudflare/circl/pke/ntruprime/ntrulpr653"
)

const (
	p            = ntrup.P
	q            = ntrup.Q
	q12          = ((q - 1) / 2)
	roundedBytes = ntrup.RoundedBytes

	w    = ntrup.W
	tau0 = ntrup.Tau0
	tau1 = ntrup.Tau1
	tau2 = ntrup.Tau2
	tau3 = ntrup.Tau3

	I = ntrup.I

	hashBytes = 32

	smallBytes = ((p + 3) / 4)

	inputsBytes      = I / 8
	seedBytes        = 32
	ciphertextsBytes = roundedBytes + topBytes
	secretKeysBytes  = smallBytes
	publicKeysBytes  = seedBytes + roundedBytes

	confirmBytes = 32

	tau      = 16
	topBytes = I / 2
)

const (
	// Size of seed for NewKeyFromSeed
	KeySeedSize = seedBytes + p*4 + inputsBytes

	// Size of seed for EncapsulateTo.
	EncapsulationSeedSize = inputsBytes

	// Size of the established shared key.
	SharedKeySize = ntrup.SharedKeySize

	// Size of the encapsulated shared key.
	CiphertextSize = ntrup.CiphertextSize

	// Size of a packed public key.
	PublicKeySize = ntrup.PublicKeySize

	// Size of a packed private key.
	PrivateKeySize = ntrup.PrivateKeySize
)

type (
	small int8
	Fq    int16
)

// arithmetic operations over GF(3)

// A polynomial of R has all of its coefficients in (-1,0,1)
// F3 is always represented as -1,0,1
// so ZZ_fromF3 is a no-op

// x must not be close to top int16
func f3Freeze(x int16) small {
	return small(internal.Int32_mod_uint14(int32(x)+1, 3)) - 1
}

/* ----- arithmetic mod q */
// GF (q)
// type Fq int16

/* always represented as -q12...q12 */
/* so ZZ_fromFq is a no-op */

/* x must not be close to top int32 */
func fqFreeze(x int32) Fq {
	return Fq(internal.Int32_mod_uint14(x+q12, q) - q12)
}

func top(C Fq) int8 {
	return int8((tau1*(int32)(C+tau0) + 16384) >> 15)
}

func right(T int8) Fq {
	return fqFreeze(tau3*int32(T) - tau2)
}

// Polynomials mod q

// h = f*g in the ring Rq */
func rqMultSmall(h []Fq, f []Fq, g []small) {
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
}

// Rounding all coefficients of a polynomial to the nearest multiple of 3
// Rounded polynomials mod q
func round(out []Fq, a []Fq) {
	for i := 0; i < p; i++ {
		out[i] = a[i] - Fq(f3Freeze(int16(a[i])))
	}
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
func shortFromList(out []small, in []int32) {
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
}

// Underlying hash function

// The input byte array, in, is prepended by the byte b
// and its SHA-512 hash is calculated
// Only the first 32 bytes of the hash are returned
// e.g., b = 0 means out = Hash0(in)
func hashPrefix(out []byte, b int, in []byte, inlen int) {
	x := make([]byte, inlen+1)
	// h := make([]byte, 64)

	x[0] = byte(b)
	copy(x[1:], in)

	hash := sha512.New()
	hash.Write([]byte(x))
	h := hash.Sum(nil)

	copy(out, h[:32])

}

// Higher level randomness
// Returns a random unsigned integer
// generator can be passed for deterministic number generation
func urandom32(seed []byte) uint32 {
	var out [4]uint32

	out[0] = uint32(seed[0])
	out[1] = uint32(seed[1]) << 8
	out[2] = uint32(seed[2]) << 16
	out[3] = uint32(seed[3]) << 24
	return out[0] + out[1] + out[2] + out[3]
}

// Generates a random short polynomial
func shortRandom(out []small, seed []byte) {

	L := make([]uint32, p)

	if seed != nil {
		for i := 0; i < p; i++ {
			L[i] = urandom32(seed[i*4 : i*4+4])
		}
	} else {
		for i := 0; i < p; i++ {
			L[i] = urandom32(nil)
		}
	}

	// Converts uint32 array to int32 array
	L_int32 := make([]int32, p)
	for i := 0; i < len(L); i++ {
		L_int32[i] = int32(L[i])
	}
	shortFromList(out, L_int32)
}

// NTRU LPRime Core

// (G,A),a = keyGen(G); leaves G unchanged
func keyGen(A []Fq, a []small, G []Fq, seed []byte) {
	aG := make([]Fq, p)
	shortRandom(a, seed)
	rqMultSmall(aG, G, a)
	round(A, aG)
}

// B,T = encrypt(r,(G,A),b)
func encrypt(B []Fq, T []int8, r []int8, G []Fq, A []Fq, b []small) {
	bG := make([]Fq, p)
	bA := make([]Fq, p)

	rqMultSmall(bG, G, b)
	round(B, bG)
	rqMultSmall(bA, A, b)

	for i := 0; i < I; i++ {
		T[i] = top(fqFreeze(int32(bA[i]) + int32(r[i])*q12))
	}
}

// r = decrypt((B,T),a)
func decrypt(B []Fq, T []int8, a []small) []int8 {
	aB := make([]Fq, p)

	r := make([]int8, I)

	rqMultSmall(aB, B, a)

	for i := 0; i < I; i++ {
		r[i] = int8(-internal.Int16_negative_mask(int16(fqFreeze(int32(right(T[i])) - int32(aB[i]) + 4*w + 1))))
	}

	return r
}

// Encoding I-bit inputs
type Inputs [I]int8

func inputsEncode(s []byte, r Inputs) {

	for i := 0; i < I; i++ {
		s[i>>3] |= byte(r[i] << (i & 7))
	}

}

// Expand

func expand(L []uint32, k []byte) {
	temp := make([]byte, len(L)) // plaintext to be encrypted. Should be of the same size as L (4*P)
	ciphertext := make([]byte, aes.BlockSize+len(temp))

	block, err := aes.NewCipher(k[:32])
	if err != nil {
		panic(err)
	}

	stream := cipher.NewCTR(block, ciphertext[:aes.BlockSize])
	stream.XORKeyStream(ciphertext[aes.BlockSize:], temp)
	ciphertext = ciphertext[aes.BlockSize:]

	// convert byte to uint32
	for i := 0; i < len(temp); i++ {
		L[i] = uint32(ciphertext[i])
	}

	for i := 0; i < p; i++ {
		var L0 uint32 = L[4*i]
		var L1 uint32 = L[4*i+1]
		var L2 uint32 = L[4*i+2]
		var L3 uint32 = L[4*i+3]
		L[i] = L0 + (L1 << 8) + (L2 << 16) + (L3 << 24)
	}
}

// generator, hashShort
// G = generator(k)
func generator(G []Fq, k []byte) {
	L := make([]uint32, 4*p)
	expand(L, k)
	for i := 0; i < p; i++ {
		G[i] = Fq(internal.Uint32_mod_uint14(L[i], q) - q12)
	}
}

// out = hashShort(r)
func hashShort(out []small, r Inputs) {
	s := make([]byte, inputsBytes)
	inputsEncode(s, r)
	h := make([]byte, hashBytes)
	L := make([]uint32, 4*p)
	L_int32 := make([]int32, p)

	hashPrefix(h, 5, s, len(s))

	expand(L, h)

	// convert []uint32 to []int32
	for i := 0; i < p; i++ {
		L_int32[i] = int32(L[i])
	}
	shortFromList(out, L_int32)
}

// NTRU LPRime expand

// (S,A),a = xKeyGen()
func xKeyGen(S []byte, A []Fq, a []small, seed []byte) {

	copy(S, seed[:seedBytes])
	seed = seed[seedBytes:]
	G := make([]Fq, p)

	generator(G, S)

	keyGen(A, a, G, seed)
}

// B,T = xEncrypt(r,(S,A))
func xEncrypt(B []Fq, T []int8, r []int8, S []byte, A []Fq) {
	G := make([]Fq, p)

	generator(G, S)
	b := make([]small, p)

	// convert []int8 to Inputs
	var r_inputs Inputs
	for i := 0; i < len(r); i++ {
		r_inputs[i] = r[i]
	}

	hashShort(b, r_inputs)

	encrypt(B, T, r, G, A, b)
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

// Encoding top polynomials

func topEncode(s []byte, T []int8) {
	for i := 0; i < topBytes; i++ {
		s[i] = byte(T[2*i] + (T[2*i+1] << 4))

	}
}

func topDecode(s []byte) (T []int8) {

	T = make([]int8, 2*topBytes+1)

	for i := 0; i < topBytes; i++ {
		T[2*i] = int8(s[i] & 15)
		T[2*i+1] = int8(s[i] >> 4)
	}
	return T
}

// Streamlined NTRU Prime Core plus encoding

func inputsRandom(seed []byte) (r Inputs) {
	for i := 0; i < I; i++ {
		r[i] = int8(1 & (seed[i>>3] >> (i & 7)))
	}
	return r
}

// Generates public key and private key
// pk,sk = zKeyGen()
func zKeyGen(pk []byte, sk []byte, seed []byte) {
	A := make([]Fq, p)
	a := make([]small, p)

	xKeyGen(pk, A, a, seed)

	pk = pk[seedBytes:]
	roundedEncode(pk, A)

	smallEncode(sk, a)
}

// c = zEncrypt(r,pk)
func zEncrypt(c []byte, r Inputs, pk []byte) {
	A := make([]Fq, p)
	B := make([]Fq, p)
	T := make([]int8, I)

	roundedDecode(A, pk[seedBytes:])
	xEncrypt(B, T, r[:], pk[:seedBytes], A)
	roundedEncode(c, B)
	c = c[roundedBytes:]

	topEncode(c, T)
}

// r = zDecrypt(C,sk)
func zDecrypt(r *Inputs, c []byte, sk []byte) {
	a := make([]small, p)
	B := make([]Fq, p)

	smallDecode(a, sk)
	roundedDecode(B, c)
	T := topDecode(c[roundedBytes:])
	copy(r[:], decrypt(B, T, a))
}

// Confirmation hash

// h = hashConfirm(r,pk,cache); cache is Hash4(pk)
func hashConfirm(h []byte, r []byte, pk []byte, cache []byte) {
	x := make([]byte, inputsBytes+hashBytes)

	copy(x, r)
	copy(x[inputsBytes:], cache)

	hashPrefix(h, 2, x, len(x))

}

// Session-key hash

// k = hashSession(b,y,z)
func hashSession(k []byte, b int, y []byte, z []byte) {
	x := make([]byte, inputsBytes+ciphertextsBytes+confirmBytes)
	copy(x[:inputsBytes], y)
	copy(x[inputsBytes:], z)

	hashPrefix(k, b, x, len(x))
}

//  Streamlined NTRU Prime

// pk,sk = kemKeyGen()
func kemKeyGen(pk []byte, sk []byte, seed []byte) {

	if seed == nil {
		seed = make([]byte, KeySeedSize)
		cryptoRand.Read(seed)
	}

	if len(seed) != KeySeedSize {
		panic("seed must be of length KeySeedSize")
	}

	zKeyGen(pk, sk, seed[:seedBytes+p*4])
	seed = seed[seedBytes+p*4:]

	sk = sk[secretKeysBytes:]

	copy(sk, pk)
	sk = sk[publicKeysBytes:]

	copy(sk[:inputsBytes], seed)

	sk = sk[inputsBytes:]
	hashPrefix(sk, 4, pk, publicKeysBytes)

}

// c,r_enc = hide(r,pk,cache); cache is Hash4(pk)
func hide(c []byte, r_enc []byte, r Inputs, pk []byte, cache []byte) {
	inputsEncode(r_enc, r)

	zEncrypt(c, r, pk)
	c = c[ciphertextsBytes:]
	hashConfirm(c, r_enc, pk, cache)

}

// Takes as input a public key
// Returns ciphertext and shared key
// c,k = encap(pk)
func (pk PublicKey) EncapsulateTo(c []byte, k []byte, seed []byte) {

	if seed == nil {
		seed = make([]byte, EncapsulationSeedSize)
		cryptoRand.Read(seed)
	}

	if len(seed) != EncapsulationSeedSize {
		panic("seed must be of length EncapsulationSeedSize")
	}
	if len(c) != CiphertextSize {
		panic("ct must be of length CiphertextSize")
	}
	if len(k) != SharedKeySize {
		panic("ss must be of length SharedKeySize")
	}

	r_enc := make([]byte, inputsBytes)
	cache := make([]byte, hashBytes)

	hashPrefix(cache, 4, pk.pk[:], publicKeysBytes)
	r := inputsRandom(seed)
	hide(c, r_enc, r, pk.pk[:], cache)
	hashSession(k, 1, r_enc, c)
}

// Returns 0 if matching ciphertext+confirm, else -1
func ciphertextsDiffMask(c []byte, c2 []byte) int {
	var differentbits uint16 = 0
	var len int = ciphertextsBytes + confirmBytes

	for i := 0; i < len; i++ {
		differentbits |= uint16((c[i]) ^ (c2[i]))
	}
	return int((1 & ((differentbits - 1) >> 8)) - 1)

}

// Returns shared key from ciphertext and private key
// k = decap(c,sk)
func (priv *PrivateKey) DecapsulateTo(ss []byte, ct []byte) {
	if len(ct) != CiphertextSize {
		panic("ct must be of length CiphertextSize")
	}

	if len(ss) != SharedKeySize {
		panic("ss must be of length SharedKeySize")
	}
	sk := priv.sk[:]
	pk := sk[secretKeysBytes:]
	rho := pk[publicKeysBytes:]
	cache := rho[inputsBytes:]
	var r Inputs

	r_enc := make([]byte, inputsBytes)
	cnew := make([]byte, ciphertextsBytes+confirmBytes)

	zDecrypt(&r, ct, sk)
	hide(cnew, r_enc, r, pk, cache)
	var mask int = ciphertextsDiffMask(ct, cnew)

	for i := 0; i < inputsBytes; i++ {
		r_enc[i] ^= byte(mask & int(r_enc[i]^rho[i]))
	}
	hashSession(ss, 1+mask, r_enc, ct)
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

func (*scheme) Name() string               { return "ntrulpr653" }
func (*scheme) PublicKeySize() int         { return PublicKeySize }
func (*scheme) PrivateKeySize() int        { return PrivateKeySize }
func (*scheme) SeedSize() int              { return KeySeedSize }
func (*scheme) SharedKeySize() int         { return SharedKeySize }
func (*scheme) CiphertextSize() int        { return CiphertextSize }
func (*scheme) EncapsulationSeedSize() int { return EncapsulationSeedSize }

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

func (*scheme) DeriveKeyPair(seed []byte) (kem.PublicKey, kem.PrivateKey) {
	var pk [PublicKeySize]byte
	var sk [PrivateKeySize]byte

	kemKeyGen(pk[:], sk[:], seed)

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

func (*scheme) EncapsulateDeterministically(pk kem.PublicKey, seed []byte) (ct, ss []byte, err error) {

	if len(seed) != EncapsulationSeedSize {
		return nil, nil, kem.ErrSeedSize
	}

	ct = make([]byte, CiphertextSize)
	ss = make([]byte, SharedKeySize)

	pub, ok := pk.(*PublicKey)
	if !ok {
		return nil, nil, kem.ErrTypeMismatch
	}

	pub.EncapsulateTo(ct, ss, seed)
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
