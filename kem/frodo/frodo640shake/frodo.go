// Package frodo640shake implements the variant FrodoKEM-640 with SHAKE.
package frodo640shake

import (
	"bytes"
	cryptoRand "crypto/rand"
	"crypto/subtle"
	"io"

	"github.com/cloudflare/circl/internal/sha3"
	"github.com/cloudflare/circl/kem"
)

const (
	paramN = 640

	// Denoted by 'mbar' in the FrodoKEM spec.
	paramNbar = 8

	logQ       = 15
	logQMask   = ((1 << logQ) - 1)
	seedASize  = 16
	pkHashSize = 16

	// Denoted by 'B' in the FrodoKEM spec.
	extractedBits = 2

	messageSize        = 16
	matrixBpPackedSize = (logQ * (paramN * paramNbar)) / 8
)

const (
	// Size of seed for NewKeyFromSeed.
	// = len(s) + len(seedSE) + len(z).
	KeySeedSize = SharedKeySize + SharedKeySize + 16

	// Size of seed for EncapsulateTo.
	EncapsulationSeedSize = 16

	// Size of the established shared key.
	SharedKeySize = 16

	// Size of the encapsulated shared key.
	CiphertextSize = 9720

	// Size of a packed public key.
	PublicKeySize = 9616

	// Size of a packed private key.
	PrivateKeySize = 19888
)

// Multi-dimensional arrays are stored in 1-dimensional arrays in
// row-major order.
type (
	nByNU16       [paramN * paramN]uint16
	nByNbarU16    [paramN * paramNbar]uint16
	nbarByNU16    [paramNbar * paramN]uint16
	nbarByNbarU16 [paramNbar * paramNbar]uint16
)

// Type of a FrodoKEM-640-SHAKE public key
type PublicKey struct {
	seedA   [seedASize]byte
	matrixB nByNbarU16
}

// Type of a FrodoKEM-640-SHAKE private key
type PrivateKey struct {
	hashInputIfDecapsFail [SharedKeySize]byte
	pk                    *PublicKey

	// matrixS stores transpose(S)
	matrixS nByNbarU16

	// H(packed(pk))
	hpk [pkHashSize]byte
}

// NewKeyFromSeed derives a public/private keypair deterministically
// from the given seed.
//
// Panics if seed is not of length KeySeedSize.
func newKeyFromSeed(seed []byte) (*PublicKey, *PrivateKey) {
	if len(seed) != KeySeedSize {
		panic("seed must be of length KeySeedSize")
	}

	var sk PrivateKey
	var pk PublicKey

	var E nByNbarU16
	var byteSE [2 * (len(sk.matrixS) + len(E))]byte

	var A nByNU16

	// Generate the secret value s, and the seed for S, E, and A. Add seedA to the public key
	shake128 := sha3.NewShake128()
	_, _ = shake128.Write(seed[2*SharedKeySize:])
	_, _ = shake128.Read(pk.seedA[:])

	shake128.Reset()
	_, _ = shake128.Write([]byte{0x5F})
	_, _ = shake128.Write(seed[SharedKeySize : 2*SharedKeySize])
	_, _ = shake128.Read(byteSE[:])

	i := 0
	for i < len(sk.matrixS) {
		sk.matrixS[i] = uint16(byteSE[i*2]) | (uint16(byteSE[(i*2)+1]) << 8)
		i++
	}
	sample(sk.matrixS[:])

	for j := range E {
		E[j] = uint16(byteSE[i*2]) | (uint16(byteSE[(i*2)+1]) << 8)
		i++
	}
	sample(E[:])

	expandSeedIntoA(&A, &pk.seedA, &shake128)
	mulAddASPlusE(&pk.matrixB, &A, &sk.matrixS, &E)

	// Populate the private key
	copy(sk.hashInputIfDecapsFail[:], seed[0:SharedKeySize])
	sk.pk = &pk

	// Add H(pk) to the private key
	shake128.Reset()
	var ppk [PublicKeySize]byte
	pk.Pack(ppk[:])
	_, _ = shake128.Write(ppk[:])
	_, _ = shake128.Read(sk.hpk[:])

	return &pk, &sk
}

// GenerateKeyPair generates public and private keys using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func generateKeyPair(rand io.Reader) (*PublicKey, *PrivateKey, error) {
	var seed [KeySeedSize]byte
	if rand == nil {
		rand = cryptoRand.Reader
	}
	_, err := io.ReadFull(rand, seed[:])
	if err != nil {
		return nil, nil, err
	}
	pk, sk := newKeyFromSeed(seed[:])
	return pk, sk, err
}

// EncapsulateTo generates a shared key and a ciphertext containing said key
// from the public key and the randomness from seed and writes the shared key
// to ss and ciphertext to ct.
//
// Panics if ss, ct, or seed are not of length SharedKeySize, CiphertextSize
// and EncapsulationSeedSize respectively.
//
// seed may be nil, in which case crypto/rand.Reader is used to generate one.
func (pk *PublicKey) EncapsulateTo(ct []byte, ss []byte, seed []byte) {
	if seed == nil {
		seed = make([]byte, EncapsulationSeedSize)
		if _, err := cryptoRand.Read(seed[:]); err != nil {
			panic(err)
		}
	}
	if len(seed) != EncapsulationSeedSize {
		panic("seed must be of length EncapsulationSeedSize")
	}
	if len(ct) != CiphertextSize {
		panic("ct must be of length CiphertextSize")
	}
	if len(ss) != SharedKeySize {
		panic("ss must be of length SharedKeySize")
	}

	var G2out [2 * SharedKeySize]byte

	var SpEpEpp [(paramN * paramNbar) + (paramN * paramNbar) + (paramNbar * paramNbar)]uint16
	var byteSpEpEpp [2 * len(SpEpEpp)]byte
	Sp := SpEpEpp[:paramN*paramNbar]
	Ep := SpEpEpp[paramN*paramNbar : 2*paramN*paramNbar]
	Epp := SpEpEpp[2*paramN*paramNbar:]

	var Bp nbarByNU16

	var V nbarByNbarU16
	var C nbarByNbarU16

	var A nByNU16

	var hpk [pkHashSize]byte

	var mu [messageSize]byte
	copy(mu[:], seed[:messageSize])

	// compute hpk = G_1(packed(pk))
	shake128 := sha3.NewShake128()
	var ppk [PublicKeySize]byte
	pk.Pack(ppk[:])
	_, _ = shake128.Write(ppk[:])
	_, _ = shake128.Read(hpk[:])

	// compute (seedSE || k) = G_2(hpk || mu)
	shake128.Reset()
	_, _ = shake128.Write(hpk[:])
	_, _ = shake128.Write(mu[:])
	_, _ = shake128.Read(G2out[:])

	// Generate Sp, Ep, Epp, and A, and compute:
	// Bp = Sp*A + Ep
	// V = Sp*B + Epp
	shake128.Reset()
	_, _ = shake128.Write([]byte{0x96})
	_, _ = shake128.Write(G2out[:SharedKeySize])
	_, _ = shake128.Read(byteSpEpEpp[:])
	for i := range SpEpEpp {
		SpEpEpp[i] = uint16(byteSpEpEpp[i*2]) | (uint16(byteSpEpEpp[(i*2)+1]) << 8)
	}
	sample(SpEpEpp[:])

	expandSeedIntoA(&A, &pk.seedA, &shake128)
	mulAddSAPlusE(&Bp, Sp, &A, Ep)

	mulAddSBPlusE(&V, Sp, &pk.matrixB, Epp)

	// Encode mu, and compute C = V + enc(mu) (mod q)
	encodeMessage(&C, &mu)
	add(&C, &V, &C)

	// Prepare the ciphertext
	pack(ct[:matrixBpPackedSize], Bp[:])
	pack(ct[matrixBpPackedSize:], C[:])

	// Compute ss = F(ct||k)
	shake128.Reset()
	_, _ = shake128.Write(ct[:])
	_, _ = shake128.Write(G2out[SharedKeySize:])
	_, _ = shake128.Read(ss[:])
}

// DecapsulateTo computes the shared key that is encapsulated in ct
// from the private key.
//
// Panics if ct or ss are not of length CiphertextSize and SharedKeySize
// respectively.
func (sk *PrivateKey) DecapsulateTo(ss, ct []byte) {
	if len(ct) != CiphertextSize {
		panic("ct must be of length CiphertextSize")
	}
	if len(ss) != SharedKeySize {
		panic("ss must be of length SharedKeySize")
	}

	var Bp nbarByNU16
	var C nbarByNbarU16

	var W nbarByNbarU16
	var CC nbarByNbarU16
	var BBp nbarByNU16

	var SpEpEpp [(paramN * paramNbar) + (paramN * paramNbar) + (paramNbar * paramNbar)]uint16
	var byteSpEpEpp [2 * len(SpEpEpp)]byte
	Sp := SpEpEpp[:paramN*paramNbar]
	Ep := SpEpEpp[paramN*paramNbar : 2*paramN*paramNbar]
	Epp := SpEpEpp[2*paramN*paramNbar:]

	var A nByNU16

	var muprime [messageSize]byte
	var G2out [2 * SharedKeySize]byte

	kprime := G2out[SharedKeySize:]

	// Compute W = C - Bp*S (mod q), and decode the randomness mu
	unpack(Bp[:], ct[0:matrixBpPackedSize])
	unpack(C[:], ct[matrixBpPackedSize:])
	mulBS(&W, &Bp, &sk.matrixS)
	sub(&W, &C, &W)

	decodeMessage(&muprime, &W)

	// Generate (seedSE' || k') = G_2(hpk || mu')
	shake128 := sha3.NewShake128()
	_, _ = shake128.Write(sk.hpk[:])
	_, _ = shake128.Write(muprime[:])
	_, _ = shake128.Read(G2out[:])

	// Generate Sp, Ep, Epp, A, and compute BBp = Sp*A + Ep.
	shake128.Reset()
	_, _ = shake128.Write([]byte{0x96})
	_, _ = shake128.Write(G2out[:SharedKeySize])
	_, _ = shake128.Read(byteSpEpEpp[:])
	for i := range SpEpEpp {
		SpEpEpp[i] = uint16(byteSpEpEpp[i*2]) | (uint16(byteSpEpEpp[(i*2)+1]) << 8)
	}

	sample(SpEpEpp[:])

	expandSeedIntoA(&A, &sk.pk.seedA, &shake128)
	mulAddSAPlusE(&BBp, Sp[:], &A, Ep[:])

	// Reduce BBp modulo q
	for i := range BBp {
		BBp[i] = BBp[i] & logQMask
	}

	// compute W = Sp*B + Epp
	mulAddSBPlusE(&W, Sp, &sk.pk.matrixB, Epp)

	// Encode mu, and compute CC = W + enc(mu') (mod q)
	encodeMessage(&CC, &muprime)
	add(&CC, &W, &CC)

	// Prepare input to F

	// If (Bp == BBp & C == CC) then ss = F(ct || k'), else ss = F(ct || s)
	// Needs to avoid branching on secret data as per:
	//     Qian Guo, Thomas Johansson, Alexander Nilsson. A key-recovery timing attack on post-quantum
	//     primitives using the Fujisaki-Okamoto transformation and its application on FrodoKEM. In CRYPTO 2020.
	selector := ctCompareU16(Bp[:], BBp[:]) | ctCompareU16(C[:], CC[:])
	// If (selector == 0) then load k' to do ss = F(ct || k'), else if (selector == 1) load s to do ss = F(ct || s)
	subtle.ConstantTimeCopy(selector, kprime[:], sk.hashInputIfDecapsFail[:])

	shake128.Reset()
	_, _ = shake128.Write(ct[:])
	_, _ = shake128.Write(kprime[:])
	_, _ = shake128.Read(ss[:])
}

// Packs sk to buf.
//
// Panics if buf is not of size PrivateKeySize.
func (sk *PrivateKey) Pack(buf []byte) {
	if len(buf) != PrivateKeySize {
		panic("buf must be of length PrivateKeySize")
	}

	copy(buf[:SharedKeySize], sk.hashInputIfDecapsFail[:])
	buf = buf[SharedKeySize:]

	sk.pk.Pack(buf[:PublicKeySize])
	buf = buf[PublicKeySize:]

	j := 0
	for i := range sk.matrixS {
		buf[j] = byte(sk.matrixS[i])
		buf[j+1] = byte(sk.matrixS[i] >> 8)
		j += 2
	}
	buf = buf[j:]

	copy(buf[:], sk.hpk[:])
}

// Unpacks sk from buf.
//
// Panics if buf is not of size PrivateKeySize.
func (sk *PrivateKey) Unpack(buf []byte) {
	if len(buf) != PrivateKeySize {
		panic("buf must be of length PrivateKeySize")
	}

	copy(sk.hashInputIfDecapsFail[:], buf[:SharedKeySize])
	buf = buf[SharedKeySize:]

	sk.pk = new(PublicKey)
	sk.pk.Unpack(buf[:PublicKeySize])
	buf = buf[PublicKeySize:]

	for i := range sk.matrixS {
		sk.matrixS[i] = uint16(buf[i*2]) | (uint16(buf[(i*2)+1]) << 8)
	}
	buf = buf[len(sk.matrixS)*2:]

	copy(sk.hpk[:], buf[:])
}

// Packs pk to buf.
//
// Panics if buf is not of size PublicKeySize.
func (pk *PublicKey) Pack(buf []byte) {
	if len(buf) != PublicKeySize {
		panic("buf must be of length PublicKeySize")
	}

	copy(buf[:seedASize], pk.seedA[:])
	pack(buf[seedASize:], pk.matrixB[:])
}

// TODO: Unpacks pk from buf.
//
// Panics if buf is not of size PublicKeySize.
func (pk *PublicKey) Unpack(buf []byte) {
	if len(buf) != PublicKeySize {
		panic("buf must be of length PublicKeySize")
	}

	copy(pk.seedA[:], buf[:seedASize])
	unpack(pk.matrixB[:], buf[seedASize:])
}

// Boilerplate down below for the KEM scheme API.

type scheme struct{}

var sch kem.Scheme = &scheme{}

// Scheme returns a KEM interface.
func Scheme() kem.Scheme { return sch }

func (scheme) Name() string                { return "FrodoKEM-640-SHAKE" }
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
	sk.Pack(ret[:])
	return ret[:], nil
}

func (sk *PrivateKey) Equal(other kem.PrivateKey) bool {
	oth, ok := other.(*PrivateKey)
	if !ok {
		return false
	}
	if sk.pk == nil && oth.pk == nil {
		return true
	}
	if sk.pk == nil || oth.pk == nil {
		return false
	}
	return ctCompareU16(sk.matrixS[:], oth.matrixS[:]) == 0 &&
		subtle.ConstantTimeCompare(sk.hashInputIfDecapsFail[:], oth.hashInputIfDecapsFail[:]) == 1 &&
		sk.pk.Equal(oth.pk) &&
		bytes.Equal(sk.hpk[:], oth.hpk[:])
}

func (pk *PublicKey) Equal(other kem.PublicKey) bool {
	oth, ok := other.(*PublicKey)
	if !ok {
		return false
	}
	if pk == nil && oth == nil {
		return true
	}
	if pk == nil || oth == nil {
		return false
	}

	for i := range pk.matrixB {
		if (pk.matrixB[i] & logQMask) != (oth.matrixB[i] & logQMask) {
			return false
		}
	}
	return bytes.Equal(pk.seedA[:], oth.seedA[:])
}

func (sk *PrivateKey) Public() kem.PublicKey {
	return sk.pk
}

func (pk *PublicKey) MarshalBinary() ([]byte, error) {
	var ret [PublicKeySize]byte
	pk.Pack(ret[:])
	return ret[:], nil
}

func (*scheme) GenerateKeyPair() (kem.PublicKey, kem.PrivateKey, error) {
	return generateKeyPair(cryptoRand.Reader)
}

func (*scheme) DeriveKeyPair(seed []byte) (kem.PublicKey, kem.PrivateKey) {
	if len(seed) != KeySeedSize {
		panic(kem.ErrSeedSize)
	}
	return newKeyFromSeed(seed[:])
}

func (*scheme) Encapsulate(pk kem.PublicKey) (ct, ss []byte, err error) {
	ct = make([]byte, CiphertextSize)
	ss = make([]byte, SharedKeySize)

	pub, ok := pk.(*PublicKey)
	if !ok {
		return nil, nil, kem.ErrTypeMismatch
	}
	pub.EncapsulateTo(ct, ss, nil)
	return
}

func (*scheme) EncapsulateDeterministically(
	pk kem.PublicKey, seed []byte,
) (ct, ss []byte, err error) {
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
	return
}

func (*scheme) Decapsulate(sk kem.PrivateKey, ct []byte) ([]byte, error) {
	if len(ct) != CiphertextSize {
		return nil, kem.ErrCiphertextSize
	}

	priv, ok := sk.(*PrivateKey)
	if !ok {
		return nil, kem.ErrTypeMismatch
	}
	ss := make([]byte, SharedKeySize)
	priv.DecapsulateTo(ss, ct)
	return ss, nil
}

func (*scheme) UnmarshalBinaryPublicKey(buf []byte) (kem.PublicKey, error) {
	if len(buf) != PublicKeySize {
		return nil, kem.ErrPubKeySize
	}
	var ret PublicKey
	ret.Unpack(buf)
	return &ret, nil
}

func (*scheme) UnmarshalBinaryPrivateKey(buf []byte) (kem.PrivateKey, error) {
	if len(buf) != PrivateKeySize {
		return nil, kem.ErrPrivKeySize
	}
	var ret PrivateKey
	ret.Unpack(buf)
	return &ret, nil
}
