// Code generated from pkg.templ.go. DO NOT EDIT.

// kyber512 implements the IND-CCA2 secure key encapsulation mechanism
// Kyber512.CCAKEM as submitted to round2 of the NIST PQC competition and
// described in
//
// https://pq-crystals.org/dilithium/data/dilithium-specification-round2.pdf
package kyber512

import (
	"github.com/cloudflare/circl/kem"
	cpapke "github.com/cloudflare/circl/pke/kyber/kyber512"

	"golang.org/x/crypto/sha3"

	"bytes"
	cryptoRand "crypto/rand"
	"crypto/subtle"
	"io"
)

const (
	// Size of seed for NewKeyFromSeed
	KeySeedSize = cpapke.KeySeedSize + 32

	// Size of seed for EncapsulateTo.
	EncapsulationSeedSize = 32

	// Size of the established shared key.
	SharedKeySize = 64

	// Size of the encapsulated shared key.
	CiphertextSize = cpapke.CiphertextSize

	// Size of a packed public key.
	PublicKeySize = cpapke.PublicKeySize

	// Size of a packed private key.
	PrivateKeySize = cpapke.PrivateKeySize + cpapke.PublicKeySize + 64
)

// Type of a Kyber512.CCAKEM public key
type PublicKey struct {
	pk *cpapke.PublicKey

	hpk [32]byte // H(pk)
}

// Type of a Kyber512.CCAKEM private key
type PrivateKey struct {
	sk  *cpapke.PrivateKey
	pk  *cpapke.PublicKey
	hpk [32]byte // H(pk)
	z   [32]byte
}

// NewKeyFromSeed derives a public/private keypair deterministically
// from the given seed.
//
// Panics if seed is not of length KeySeedSize.
func NewKeyFromSeed(seed []byte) (*PublicKey, *PrivateKey) {
	var sk PrivateKey
	var pk PublicKey

	if len(seed) != KeySeedSize {
		panic("seed must be of length KeySeedSize")
	}

	pk.pk, sk.sk = cpapke.NewKeyFromSeed(seed[:cpapke.KeySeedSize])
	sk.pk = pk.pk
	copy(sk.z[:], seed[cpapke.KeySeedSize:])

	// Compute H(pk)
	var ppk [cpapke.PublicKeySize]byte
	sk.pk.Pack(ppk[:])
	h := sha3.New256() // XXX use internal sha3
	h.Write(ppk[:])
	h.Sum(sk.hpk[:0])
	copy(pk.hpk[:], sk.hpk[:])

	return &pk, &sk
}

// GenerateKey generates a public/private keypair using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func GenerateKey(rand io.Reader) (*PublicKey, *PrivateKey, error) {
	var seed [KeySeedSize]byte
	if rand == nil {
		rand = cryptoRand.Reader
	}
	_, err := io.ReadFull(rand, seed[:])
	if err != nil {
		return nil, nil, err
	}
	pk, sk := NewKeyFromSeed(seed[:])
	return pk, sk, nil
}

// EncapsulateTo generates a shared key and ciphertext that contains it
// for the public key using randomness from seed and writes the shared key
// to ss and ciphertext to ct.
//
// Panics if ss, ct or seed are not of length SharedKeySize, CiphertextSize
// and EncapsulationSeedSize respectively.
//
// seed may be nil, in which case crypto/rand.Reader is used to generate one.
func (pk *PublicKey) EncapsulateTo(ss []byte, ct []byte, seed []byte) {
	if seed == nil {
		seed := make([]byte, EncapsulationSeedSize)
		cryptoRand.Read(seed[:])
	} else {
		if len(seed) != EncapsulationSeedSize {
			panic("seed must be of length EncapsulationSeedSize")
		}
	}

	if len(ct) != CiphertextSize {
		panic("ct must be of length CiphertextSize")
	}

	if len(ss) != SharedKeySize {
		panic("ss must be of length SharedKeySize")
	}

	// m = H(seed)
	var m [32]byte
	h := sha3.New256()
	h.Write(seed[:])
	h.Sum(m[:0])

	// (K', r) = G(m ‖ H(pk))
	var kr [64]byte
	g := sha3.New512()
	g.Write(m[:])
	g.Write(pk.hpk[:])
	g.Sum(kr[:0])

	// c = Kyber.CPAPKE.Enc(pk, m, r)
	pk.pk.EncryptTo(ct, kr[32:], m[:])

	// Compute H(c) and put in second slot of kr, which will be (K', H(c)).
	h.Reset()
	h.Write(ct[:CiphertextSize])
	h.Sum(kr[32:])

	// K = KDF(K' ‖ H(c))
	kdf := sha3.NewShake256()
	kdf.Write(kr[:])
	kdf.Read(ss[:SharedKeySize])
}

// DecapsulateTo computes the shared key which is encapsulated in ct
// for the private key.
//
// Panics if ct or ss are not of length CiphertextSize and SharedKeySize
// respectively.
func (sk *PrivateKey) DecapsulateTo(ct []byte, ss []byte) {
	if len(ct) != CiphertextSize {
		panic("ct must be of length CiphertextSize")
	}

	if len(ss) != SharedKeySize {
		panic("ss must be of length SharedKeySize")
	}

	// m' = Kyber.CPAPKE.Dec(sk, ct)
	var m2 [32]byte
	sk.sk.DecryptTo(m2[:], ct)

	// (K'', r') = G(m' ‖ H(pk))
	var kr2 [64]byte
	g := sha3.New512()
	g.Write(m2[:])
	g.Write(sk.hpk[:])
	g.Sum(kr2[:0])

	// c' = Kyber.CPAPKE.Enc(pk, m', r')
	var ct2 [CiphertextSize]byte
	sk.pk.EncryptTo(ct2[:], kr2[32:], m2[:])

	// Compute H(c) and put in second slot of kr2, which will be (K'', H(c)).
	h := sha3.New256()
	h.Write(ct[:CiphertextSize])
	h.Sum(kr2[32:])

	// Replace K'' by  z in the first slot of kr2 if c ≠ c'.
	subtle.ConstantTimeCopy(
		1-subtle.ConstantTimeCompare(ct, ct2[:]),
		kr2[:32],
		sk.z[:],
	)

	// K = KDF(K''/z, H(c))
	kdf := sha3.NewShake256()
	kdf.Write(kr2[:])
	kdf.Read(ss[:SharedKeySize])
}

// Packs sk to buf.
//
// Panics if buf is not of size PrivateKeySize.
func (sk *PrivateKey) Pack(buf []byte) {
	if len(buf) != PrivateKeySize {
		panic("buf must be of length PrivateKeySize")
	}

	sk.sk.Pack(buf[:cpapke.PrivateKeySize])
	buf = buf[cpapke.PrivateKeySize:]
	sk.pk.Pack(buf[:cpapke.PublicKeySize])
	buf = buf[cpapke.PublicKeySize:]
	copy(buf, sk.hpk[:])
	buf = buf[32:]
	copy(buf, sk.z[:])
}

// Unpacks sk from buf.
//
// Panics if buf is not of size PrivateKeySize.
func (sk *PrivateKey) Unpack(buf []byte) {
	if len(buf) != PrivateKeySize {
		panic("buf must be of length PrivateKeySize")
	}

	sk.sk = new(cpapke.PrivateKey)
	sk.sk.Unpack(buf[:cpapke.PrivateKeySize])
	buf = buf[cpapke.PrivateKeySize:]
	sk.pk = new(cpapke.PublicKey)
	sk.pk.Unpack(buf[:cpapke.PublicKeySize])
	buf = buf[cpapke.PublicKeySize:]
	copy(sk.hpk[:], buf[:32])
	copy(sk.z[:], buf[32:])
}

// Packs pk to buf.
//
// Panics if buf is not of size PublicKeySize.
func (pk *PublicKey) Pack(buf []byte) {
	if len(buf) != PublicKeySize {
		panic("buf must be of length PublicKeySize")
	}

	pk.pk.Pack(buf)
}

// Unpacks pk from buf.
//
// Panics if buf is not of size PublicKeySize.
func (pk *PublicKey) Unpack(buf []byte) {
	if len(buf) != PublicKeySize {
		panic("buf must be of length PublicKeySize")
	}

	pk.pk = new(cpapke.PublicKey)
	pk.pk.Unpack(buf)

	// Compute cached H(pk)
	h := sha3.New256()
	h.Write(buf)
	h.Sum(pk.hpk[:0])
}

// Boilerplate down below for the KEM scheme API.

type scheme struct{}

var Scheme kem.Scheme = &scheme{}

func (*scheme) Name() string        { return "Kyber512" }
func (*scheme) PublicKeySize() int  { return PublicKeySize }
func (*scheme) PrivateKeySize() int { return PrivateKeySize }
func (*scheme) SeedSize() int       { return KeySeedSize }
func (*scheme) SharedKeySize() int  { return SharedKeySize }
func (*scheme) CiphertextSize() int { return CiphertextSize }

func (sk *PrivateKey) Scheme() kem.Scheme { return Scheme }
func (pk *PublicKey) Scheme() kem.Scheme  { return Scheme }

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
	if !bytes.Equal(sk.hpk[:], oth.hpk[:]) ||
		!bytes.Equal(sk.z[:], oth.z[:]) {
		return false
	}
	return sk.sk.Equal(oth.sk)
}

func (pk *PublicKey) Equal(other kem.PublicKey) bool {
	oth, ok := other.(*PublicKey)
	if !ok {
		return false
	}
	if pk.pk == nil && oth.pk == nil {
		return true
	}
	if pk.pk == nil || oth.pk == nil {
		return false
	}
	return bytes.Equal(pk.hpk[:], oth.hpk[:])
}

func (pk *PublicKey) MarshalBinary() ([]byte, error) {
	var ret [PublicKeySize]byte
	pk.Pack(ret[:])
	return ret[:], nil
}

func (*scheme) GenerateKey() (kem.PublicKey, kem.PrivateKey, error) {
	return GenerateKey(cryptoRand.Reader)
}

func (*scheme) DeriveKey(seed []byte) (kem.PublicKey, kem.PrivateKey) {
	if len(seed) != KeySeedSize {
		panic(kem.ErrSeedSize)
	}
	return NewKeyFromSeed(seed[:])
}

func (*scheme) Encapsulate(pk kem.PublicKey) (ct []byte, ss []byte) {
	ct = make([]byte, CiphertextSize)
	ss = make([]byte, SharedKeySize)

	pub, ok := pk.(*PublicKey)
	if !ok {
		panic(kem.ErrTypeMismatch)
	}
	pub.EncapsulateTo(ss, ct, nil)
	return
}

func (*scheme) Decapsulate(sk kem.PrivateKey, ct []byte) []byte {
	if len(ct) != CiphertextSize {
		panic(kem.ErrCiphertextSize)
	}

	priv, ok := sk.(*PrivateKey)
	if !ok {
		panic(kem.ErrTypeMismatch)
	}
	ss := make([]byte, SharedKeySize)
	priv.DecapsulateTo(ct, ss)
	return ss
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
