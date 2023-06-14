package blindrsa

// This package implements a partially blind RSA protocol.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"hash"
	"io"
	"math/big"

	"golang.org/x/crypto/hkdf"
)

// BigPublicKey is the same as an rsa.PublicKey struct, except the public
// key is represented as a big integer as opposed to an int. For the partially
// blind scheme, this is required since the public key will typically be
// any value in the RSA group.
type BigPublicKey struct {
	N *big.Int
	e *big.Int
}

// Size returns the size of the public key.
func (pub *BigPublicKey) Size() int {
	return (pub.N.BitLen() + 7) / 8
}

// Marshal encodes the public key exponent (e).
func (pub *BigPublicKey) Marshal() []byte {
	buf := make([]byte, (pub.e.BitLen()+7)/8)
	pub.e.FillBytes(buf)
	return buf
}

// CustomPublicKey is similar to rsa.PrivateKey, containing information needed
// for a private key used in the partially blind signature protocol.
type BigPrivateKey struct {
	d  *big.Int
	pk *BigPublicKey
	p  *big.Int
	q  *big.Int
}

// A PBRSAVerifier represents a Verifier in the RSA blind signature protocol.
// It carries state needed to produce and validate an RSA signature produced
// using the blind RSA protocol.
type RandomizedPBRSAVerifier struct {
	// Public key of the Signer
	pk *BigPublicKey

	// Identifier of the cryptographic hash function used in producing the message signature
	cryptoHash crypto.Hash

	// Hash function used in producing the message signature
	hash hash.Hash
}

func newCustomPublicKey(pk *rsa.PublicKey) *BigPublicKey {
	return &BigPublicKey{
		N: pk.N,
		e: new(big.Int).SetInt64(int64(pk.E)),
	}
}

// RandomizedPBRSAVerifier creates a new PBRSAVerifier using the corresponding Signer parameters.
func NewRandomizedPBRSAVerifier(pk *rsa.PublicKey, hash crypto.Hash) PBRSAVerifier {
	h := convertHashFunction(hash)
	return RandomizedPBRSAVerifier{
		pk:         newCustomPublicKey(pk),
		cryptoHash: hash,
		hash:       h,
	}
}

// augmentPublicKey tweaks the public key based on the input metadata.
//
// See the specification for more details:
// https://datatracker.ietf.org/doc/html/draft-amjad-cfrg-partially-blind-rsa-00#name-public-key-augmentation
//
// See the following issue for more discussion on HKDF vs hash-to-field:
// https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve/issues/202
func augmentPublicKey(h crypto.Hash, pk *BigPublicKey, metadata []byte) *BigPublicKey {
	// expandLen = ceil((ceil(log2(\lambda)) + k) / 8), where k is the security parameter of the suite (e.g., k = 128).
	// We stretch the input metadata beyond \lambda bits s.t. the output bytes are indifferentiable from truly random bytes
	lambda := pk.N.BitLen() / 2
	expandLen := uint((lambda + 128) / 8)

	hkdfSalt := make([]byte, (pk.N.BitLen()+7)/8)
	pk.N.FillBytes(hkdfSalt)
	hkdfInput := append([]byte("key"), append(metadata, 0x00)...)

	hkdf := hkdf.New(h.New, hkdfInput, hkdfSalt, []byte("PBRSA"))
	bytes := make([]byte, expandLen)
	_, err := hkdf.Read(bytes)
	if err != nil {
		panic(err)
	}

	// H_MD(D) = 1 || G(x), where G(x) is output of length \lambda-2 bits
	// We do this by sampling \lambda bits, clearing the top two bits (so the output is \lambda-2 bits)
	// and setting the bottom bit (so the result is odd).
	hmd := new(big.Int).SetBytes(bytes[:lambda/8])
	hmd.SetBit(hmd, 0, 1)
	hmd.SetBit(hmd, lambda-1, 0)
	hmd.SetBit(hmd, lambda-2, 0)

	// Compute e_MD = e * H_MD(D)
	newE := new(big.Int).Mul(hmd, pk.e)
	return &BigPublicKey{
		N: pk.N,
		e: newE,
	}
}

func convertToCustomPublicKey(pk *rsa.PublicKey) *BigPublicKey {
	return &BigPublicKey{
		N: pk.N,
		e: new(big.Int).SetInt64(int64(pk.E)),
	}
}

func convertToCustomPrivateKey(sk *rsa.PrivateKey) *BigPrivateKey {
	return &BigPrivateKey{
		pk: &BigPublicKey{
			N: sk.N,
			e: new(big.Int).SetInt64(int64(sk.PublicKey.E)),
		},
		d: sk.D,
		p: sk.Primes[0],
		q: sk.Primes[1],
	}
}

// augmentPrivateKey tweaks the private key using the metadata as input.
//
// See the specification for more details:
// https://datatracker.ietf.org/doc/html/draft-amjad-cfrg-partially-blind-rsa-00#name-private-key-augmentation
func augmentPrivateKey(h crypto.Hash, sk *BigPrivateKey, metadata []byte) *BigPrivateKey {
	// pih(N) = (p-1)(q-1)
	pm1 := new(big.Int).Set(sk.p)
	pm1.Sub(pm1, new(big.Int).SetInt64(int64(1)))
	qm1 := new(big.Int).Set(sk.q)
	qm1.Sub(qm1, new(big.Int).SetInt64(int64(1)))
	phi := new(big.Int).Mul(pm1, qm1)

	// d = e^-1 mod phi(N)
	pk := augmentPublicKey(h, sk.pk, metadata)
	bigE := new(big.Int).Mod(pk.e, phi)
	d := new(big.Int).ModInverse(bigE, phi)
	return &BigPrivateKey{
		pk: pk,
		d:  d,
		p:  sk.p,
		q:  sk.q,
	}
}

func fixedPartiallyBlind(message, salt []byte, r, rInv *big.Int, pk *BigPublicKey, hash hash.Hash) ([]byte, PBRSAVerifierState, error) {
	encodedMsg, err := encodeMessageEMSAPSS(message, pk.N, hash, salt)
	if err != nil {
		return nil, PBRSAVerifierState{}, err
	}

	m := new(big.Int).SetBytes(encodedMsg)

	bigE := pk.e
	x := new(big.Int).Exp(r, bigE, pk.N)
	z := new(big.Int).Set(m)
	z.Mul(z, x)
	z.Mod(z, pk.N)

	kLen := (pk.N.BitLen() + 7) / 8
	blindedMsg := make([]byte, kLen)
	z.FillBytes(blindedMsg)

	return blindedMsg, PBRSAVerifierState{
		encodedMsg: encodedMsg,
		pk:         pk,
		hash:       hash,
		salt:       salt,
		rInv:       rInv,
	}, nil
}

type PBRSAVerifier interface {
	Blind(random io.Reader, message, metadata []byte) ([]byte, PBRSAVerifierState, error)
	Verify(message, signature, metadata []byte) error
	Hash() hash.Hash
}

// Blind initializes the blind RSA protocol using an input message and source of randomness. The
// signature includes a randomly generated PSS salt whose length equals the size of the underlying
// hash function. This function fails if randomness was not provided.
//
// See the specification for more details:
// https://datatracker.ietf.org/doc/html/draft-amjad-cfrg-partially-blind-rsa-00#name-blind
func (v RandomizedPBRSAVerifier) Blind(random io.Reader, message, metadata []byte) ([]byte, PBRSAVerifierState, error) {
	if random == nil {
		return nil, PBRSAVerifierState{}, ErrInvalidRandomness
	}

	salt := make([]byte, v.hash.Size())
	_, err := random.Read(salt)
	if err != nil {
		return nil, PBRSAVerifierState{}, err
	}

	r, rInv, err := generateBlindingFactor(random, v.pk.N)
	if err != nil {
		return nil, PBRSAVerifierState{}, err
	}

	metadataKey := augmentPublicKey(v.cryptoHash, v.pk, metadata)
	inputMsg := encodeMessageMetadata(message, metadata)
	return fixedPartiallyBlind(inputMsg, salt, r, rInv, metadataKey, v.hash)
}

// Verify verifies the input (message, signature) pair using the augmented public key
// and produces an error upon failure.
//
// See the specification for more details:
// https://datatracker.ietf.org/doc/html/draft-amjad-cfrg-partially-blind-rsa-00#name-verification-2
func (v RandomizedPBRSAVerifier) Verify(message, metadata, signature []byte) error {
	metadataKey := augmentPublicKey(v.cryptoHash, v.pk, metadata)
	inputMsg := encodeMessageMetadata(message, metadata)
	return verifyMessageSignature(inputMsg, signature, v.hash.Size(), metadataKey, v.cryptoHash)
}

// Hash returns the hash function associated with the PBRSAVerifier.
func (v RandomizedPBRSAVerifier) Hash() hash.Hash {
	return v.hash
}

// A PBRSAVerifierState carries state needed to complete the blind signature protocol
// as a verifier.
type PBRSAVerifierState struct {
	// Public key of the Signer
	pk *BigPublicKey

	// Hash function used in producing the message signature
	hash hash.Hash

	// The hashed and encoded message being signed
	encodedMsg []byte

	// The salt used when encoding the message
	salt []byte

	// Inverse of the blinding factor produced by the Verifier
	rInv *big.Int
}

// Finalize computes and outputs the final signature, if it's valid. Otherwise, it returns an error.
//
// See the specification for more details:
// https://datatracker.ietf.org/doc/html/draft-amjad-cfrg-partially-blind-rsa-00#name-finalize
func (state PBRSAVerifierState) Finalize(data []byte) ([]byte, error) {
	kLen := (state.pk.N.BitLen() + 7) / 8
	if len(data) != kLen {
		return nil, ErrUnexpectedSize
	}

	z := new(big.Int).SetBytes(data)
	s := new(big.Int).Set(state.rInv)
	s.Mul(s, z)
	s.Mod(s, state.pk.N)

	sig := make([]byte, kLen)
	s.FillBytes(sig)

	err := verifyBlindSignature(state.pk, state.encodedMsg, sig)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// CopyBlind returns an encoding of the blind value used in the protocol.
func (state PBRSAVerifierState) CopyBlind() []byte {
	r := new(big.Int).ModInverse(state.rInv, state.pk.N)
	return r.Bytes()
}

// CopySalt returns an encoding of the per-message salt used in the protocol.
func (state PBRSAVerifierState) CopySalt() []byte {
	salt := make([]byte, len(state.salt))
	copy(salt, state.salt)
	return salt
}

// An PBRSASigner represents the Signer in the blind RSA protocol.
// It carries the raw RSA private key used for signing blinded messages.
type PBRSASigner struct {
	// An RSA private key
	sk *BigPrivateKey
	h  crypto.Hash
}

// NewPBRSASigner creates a new Signer for the blind RSA protocol using an RSA private key.
func NewPBRSASigner(sk *rsa.PrivateKey, h crypto.Hash) PBRSASigner {
	return PBRSASigner{
		sk: convertToCustomPrivateKey(sk),
		h:  h,
	}
}

// BlindSign blindly computes the RSA operation using the Signer's private key on the blinded
// message input, if it's of valid length, and returns an error should the function fail.
//
// See the specification for more details:
// https://datatracker.ietf.org/doc/html/draft-amjad-cfrg-partially-blind-rsa-00#name-blindsign
func (signer PBRSASigner) BlindSign(data, metadata []byte) ([]byte, error) {
	kLen := (signer.sk.pk.N.BitLen() + 7) / 8
	if len(data) != kLen {
		return nil, ErrUnexpectedSize
	}

	m := new(big.Int).SetBytes(data)
	if m.Cmp(signer.sk.pk.N) > 0 {
		return nil, ErrInvalidMessageLength
	}

	skPrime := augmentPrivateKey(signer.h, signer.sk, metadata)

	s, err := decryptAndCheck(rand.Reader, skPrime, m)
	if err != nil {
		return nil, err
	}

	blindSig := make([]byte, kLen)
	s.FillBytes(blindSig)

	return blindSig, nil
}
