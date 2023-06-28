// Package partiallyblindrsa implements a partially blind RSA protocol.
package partiallyblindrsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"math/big"

	"github.com/cloudflare/circl/blindsign/blindrsa/internal/common"
	"github.com/cloudflare/circl/blindsign/blindrsa/internal/keys"
	"golang.org/x/crypto/hkdf"
)

func encodeMessageMetadata(message, metadata []byte) []byte {
	lenBuffer := []byte{'m', 's', 'g', 0, 0, 0, 0}

	binary.BigEndian.PutUint32(lenBuffer[3:], uint32(len(metadata)))
	framedMetadata := append(lenBuffer, metadata...)
	return append(framedMetadata, message...)
}

// A randomizedVerifier represents a Verifier in the partially blind RSA signature protocol.
// It carries state needed to produce and validate an RSA signature produced
// using the blind RSA protocol.
type randomizedVerifier struct {
	// Public key of the Signer
	pk *keys.BigPublicKey

	// Identifier of the cryptographic hash function used in producing the message signature
	cryptoHash crypto.Hash

	// Hash function used in producing the message signature
	hash hash.Hash
}

// NewVerifier creates a new PBRSAVerifier using the corresponding Signer parameters.
// This corresponds to the RSAPBSSA-SHA384-PSS-Deterministic variant. See the specification for more details:
// https://datatracker.ietf.org/doc/html/draft-amjad-cfrg-partially-blind-rsa#name-rsapbssa-variants
func NewVerifier(pk *rsa.PublicKey, hash crypto.Hash) Verifier {
	h := common.ConvertHashFunction(hash)
	return randomizedVerifier{
		pk:         keys.NewBigPublicKey(pk),
		cryptoHash: hash,
		hash:       h,
	}
}

// derivePublicKey tweaks the public key based on the input metadata.
//
// See the specification for more details:
// https://datatracker.ietf.org/doc/html/draft-amjad-cfrg-partially-blind-rsa-00#name-public-key-augmentation
//
// See the following issue for more discussion on HKDF vs hash-to-field:
// https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve/issues/202
func derivePublicKey(h crypto.Hash, pk *keys.BigPublicKey, metadata []byte) *keys.BigPublicKey {
	// expandLen = ceil((ceil(log2(\lambda)/2) + k) / 8), where k is the security parameter of the suite (e.g., k = 128).
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
	newE := new(big.Int).SetBytes(bytes[:lambda/8])
	newE.SetBit(newE, 0, 1)
	newE.SetBit(newE, lambda-1, 0)
	newE.SetBit(newE, lambda-2, 0)

	// Compute e_MD = e * H_MD(D)
	return &keys.BigPublicKey{
		N: pk.N,
		E: newE,
	}
}

// deriveKeyPair tweaks the private key using the metadata as input.
//
// See the specification for more details:
// https://datatracker.ietf.org/doc/html/draft-amjad-cfrg-partially-blind-rsa-00#name-private-key-augmentation
func deriveKeyPair(h crypto.Hash, sk *keys.BigPrivateKey, metadata []byte) *keys.BigPrivateKey {
	// pih(N) = (p-1)(q-1)
	pm1 := new(big.Int).Set(sk.P)
	pm1.Sub(pm1, new(big.Int).SetInt64(int64(1)))
	qm1 := new(big.Int).Set(sk.Q)
	qm1.Sub(qm1, new(big.Int).SetInt64(int64(1)))
	phi := new(big.Int).Mul(pm1, qm1)

	// d = e^-1 mod phi(N)
	pk := derivePublicKey(h, sk.Pk, metadata)
	bigE := new(big.Int).Mod(pk.E, phi)
	d := new(big.Int).ModInverse(bigE, phi)
	return &keys.BigPrivateKey{
		Pk: pk,
		D:  d,
		P:  sk.P,
		Q:  sk.Q,
	}
}

func fixedPartiallyBlind(message, salt []byte, r, rInv *big.Int, pk *keys.BigPublicKey, hash hash.Hash) ([]byte, VerifierState, error) {
	encodedMsg, err := common.EncodeMessageEMSAPSS(message, pk.N, hash, salt)
	if err != nil {
		return nil, VerifierState{}, err
	}

	m := new(big.Int).SetBytes(encodedMsg)

	bigE := pk.E
	x := new(big.Int).Exp(r, bigE, pk.N)
	z := new(big.Int).Set(m)
	z.Mul(z, x)
	z.Mod(z, pk.N)

	kLen := (pk.N.BitLen() + 7) / 8
	blindedMsg := make([]byte, kLen)
	z.FillBytes(blindedMsg)

	return blindedMsg, VerifierState{
		encodedMsg: encodedMsg,
		pk:         pk,
		hash:       hash,
		salt:       salt,
		rInv:       rInv,
	}, nil
}

// Verifier is a type that implements the client side of the partially blind RSA
// protocol, described in https://datatracker.ietf.org/doc/html/draft-amjad-cfrg-partially-blind-rsa-00
type Verifier interface {
	// Blind initializes the blind RSA protocol using an input message and source of randomness. The
	// signature includes a randomly generated PSS salt whose length equals the size of the underlying
	// hash function. This function fails if randomness was not provided.
	Blind(random io.Reader, message, metadata []byte) ([]byte, VerifierState, error)

	// Verify verifies the input (message, signature) pair using the augmented public key
	// and produces an error upon failure.
	Verify(message, signature, metadata []byte) error

	// Hash returns the hash function associated with the Verifier.
	Hash() hash.Hash
}

// Blind initializes the blind RSA protocol using an input message and source of randomness. The
// signature includes a randomly generated PSS salt whose length equals the size of the underlying
// hash function. This function fails if randomness was not provided.
//
// See the specification for more details:
// https://datatracker.ietf.org/doc/html/draft-amjad-cfrg-partially-blind-rsa-00#name-blind
func (v randomizedVerifier) Blind(random io.Reader, message, metadata []byte) ([]byte, VerifierState, error) {
	if random == nil {
		return nil, VerifierState{}, common.ErrInvalidRandomness
	}

	salt := make([]byte, v.hash.Size())
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, VerifierState{}, err
	}

	r, rInv, err := common.GenerateBlindingFactor(random, v.pk.N)
	if err != nil {
		return nil, VerifierState{}, err
	}

	metadataKey := derivePublicKey(v.cryptoHash, v.pk, metadata)
	inputMsg := encodeMessageMetadata(message, metadata)
	return fixedPartiallyBlind(inputMsg, salt, r, rInv, metadataKey, v.hash)
}

// Verify verifies the input (message, signature) pair using the augmented public key
// and produces an error upon failure.
//
// See the specification for more details:
// https://datatracker.ietf.org/doc/html/draft-amjad-cfrg-partially-blind-rsa-00#name-verification-2
func (v randomizedVerifier) Verify(message, metadata, signature []byte) error {
	metadataKey := derivePublicKey(v.cryptoHash, v.pk, metadata)
	inputMsg := encodeMessageMetadata(message, metadata)
	return common.VerifyMessageSignature(inputMsg, signature, v.hash.Size(), metadataKey, v.cryptoHash)
}

// Hash returns the hash function associated with the Verifier.
func (v randomizedVerifier) Hash() hash.Hash {
	return v.hash
}

// A VerifierState carries state needed to complete the blind signature protocol
// as a verifier.
type VerifierState struct {
	// Public key of the Signer
	pk *keys.BigPublicKey

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
func (state VerifierState) Finalize(data []byte) ([]byte, error) {
	kLen := (state.pk.N.BitLen() + 7) / 8
	if len(data) != kLen {
		return nil, common.ErrUnexpectedSize
	}

	z := new(big.Int).SetBytes(data)
	s := new(big.Int).Set(state.rInv)
	s.Mul(s, z)
	s.Mod(s, state.pk.N)

	sig := make([]byte, kLen)
	s.FillBytes(sig)

	err := common.VerifyBlindSignature(state.pk, state.encodedMsg, sig)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// CopyBlind returns an encoding of the blind value used in the protocol.
func (state VerifierState) CopyBlind() []byte {
	r := new(big.Int).ModInverse(state.rInv, state.pk.N)
	return r.Bytes()
}

// CopySalt returns an encoding of the per-message salt used in the protocol.
func (state VerifierState) CopySalt() []byte {
	salt := make([]byte, len(state.salt))
	copy(salt, state.salt)
	return salt
}

// An Signer represents the Signer in the blind RSA protocol.
// It carries the raw RSA private key used for signing blinded messages.
type Signer struct {
	// An RSA private key
	sk *keys.BigPrivateKey
	h  crypto.Hash
}

// isSafePrime returns true if the input prime p is safe, i.e., p = (2 * q) + 1 for some prime q
func isSafePrime(p *big.Int) bool {
	q := new(big.Int).Set(p)
	q.Sub(q, big.NewInt(1))
	q.Div(q, big.NewInt(2))
	return q.ProbablyPrime(20)
}

// NewSigner creates a new Signer for the blind RSA protocol using an RSA private key.
func NewSigner(sk *rsa.PrivateKey, h crypto.Hash) (Signer, error) {
	bigSk := keys.NewBigPrivateKey(sk)
	if !(isSafePrime(bigSk.P) && isSafePrime(bigSk.Q)) {
		return Signer{}, ErrInvalidPrivateKey
	}

	return Signer{
		sk: bigSk,
		h:  h,
	}, nil
}

// BlindSign blindly computes the RSA operation using the Signer's private key on the blinded
// message input, if it's of valid length, and returns an error should the function fail.
//
// See the specification for more details:
// https://datatracker.ietf.org/doc/html/draft-amjad-cfrg-partially-blind-rsa-00#name-blindsign
func (signer Signer) BlindSign(data, metadata []byte) ([]byte, error) {
	kLen := (signer.sk.Pk.N.BitLen() + 7) / 8
	if len(data) != kLen {
		return nil, common.ErrUnexpectedSize
	}

	m := new(big.Int).SetBytes(data)
	if m.Cmp(signer.sk.Pk.N) > 0 {
		return nil, common.ErrInvalidMessageLength
	}

	skPrime := deriveKeyPair(signer.h, signer.sk, metadata)

	s, err := common.DecryptAndCheck(rand.Reader, skPrime, m)
	if err != nil {
		return nil, err
	}

	blindSig := make([]byte, kLen)
	s.FillBytes(blindSig)

	return blindSig, nil
}

var (
	// ErrInvalidPrivateKey is the error used if a private key is invalid
	ErrInvalidPrivateKey    = errors.New("blindsign/blindrsa/partiallyblindrsa: invalid private key")
	ErrUnexpectedSize       = common.ErrUnexpectedSize
	ErrInvalidMessageLength = common.ErrInvalidMessageLength
	ErrInvalidRandomness    = common.ErrInvalidRandomness
)
