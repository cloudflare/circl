package blindrsa

// This package implements the blind RSA protocol based on the CFRG specification:
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-rsa-blind-signatures-02
//
// Blind RSA is an example of a blind signature protocol is a two-party protocol
// for computing a digital signature. One party (the server) holds the signing
// key, and the other (the client) holds the message input. Blindness
// ensures that the server does not learn anything about the client's
// input during the BlindSign step.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
)

var errUnsupportedHashFunction = errors.New("unsupported hash function")

// An RandomBRSAVerifier represents a Verifier in the RSA blind signature protocol.
// It carries state needed to produce and validate an RSA signature produced
// using the blind RSA protocol.
type RandomBRSAVerifier struct {
	// Public key of the Signer
	pk *rsa.PublicKey

	// Identifier of the cryptographic hash function used in producing the message signature
	cryptoHash crypto.Hash

	// Hash function used in producing the message signature
	hash hash.Hash
}

// A DeterminsiticBRSAVerifier is a BRSAVerifier that supports deterministic signatures.
type DeterminsiticBRSAVerifier struct {
	// Public key of the Signer
	pk *rsa.PublicKey

	// Identifier of the cryptographic hash function used in producing the message signature
	cryptoHash crypto.Hash

	// Hash function used in producing the message signature
	hash hash.Hash
}

type BRSAVerifier interface {
	Blind(random io.Reader, message []byte) ([]byte, BRSAVerifierState, error)
	FixedBlind(message, blind, salt []byte) ([]byte, BRSAVerifierState, error)
	Verify(message, signature []byte) error
	Hash() hash.Hash
	PublicKey() *rsa.PublicKey
}

func convertHashFunction(hash crypto.Hash) hash.Hash {
	switch hash {
	case crypto.SHA256:
		return sha256.New()
	case crypto.SHA384:
		return sha512.New384()
	case crypto.SHA512:
		return sha512.New()
	default:
		panic(errUnsupportedHashFunction)
	}
}

// NewDeterministicBRSAVerifier creates a new DeterminsiticBRSAVerifier using the corresponding Signer parameters.
func NewDeterministicBRSAVerifier(pk *rsa.PublicKey, hash crypto.Hash) BRSAVerifier {
	h := convertHashFunction(hash)
	return DeterminsiticBRSAVerifier{
		pk:         pk,
		cryptoHash: hash,
		hash:       h,
	}
}

func (v DeterminsiticBRSAVerifier) Hash() hash.Hash {
	return v.hash
}

func (v DeterminsiticBRSAVerifier) PublicKey() *rsa.PublicKey {
	return v.pk
}

// NewBRSAVerifier creates a new BRSAVerifier using the corresponding Signer parameters.
func NewBRSAVerifier(pk *rsa.PublicKey, hash crypto.Hash) BRSAVerifier {
	h := convertHashFunction(hash)
	return RandomBRSAVerifier{
		pk:         pk,
		cryptoHash: hash,
		hash:       h,
	}
}

func (v RandomBRSAVerifier) Hash() hash.Hash {
	return v.hash
}

func (v RandomBRSAVerifier) PublicKey() *rsa.PublicKey {
	return v.pk
}

func encodeMessageEMSAPSS(message []byte, N *big.Int, hash hash.Hash, salt []byte) ([]byte, error) {
	hash.Reset() // Ensure the hash state is cleared
	hash.Write(message)
	digest := hash.Sum(nil)
	hash.Reset()
	emBits := N.BitLen() - 1
	encodedMsg, err := emsaPSSEncode(digest[:], emBits, salt, hash)
	return encodedMsg, err
}

func generateBlindingFactor(random io.Reader, N *big.Int) (*big.Int, *big.Int, error) {
	randReader := random
	if randReader == nil {
		randReader = rand.Reader
	}
	r, err := rand.Int(randReader, N)
	if err != nil {
		return nil, nil, err
	}

	if r.Sign() == 0 {
		r = bigOne
	}
	rInv := new(big.Int).ModInverse(r, N)
	if rInv == nil {
		fmt.Println(r, N)
		return nil, nil, ErrInvalidBlind
	}

	return r, rInv, nil
}

func fixedBlind(message, salt []byte, r, rInv *big.Int, pk *rsa.PublicKey, hash hash.Hash) ([]byte, BRSAVerifierState, error) {
	encodedMsg, err := encodeMessageEMSAPSS(message, pk.N, hash, salt)
	if err != nil {
		return nil, BRSAVerifierState{}, err
	}

	m := new(big.Int).SetBytes(encodedMsg)

	bigE := big.NewInt(int64(pk.E))
	x := new(big.Int).Exp(r, bigE, pk.N)
	z := new(big.Int).Set(m)
	z.Mul(z, x)
	z.Mod(z, pk.N)

	kLen := (pk.N.BitLen() + 7) / 8
	blindedMsg := make([]byte, kLen)
	z.FillBytes(blindedMsg)

	return blindedMsg, BRSAVerifierState{
		encodedMsg: encodedMsg,
		pk:         pk,
		hash:       hash,
		salt:       salt,
		rInv:       rInv,
	}, nil
}

// Blind initializes the blind RSA protocol using an input message and source of randomness. The
// signature is deterministic. This function fails if randomness was not provided.
//
// See the specification for more details:
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-rsa-blind-signatures-02#section-5.1.1
func (v DeterminsiticBRSAVerifier) Blind(random io.Reader, message []byte) ([]byte, BRSAVerifierState, error) {
	if random == nil {
		return nil, BRSAVerifierState{}, ErrInvalidRandomness
	}

	r, rInv, err := generateBlindingFactor(random, v.pk.N)
	if err != nil {
		return nil, BRSAVerifierState{}, err
	}

	return fixedBlind(message, nil, r, rInv, v.pk, v.hash)
}

func saltLength(opts *rsa.PSSOptions) int {
	if opts == nil {
		return rsa.PSSSaltLengthAuto
	}
	return opts.SaltLength
}

// FixedBlind runs the Blind function with fixed blind and salt inputs.
func (v DeterminsiticBRSAVerifier) FixedBlind(message, blind, salt []byte) ([]byte, BRSAVerifierState, error) {
	if blind == nil {
		return nil, BRSAVerifierState{}, ErrInvalidRandomness
	}

	r := new(big.Int).SetBytes(blind)
	rInv := new(big.Int).ModInverse(r, v.pk.N)
	if rInv == nil {
		return nil, BRSAVerifierState{}, ErrInvalidBlind
	}

	return fixedBlind(message, salt, r, rInv, v.pk, v.hash)
}

// Verify verifies the input (message, signature) pair and produces an error upon failure.
func (v DeterminsiticBRSAVerifier) Verify(message, signature []byte) error {
	return verifyMessageSignature(message, signature, 0, convertToCustomPublicKey(v.pk), v.cryptoHash)
}

// Blind initializes the blind RSA protocol using an input message and source of randomness. The
// signature includes a randomly generated PSS salt whose length equals the size of the underlying
// hash function. This function fails if randomness was not provided.
//
// See the specification for more details:
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-rsa-blind-signatures-02#section-5.1.1
func (v RandomBRSAVerifier) Blind(random io.Reader, message []byte) ([]byte, BRSAVerifierState, error) {
	if random == nil {
		return nil, BRSAVerifierState{}, ErrInvalidRandomness
	}

	salt := make([]byte, v.hash.Size())
	_, err := io.ReadFull(random, salt)
	if err != nil {
		return nil, BRSAVerifierState{}, err
	}

	r, rInv, err := generateBlindingFactor(random, v.pk.N)
	if err != nil {
		return nil, BRSAVerifierState{}, err
	}

	return fixedBlind(message, salt, r, rInv, v.pk, v.hash)
}

// FixedBlind runs the Blind function with fixed blind and salt inputs.
func (v RandomBRSAVerifier) FixedBlind(message, blind, salt []byte) ([]byte, BRSAVerifierState, error) {
	if blind == nil {
		return nil, BRSAVerifierState{}, ErrInvalidRandomness
	}

	r := new(big.Int).SetBytes(blind)
	rInv := new(big.Int).ModInverse(r, v.pk.N)
	if rInv == nil {
		return nil, BRSAVerifierState{}, ErrInvalidBlind
	}

	return fixedBlind(message, salt, r, rInv, v.pk, v.hash)
}

// Verify verifies the input (message, signature) pair and produces an error upon failure.
func (v RandomBRSAVerifier) Verify(message, signature []byte) error {
	return verifyMessageSignature(message, signature, v.hash.Size(), convertToCustomPublicKey(v.pk), v.cryptoHash)
}

// An BRSAVerifierState carries state needed to complete the blind signature protocol
// as a verifier.
type BRSAVerifierState struct {
	// Public key of the Signer
	pk *rsa.PublicKey

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
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-rsa-blind-signatures-02#section-5.1.3
func (state BRSAVerifierState) Finalize(data []byte) ([]byte, error) {
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

	err := verifyBlindSignature(convertToCustomPublicKey(state.pk), state.encodedMsg, sig)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// CopyBlind returns an encoding of the blind value used in the protocol.
func (state BRSAVerifierState) CopyBlind() []byte {
	r := new(big.Int).ModInverse(state.rInv, state.pk.N)
	return r.Bytes()
}

// CopySalt returns an encoding of the per-message salt used in the protocol.
func (state BRSAVerifierState) CopySalt() []byte {
	salt := make([]byte, len(state.salt))
	copy(salt, state.salt)
	return salt
}

// An BRSASigner represents the Signer in the blind RSA protocol.
// It carries the raw RSA private key used for signing blinded messages.
type BRSASigner struct {
	// An RSA private key
	sk *rsa.PrivateKey
}

// NewBRSASigner creates a new Signer for the blind RSA protocol using an RSA private key.
func NewBRSASigner(sk *rsa.PrivateKey) BRSASigner {
	return BRSASigner{
		sk: sk,
	}
}

// BlindSign blindly computes the RSA operation using the Signer's private key on the blinded
// message input, if it's of valid length, and returns an error should the function fail.
//
// See the specification for more details:
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-rsa-blind-signatures-02#section-5.1.2
func (signer BRSASigner) BlindSign(data []byte) ([]byte, error) {
	kLen := (signer.sk.N.BitLen() + 7) / 8
	if len(data) != kLen {
		return nil, ErrUnexpectedSize
	}

	m := new(big.Int).SetBytes(data)
	if m.Cmp(signer.sk.N) > 0 {
		return nil, ErrInvalidMessageLength
	}

	s, err := decryptAndCheck(rand.Reader, convertToCustomPrivateKey(signer.sk), m)
	if err != nil {
		return nil, err
	}

	blindSig := make([]byte, kLen)
	s.FillBytes(blindSig)

	return blindSig, nil
}

var (
	// ErrUnexpectedSize is the error used if the size of a parameter does not match its expected value.
	ErrUnexpectedSize = errors.New("blindsign/blindrsa: unexpected input size")

	// ErrInvalidMessageLength is the error used if the size of a protocol message does not match its expected value.
	ErrInvalidMessageLength = errors.New("blindsign/blindrsa: invalid message length")

	// ErrInvalidBlind is the error used if the blind generated by the Verifier fails.
	ErrInvalidBlind = errors.New("blindsign/blindrsa: invalid blind")

	// ErrInvalidRandomness is the error used if caller did not provide randomness to the Blind() function.
	ErrInvalidRandomness = errors.New("blindsign/blindrsa: invalid random parameter")
)
