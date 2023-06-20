package blindrsa

// This package implements the blind RSA protocol based on the CFRG specification:
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-rsa-blind-signatures
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
	"hash"
	"io"
	"math/big"

	"github.com/cloudflare/circl/blindsign/blindrsa/internal/common"
	"github.com/cloudflare/circl/blindsign/blindrsa/internal/keys"
)

// An randomBRSAVerifier represents a Verifier in the RSA blind signature protocol.
// It carries state needed to produce and validate an RSA signature produced
// using the blind RSA protocol.
type randomBRSAVerifier struct {
	// Public key of the Signer
	pk *rsa.PublicKey

	// Identifier of the cryptographic hash function used in producing the message signature
	cryptoHash crypto.Hash

	// Hash function used in producing the message signature
	hash hash.Hash
}

// A determinsiticBRSAVerifier is a BRSAVerifier that supports deterministic signatures.
type determinsiticBRSAVerifier struct {
	// Public key of the Signer
	pk *rsa.PublicKey

	// Identifier of the cryptographic hash function used in producing the message signature
	cryptoHash crypto.Hash

	// Hash function used in producing the message signature
	hash hash.Hash
}

// Verifier is a type that implements the client side of the blind RSA
// protocol, described in https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-rsa-blind-signatures
type Verifier interface {
	// Blind initializes the blind RSA protocol using an input message and source of randomness. The
	// signature is deterministic. This function fails if randomness was not provided.
	Blind(random io.Reader, message []byte) ([]byte, VerifierState, error)

	// FixedBlind runs the Blind function with fixed blind and salt inputs.
	FixedBlind(message, blind, salt []byte) ([]byte, VerifierState, error)

	// Verify verifies the input (message, signature) pair and produces an error upon failure.
	Verify(message, signature []byte) error

	// Hash returns the hash function associated with the Verifier.
	Hash() hash.Hash
}

// NewDeterministicVerifier creates a new DeterminsiticBRSAVerifier using the corresponding Signer parameters.
// This corresponds to the RSABSSA-SHA384-PSSZERO-Deterministic variant. See the specification for more details:
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-rsa-blind-signatures#name-rsabssa-variants
func NewDeterministicVerifier(pk *rsa.PublicKey, hash crypto.Hash) Verifier {
	h := common.ConvertHashFunction(hash)
	return determinsiticBRSAVerifier{
		pk:         pk,
		cryptoHash: hash,
		hash:       h,
	}
}

// Hash returns the hash function associated with the BRSAVerifier.
func (v determinsiticBRSAVerifier) Hash() hash.Hash {
	return v.hash
}

// NewVerifier creates a new BRSAVerifier using the corresponding Signer parameters.
// This corresponds to the RSABSSA-SHA384-PSS-Deterministic variant. See the specification for more details:
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-rsa-blind-signatures#name-rsabssa-variants
func NewVerifier(pk *rsa.PublicKey, hash crypto.Hash) Verifier {
	h := common.ConvertHashFunction(hash)
	return randomBRSAVerifier{
		pk:         pk,
		cryptoHash: hash,
		hash:       h,
	}
}

// Hash returns the hash function associated with the BRSAVerifier.
func (v randomBRSAVerifier) Hash() hash.Hash {
	return v.hash
}

func fixedBlind(message, salt []byte, r, rInv *big.Int, pk *rsa.PublicKey, hash hash.Hash) ([]byte, VerifierState, error) {
	encodedMsg, err := common.EncodeMessageEMSAPSS(message, pk.N, hash, salt)
	if err != nil {
		return nil, VerifierState{}, err
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

	return blindedMsg, VerifierState{
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
func (v determinsiticBRSAVerifier) Blind(random io.Reader, message []byte) ([]byte, VerifierState, error) {
	if random == nil {
		return nil, VerifierState{}, common.ErrInvalidRandomness
	}

	r, rInv, err := common.GenerateBlindingFactor(random, v.pk.N)
	if err != nil {
		return nil, VerifierState{}, err
	}

	return fixedBlind(message, nil, r, rInv, v.pk, v.hash)
}

// FixedBlind runs the Blind function with fixed blind and salt inputs.
func (v determinsiticBRSAVerifier) FixedBlind(message, blind, salt []byte) ([]byte, VerifierState, error) {
	if blind == nil {
		return nil, VerifierState{}, common.ErrInvalidRandomness
	}

	r := new(big.Int).SetBytes(blind)
	if r.Cmp(v.pk.N) >= 0 {
		return nil, VerifierState{}, common.ErrInvalidBlind
	}
	rInv := new(big.Int).ModInverse(r, v.pk.N)
	if rInv == nil {
		return nil, VerifierState{}, common.ErrInvalidBlind
	}

	return fixedBlind(message, salt, r, rInv, v.pk, v.hash)
}

// Verify verifies the input (message, signature) pair and produces an error upon failure.
func (v determinsiticBRSAVerifier) Verify(message, signature []byte) error {
	return common.VerifyMessageSignature(message, signature, 0, keys.NewBigPublicKey(v.pk), v.cryptoHash)
}

// Blind initializes the blind RSA protocol using an input message and source of randomness. The
// signature includes a randomly generated PSS salt whose length equals the size of the underlying
// hash function. This function fails if randomness was not provided.
//
// See the specification for more details:
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-rsa-blind-signatures-02#section-5.1.1
func (v randomBRSAVerifier) Blind(random io.Reader, message []byte) ([]byte, VerifierState, error) {
	if random == nil {
		return nil, VerifierState{}, common.ErrInvalidRandomness
	}

	salt := make([]byte, v.hash.Size())
	_, err := io.ReadFull(random, salt)
	if err != nil {
		return nil, VerifierState{}, err
	}

	r, rInv, err := common.GenerateBlindingFactor(random, v.pk.N)
	if err != nil {
		return nil, VerifierState{}, err
	}

	return fixedBlind(message, salt, r, rInv, v.pk, v.hash)
}

// FixedBlind runs the Blind function with fixed blind and salt inputs.
func (v randomBRSAVerifier) FixedBlind(message, blind, salt []byte) ([]byte, VerifierState, error) {
	if blind == nil {
		return nil, VerifierState{}, common.ErrInvalidRandomness
	}

	r := new(big.Int).SetBytes(blind)
	if r.Cmp(v.pk.N) >= 0 {
		return nil, VerifierState{}, common.ErrInvalidBlind
	}

	rInv := new(big.Int).ModInverse(r, v.pk.N)
	if rInv == nil {
		return nil, VerifierState{}, common.ErrInvalidBlind
	}

	return fixedBlind(message, salt, r, rInv, v.pk, v.hash)
}

// Verify verifies the input (message, signature) pair and produces an error upon failure.
func (v randomBRSAVerifier) Verify(message, signature []byte) error {
	return common.VerifyMessageSignature(message, signature, v.hash.Size(), keys.NewBigPublicKey(v.pk), v.cryptoHash)
}

// An VerifierState carries state needed to complete the blind signature protocol
// as a verifier.
type VerifierState struct {
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

	err := common.VerifyBlindSignature(keys.NewBigPublicKey(state.pk), state.encodedMsg, sig)
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
	sk *rsa.PrivateKey
}

// NewSigner creates a new Signer for the blind RSA protocol using an RSA private key.
func NewSigner(sk *rsa.PrivateKey) Signer {
	return Signer{
		sk: sk,
	}
}

// BlindSign blindly computes the RSA operation using the Signer's private key on the blinded
// message input, if it's of valid length, and returns an error should the function fail.
//
// See the specification for more details:
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-rsa-blind-signatures-02#section-5.1.2
func (signer Signer) BlindSign(data []byte) ([]byte, error) {
	kLen := (signer.sk.N.BitLen() + 7) / 8
	if len(data) != kLen {
		return nil, common.ErrUnexpectedSize
	}

	m := new(big.Int).SetBytes(data)
	if m.Cmp(signer.sk.N) > 0 {
		return nil, common.ErrInvalidMessageLength
	}

	s, err := common.DecryptAndCheck(rand.Reader, keys.NewBigPrivateKey(signer.sk), m)
	if err != nil {
		return nil, err
	}

	blindSig := make([]byte, kLen)
	s.FillBytes(blindSig)

	return blindSig, nil
}

var (
	ErrUnexpectedSize          = common.ErrUnexpectedSize
	ErrInvalidMessageLength    = common.ErrInvalidMessageLength
	ErrInvalidBlind            = common.ErrInvalidBlind
	ErrInvalidRandomness       = common.ErrInvalidRandomness
	ErrUnsupportedHashFunction = common.ErrUnsupportedHashFunction
)
