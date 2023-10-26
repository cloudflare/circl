// Package blindrsa implements the RSA Blind Signature Protocol as defined in [RFC9474].
//
// The RSA Blind Signature protocol, and its variant RSABSSA
// (RSA Blind Signature with Appendix) is a two-party protocol
// between a Client and Server where they interact to compute
//
//	sig = Sign(sk, input_msg),
//
// where `input_msg = Prepare(msg)` is a prepared version of a private
// message `msg` provided by the Client, and `sk` is the private signing
// key provided by the server.
//
// # Supported Variants
//
// This package is compliant with the [RFC-9474] document
// and supports the following variants:
//   - [NewVerifier] implements RSABSSA-SHA384-PSS-Deterministic
//   - [NewDeterministicVerifier] implements RSABSSA-SHA384-PSSZERO-Deterministic
//
// while these variants are not supported yet:
//   - RSABSSA-SHA384-PSS-Randomized
//   - RSABSSA-SHA384-PSSZERO-Randomized
//
// [RFC-9474]: https://www.rfc-editor.org/info/rfc9474
package blindrsa

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

// A deterministicBRSAVerifier is a BRSAVerifier that supports deterministic signatures.
type deterministicBRSAVerifier struct {
	// Public key of the Signer
	pk *rsa.PublicKey

	// Identifier of the cryptographic hash function used in producing the message signature
	cryptoHash crypto.Hash

	// Hash function used in producing the message signature
	hash hash.Hash
}

// Verifier is a type that implements the client side of the blind RSA
// protocol, described in https://www.rfc-editor.org/rfc/rfc9474.html#name-rsabssa-variants
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

// NewDeterministicVerifier creates a new DeterministicBRSAVerifier using the corresponding Signer parameters.
// This corresponds to the RSABSSA-SHA384-PSSZERO-Deterministic variant. See the specification for more details:
// https://www.rfc-editor.org/rfc/rfc9474.html#name-rsabssa-variants
func NewDeterministicVerifier(pk *rsa.PublicKey, hash crypto.Hash) Verifier {
	h := common.ConvertHashFunction(hash)
	return deterministicBRSAVerifier{
		pk:         pk,
		cryptoHash: hash,
		hash:       h,
	}
}

// Hash returns the hash function associated with the BRSAVerifier.
func (v deterministicBRSAVerifier) Hash() hash.Hash {
	return v.hash
}

// NewVerifier creates a new BRSAVerifier using the corresponding Signer parameters.
// This corresponds to the RSABSSA-SHA384-PSS-Deterministic variant. See the specification for more details:
// https://www.rfc-editor.org/rfc/rfc9474.html#name-rsabssa-variants
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

func prepareMsg(message, prefix []byte) []byte {
	return append(prefix, message...)
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
// https://www.rfc-editor.org/rfc/rfc9474.html#name-blind
func (v deterministicBRSAVerifier) Blind(random io.Reader, message []byte) ([]byte, VerifierState, error) {
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
func (v deterministicBRSAVerifier) FixedBlind(message, blind, salt []byte) ([]byte, VerifierState, error) {
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
func (v deterministicBRSAVerifier) Verify(message, signature []byte) error {
	return common.VerifyMessageSignature(message, signature, 0, keys.NewBigPublicKey(v.pk), v.cryptoHash)
}

// Blind initializes the blind RSA protocol using an input message and source of randomness. The
// signature includes a randomly generated PSS salt whose length equals the size of the underlying
// hash function. This function fails if randomness was not provided.
//
// See the specification for more details:
// https://www.rfc-editor.org/rfc/rfc9474.html#name-blind
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
// https://www.rfc-editor.org/rfc/rfc9474.html#name-finalize
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
// https://www.rfc-editor.org/rfc/rfc9474.html#name-blindsign
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
