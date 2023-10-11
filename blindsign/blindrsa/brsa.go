// Package blindrsa implements the RSA Blind Signature Protocol as defined in [RFC9474].
//
// The RSA Blind Signature protocol, and its variant RSABSSA
// (RSA Blind Signature Scheme with Appendix) is a two-party protocol
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
//   - RSABSSA-SHA384-PSS-Deterministic
//   - RSABSSA-SHA384-PSSZERO-Deterministic
//   - RSABSSA-SHA384-PSS-Randomized
//   - RSABSSA-SHA384-PSSZERO-Randomized
//
// [RFC-9474]: https://www.rfc-editor.org/info/rfc9474
package blindrsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"math/big"

	"github.com/cloudflare/circl/blindsign/blindrsa/internal/common"
	"github.com/cloudflare/circl/blindsign/blindrsa/internal/keys"
)

type Variant int

const (
	SHA384PSSRandomized        Variant = iota // RSABSSA-SHA384_PSS_Randomized
	SHA384PSSZeroRandomized                   // RSABSSA-SHA384_PSSZero_Randomized
	SHA384PSSDeterministic                    // RSABSSA-SHA384_PSS_Deterministic
	SHA384PSSZeroDeterministic                // RSABSSA-SHA384_PSSZero_Deterministic
)

func (v Variant) String() string {
	switch v {
	case SHA384PSSRandomized:
		return "RSABSSA-SHA384-PSS-Randomized"
	case SHA384PSSZeroRandomized:
		return "RSABSSA-SHA384-PSSZero-Randomized"
	case SHA384PSSDeterministic:
		return "RSABSSA-SHA384-PSS-Deterministic"
	case SHA384PSSZeroDeterministic:
		return "RSABSSA-SHA384-PSSZero-Deterministic"
	default:
		return "invalid RSABSSA variant"
	}
}

// Client is a type that implements the client side of the blind RSA
// protocol, described in https://www.rfc-editor.org/rfc/rfc9474.html#name-rsabssa-variants
type Client struct {
	v         Verifier
	prefixLen int
}

func NewClient(v Variant, pk *rsa.PublicKey) (Client, error) {
	verif, err := NewVerifier(v, pk)
	if err != nil {
		return Client{}, err
	}
	var prefixLen int
	switch v {
	case SHA384PSSDeterministic, SHA384PSSZeroDeterministic:
		prefixLen = 0
	case SHA384PSSRandomized, SHA384PSSZeroRandomized:
		prefixLen = 32
	default:
		return Client{}, ErrInvalidVariant
	}

	return Client{verif, prefixLen}, nil
}

type State struct {
	// The hashed and encoded message being signed
	encodedMsg []byte

	// Inverse of the blinding factor produced by the Verifier
	rInv *big.Int
}

// Prepare is the process by which the message to be signed and
// verified is prepared for input to the blind signing protocol.
func (c Client) Prepare(random io.Reader, message []byte) ([]byte, error) {
	if random == nil {
		return nil, common.ErrInvalidRandomness
	}

	prefix := make([]byte, c.prefixLen)
	_, err := io.ReadFull(random, prefix)
	if err != nil {
		return nil, err
	}

	return append(append([]byte{}, prefix...), message...), nil
}

// Blind initializes the blind RSA protocol using an input message and source of randomness.
// This function fails if randomness was not provided.
func (c Client) Blind(random io.Reader, preparedMessage []byte) (blindedMsg []byte, state State, err error) {
	if random == nil {
		return nil, State{}, common.ErrInvalidRandomness
	}

	salt := make([]byte, c.v.SaltLength)
	_, err = io.ReadFull(random, salt)
	if err != nil {
		return nil, State{}, err
	}

	r, rInv, err := common.GenerateBlindingFactor(random, c.v.pk.N)
	if err != nil {
		return nil, State{}, err
	}

	return c.fixedBlind(preparedMessage, salt, r, rInv)
}

func (c Client) fixedBlind(message, salt []byte, r, rInv *big.Int) (blindedMsg []byte, state State, err error) {
	encodedMsg, err := common.EncodeMessageEMSAPSS(message, c.v.pk.N, c.v.Hash.New(), salt)
	if err != nil {
		return nil, State{}, err
	}

	m := new(big.Int).SetBytes(encodedMsg)

	bigE := big.NewInt(int64(c.v.pk.E))
	x := new(big.Int).Exp(r, bigE, c.v.pk.N)
	z := new(big.Int).Set(m)
	z.Mul(z, x)
	z.Mod(z, c.v.pk.N)

	kLen := (c.v.pk.N.BitLen() + 7) / 8
	blindedMsg = make([]byte, kLen)
	z.FillBytes(blindedMsg)

	return blindedMsg, State{encodedMsg, rInv}, nil
}

func (c Client) Finalize(state State, blindedSig []byte) ([]byte, error) {
	kLen := (c.v.pk.N.BitLen() + 7) / 8
	if len(blindedSig) != kLen {
		return nil, common.ErrUnexpectedSize
	}

	z := new(big.Int).SetBytes(blindedSig)
	s := new(big.Int).Set(state.rInv)
	s.Mul(s, z)
	s.Mod(s, c.v.pk.N)

	sig := make([]byte, kLen)
	s.FillBytes(sig)

	err := common.VerifyBlindSignature(keys.NewBigPublicKey(c.v.pk), state.encodedMsg, sig)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// Verify verifies the input (message, signature) pair and produces an error upon failure.
func (c Client) Verify(message, signature []byte) error { return c.v.Verify(message, signature) }

type Verifier struct {
	// Public key of the Signer
	pk *rsa.PublicKey
	rsa.PSSOptions
}

func NewVerifier(v Variant, pk *rsa.PublicKey) (Verifier, error) {
	switch v {
	case SHA384PSSRandomized, SHA384PSSDeterministic:
		return Verifier{pk, rsa.PSSOptions{Hash: crypto.SHA384, SaltLength: crypto.SHA384.Size()}}, nil
	case SHA384PSSZeroRandomized, SHA384PSSZeroDeterministic:
		return Verifier{pk, rsa.PSSOptions{Hash: crypto.SHA384, SaltLength: 0}}, nil
	default:
		return Verifier{}, ErrInvalidVariant
	}
}

// Verify verifies the input (message, signature) pair and produces an error upon failure.
func (v Verifier) Verify(message, signature []byte) error {
	return common.VerifyMessageSignature(message, signature, v.SaltLength, keys.NewBigPublicKey(v.pk), v.Hash)
}

// Signer structure represents the signing server in the blind RSA protocol.
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
	ErrInvalidVariant          = common.ErrInvalidVariant
	ErrUnexpectedSize          = common.ErrUnexpectedSize
	ErrInvalidMessageLength    = common.ErrInvalidMessageLength
	ErrInvalidBlind            = common.ErrInvalidBlind
	ErrInvalidRandomness       = common.ErrInvalidRandomness
	ErrUnsupportedHashFunction = common.ErrUnsupportedHashFunction
)
