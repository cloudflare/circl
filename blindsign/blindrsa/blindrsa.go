package blindrsa

// This package implements the blind RSA protocol based on the CFRG specification:
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-rsa-blind-signatures-02

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"hash"
	"io"
	"math/big"

	"github.com/cloudflare/circl/blindsign"
)

// An RSAVerifier represents a Verifier in the RSA blind signature protocol.
// It carries state needed to produce and validate an RSA blind signature.
type RSAVerifier struct {
	// Public key of the Signer
	pk *rsa.PublicKey

	// Hash function used in producing the message signature
	hash hash.Hash
}

// NewRSAVerifier creates a new RSAVerifier using the corresponding Signer parameters.
func NewRSAVerifier(pk *rsa.PublicKey, hash hash.Hash) RSAVerifier {
	return RSAVerifier{
		pk:   pk,
		hash: hash,
	}
}

func encodeMessageEMSAPSS(message []byte, key *rsa.PublicKey, hash hash.Hash, salt []byte) ([]byte, error) {
	hash.Reset() // Ensure the hash state is cleared
	hash.Write(message)
	digest := hash.Sum(nil)
	hash.Reset()
	emBits := key.N.BitLen() - 1
	encodedMsg, err := emsaPSSEncode(digest[:], emBits, salt, hash)
	return encodedMsg, err
}

func generateBlindingFactor(random io.Reader, key *rsa.PublicKey) (*big.Int, *big.Int, error) {
	randReader := random
	if randReader == nil {
		randReader = rand.Reader
	}
	r, err := rand.Int(randReader, key.N)
	if err != nil {
		return nil, nil, err
	}

	if r.Sign() == 0 {
		r = bigOne
	}
	rInv := new(big.Int).ModInverse(r, key.N)
	if rInv == nil {
		return nil, nil, ErrInvalidBlind
	}

	return r, rInv, nil
}

func (v RSAVerifier) fixedBlind(message, salt []byte, r, rInv *big.Int) ([]byte, blindsign.VerifierState, error) {
	encodedMsg, err := encodeMessageEMSAPSS(message, v.pk, v.hash, salt)
	if err != nil {
		return nil, nil, err
	}

	m := new(big.Int).SetBytes(encodedMsg)

	bigE := big.NewInt(int64(v.pk.E))
	x := new(big.Int).Exp(r, bigE, v.pk.N)
	z := new(big.Int).Set(m)
	z.Mul(z, x)
	z.Mod(z, v.pk.N)

	blindedMsg := z.Bytes()

	return blindedMsg, RSAVerifierState{
		encodedMsg: encodedMsg,
		verifier:   v,
		rInv:       rInv,
	}, nil
}

// Blind initializes the blind RSA protocol using an input message and source of randomness. The
// signature includes a randomly generated PSS salt whose length equals the size of the underlying
// hash function. This function fails if randomness was not provided.
//
// See the specification for more details:
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-rsa-blind-signatures-02#section-5.1.1
func (v RSAVerifier) Blind(random io.Reader, message []byte) ([]byte, blindsign.VerifierState, error) {
	if random == nil {
		return nil, nil, ErrInvalidRandomness
	}

	salt := make([]byte, v.hash.Size())
	_, err := random.Read(salt)
	if err != nil {
		return nil, nil, err
	}

	r, rInv, err := generateBlindingFactor(random, v.pk)
	if err != nil {
		return nil, nil, err
	}

	return v.fixedBlind(message, salt, r, rInv)
}

// An RSAVerifierState carries state needed to complete the blind signature protocol
// as a verifier.
type RSAVerifierState struct {
	// An RSA verifier carrying Signer verification state
	verifier RSAVerifier

	// The hashed and encoded message being signed
	encodedMsg []byte

	// Inverse of the blinding factor produced by the Verifier
	rInv *big.Int
}

func verifyBlindSignature(pub *rsa.PublicKey, hashed, sig []byte) error {
	m := new(big.Int).SetBytes(hashed)
	bigSig := new(big.Int).SetBytes(sig)

	c := encrypt(new(big.Int), pub, bigSig)
	if subtle.ConstantTimeCompare(m.Bytes(), c.Bytes()) == 1 {
		return nil
	} else {
		return rsa.ErrVerification
	}
}

// Finalize computes and outputs the final signature, if it's valid. Otherwise, it returns an error.
//
// See the specification for more details:
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-rsa-blind-signatures-02#section-5.1.3
func (state RSAVerifierState) Finalize(data []byte) ([]byte, error) {
	kLen := (state.verifier.pk.N.BitLen() + 7) / 8
	if len(data) != kLen {
		return nil, ErrUnexpectedSize
	}

	z := new(big.Int).SetBytes(data)
	s := new(big.Int).Set(state.rInv)
	s.Mul(s, z)
	s.Mod(s, state.verifier.pk.N)

	sig := s.Bytes()

	err := verifyBlindSignature(state.verifier.pk, state.encodedMsg, sig)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// An RSASigner represents the Signer in the blind RSA protocol.
// It carries the raw RSA private key used for signing blinded messages.
type RSASigner struct {
	// An RSA private key
	sk *rsa.PrivateKey
}

// NewRSASigner creates a new Signer for the blind RSA protocol using an RSA private key.
func NewRSASigner(sk *rsa.PrivateKey) RSASigner {
	return RSASigner{
		sk: sk,
	}
}

// BlindSign blindly computes the RSA operation using the Signer's private key on the blinded
// message input, if it's of valid length, and returns an error should the function fail.
//
// See the specification for more details:
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-rsa-blind-signatures-02#section-5.1.2
func (signer RSASigner) BlindSign(data []byte) ([]byte, error) {
	kLen := (signer.sk.N.BitLen() + 7) / 8
	if len(data) != kLen {
		return nil, ErrUnexpectedSize
	}

	m := new(big.Int).SetBytes(data)
	if m.Cmp(signer.sk.N) > 0 {
		return nil, ErrInvalidMessageLength
	}

	s, err := decryptAndCheck(rand.Reader, signer.sk, m)
	if err != nil {
		return nil, err
	}

	return s.Bytes(), nil
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
