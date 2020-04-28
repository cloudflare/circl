// Package ed448 implements Ed448 signature scheme as described in RFC-8032.
//
// References:
//  - RFC8032 https://rfc-editor.org/rfc/rfc8032.txt
//  - EdDSA for more curves https://eprint.iacr.org/2015/677
//  - High-speed high-security signatures. https://doi.org/10.1007/s13389-012-0027-1
package ed448

import (
	"bytes"
	"crypto"
	cryptoRand "crypto/rand"
	"errors"
	"io"

	"github.com/cloudflare/circl/ecc/goldilocks"
	sha3 "github.com/cloudflare/circl/internal/shake"
)

const (
	// PublicKeySize is the length in bytes of Ed448 public keys.
	PublicKeySize = 57
	// PrivateKeySize is the length in bytes of Ed448 private keys.
	PrivateKeySize = 57
	// SignatureSize is the length in bytes of signatures.
	SignatureSize = 114
	// MaxContextLength is the maximum length in bytes of context strings.
	MaxContextLength = 255
)
const (
	paramB   = 456 / 8    // Size of keys in bytes.
	hashSize = 2 * paramB // Size of the hash function's output.
)

// PublicKey represents a public key of Ed448.
type PublicKey []byte

// PrivateKey represents a private key of Ed448.
type PrivateKey []byte

// KeyPair implements crypto.Signer (golang.org/pkg/crypto/#Signer) interface.
type KeyPair struct {
	private [PrivateKeySize]byte
	public  [PublicKeySize]byte
}

// GetPrivate returns a copy of the private key.
func (kp *KeyPair) GetPrivate() PrivateKey { z := kp.private; return z[:] }

// GetPublic returns a copy of the public key.
func (kp *KeyPair) GetPublic() PublicKey { z := kp.public; return z[:] }

// Seed returns the private key seed.
func (kp *KeyPair) Seed() []byte { return kp.GetPrivate() }

// Public returns a crypto.PublicKey.
func (kp *KeyPair) Public() crypto.PublicKey { return kp.GetPublic() }

// Sign creates a signature of a message given a key pair.
// Ed448 performs two passes over messages to be signed and therefore cannot
// handle pre-hashed messages.
// The opts.HashFunc() must return zero to indicate the message hasn't been
// hashed. This can be achieved by passing crypto.Hash(0) as the value for opts.
// This function signs using as context the empty string.
func (kp *KeyPair) Sign(rand io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.Hash(0) {
		return nil, errors.New("ed448: cannot sign hashed message")
	}
	return kp.SignWithContext(message, nil)
}

// GenerateKey produces public and private keys using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func GenerateKey(rand io.Reader) (*KeyPair, error) {
	if rand == nil {
		rand = cryptoRand.Reader
	}
	seed := make(PrivateKey, PrivateKeySize)
	if _, err := io.ReadFull(rand, seed); err != nil {
		return nil, err
	}
	return NewKeyFromSeed(seed), nil
}

// NewKeyFromSeed generates a pair of Ed448 keys given a private key.
func NewKeyFromSeed(seed PrivateKey) *KeyPair {
	if len(seed) != PrivateKeySize {
		panic("ed448: bad private key length")
	}
	var h [hashSize]byte
	H := sha3.NewShake256()
	_, _ = H.Write(seed)
	_, _ = H.Read(h[:])
	s := &goldilocks.Scalar{}
	deriveSecretScalar(s, h[:paramB])

	pair := &KeyPair{}
	copy(pair.private[:], seed)
	_ = goldilocks.Curve{}.ScalarBaseMult(s).ToBytes(pair.public[:])
	return pair
}

// SignWithContext creates a signature of a message and context. The context is a
// constant string that separates uses of the signature between different protocols.
// See Section 8.3 of RFC-8032 (https://tools.ietf.org/html/rfc8032#section-8.3).
func (kp *KeyPair) SignWithContext(message, context []byte) ([]byte, error) {
	if len(context) > MaxContextLength {
		return nil, errors.New("context should be at most ed448.MaxContextLength bytes")
	}
	// 1.  Hash the 57-byte private key using SHAKE256(x, 114).
	var h [hashSize]byte
	H := sha3.NewShake256()
	_, _ = H.Write(kp.private[:])
	_, _ = H.Read(h[:])
	s := &goldilocks.Scalar{}
	deriveSecretScalar(s, h[:paramB])
	prefix := h[paramB:]

	// 2.  Compute SHAKE256(dom4(F, C) || prefix || PH(M), 114).
	var rPM [hashSize]byte
	dom4 := [10]byte{'S', 'i', 'g', 'E', 'd', '4', '4', '8', byte(0), byte(len(context))}
	H.Reset()
	_, _ = H.Write(dom4[:])
	_, _ = H.Write(context)
	_, _ = H.Write(prefix)
	_, _ = H.Write(message)
	_, _ = H.Read(rPM[:])

	// 3.  Compute the point [r]B.
	r := &goldilocks.Scalar{}
	r.FromBytes(rPM[:])
	R := (&[paramB]byte{})[:]
	err := goldilocks.Curve{}.ScalarBaseMult(r).ToBytes(R)

	// 4.  Compute SHAKE256(dom4(F, C) || R || A || PH(M), 114)
	var hRAM [hashSize]byte
	H.Reset()
	_, _ = H.Write(dom4[:])
	_, _ = H.Write(context)
	_, _ = H.Write(R)
	_, _ = H.Write(kp.public[:])
	_, _ = H.Write(message)
	_, _ = H.Read(hRAM[:])

	// 5.  Compute S = (r + k * s) mod order.
	k := &goldilocks.Scalar{}
	k.FromBytes(hRAM[:])
	S := &goldilocks.Scalar{}
	S.Mul(k, s)
	S.Add(S, r)

	// 6.  The signature is the concatenation of R and S.
	var signature [SignatureSize]byte
	copy(signature[:paramB], R[:])
	copy(signature[paramB:], S[:])
	return signature[:], err
}

// Verify returns true if the signature is valid. Failure cases are invalid
// signature, or when the public key cannot be decoded.
func Verify(public PublicKey, message, context, signature []byte) bool {
	if len(public) != PublicKeySize ||
		len(signature) != SignatureSize ||
		len(context) > MaxContextLength ||
		!isLessThanOrder(signature[paramB:]) {
		return false
	}
	P, err := goldilocks.FromBytes(public)
	if err != nil {
		return false
	}

	var hRAM [hashSize]byte
	dom4 := [10]byte{'S', 'i', 'g', 'E', 'd', '4', '4', '8', byte(0), byte(len(context))}
	R := signature[:paramB]
	H := sha3.NewShake256()
	_, _ = H.Write(dom4[:])
	_, _ = H.Write(context)
	_, _ = H.Write(R)
	_, _ = H.Write(public)
	_, _ = H.Write(message)
	_, _ = H.Read(hRAM[:])

	k := &goldilocks.Scalar{}
	k.FromBytes(hRAM[:])
	S := &goldilocks.Scalar{}
	S.FromBytes(signature[paramB:])

	encR := (&[paramB]byte{})[:]
	P.Neg()
	_ = goldilocks.Curve{}.CombinedMult(S, k, P).ToBytes(encR)
	return bytes.Equal(R, encR)
}

func deriveSecretScalar(s *goldilocks.Scalar, h []byte) {
	h[0] &= 0xFC        // The two least significant bits of the first octet are cleared,
	h[paramB-1] = 0x00  // all eight bits the last octet are cleared, and
	h[paramB-2] |= 0x80 // the highest bit of the second to last octet is set.
	s.FromBytes(h[:paramB])
}

// isLessThanOrder returns true if 0 <= x < order and if the last byte of x is zero.
func isLessThanOrder(x []byte) bool {
	order := goldilocks.Curve{}.Order()
	i := len(order) - 1
	for i > 0 && x[i] == order[i] {
		i--
	}
	return x[paramB-1] == 0 && x[i] < order[i]
}
