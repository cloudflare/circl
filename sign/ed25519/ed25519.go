// Package ed25519 implements Ed25519 signature scheme as described in RFC-8032.
//
// References:
//  - RFC8032 https://rfc-editor.org/rfc/rfc8032.txt
//  - Ed25519 https://ed25519.cr.yp.to/
//  - High-speed high-security signatures. https://doi.org/10.1007/s13389-012-0027-1
package ed25519

import (
	"bytes"
	"crypto"
	cryptoRand "crypto/rand"
	"crypto/sha512"
	"errors"
	"io"
)

const (
	// PublicKeySize is the length in bytes of Ed25519 public keys.
	PublicKeySize = 32
	// PrivateKeySize is the length in bytes of Ed25519 private keys.
	PrivateKeySize = 32
	// SignatureSize is the length in bytes of signatures.
	SignatureSize = 64
)
const (
	paramB = 256 / 8 // Size of keys in bytes.
)

// PublicKey represents a public key of Ed25519.
type PublicKey []byte

// PrivateKey represents a private key of Ed25519.
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
// This function can handle unhashed messages or messages that have been
// prehashed with SHA512, but does not handle context.
// The opts.HashFunc() must return zero to indicate the message hasn't been
// hashed. This can be achieved by passing crypto.Hash(0) as the value for opts.
// The opts.HashFunc() must return SHA512 to indicate the message has been
// hashed with SHA512. This can be achieved by passing crypto.SHA512 as the value
// for opts.
// Messages prehashed with other algorithms are not handled.
func (kp *KeyPair) Sign(rand io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	switch opts.HashFunc() {
	case crypto.SHA512:
		if len(message) != sha512.Size {
			return nil, errors.New("ed25519: incorrect message lenght")
		}
		return kp.SignPure(message, true)
	case crypto.Hash(0):
		return kp.SignPure(message, false)
	default:
		return nil, errors.New("ed25519: expected unhashed message or message hashed with SHA-512")
	}
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

// NewKeyFromSeed generates a pair of Ed25519 keys given a private key.
func NewKeyFromSeed(seed PrivateKey) *KeyPair {
	if len(seed) != PrivateKeySize {
		panic("ed25519: bad private key length")
	}
	var P pointR1
	k := sha512.Sum512(seed)
	clamp(k[:])
	reduceModOrder(k[:paramB], false)
	P.fixedMult(k[:paramB])

	pair := &KeyPair{}
	copy(pair.private[:], seed)
	_ = P.ToBytes(pair.public[:])
	return pair
}

// SignPure creates a signature of a message.
func (kp *KeyPair) SignPure(message []byte, preHash bool) ([]byte, error) {
	// 1.  Hash the 32-byte private key using SHA-512.
	H := sha512.New()
	_, _ = H.Write(kp.private[:])
	h := H.Sum(nil)
	clamp(h[:])
	prefix, s := h[paramB:], h[:paramB]

	// 2.  Compute SHA-512(dom2(F, C) || prefix || PH(M))
	H.Reset()

	if preHash {
		dom2 := "SigEd25519 no Ed25519 collisions\x01\x00"
		_, _ = H.Write([]byte(dom2))
	}
	_, _ = H.Write(prefix)
	_, _ = H.Write(message)
	r := H.Sum(nil)
	reduceModOrder(r[:], true)

	// 3.  Compute the point [r]B.
	var P pointR1
	P.fixedMult(r[:paramB])
	R := (&[paramB]byte{})[:]
	err := P.ToBytes(R)

	// 4.  Compute SHA512(dom2(F, C) || R || A || PH(M)).
	H.Reset()

	if preHash {
		dom2 := "SigEd25519 no Ed25519 collisions\x01\x00"
		_, _ = H.Write([]byte(dom2))
	}
	_, _ = H.Write(R)
	_, _ = H.Write(kp.public[:])
	_, _ = H.Write(message)
	hRAM := H.Sum(nil)

	reduceModOrder(hRAM[:], true)

	// 5.  Compute S = (r + k * s) mod order.
	S := (&[paramB]byte{})[:]
	calculateS(S, r[:paramB], hRAM[:paramB], s)

	// 6.  The signature is the concatenation of R and S.
	var signature [SignatureSize]byte
	copy(signature[:paramB], R[:])
	copy(signature[paramB:], S[:])

	return signature[:], err
}

func verify(public PublicKey, message, signature []byte, preHash bool) bool {
	var P pointR1
	if ok := P.FromBytes(public); !ok {
		return false
	}

	R := signature[:paramB]
	H := sha512.New()

	if preHash {
		dom2 := "SigEd25519 no Ed25519 collisions\x01\x00"
		_, _ = H.Write([]byte(dom2))
	}
	_, _ = H.Write(R)
	_, _ = H.Write(public)
	_, _ = H.Write(message)
	hRAM := H.Sum(nil)
	reduceModOrder(hRAM[:], true)

	var Q pointR1
	encR := (&[paramB]byte{})[:]
	P.neg()
	Q.doubleMult(&P, signature[paramB:], hRAM[:paramB])
	_ = Q.ToBytes(encR)
	return bytes.Equal(R, encR)
}

// Verify returns true if the signature is valid. Failure cases are invalid
// signature, or when the public key cannot be decoded.
// This function does not handle prehashed messages.
func Verify(public PublicKey, message, signature []byte) bool {
	if len(public) != PublicKeySize ||
		len(signature) != SignatureSize ||
		!isLessThanOrder(signature[paramB:]) {
		return false
	}

	return verify(public, message, signature, false)
}

// VerifyPh returns true if the signature is valid. Failure cases are invalid
// signature, or when the public key cannot be decoded.
// This function handle prehashed messages with SHA512.
func VerifyPh(public PublicKey, message, signature []byte, opts crypto.SignerOpts) bool {
	if len(public) != PublicKeySize ||
		len(signature) != SignatureSize ||
		!isLessThanOrder(signature[paramB:]) {
		return false
	}

	if opts.HashFunc() != crypto.SHA512 || len(message) != sha512.Size {
		return false
	}

	return verify(public, message, signature, true)
}

func clamp(k []byte) {
	k[0] &= 248
	k[paramB-1] = (k[paramB-1] & 127) | 64
}

// isLessThanOrder returns true if 0 <= x < order.
func isLessThanOrder(x []byte) bool {
	i := len(order) - 1
	for i > 0 && x[i] == order[i] {
		i--
	}
	return x[i] < order[i]
}
