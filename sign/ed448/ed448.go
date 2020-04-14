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
	"fmt"
	"io"

	"github.com/cloudflare/circl/ecc/goldilocks"
	sha3 "github.com/cloudflare/circl/internal/shake"
)

const (
	// Size is the length in bytes of Ed448 keys.
	Size = 57
	// SignatureSize is the length in bytes of signatures.
	SignatureSize = 2 * Size
	// MaxContextLength is the maximum length in bytes of context strings.
	MaxContextLength = 255
)

// PublicKey represents a public key of Ed448.
type PublicKey []byte

// PrivateKey represents a private key of Ed448.
type PrivateKey []byte

// KeyPair implements crypto.Signer (golang.org/pkg/crypto/#Signer) interface.
type KeyPair struct{ private, public [Size]byte }

// GetPrivate returns a copy of the private key.
func (k *KeyPair) GetPrivate() PrivateKey { return makeCopy(&k.private) }

// GetPublic returns the public key corresponding to the private key.
func (k *KeyPair) GetPublic() PublicKey { return makeCopy(&k.public) }

// Seed returns the private key seed.
func (k *KeyPair) Seed() []byte { return k.GetPrivate() }

// Public returns a crypto.PublicKey corresponding to the private key.
func (k *KeyPair) Public() crypto.PublicKey { return k.GetPublic() }

// Sign creates a signature of a message given a key pair.
// The opts.HashFunc() must return zero to indicate the message hasn't been
// hashed. This can be achieved by passing crypto.Hash(0) as the value for opts.
// This function signs using as context the empty string.
func (k *KeyPair) Sign(rand io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.Hash(0) {
		return nil, errors.New("ed448: cannot sign hashed message")
	}
	return Sign(k, message, nil), nil
}

// GenerateKey produces a pair of public and private keys using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func GenerateKey(rand io.Reader) (*KeyPair, error) {
	if rand == nil {
		rand = cryptoRand.Reader
	}
	seed := make(PrivateKey, Size)
	if _, err := io.ReadFull(rand, seed); err != nil {
		return nil, err
	}
	return NewKeyFromSeed(seed), nil
}

// NewKeyFromSeed generates a pair of Ed448 keys given a private key.
func NewKeyFromSeed(seed PrivateKey) *KeyPair {
	if len(seed) != Size {
		panic("ed448: bad private key length")
	}
	var h [2 * Size]byte
	H := sha3.NewShake256()
	_, _ = H.Write(seed)
	_, _ = H.Read(h[:])
	s := &goldilocks.Scalar{}
	deriveSecretScalar(s, h[:Size])

	pair := &KeyPair{}
	copy(pair.private[:], seed)
	goldilocks.Curve{}.ScalarBaseMult(s).ToBytes(pair.public[:])
	return pair
}

// Sign creates a signature of a message given a key pair. The context is a
// constant string that separates uses of the signature between different protocols.
// See Section 8.3 of RFC-8032 (https://tools.ietf.org/html/rfc8032#section-8.3).
func Sign(kp *KeyPair, message, context []byte) []byte {
	if len(context) > MaxContextLength {
		panic(fmt.Sprintf("context should be at most %v bytes", MaxContextLength))
	}
	// 1.  Hash the 57-byte private key using SHAKE256(x, 114).
	var h [2 * Size]byte
	H := sha3.NewShake256()
	_, _ = H.Write(kp.private[:])
	_, _ = H.Read(h[:])
	s := &goldilocks.Scalar{}
	deriveSecretScalar(s, h[:Size])
	prefix := h[Size:]

	// 2.  Compute SHAKE256(dom4(F, C) || prefix || PH(M), 114).
	var rPM [2 * Size]byte
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
	R := (&[Size]byte{})[:]
	goldilocks.Curve{}.ScalarBaseMult(r).ToBytes(R)

	// 4.  Compute SHAKE256(dom4(F, C) || R || A || PH(M), 114)
	var hRAM [2 * Size]byte
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
	copy(signature[:Size], R[:])
	copy(signature[Size:], S[:])
	return signature[:SignatureSize]
}

// Verify returns true if the signature is valid. Failure cases are invalid
// signature, or when the public key cannot be decoded.
func Verify(public PublicKey, message, context, signature []byte) bool {
	if len(public) != Size ||
		len(signature) != SignatureSize ||
		len(context) > MaxContextLength ||
		!isLessThanOrder(signature[Size:]) {
		return false
	}
	P, err := goldilocks.FromBytes(public)
	if err != nil {
		return false
	}

	var hRAM [2 * Size]byte
	dom4 := [10]byte{'S', 'i', 'g', 'E', 'd', '4', '4', '8', byte(0), byte(len(context))}
	R := signature[:Size]
	H := sha3.NewShake256()
	_, _ = H.Write(dom4[:])
	_, _ = H.Write(context)
	_, _ = H.Write(R)
	_, _ = H.Write(public[:Size])
	_, _ = H.Write(message)
	_, _ = H.Read(hRAM[:])

	k := &goldilocks.Scalar{}
	k.FromBytes(hRAM[:])
	S := &goldilocks.Scalar{}
	S.FromBytes(signature[Size:])

	encR := (&[Size]byte{})[:]
	P.Neg()
	goldilocks.Curve{}.CombinedMult(S, k, P).ToBytes(encR)
	return bytes.Equal(R, encR)
}

func deriveSecretScalar(s *goldilocks.Scalar, h []byte) {
	h[0] &= 0xFC      // The two least significant bits of the first octet are cleared,
	h[Size-1] = 0x00  // all eight bits the last octet are cleared, and
	h[Size-2] |= 0x80 // the highest bit of the second to last octet is set.
	s.FromBytes(h[:Size])
}

// isLessThanOrder returns true if 0 <= x < order.
func isLessThanOrder(x []byte) bool {
	order := goldilocks.Curve{}.Order()
	i := len(order) - 1
	for i > 0 && x[i] == order[i] {
		i--
	}
	return x[Size-1] == 0 && x[i] < order[i]
}

func makeCopy(in *[Size]byte) []byte {
	out := make([]byte, Size)
	copy(out, in[:])
	return out
}
