// Package ed448 provides the signature scheme Ed448 as described in RFC-8032.
//
// References:
//  - RFC8032 https://rfc-editor.org/rfc/rfc8032.txt
//  - EdDSA for more curves https://eprint.iacr.org/2015/677
//  - High-speed high-security signatures. https://doi.org/10.1007/s13389-012-0027-1
package ed448

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"errors"
	"io"

	"github.com/cloudflare/circl/ecc/goldilocks"
	sha3 "github.com/cloudflare/circl/internal/shake"
)

const (
	// Size is the length in bytes of Ed448 keys.
	Size = 57
	// SignatureSize is the length in bytes of signatures.
	SignatureSize = 2 * Size
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

// Sign signs the given message with priv.
// Ed448 performs two passes over messages to be signed and therefore cannot
// handle pre-hashed messages. Thus opts.HashFunc() must return zero to
// indicate the message hasn't been hashed. This can be achieved by passing
// crypto.Hash(0) as the value for opts.
func (k *KeyPair) Sign(rand io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.Hash(0) {
		return nil, errors.New("ed448: cannot sign hashed message")
	}
	return Sign(k, message, nil), nil
}

// GenerateKey generates a public and private key pair using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func GenerateKey(rnd io.Reader) (*KeyPair, error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	seed := make(PrivateKey, Size)
	if _, err := io.ReadFull(rnd, seed); err != nil {
		return nil, err
	}
	return NewKeyFromSeed(seed), nil
}

// NewKeyFromSeed generates a pair of Ed448 signing keys given a
// previously-generated private key.
func NewKeyFromSeed(seed PrivateKey) *KeyPair {
	if len(seed) != Size {
		panic("ed448: bad private key length")
	}
	var h [2 * Size]byte
	H := sha3.NewShake256()
	_, _ = H.Write(seed)
	_, _ = H.Read(h[:])
	clamp(h[:Size])

	var _r goldilocks.Scalar
	_r.FromBytes(h[:Size])
	pk := &KeyPair{}
	goldilocks.Curve{}.ScalarBaseMult(&_r).ToBytes(pk.public[:])
	copy(pk.private[:], seed)
	return pk
}

// Sign returns the signature of a message using both the private and public
// keys of the signer.
func Sign(kp *KeyPair, message, context []byte) []byte {
	if len(context) > 255 {
		panic("context should be at most 255 octets")
	}
	var r, h, hRAM [2 * Size]byte
	H := sha3.NewShake256()
	_, _ = H.Write(kp.private[:])
	_, _ = H.Read(h[:])

	prefix := [10]byte{'S', 'i', 'g', 'E', 'd', '4', '4', '8', byte(0), byte(len(context))}
	H.Reset()
	_, _ = H.Write(prefix[:])
	_, _ = H.Write(context)
	_, _ = H.Write(h[Size:])
	_, _ = H.Write(message)
	_, _ = H.Read(r[:])

	var _r goldilocks.Scalar
	_r.FromBytes(r[:])
	signature := make([]byte, 2*Size)
	goldilocks.Curve{}.ScalarBaseMult(&_r).ToBytes(signature[:Size])

	H.Reset()
	_, _ = H.Write(prefix[:])
	_, _ = H.Write(context)
	_, _ = H.Write(signature[:Size])
	_, _ = H.Write(kp.public[:])
	_, _ = H.Write(message)
	_, _ = H.Read(hRAM[:])

	var _hRAM, _h, _s goldilocks.Scalar
	_hRAM.FromBytes(hRAM[:])
	clamp(h[:Size])
	_h.FromBytes(h[:Size])
	_s.Mul(&_h, &_hRAM)
	_s.Add(&_s, &_r)
	copy(signature[Size:], _s[:])
	return signature
}

// Verify returns true if the signature is valid. Failure cases are invalid
// signature, or when the public key cannot be decoded.
func Verify(public PublicKey, message, context, signature []byte) bool {
	P, errDecoding := goldilocks.FromBytes(public)
	if len(public) != Size ||
		len(signature) != 2*Size ||
		len(context) > 255 ||
		!isLessThanOrder(signature[Size:]) ||
		errDecoding != nil {
		return false
	}

	var hRAM [2 * Size]byte
	prefix := [10]byte{'S', 'i', 'g', 'E', 'd', '4', '4', '8', byte(0), byte(len(context))}
	H := sha3.NewShake256()
	_, _ = H.Write(prefix[:])
	_, _ = H.Write(context)
	_, _ = H.Write(signature[:Size])
	_, _ = H.Write(public[:Size])
	_, _ = H.Write(message)
	_, _ = H.Read(hRAM[:])

	var _s, _hRAM goldilocks.Scalar
	_hRAM.FromBytes(hRAM[:])
	_s.FromBytes(signature[Size:])

	P.Neg()
	var enc [Size]byte
	goldilocks.Curve{}.CombinedMult(&_s, &_hRAM, P).ToBytes(enc[:])
	return bytes.Equal(enc[:], signature[:Size])
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

// clamp prines the buffer as indicated in rfc8032 (https://tools.ietf.org/html/rfc8032#section-5.2.5)
// 1. The two least significant bits of the first octet are cleared,
// 2. all eight bits the last octet are cleared, and
// 3. the highest bit of the second to last octet is set.
func clamp(k []byte) {
	k[0] &= 252
	k[Size-1] = 0x00
	k[Size-2] |= 0x80
}

func makeCopy(in *[Size]byte) []byte {
	out := make([]byte, Size)
	copy(out, in[:])
	return out
}
