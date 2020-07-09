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
	"strconv"

	"github.com/cloudflare/circl/ecc/goldilocks"
	"github.com/cloudflare/circl/internal/shake"
	sha3 "github.com/cloudflare/circl/internal/shake"
)

const (
	// PublicKeySize is the length in bytes of Ed448 public keys.
	PublicKeySize = 57
	// PrivateKeySize is the length in bytes of Ed448 private keys.
	PrivateKeySize = 57
	// SignatureSize is the length in bytes of signatures.
	SignatureSize = 114
	// ContextMaxSize is the maximum length (in bytes) allowed for context.
	ContextMaxSize = 255
)
const (
	paramB   = 456 / 8    // Size of keys in bytes.
	hashSize = 2 * paramB // Size of the hash function's output.
)

// Options are the options that the ed448 functions can take.
type Options struct {
	// Hash should be crypto.Hash(0) for Ed448
	crypto.Hash

	// Context is an optional domain separation string for Ed448ph.
	// Its length  must be less or equal than 255 bytes.
	Context string

	// Prehash should be set for ed448ph, indicating that the message
	// will be prehashed with SHAKE256.
	PreHash bool
}

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
// This function supports all the two signature variants defined in RFC-8032,
// namely Ed448 (or pure EdDSA) and Ed448Ph.
// The opts.HashFunc() must return zero to the specify Ed448 variant. This can
// be achieved by passing crypto.Hash(0) as the value for opts.
// Use an Options struct to pass a bool indicating that the ed448Ph variant
// should be used.
// The struct can also be optionally used to pass a context string for signing.
func (kp *KeyPair) Sign(rand io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	var ctx string
	var preHash bool

	if o, ok := opts.(*Options); ok {
		preHash = o.PreHash
		ctx = o.Context
	}

	if preHash {
		return kp.SignPh(message, ctx)
	}

	switch opts.HashFunc() {
	case crypto.Hash(0):
		return kp.SignPure(message, ctx)
	default:
		return nil, errors.New("ed448: bad hash algorithm")
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

func sign(kp *KeyPair, message, ctx []byte, preHash bool) ([]byte, error) {
	H := sha3.NewShake256()
	var d []byte

	if preHash {
		_, _ = H.Write(message)
		d = H.Sum(nil)
		H.Reset()
	} else {
		d = message
	}

	// 1.  Hash the 57-byte private key using SHAKE256(x, 114).
	var h [hashSize]byte
	_, _ = H.Write(kp.private[:])
	_, _ = H.Read(h[:])
	s := &goldilocks.Scalar{}
	deriveSecretScalar(s, h[:paramB])
	prefix := h[paramB:]

	// 2.  Compute SHAKE256(dom4(F, C) || prefix || PH(M), 114).
	var rPM [hashSize]byte
	H.Reset()

	H = writeDom(H, ctx, preHash)

	_, _ = H.Write(prefix)
	_, _ = H.Write(d)
	_, _ = H.Read(rPM[:])

	// 3.  Compute the point [r]B.
	r := &goldilocks.Scalar{}
	r.FromBytes(rPM[:])
	R := (&[paramB]byte{})[:]
	err := goldilocks.Curve{}.ScalarBaseMult(r).ToBytes(R)

	// 4.  Compute SHAKE256(dom4(F, C) || R || A || PH(M), 114)
	var hRAM [hashSize]byte
	H.Reset()

	H = writeDom(H, ctx, preHash)

	_, _ = H.Write(R)
	_, _ = H.Write(kp.public[:])
	_, _ = H.Write(d)
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

// SignPure creates a signature of a message given a keypair.
// This function supports the signature variant defined in RFC-8032: Ed448,
// also known as the pure version of EdDSA.
func (kp *KeyPair) SignPure(message []byte, ctx string) ([]byte, error) {
	if len(ctx) > ContextMaxSize {
		return nil, errors.New("ed448: bad context length: " + strconv.Itoa(len(ctx)))
	}

	return sign(kp, message, []byte(ctx), false)
}

// SignPh creates a signature of a message given a keypair.
// This function supports the signature variant defined in RFC-8032: Ed448ph,
// meaning it internally hashes the message using SHAKE-256.
// Context could be passed to this function, which length should be no more than
// 255. It can be empty.
func (kp *KeyPair) SignPh(message []byte, ctx string) ([]byte, error) {
	if len(ctx) > ContextMaxSize {
		return nil, errors.New("ed448: bad context length: " + strconv.Itoa(len(ctx)))
	}

	return sign(kp, message, []byte(ctx), true)
}

func verify(public PublicKey, message, signature, ctx []byte, preHash bool) bool {
	if len(public) != PublicKeySize ||
		len(signature) != SignatureSize ||
		len(ctx) > ContextMaxSize ||
		!isLessThanOrder(signature[paramB:]) {
		return false
	}

	P, err := goldilocks.FromBytes(public)
	if err != nil {
		return false
	}

	H := sha3.NewShake256()
	var d []byte

	if preHash {
		_, _ = H.Write(message)
		d = H.Sum(nil)
		H.Reset()
	} else {
		d = message
	}

	var hRAM [hashSize]byte
	R := signature[:paramB]

	H = writeDom(H, ctx, preHash)

	_, _ = H.Write(R)
	_, _ = H.Write(public)
	_, _ = H.Write(d)
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

// Verify returns true if the signature is valid. Failure cases are invalid
// signature, or when the public key cannot be decoded.
func Verify(public PublicKey, message, signature []byte, opts crypto.SignerOpts) bool {
	var ctx string
	var preHash bool

	if o, ok := opts.(*Options); ok {
		preHash = o.PreHash
		ctx = o.Context
	}

	if preHash {
		return VerifyPh(public, message, signature, ctx)
	}

	switch opts.HashFunc() {
	case crypto.Hash(0):
		return VerifyPure(public, message, signature, ctx)
	default:
		return false
	}
}

// VerifyPure returns true if the signature is valid. Failure cases are invalid
// signature, or when the public key cannot be decoded.
// This function supports the signature variant defined in RFC-8032: Ed448,
// also known as the pure version of EdDSA.
func VerifyPure(public PublicKey, message, signature []byte, ctx string) bool {
	return verify(public, message, signature, []byte(ctx), false)
}

// VerifyPh returns true if the signature is valid. Failure cases are invalid
// signature, or when the public key cannot be decoded.
// This function supports the signature variant defined in RFC-8032: Ed25519ph,
// meaning it internally hashes the message using SHAKE-256.
// Context could be passed to this function, which length should be no more than
// 255. It can be empty.
func VerifyPh(public PublicKey, message, signature []byte, ctx string) bool {
	return verify(public, message, signature, []byte(ctx), true)
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

func writeDom(h shake.Shake, ctx []byte, preHash bool) shake.Shake {
	dom4 := "SigEd448"
	_, _ = h.Write([]byte(dom4))

	if preHash {
		_, _ = h.Write([]byte{byte(0x01), byte(len(ctx))})
	} else {
		_, _ = h.Write([]byte{byte(0x00), byte(len(ctx))})
	}
	_, _ = h.Write(ctx)

	return h
}
