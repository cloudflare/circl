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
	"fmt"
	"io"
	"strconv"
)

const (
	// PublicKeySize is the length in bytes of Ed25519 public keys.
	PublicKeySize = 32
	// PrivateKeySize is the length in bytes of Ed25519 private keys.
	PrivateKeySize = 32
	// SignatureSize is the length in bytes of signatures.
	SignatureSize = 64

	// ContextMaxSize is the maximum length (in bytes) allowed for context.
	ContextMaxSize = 255
)
const (
	paramB = 256 / 8 // Size of keys in bytes.
)

// Options are the options that the ed25519 functions can take.
type Options struct {
	// Hash can be crypto.Hash(0) for Ed25519/Ed25519ctx, or crypto.SHA512
	// for Ed25519ph.
	crypto.Hash

	// Context is an optional domain separation string for Ed25519ph and a
	// must for Ed25519ctx. It must be less than or equal to 255.
	Context string
}

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
// This function supports all the three signature variants defined in RFC-8032,
// namely Ed25519 (or pure EdDSA), Ed25519Ph, and Ed25519Ctx.
// The opts.HashFunc() must return zero to indicate the message hasn't been
// hashed. This can be achieved by passing crypto.Hash(0) as the value for opts.
// The opts.HashFunc() must return SHA512 to indicate that the message will be
// hashed with SHA512. This can be achieved by passing crypto.SHA512 as the value
// for opts.
func (kp *KeyPair) Sign(rand io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	var ctx string
	if o, ok := opts.(*Options); ok {
		ctx = o.Context
	}

	switch opts.HashFunc() {
	case crypto.SHA512:
		return kp.SignPh(message, ctx)
	case crypto.Hash(0):
		if len(ctx) > 0 {
			return kp.SignWithCtx(message, ctx)
		}

		return kp.SignPure(message)
	default:
		return nil, errors.New("ed25519: expected unhashed message or message to be hashed with SHA-512")
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

func sign(kp *KeyPair, message []byte, preHash bool, ctx []byte) ([]byte, error) {
	H := sha512.New()
	var d []byte

	if preHash {
		_, _ = H.Write(message)
		d = H.Sum(nil)
		H.Reset()
	} else {
		d = message
	}

	// 1.  Hash the 32-byte private key using SHA-512.
	_, _ = H.Write(kp.private[:])
	h := H.Sum(nil)
	clamp(h[:])
	prefix, s := h[paramB:], h[:paramB]

	// 2.  Compute SHA-512(dom2(F, C) || prefix || PH(M))
	H.Reset()

	writeDom(H, ctx, preHash)

	_, _ = H.Write(prefix)
	_, _ = H.Write(d)
	r := H.Sum(nil)
	reduceModOrder(r[:], true)

	// 3.  Compute the point [r]B.
	var P pointR1
	P.fixedMult(r[:paramB])
	R := (&[paramB]byte{})[:]
	err := P.ToBytes(R)

	// 4.  Compute SHA512(dom2(F, C) || R || A || PH(M)).
	H.Reset()

	writeDom(H, ctx, preHash)

	_, _ = H.Write(R)
	_, _ = H.Write(kp.public[:])
	_, _ = H.Write(d)
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

// SignPure creates a signature of a message given a keypair.
// This function supports the signature variant defined in RFC-8032: Ed25519,
// meaning it handles messages that will not be prehashed, with no context.
func (kp *KeyPair) SignPure(message []byte) ([]byte, error) {
	ctx := ""
	return sign(kp, message, false, []byte(ctx))
}

// SignPh creates a signature of a message given a keypair.
// This function supports the signature variant defined in RFC-8032: Ed25519ph,
// meaning it handles messages to be prehashed with SHA512.
// Context could be passed to this function, which length should be no more than
// 255. It can be empty.
func (kp *KeyPair) SignPh(message []byte, ctx string) ([]byte, error) {
	if len(ctx) > ContextMaxSize {
		return nil, errors.New("ed25519: bad context length: " + strconv.Itoa(len(ctx)))
	}

	return sign(kp, message, true, []byte(ctx))
}

// SignWithCtx creates a signature of a message given a keypair.
// This function supports the signature variant defined in RFC-8032: Ed25519ctx,
// meaning it handles unhashed messages with context.
// Context should be passed to this function, which length should be no more than
// 255. It should not be empty.
func (kp *KeyPair) SignWithCtx(message []byte, ctx string) ([]byte, error) {
	if len(ctx) == 0 || len(ctx) > ContextMaxSize {
		return nil, fmt.Errorf("ed25519: bad context length: %v > %v", len(ctx), ContextMaxSize)
	}

	return sign(kp, message, false, []byte(ctx))
}

func verify(public PublicKey, message, signature []byte, preHash bool, ctx []byte) bool {
	if len(public) != PublicKeySize ||
		len(signature) != SignatureSize ||
		!isLessThanOrder(signature[paramB:]) {
		return false
	}

	var P pointR1
	if ok := P.FromBytes(public); !ok {
		return false
	}

	H := sha512.New()
	var d []byte

	if preHash {
		_, _ = H.Write(message)
		d = H.Sum(nil)
		H.Reset()
	} else {
		d = message
	}

	R := signature[:paramB]

	writeDom(H, ctx, preHash)

	_, _ = H.Write(R)
	_, _ = H.Write(public)
	_, _ = H.Write(d)
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
// This function supports all the three signature variants defined in RFC-8032,
// namely Ed25519 (or pure EdDSA), Ed25519Ph, and Ed25519Ctx.
// Context could be passed to this function, which length should be no more than
// 255. It can be empty.
func Verify(public PublicKey, message, signature []byte, opts crypto.SignerOpts) bool {
	var ctx string
	if o, ok := opts.(*Options); ok {
		ctx = o.Context
	}

	switch opts.HashFunc() {
	case crypto.SHA512:
		return VerifyPh(public, message, signature, ctx)
	case crypto.Hash(0):
		if len(ctx) > 0 {
			return VerifyWithCtx(public, message, signature, ctx)
		}

		return VerifyPure(public, message, signature)
	default:
		return false
	}
}

// VerifyPure returns true if the signature is valid. Failure cases are invalid
// signature, or when the public key cannot be decoded.
// This function does not handle prehashed messages.
func VerifyPure(public PublicKey, message, signature []byte) bool {
	ctx := ""
	return verify(public, message, signature, false, []byte(ctx))
}

// VerifyPh returns true if the signature is valid. Failure cases are invalid
// signature, or when the public key cannot be decoded.
// This function supports the signature variant defined in RFC-8032: Ed25519ph,
// meaning it handles messages to be prehashed with SHA512.
// Context could be passed to this function, which length should be no more than
// 255. It can be empty.
func VerifyPh(public PublicKey, message, signature []byte, ctx string) bool {
	return verify(public, message, signature, true, []byte(ctx))
}

// VerifyWithCtx returns true if the signature is valid. Failure cases are invalid
// signature, or when the public key cannot be decoded, or when context is
// not provided.
// This function supports the signature variant defined in RFC-8032: Ed25519ctx,
// meaning it does not handle prehashed messages. Context string must be
// provided, and must not be more than 255 of length.
func VerifyWithCtx(public PublicKey, message, signature []byte, ctx string) bool {
	if len(ctx) == 0 || len(ctx) > ContextMaxSize {
		return false
	}

	return verify(public, message, signature, false, []byte(ctx))
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

func writeDom(h io.Writer, ctx []byte, preHash bool) {
	dom2 := "SigEd25519 no Ed25519 collisions"

	if len(ctx) > 0 {
		_, _ = h.Write([]byte(dom2))
		if preHash {
			_, _ = h.Write([]byte{byte(0x01), byte(len(ctx))})
		} else {
			_, _ = h.Write([]byte{byte(0x00), byte(len(ctx))})
		}
		_, _ = h.Write(ctx)
	} else if preHash {
		_, _ = h.Write([]byte(dom2))
		_, _ = h.Write([]byte{0x01, 0x00})
	}
}
