package ed448

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/sha3"
)

// Size is the length in bytes of Ed448 keys.
const Size = 57

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

// GenerateKey generates a public/private key pair using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func GenerateKey(rnd io.Reader) (*KeyPair, error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	private := make(PrivateKey, Size)
	if _, err := io.ReadFull(rnd, private); err != nil {
		return nil, err
	}
	return NewKeyFromSeed(private), nil
}

// NewKeyFromSeed generates a pair of Ed448 signing keys given a
// previously-generated private key.
func NewKeyFromSeed(private PrivateKey) *KeyPair {
	if len(private) != Size {
		panic("ed448: bad private key length")
	}
	var h [2 * Size]byte
	sha3.ShakeSum256(h[:], private[:])
	clamp(h[:Size])
	reduceModOrder(h[:Size])
	div4(h[:Size])
	var P pointR1
	P.fixedMult(h[:Size])
	deg4isogeny{}.Pull(&P)
	pk := new(KeyPair)
	P.ToBytes(pk.public[:])
	copy(pk.private[:], private[:Size])
	return pk
}

// Sign returns the signature of a message using both the private and public
// keys of the signer.
func Sign(k *KeyPair, message, context []byte) []byte {
	if len(context) > 255 {
		panic("context should be at most 255 octets")
	}
	var r, h, hRAM [2 * Size]byte
	H := sha3.NewShake256()
	_, _ = H.Write(k.private[:])
	_, _ = H.Read(h[:])
	clamp(h[:Size])

	prefix := [10]byte{'S', 'i', 'g', 'E', 'd', '4', '4', '8', byte(0), byte(len(context))}
	H.Reset()
	_, _ = H.Write(prefix[:])
	_, _ = H.Write(context)
	_, _ = H.Write(h[Size:])
	_, _ = H.Write(message)
	_, _ = H.Read(r[:])
	reduceModOrder(r[:])
	rDiv4 := r
	div4(rDiv4[:Size])

	var P pointR1
	P.fixedMult(rDiv4[:Size])
	deg4isogeny{}.Pull(&P)
	signature := make([]byte, 2*Size)
	P.ToBytes(signature[:Size])

	H.Reset()
	_, _ = H.Write(prefix[:])
	_, _ = H.Write(context)
	_, _ = H.Write(signature[:Size])
	_, _ = H.Write(k.public[:])
	_, _ = H.Write(message)
	_, _ = H.Read(hRAM[:])
	reduceModOrder(hRAM[:])
	calculateS(signature[Size:], r[:Size], hRAM[:Size], h[:Size])
	return signature
}

// Verify returns true if the signature is valid. Failure cases are invalid
// signature, or when the public key cannot be decoded.
func Verify(public PublicKey, message, context, signature []byte) bool {
	if len(public) != Size ||
		len(signature) != 2*Size ||
		!isLessThan(signature[Size:], order[:]) ||
		len(context) > 255 {
		return false
	}
	var P pointR1
	if ok := P.FromBytes(public); !ok {
		return false
	}
	P.neg()
	deg4isogeny{}.Push(&P)

	var hRAM [2 * Size]byte
	prefix := [10]byte{'S', 'i', 'g', 'E', 'd', '4', '4', '8', byte(0), byte(len(context))}
	H := sha3.NewShake256()
	_, _ = H.Write(prefix[:])
	_, _ = H.Write(context)
	_, _ = H.Write(signature[:Size])
	_, _ = H.Write(public[:Size])
	_, _ = H.Write(message)
	_, _ = H.Read(hRAM[:])
	reduceModOrder(hRAM[:])

	var signatureDiv4, hRAMDiv4 [Size]byte
	copy(signatureDiv4[:], signature[Size:])
	copy(hRAMDiv4[:], hRAM[:Size])
	div4(signatureDiv4[:])
	div4(hRAMDiv4[:])

	var Q pointR1
	Q.doubleMult(&P, signatureDiv4[:], hRAMDiv4[:])
	deg4isogeny{}.Pull(&Q)

	var enc [Size]byte
	Q.ToBytes(enc[:])
	return bytes.Equal(enc[:], signature[:Size])
}

func clamp(k []byte) {
	k[0] &= 252
	k[Size-2] |= 0x80
	k[Size-1] = 0x00
}

func makeCopy(in *[Size]byte) []byte {
	out := make([]byte, Size)
	copy(out, in[:])
	return out
}
