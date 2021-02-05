package hpke

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"

	"github.com/cloudflare/circl/dh/x25519"
	"github.com/cloudflare/circl/dh/x448"
	"github.com/cloudflare/circl/ecc/p384"
	"github.com/cloudflare/circl/kem"
	"golang.org/x/crypto/chacha20poly1305"
)

type KemID uint16

const (
	// DHKemP256HkdfSha256 is a KEM using the P256 curve with HKDF based on
	// SHA-256.
	DHKemP256HkdfSha256 KemID = 0x10
	// DHKemP384HkdfSha384 is a KEM using the P384 curve with HKDF based on
	// SHA-384.
	DHKemP384HkdfSha384 KemID = 0x11
	// DHKemP521HkdfSha512 is a KEM using the P521 curve with HKDF based on
	// SHA-512.
	DHKemP521HkdfSha512 KemID = 0x12
	// DHKemX25519HkdfSha256 is a KEM using the X25519 Diffie-Hellman function
	// with HKDF based on SHA-256.
	DHKemX25519HkdfSha256 KemID = 0x20
	// DHKemX448HkdfSha512 is a KEM using the X448 Diffie-Hellman function with
	// HKDF based on SHA-512.
	DHKemX448HkdfSha512 KemID = 0x21
)

func (k KemID) IsValid() bool {
	switch k {
	case DHKemP256HkdfSha256,
		DHKemP384HkdfSha384,
		DHKemP521HkdfSha512,
		DHKemX25519HkdfSha256,
		DHKemX448HkdfSha512:
		return true
	default:
		return false
	}
}

func (k KemID) Scheme() kem.AuthScheme {
	switch k {
	case DHKemP256HkdfSha256:
		return dhkemP256HkdfSha256
	case DHKemP384HkdfSha384:
		return dhkemP384HkdfSha384
	case DHKemP521HkdfSha512:
		return dhkemP521HkdfSha512
	case DHKemX25519HkdfSha256:
		return dhkemX25519HkdfSha256
	case DHKemX448HkdfSha512:
		return dhkemX448HkdfSha512
	default:
		return nil
	}
}

func (k KemID) validatePublicKey(pk kem.PublicKey) bool {
	switch k {
	case DHKemP256HkdfSha256, DHKemP384HkdfSha384, DHKemP521HkdfSha512:
		pub, ok := pk.(*shortPubKey)
		return ok && k == pub.scheme.id && pub.Validate()
	case DHKemX25519HkdfSha256, DHKemX448HkdfSha512:
		pub, ok := pk.(*xkemPubKey)
		return ok && k == pub.scheme.id && pub.Validate()
	default:
		panic("invalid KemID")
	}
}

func (k KemID) validatePrivateKey(sk kem.PrivateKey) bool {
	switch k {
	case DHKemP256HkdfSha256, DHKemP384HkdfSha384, DHKemP521HkdfSha512:
		priv, ok := sk.(*shortPrivKey)
		return ok && k == priv.scheme.id && priv.Validate()
	case DHKemX25519HkdfSha256, DHKemX448HkdfSha512:
		priv, ok := sk.(*xkemPrivKey)
		return ok && k == priv.scheme.id && priv.Validate()
	default:
		panic("invalid KemID")
	}
}

type KdfID uint16

const (
	// HKDF using SHA-256 hash function.
	HkdfSha256 KdfID = 0x01
	// HKDF using SHA-384 hash function.
	HkdfSha384 KdfID = 0x02
	// HKDF using SHA-512 hash function.
	HkdfSha512 KdfID = 0x03
)

func (k KdfID) IsValid() bool {
	switch k {
	case HkdfSha256,
		HkdfSha384,
		HkdfSha512:
		return true
	default:
		return false
	}
}

func (k KdfID) Hash() crypto.Hash {
	switch k {
	case HkdfSha256:
		return crypto.SHA256
	case HkdfSha384:
		return crypto.SHA384
	case HkdfSha512:
		return crypto.SHA512
	default:
		panic("invalid KdfID")
	}
}

type AeadID uint16

const (
	// AES-128 block cipher in Galois Counter Mode (GCM).
	AeadAes128Gcm AeadID = 0x01
	// AES-256 block cipher in Galois Counter Mode (GCM).
	AeadAes256Gcm AeadID = 0x02
	// ChaCha20 stream cipher and Poly1305 MAC.
	AeadChaCha20Poly1305 AeadID = 0x03
)

// New instantiates an AEAD cipher from the identifier, returns an error if the
// identifier is not known.
func (a AeadID) New(key []byte) (cipher.AEAD, error) {
	switch a {
	case AeadAes128Gcm, AeadAes256Gcm:
		return aesGCM(key)
	case AeadChaCha20Poly1305:
		return chacha20poly1305.New(key)
	default:
		panic("invalid AeadID")
	}
}

func (a AeadID) IsValid() bool {
	switch a {
	case AeadAes128Gcm,
		AeadAes256Gcm,
		AeadChaCha20Poly1305:
		return true
	default:
		return false
	}
}

// KeySize returns the size in bytes of the keys used by AEAD cipher.
func (a AeadID) KeySize() uint {
	switch a {
	case AeadAes128Gcm:
		return 16
	case AeadAes256Gcm:
		return 32
	case AeadChaCha20Poly1305:
		return chacha20poly1305.KeySize
	default:
		panic("invalid AeadID")
	}
}

func aesGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

var dhkemP256HkdfSha256, dhkemP384HkdfSha384, dhkemP521HkdfSha512 shortKem
var dhkemX25519HkdfSha256, dhkemX448HkdfSha512 xkem

func init() {
	dhkemP256HkdfSha256.Curve = elliptic.P256()
	dhkemP256HkdfSha256.kemBase.id = DHKemP256HkdfSha256
	dhkemP256HkdfSha256.kemBase.name = "HpkeDHKemP256HkdfSha256"
	dhkemP256HkdfSha256.kemBase.Hash = crypto.SHA256
	dhkemP256HkdfSha256.kemBase.dh = dhkemP256HkdfSha256

	dhkemP384HkdfSha384.Curve = p384.P384()
	dhkemP384HkdfSha384.kemBase.id = DHKemP384HkdfSha384
	dhkemP384HkdfSha384.kemBase.name = "HpkeDHKemP384HkdfSha384"
	dhkemP384HkdfSha384.kemBase.Hash = crypto.SHA384
	dhkemP384HkdfSha384.kemBase.dh = dhkemP384HkdfSha384

	dhkemP521HkdfSha512.Curve = elliptic.P521()
	dhkemP521HkdfSha512.kemBase.id = DHKemP521HkdfSha512
	dhkemP521HkdfSha512.kemBase.name = "HpkeDHKemP521HkdfSha512"
	dhkemP521HkdfSha512.kemBase.Hash = crypto.SHA512
	dhkemP521HkdfSha512.kemBase.dh = dhkemP521HkdfSha512

	dhkemX25519HkdfSha256.size = x25519.Size
	dhkemX25519HkdfSha256.kemBase.id = DHKemX25519HkdfSha256
	dhkemX25519HkdfSha256.kemBase.name = "HpkeDHKemX25519HkdfSha256"
	dhkemX25519HkdfSha256.kemBase.Hash = crypto.SHA256
	dhkemX25519HkdfSha256.kemBase.dh = dhkemX25519HkdfSha256

	dhkemX448HkdfSha512.size = x448.Size
	dhkemX448HkdfSha512.kemBase.id = DHKemX448HkdfSha512
	dhkemX448HkdfSha512.kemBase.name = "HpkeDHKemX448HkdfSha512"
	dhkemX448HkdfSha512.kemBase.Hash = crypto.SHA512
	dhkemX448HkdfSha512.kemBase.dh = dhkemX448HkdfSha512
}
