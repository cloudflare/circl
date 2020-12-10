package hpke

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"math"

	"github.com/cloudflare/circl/dh/x25519"
	"github.com/cloudflare/circl/dh/x448"
	"github.com/cloudflare/circl/ecc/p384"
	"github.com/cloudflare/circl/kem"
	"golang.org/x/crypto/chacha20poly1305"
)

// AEAD Documentation.
//
// AEAD.Parse
//
// Use function AEAD.Parse(v int) (*aeadID,error)
//
//  id, err := hpke.AEAD.Parse(1)
//  fmt.Print(*id == hpke.AEAD.AES128GCM)
//  // Outputs: true
//
// AEAD
//
// AEAD enables access to the key derivation functions supported.
var AEAD supportedAEAD /*
Use one of the following constants:
 AEAD.AES128GCM        = 0x1 // AES-128 block cipher in Galois Counter Mode (GCM).
 AEAD.AES256GCM        = 0x2 // AES-256 block cipher in Galois Counter Mode (GCM).
 AEAD.ChaCha20Poly1305 = 0x3 // ChaCha20 stream cipher and Poly1305 MAC.
*/

type supportedAEAD struct {
	AES128GCM        aeadID
	AES256GCM        aeadID
	ChaCha20Poly1305 aeadID
}

func (supportedAEAD) Parse(v int) (*aeadID, error) {
	if 0 < v && v < math.MaxUint16 {
		switch v16 := uint16(v); v16 {
		case AEAD.AES128GCM.uint16,
			AEAD.AES256GCM.uint16,
			AEAD.ChaCha20Poly1305.uint16:
			return &aeadID{v16}, nil
		}
	}
	return nil, errInvalidAEAD
}

type aeadID struct{ uint16 }

// New instantiates an AEAD cipher from the identifier, returns an error if the
// identifier is not known.
func (a aeadID) New(key []byte) (cipher.AEAD, error) {
	switch a {
	case AEAD.AES128GCM, AEAD.AES256GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case AEAD.ChaCha20Poly1305:
		return chacha20poly1305.New(key)
	default:
		panic(errInvalidAEAD)
	}
}

// KeySize returns the size in bytes of the keys used by AEAD cipher.
func (a aeadID) KeySize() uint {
	switch a {
	case AEAD.AES128GCM:
		return 16
	case AEAD.AES256GCM:
		return 32
	case AEAD.ChaCha20Poly1305:
		return chacha20poly1305.KeySize
	default:
		panic(errInvalidAEAD)
	}
}

// KDF Documentation.
//
// KDF.Parse
//
// Use function KDF.Parse(v int) (*kdfID, error)
//
//  id, err := hpke.KDF.Parse(1)
//  fmt.Print(*id == hpke.KDF.HKDF.SHA256)
//  // Outputs: true
//
// KDF
//
// KDF enables access to the key derivation functions supported.
var KDF supportedKDF /*
Use one of the following constants:
 KDF.HKDF.SHA384 = 0x2 // Key derivation using HKDF with SHA-384.
 KDF.HKDF.SHA256 = 0x1 // Key derivation using HKDF with SHA-256.
 KDF.HKDF.SHA512 = 0x3 // Key derivation using HKDF with SHA-512.
*/

type supportedKDF struct {
	HKDF struct{ SHA256, SHA384, SHA512 kdfID }
}

func (supportedKDF) Parse(v int) (*kdfID, error) {
	if 0 < v && v < math.MaxUint16 {
		switch v16 := uint16(v); v16 {
		case KDF.HKDF.SHA256.uint16,
			KDF.HKDF.SHA384.uint16,
			KDF.HKDF.SHA512.uint16:
			return &kdfID{v16}, nil
		}
	}
	return nil, errInvalidKDF
}

type kdfID struct{ uint16 }

func (k kdfID) Hash() crypto.Hash {
	switch k {
	case KDF.HKDF.SHA256:
		return crypto.SHA256
	case KDF.HKDF.SHA384:
		return crypto.SHA384
	case KDF.HKDF.SHA512:
		return crypto.SHA512
	default:
		panic(errInvalidKDF)
	}
}

// KEM Documentation
//
// KEM.Parse
//
// Use function KEM.Parse(v int) (*kemID, error)
//
//  id, err := hpke.KEM.Parse(0x10)
//  fmt.Print(*id == hpke.KEM.P256.HKDF.SHA256)
//  // Outputs: true
//
// KEM
//
// KEM enables access to the key encapsulation methods supported.
var KEM supportedKEM /*
Use one of the following constants:
 KEM.P256.HKDF.SHA256   = 0x10 // KEM using the P256 curve and HKDF with SHA-256.
 KEM.P384.HKDF.SHA384   = 0x11 // KEM using the P384 curve and HKDF with SHA-384.
 KEM.P521.HKDF.SHA512   = 0x12 // KEM using the P521 curve and HKDF with SHA-512.
 KEM.X25519.HKDF.SHA256 = 0x20 // KEM using the X25519 Diffie-Hellman function and HKDF with SHA-256.
 KEM.X448.HKDF.SHA512   = 0x21 // KEM using the X448 Diffie-Hellman function and HKDF with SHA-512.
*/

type supportedKEM struct {
	P256   struct{ HKDF struct{ SHA256 kemID } }
	P384   struct{ HKDF struct{ SHA384 kemID } }
	P521   struct{ HKDF struct{ SHA512 kemID } }
	X25519 struct{ HKDF struct{ SHA256 kemID } }
	X448   struct{ HKDF struct{ SHA512 kemID } }
}

func (supportedKEM) Parse(v int) (*kemID, error) {
	if 0 < v && v < math.MaxUint16 {
		switch v16 := uint16(v); v16 {
		case KEM.P256.HKDF.SHA256.uint16,
			KEM.P384.HKDF.SHA384.uint16,
			KEM.P521.HKDF.SHA512.uint16,
			KEM.X25519.HKDF.SHA256.uint16,
			KEM.X448.HKDF.SHA512.uint16:
			return &kemID{v16}, nil
		}
	}
	return nil, errInvalidKEM
}

type kemID struct{ uint16 }

func (k kemID) Scheme() kem.AuthScheme {
	switch k {
	case KEM.P256.HKDF.SHA256:
		return dhkemp256hkdfsha256
	case KEM.P384.HKDF.SHA384:
		return dhkemp384hkdfsha384
	case KEM.P521.HKDF.SHA512:
		return dhkemp521hkdfsha512
	case KEM.X25519.HKDF.SHA256:
		return dhkemx25519hkdfsha256
	case KEM.X448.HKDF.SHA512:
		return dhkemx448hkdfsha512
	default:
		return nil
	}
}

func (k kemID) validatePublicKey(pk kem.PublicKey) bool {
	switch k {
	case KEM.P256.HKDF.SHA256, KEM.P384.HKDF.SHA384, KEM.P521.HKDF.SHA512:
		pub, ok := pk.(*shortPubKey)
		return ok && k == pub.scheme.id && pub.Validate()
	case KEM.X25519.HKDF.SHA256, KEM.X448.HKDF.SHA512:
		pub, ok := pk.(*xkemPubKey)
		return ok && k == pub.kemID && pub.Validate()
	default:
		panic(errInvalidKEM)
	}
}

func (k kemID) validatePrivateKey(sk kem.PrivateKey) bool {
	switch k {
	case KEM.P256.HKDF.SHA256, KEM.P384.HKDF.SHA384, KEM.P521.HKDF.SHA512:
		priv, ok := sk.(*shortPrivKey)
		return ok && k == priv.scheme.id && priv.Validate()
	case KEM.X25519.HKDF.SHA256, KEM.X448.HKDF.SHA512:
		priv, ok := sk.(*xkemPrivKey)
		return ok && k == priv.kemID && priv.Validate()
	default:
		panic(errInvalidKEM)
	}
}

var dhkemp256hkdfsha256, dhkemp384hkdfsha384, dhkemp521hkdfsha512 shortKem
var dhkemx25519hkdfsha256, dhkemx448hkdfsha512 xkem

func init() {
	AEAD.AES128GCM.uint16 = 0x01
	AEAD.AES256GCM.uint16 = 0x02
	AEAD.ChaCha20Poly1305.uint16 = 0x03

	KDF.HKDF.SHA256.uint16 = 0x01
	KDF.HKDF.SHA384.uint16 = 0x02
	KDF.HKDF.SHA512.uint16 = 0x03

	KEM.P256.HKDF.SHA256.uint16 = 0x10
	KEM.P384.HKDF.SHA384.uint16 = 0x11
	KEM.P521.HKDF.SHA512.uint16 = 0x12
	KEM.X25519.HKDF.SHA256.uint16 = 0x20
	KEM.X448.HKDF.SHA512.uint16 = 0x21

	dhkemp256hkdfsha256.Curve = elliptic.P256()
	dhkemp256hkdfsha256.kemBase.id = KEM.P256.HKDF.SHA256
	dhkemp256hkdfsha256.kemBase.name = "HPKE_DHKEM_P256_HKDF_SHA256"
	dhkemp256hkdfsha256.kemBase.Hash = crypto.SHA256
	dhkemp256hkdfsha256.kemBase.dh = dhkemp256hkdfsha256

	dhkemp384hkdfsha384.Curve = p384.P384()
	dhkemp384hkdfsha384.kemBase.id = KEM.P384.HKDF.SHA384
	dhkemp384hkdfsha384.kemBase.name = "HPKE_DHKEM_P384_HKDF_SHA384"
	dhkemp384hkdfsha384.kemBase.Hash = crypto.SHA384
	dhkemp384hkdfsha384.kemBase.dh = dhkemp384hkdfsha384

	dhkemp521hkdfsha512.Curve = elliptic.P521()
	dhkemp521hkdfsha512.kemBase.id = KEM.P521.HKDF.SHA512
	dhkemp521hkdfsha512.kemBase.name = "HPKE_DHKEM_P521_HKDF_SHA512"
	dhkemp521hkdfsha512.kemBase.Hash = crypto.SHA512
	dhkemp521hkdfsha512.kemBase.dh = dhkemp521hkdfsha512

	dhkemx25519hkdfsha256.size = x25519.Size
	dhkemx25519hkdfsha256.kemBase.id = KEM.X25519.HKDF.SHA256
	dhkemx25519hkdfsha256.kemBase.name = "HPKE_DHKEM_X25519_HKDF_SHA256"
	dhkemx25519hkdfsha256.kemBase.Hash = crypto.SHA256
	dhkemx25519hkdfsha256.kemBase.dh = dhkemx25519hkdfsha256

	dhkemx448hkdfsha512.size = x448.Size
	dhkemx448hkdfsha512.kemBase.id = KEM.X448.HKDF.SHA512
	dhkemx448hkdfsha512.kemBase.name = "HPKE_DHKEM_X448_HKDF_SHA512"
	dhkemx448hkdfsha512.kemBase.Hash = crypto.SHA512
	dhkemx448hkdfsha512.kemBase.dh = dhkemx448hkdfsha512
}
