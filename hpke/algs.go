package hpke

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/shortkem"
	"github.com/cloudflare/circl/kem/xkem"
	"golang.org/x/crypto/chacha20poly1305"
)

type KemID = uint16

const (
	KemP256HkdfSha256   KemID = 0x10 // KEM based on P-256 curve with HKDF using SHA-256.
	KemP384HkdfSha384   KemID = 0x11 // KEM based on P-384 curve with HKDF using SHA-384.
	KemP521HkdfSha512   KemID = 0x12 // KEM based on P-521 curve with HKDF using SHA-512.
	KemX25519HkdfSha256 KemID = 0x20 // KEM based on X25519 Diffie-Helman with HKDF using SHA-256.
	KemX448HkdfSha512   KemID = 0x21 // KEM based on X448 Diffie-Helman with HKDF using SHA-512.
)

type KdfID = uint16

const (
	HkdfSha256 KdfID = 0x01 // HKDF using SHA-256 hash function.
	HkdfSha384 KdfID = 0x02 // HKDF using SHA-384 hash function.
	HkdfSha512 KdfID = 0x03 // HKDF using SHA-512 hash function.
)

type AeadID = uint16

const (
	AeadAES128GCM AeadID = 0x01 // AES-128 block cipher in Galois Counter Mode (GCM).
	AeadAES256GCM AeadID = 0x02 // AES-256 block cipher in Galois Counter Mode (GCM).
	AeadCC20P1305 AeadID = 0x03 // ChaCha20 stream cipher and Poly1305 MAC.
)

var kemParams map[KemID]func() kem.AuthScheme
var kdfParams map[KdfID]crypto.Hash
var aeadParams map[AeadID]aeadInfo

func init() {
	kemParams = make(map[KemID]func() kem.AuthScheme)
	kemParams[KemP256HkdfSha256] = shortkem.P256HkdfSha256
	kemParams[KemP384HkdfSha384] = shortkem.P384HkdfSha384
	kemParams[KemP521HkdfSha512] = shortkem.P521HkdfSha512
	kemParams[KemX25519HkdfSha256] = xkem.X25519HkdfSha256
	kemParams[KemX448HkdfSha512] = xkem.X448HkdfSha512

	kdfParams = make(map[KdfID]crypto.Hash)
	kdfParams[HkdfSha256] = crypto.SHA256
	kdfParams[HkdfSha384] = crypto.SHA384
	kdfParams[HkdfSha512] = crypto.SHA512

	aeadParams = make(map[AeadID]aeadInfo)
	aeadParams[AeadAES128GCM] = aeadInfo{aesGCM, 16}
	aeadParams[AeadAES256GCM] = aeadInfo{aesGCM, 32}
	aeadParams[AeadCC20P1305] = aeadInfo{chacha20poly1305.New, chacha20poly1305.KeySize}
}

type aeadInfo struct {
	New func(key []byte) (cipher.AEAD, error)
	Nk  uint
}

func aesGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
