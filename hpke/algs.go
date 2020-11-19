package hpke

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/short"
	"github.com/cloudflare/circl/kem/xkem"
	"golang.org/x/crypto/chacha20poly1305"
)

type KemID = uint16

const (
	KemP256Sha256   KemID = 0x10
	KemP384Sha384   KemID = 0x11
	KemP521Sha512   KemID = 0x12
	KemX25519Sha256 KemID = 0x20
	KemX448Sha512   KemID = 0x21
)

type KdfID = uint16

const (
	HkdfSha256 KdfID = 0x01
	HkdfSha384 KdfID = 0x02
	HkdfSha512 KdfID = 0x03
)

type AeadID = uint16

const (
	AeadAES128GCM AeadID = 0x01
	AeadAES256GCM AeadID = 0x02
	AeadCC20P1305 AeadID = 0x03
)

var kemParams map[KemID]kem.Scheme
var kdfParams map[KdfID]crypto.Hash
var aeadParams map[AeadID]aeadInfo

func init() {
	kemParams = make(map[KemID]kem.Scheme)
	kemParams[KemP256Sha256] = short.KemP256Sha256
	kemParams[KemP384Sha384] = short.KemP384Sha384
	kemParams[KemP521Sha512] = short.KemP521Sha512
	kemParams[KemX25519Sha256] = xkem.KemX25519Sha256
	kemParams[KemX448Sha512] = xkem.KemX448Sha512

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
