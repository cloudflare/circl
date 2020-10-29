package hpke

import (
	"crypto"

	"github.com/cloudflare/circl/kem/short"
)

type KemID = uint16

const (
	KemP256Sha256   KemID = short.KemP256Sha256
	KemP384Sha384   KemID = short.KemP384Sha384
	KemP521Sha512   KemID = short.KemP521Sha512
	KemX25519Sha256 KemID = 0x0020
	KemX448Sha512   KemID = 0x0021
)

type KdfID = uint16

const (
	HkdfSha256 KdfID = iota + 1
	HkdfSha384
	HkdfSha512
)

type AeadID = uint16

const (
	AeadAES128GCM AeadID = iota + 1
	AeadAES256GCM
	AeadCC20P1305
)

var kemParams map[KemID]kemInfo
var kdfParams map[KdfID]kdfInfo
var aeadParams map[AeadID]aeadInfo

func init() {
	kemParams = make(map[KemID]kemInfo)
	kemParams[KemP256Sha256] = kemInfo{32, 65, 65, 32, crypto.SHA256}
	kemParams[KemP384Sha384] = kemInfo{48, 97, 97, 48, crypto.SHA384}
	kemParams[KemP521Sha512] = kemInfo{64, 133, 133, 66, crypto.SHA512}
	kemParams[KemX25519Sha256] = kemInfo{32, 32, 32, 32, crypto.SHA256}
	kemParams[KemX448Sha512] = kemInfo{64, 56, 56, 56, crypto.SHA512}

	kdfParams = make(map[KdfID]kdfInfo)
	kdfParams[HkdfSha256] = kdfInfo{crypto.SHA256}
	kdfParams[HkdfSha384] = kdfInfo{crypto.SHA384}
	kdfParams[HkdfSha512] = kdfInfo{crypto.SHA512}

	aeadParams = make(map[AeadID]aeadInfo)
	aeadParams[AeadAES128GCM] = aeadInfo{AeadAES128GCM, 16, 12}
	aeadParams[AeadAES256GCM] = aeadInfo{AeadAES256GCM, 32, 12}
	aeadParams[AeadCC20P1305] = aeadInfo{AeadCC20P1305, 32, 12}
}

type kemInfo struct {
	Nsecret uint16
	Nenc    uint
	Npk     uint
	Nsk     uint
	H       crypto.Hash
}

type kdfInfo struct {
	H crypto.Hash
}

type aeadInfo struct {
	ID AeadID
	Nk uint16
	Nn uint16
}
