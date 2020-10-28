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
	_lastHkdf
)

type AeadID = uint16

const (
	AeadAES128GCM AeadID = iota + 1
	AeadAES256GCM
	AeadCC20P1305
	_lastAead
)

var aeadParams [_lastAead]aeadInfo
var hkdfParams [_lastHkdf]kdfInfo

// var dhkemParams [_lastDHKem]dhkemInfo

func init() {
	// dhkemParams[KemP256_SHA256] = dhkemInfo{32, 65, 65, 32, crypto.SHA256}
	// dhkemParams[KemP384_SHA384] = dhkemInfo{48, 97, 97, 48, crypto.SHA384}
	// dhkemParams[KemP521_SHA512] = dhkemInfo{64, 133, 133, 66, crypto.SHA512}
	// dhkemParams[KemX25519_SHA256] = dhkemInfo{32, 32, 32, 32, crypto.SHA256}
	// dhkemParams[KemX448_SHA512] = dhkemInfo{64, 56, 56, 56, crypto.SHA512}

	hkdfParams[HkdfSha256] = kdfInfo{crypto.SHA256}
	hkdfParams[HkdfSha384] = kdfInfo{crypto.SHA384}
	hkdfParams[HkdfSha512] = kdfInfo{crypto.SHA512}

	aeadParams[AeadAES128GCM] = aeadInfo{AeadAES128GCM, 16, 12}
	aeadParams[AeadAES256GCM] = aeadInfo{AeadAES256GCM, 32, 12}
	aeadParams[AeadCC20P1305] = aeadInfo{AeadCC20P1305, 32, 12}
}

// type dhkemInfo struct {
// 	Nsecret uint16
// 	Nenc    uint
// 	Npk     uint
// 	Nsk     uint
// 	H       crypto.Hash
// }

type kdfInfo struct {
	H crypto.Hash
}

type aeadInfo struct {
	ID AeadID
	Nk uint16
	Nn uint16
}
