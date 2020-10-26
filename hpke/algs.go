package hpke

import "crypto"

type DHkemID uint16

const (
	DHKemP256hkdfsha256 DHkemID = 0x0010 + iota
	DHKemP384hkdfsha384
	DHKemP521hkdfsha512
	DHKemX25519hkdfsha256 = 0x0020 + iota
	DHKemX448hkdfsha512
	_lastDHKem
)

type HkdfID uint16

const (
	HkdfSHA256 HkdfID = iota + 1
	HkdfSHA384
	HkdfSHA512
	_lastHkdf
)

type AeadID uint16

const (
	AeadAES128GCM AeadID = iota + 1
	AeadAES256GCM
	AeadCC20P1305
	_lastAead
)

var aeadParams [_lastAead]aeadInfo
var hkdfParams [_lastHkdf]hkdfInfo
var dhkemParams [_lastDHKem]dhkemInfo

func init() {
	dhkemParams[DHKemP256hkdfsha256] = dhkemInfo{32, 65, 65, 32, crypto.SHA256}
	dhkemParams[DHKemP384hkdfsha384] = dhkemInfo{48, 97, 97, 48, crypto.SHA384}
	dhkemParams[DHKemP521hkdfsha512] = dhkemInfo{64, 133, 133, 66, crypto.SHA512}
	dhkemParams[DHKemX25519hkdfsha256] = dhkemInfo{32, 32, 32, 32, crypto.SHA256}
	dhkemParams[DHKemX448hkdfsha512] = dhkemInfo{64, 56, 56, 56, crypto.SHA512}

	hkdfParams[HkdfSHA256] = hkdfInfo{crypto.SHA256, 32}
	hkdfParams[HkdfSHA384] = hkdfInfo{crypto.SHA384, 48}
	hkdfParams[HkdfSHA512] = hkdfInfo{crypto.SHA512, 64}

	aeadParams[AeadAES128GCM] = aeadInfo{AeadAES128GCM, 16, 12}
	aeadParams[AeadAES256GCM] = aeadInfo{AeadAES256GCM, 32, 12}
	aeadParams[AeadCC20P1305] = aeadInfo{AeadCC20P1305, 32, 12}
}

type dhkemInfo struct {
	Nsecret uint16
	Nenc    uint
	Npk     uint
	Nsk     uint
	H       crypto.Hash
}

type hkdfInfo struct {
	H  crypto.Hash
	Nh uint
}

type aeadInfo struct {
	ID AeadID
	Nk uint16
	Nn uint16
}
