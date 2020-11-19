package xkem

import (
	"crypto"
	_ "crypto/sha256" // linking sha256 packages.
	_ "crypto/sha512" // linking sha512 packages.
	"encoding/binary"
	"io"

	"github.com/cloudflare/circl/dh/x25519"
	"github.com/cloudflare/circl/dh/x448"
	"golang.org/x/crypto/hkdf"
)

const versionLabel = "HPKE-06"

type xkem struct {
	size int
	id   uint16
	name string
	h    crypto.Hash
}

func (x xkem) Name() string               { return x.name }
func (x xkem) SharedKeySize() int         { return x.h.Size() }
func (x xkem) PrivateKeySize() int        { return x.size }
func (x xkem) SeedSize() int              { return x.size }
func (x xkem) CiphertextSize() int        { return x.size }
func (x xkem) PublicKeySize() int         { return x.size }
func (x xkem) EncapsulationSeedSize() int { return x.size }

func (x xkem) getSuiteID() (sid [5]byte) {
	sid[0], sid[1], sid[2] = 'K', 'E', 'M'
	binary.BigEndian.PutUint16(sid[3:5], x.id)
	return
}

func (x xkem) calcDH(dh []byte, priv xkemPrivKey, pub xkemPubKey) {
	switch x.size {
	case x25519.Size:
		var dd, sk, pk x25519.Key
		copy(sk[:], priv.k)
		copy(pk[:], pub.k)
		x25519.Shared(&dd, &sk, &pk)
		copy(dh, dd[:])
	case x448.Size:
		var dd, sk, pk x448.Key
		copy(sk[:], priv.k)
		copy(pk[:], pub.k)
		x448.Shared(&dd, &sk, &pk)
		copy(dh, dd[:])
	}
}

func (x xkem) extractExpand(dh, kemCtx []byte) []byte {
	eaePkr := x.labeledExtract(nil, []byte("eae_prk"), dh)
	return x.labeledExpand(eaePkr, []byte("shared_secret"), kemCtx, uint16(x.h.Size()))
}

func (x xkem) labeledExtract(salt, label, info []byte) []byte {
	suiteID := x.getSuiteID()
	labeledIKM := append(append(append(append(
		make([]byte, 0, len(versionLabel)+len(suiteID)+len(label)+len(info)),
		versionLabel...),
		suiteID[:]...),
		label...),
		info...)
	return hkdf.Extract(x.h.New, labeledIKM, salt)
}

func (x xkem) labeledExpand(prk, label, info []byte, l uint16) []byte {
	suiteID := x.getSuiteID()
	labeledInfo := make([]byte, 2, 2+len(versionLabel)+len(suiteID)+len(label)+len(info))
	binary.BigEndian.PutUint16(labeledInfo[0:2], l)
	labeledInfo = append(append(append(append(labeledInfo,
		versionLabel...),
		suiteID[:]...),
		label...),
		info...)
	b := make([]byte, l)
	rd := hkdf.Expand(x.h.New, prk, labeledInfo)
	_, _ = io.ReadFull(rd, b)
	return b
}
