package xkem

import (
	"crypto"
	"encoding/binary"
	"io"

	"github.com/cloudflare/circl/dh/x25519"
	"github.com/cloudflare/circl/dh/x448"
	"golang.org/x/crypto/hkdf"
)

type xkem struct {
	id   KemID
	size int
	h    crypto.Hash
	dst  []byte
}

func (x xkem) Name() string               { return names[x.id] }
func (x xkem) SharedKeySize() int         { return x.size }
func (x xkem) PrivateKeySize() int        { return x.size }
func (x xkem) SeedSize() int              { return x.size }
func (x xkem) CiphertextSize() int        { return x.size }
func (x xkem) PublicKeySize() int         { return x.size }
func (x xkem) EncapsulationSeedSize() int { return x.size }

func (x xkem) getSuiteID() (sid [5]byte) {
	copy(sid[:], "KEM")
	binary.BigEndian.PutUint16(sid[3:5], x.id)
	return
}

func (x xkem) calcDH(dh []byte, priv xkemPrivKey, pub xkemPubKey) {
	switch x.id {
	case KemX25519Sha256:
		var dd, sk, pk x25519.Key
		copy(sk[:], priv.k)
		copy(pk[:], pub.k)
		x25519.Shared(&dd, &sk, &pk)
		copy(dh, dd[:])
	case KemX448Sha512:
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
		make([]byte, 0, len(x.dst)+len(suiteID)+len(label)+len(info)),
		x.dst...),
		suiteID[:]...),
		label...),
		info...)
	return hkdf.Extract(x.h.New, labeledIKM, salt)
}

func (x xkem) labeledExpand(prk, label, info []byte, l uint16) []byte {
	suiteID := x.getSuiteID()
	labeledInfo := make([]byte, 2, 2+len(x.dst)+len(suiteID)+len(label)+len(info))
	binary.BigEndian.PutUint16(labeledInfo[0:2], l)
	labeledInfo = append(append(append(append(labeledInfo,
		x.dst...),
		suiteID[:]...),
		label...),
		info...)
	b := make([]byte, l)
	rd := hkdf.Expand(x.h.New, prk, labeledInfo)
	_, _ = io.ReadFull(rd, b)
	return b
}
