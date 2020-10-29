package short

import (
	"crypto"
	"crypto/elliptic"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/hkdf"
)

type short struct {
	*elliptic.CurveParams
	id  KemID
	h   crypto.Hash
	dst []byte
}

func (s short) Name() string               { return names[s.id] }
func (s short) SharedKeySize() int         { return s.byteSize() }
func (s short) PrivateKeySize() int        { return s.byteSize() }
func (s short) SeedSize() int              { return s.byteSize() }
func (s short) CiphertextSize() int        { return 1 + 2*s.byteSize() }
func (s short) PublicKeySize() int         { return 1 + 2*s.byteSize() }
func (s short) EncapsulationSeedSize() int { return s.byteSize() }
func (s short) byteSize() int              { return (s.BitSize + 7) / 8 }

func (s short) getSuiteID() (sid [5]byte) {
	copy(sid[:], "KEM")
	binary.BigEndian.PutUint16(sid[3:5], s.id)
	return
}

func (s short) calcDH(dh []byte, sk shortPrivKey, pk shortPubKey) {
	l := len(dh)
	x, _ := s.ScalarMult(pk.x, pk.y, sk.k)
	b := x.Bytes()
	copy(dh[1*l-len(b):1*l], b)
}

func (s short) extractExpand(dh, kemCtx []byte) []byte {
	eaePkr := s.labeledExtract(nil, []byte("eae_prk"), dh)
	return s.labeledExpand(eaePkr, []byte("shared_secret"), kemCtx, uint16(s.byteSize()))
}

func (s short) labeledExtract(salt, label, info []byte) []byte {
	suiteID := s.getSuiteID()
	labeledIKM := append(append(append(append(
		make([]byte, 0, len(s.dst)+len(suiteID)+len(label)+len(info)),
		s.dst...),
		suiteID[:]...),
		label...),
		info...)
	return hkdf.Extract(s.h.New, labeledIKM, salt)
}

func (s short) labeledExpand(prk, label, info []byte, l uint16) []byte {
	suiteID := s.getSuiteID()
	labeledInfo := make([]byte, 2, 2+len(s.dst)+len(suiteID)+len(label)+len(info))
	binary.BigEndian.PutUint16(labeledInfo[0:2], uint16(l))
	labeledInfo = append(append(append(append(labeledInfo,
		s.dst...),
		suiteID[:]...),
		label...),
		info...)
	b := make([]byte, l)
	rd := hkdf.Expand(s.h.New, prk, labeledInfo)
	_, _ = io.ReadFull(rd, b)
	return b
}
