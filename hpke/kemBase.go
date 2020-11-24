package hpke

import (
	"crypto"
	_ "crypto/sha256" // linking sha256 packages.
	_ "crypto/sha512" // linking sha512 packages.
	"encoding"
	"encoding/binary"
	"io"

	"github.com/cloudflare/circl/kem"
	"golang.org/x/crypto/hkdf"
)

type dhKEM interface {
	sizeDH() int
	calcDH(dh []byte, sk kem.PrivateKey, pk kem.PublicKey) error
	GenerateKey() (kem.PublicKey, kem.PrivateKey, error)
	DeriveKey(seed []byte) (kem.PublicKey, kem.PrivateKey)
	UnmarshalBinaryPrivateKey(data []byte) (kem.PrivateKey, error)
	UnmarshalBinaryPublicKey(data []byte) (kem.PublicKey, error)
}

type kemBase struct {
	id   KemID
	name string
	crypto.Hash
	dh dhKEM
}

func (k kemBase) Name() string       { return k.name }
func (k kemBase) SharedKeySize() int { return k.Hash.Size() }

func (k kemBase) getSuiteID() (sid [5]byte) {
	sid[0], sid[1], sid[2] = 'K', 'E', 'M'
	binary.BigEndian.PutUint16(sid[3:5], uint16(k.id))
	return
}

func (k kemBase) extractExpand(dh, kemCtx []byte) []byte {
	eaePkr := k.labeledExtract(nil, []byte("eae_prk"), dh)
	return k.labeledExpand(
		eaePkr,
		[]byte("shared_secret"),
		kemCtx,
		uint16(k.Size()),
	)
}

func (k kemBase) labeledExtract(salt, label, info []byte) []byte {
	suiteID := k.getSuiteID()
	labeledIKM := append(append(append(append(
		make([]byte, 0, len(versionLabel)+len(suiteID)+len(label)+len(info)),
		versionLabel...),
		suiteID[:]...),
		label...),
		info...)
	return hkdf.Extract(k.New, labeledIKM, salt)
}

func (k kemBase) labeledExpand(prk, label, info []byte, l uint16) []byte {
	suiteID := k.getSuiteID()
	labeledInfo := make(
		[]byte,
		2,
		2+len(versionLabel)+len(suiteID)+len(label)+len(info),
	)
	binary.BigEndian.PutUint16(labeledInfo[0:2], l)
	labeledInfo = append(append(append(append(labeledInfo,
		versionLabel...),
		suiteID[:]...),
		label...),
		info...)
	b := make([]byte, l)
	rd := hkdf.Expand(k.New, prk, labeledInfo)
	_, _ = io.ReadFull(rd, b)
	return b
}

func (k kemBase) AuthEncapsulate(
	pkr kem.PublicKey,
	sks kem.PrivateKey,
) (ct []byte, ss []byte, err error) {
	pke, ske, err := k.dh.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	return k.authEncap(pkr, sks, pke, ske)
}

func (k kemBase) AuthEncapsulateDeterministically(
	pkr kem.PublicKey,
	seed []byte,
	sks kem.PrivateKey,
) (ct, ss []byte, err error) {
	pke, ske := k.dh.DeriveKey(seed)
	return k.authEncap(pkr, sks, pke, ske)
}

func (k kemBase) Encapsulate(
	pkr kem.PublicKey,
) (ct []byte, ss []byte, err error) {
	pke, ske, err := k.dh.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	return k.encap(pkr, pke, ske)
}

func (k kemBase) EncapsulateDeterministically(
	pkr kem.PublicKey,
	seed []byte,
) (ct, ss []byte, err error) {
	pke, ske := k.dh.DeriveKey(seed)
	return k.encap(pkr, pke, ske)
}

func (k kemBase) encap(
	pkR kem.PublicKey,
	pkE encoding.BinaryMarshaler, // kem.PublicKey
	skE kem.PrivateKey,
) (ct []byte, ss []byte, err error) {
	dh := make([]byte, k.dh.sizeDH())
	enc, kemCtx, err := k.coreEncap(dh, pkR, skE, pkE)
	if err != nil {
		return nil, nil, err
	}
	ss = k.extractExpand(dh, kemCtx)
	return enc, ss, nil
}

func (k kemBase) authEncap(
	pkR kem.PublicKey,
	skS kem.PrivateKey,
	pkE encoding.BinaryMarshaler, // kem.PublicKey
	skE kem.PrivateKey,
) (ct []byte, ss []byte, err error) {
	dhLen := k.dh.sizeDH()
	dh := make([]byte, 2*dhLen)
	enc, kemCtx, err := k.coreEncap(dh[:dhLen], pkR, skE, pkE)
	if err != nil {
		return nil, nil, err
	}

	err = k.dh.calcDH(dh[dhLen:], skS, pkR)
	if err != nil {
		return nil, nil, err
	}

	pkS := skS.Public()
	pkSm, err := pkS.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	kemCtx = append(kemCtx, pkSm...)

	ss = k.extractExpand(dh, kemCtx)
	return enc, ss, nil
}

func (k kemBase) coreEncap(
	dh []byte,
	pkR kem.PublicKey,
	skE kem.PrivateKey,
	pkE encoding.BinaryMarshaler, // kem.PublicKey
) (enc []byte, kemCtx []byte, err error) {
	err = k.dh.calcDH(dh, skE, pkR)
	if err != nil {
		return nil, nil, err
	}

	enc, err = pkE.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	pkRm, err := pkR.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	kemCtx = append(append([]byte{}, enc...), pkRm...)

	return enc, kemCtx, nil
}

func (k kemBase) Decapsulate(skr kem.PrivateKey, ct []byte) ([]byte, error) {
	dh := make([]byte, k.dh.sizeDH())
	kemCtx, err := k.coreDecap(dh, skr, ct)
	if err != nil {
		return nil, err
	}
	return k.extractExpand(dh, kemCtx), nil
}

func (k kemBase) AuthDecapsulate(
	skR kem.PrivateKey,
	ct []byte,
	pkS kem.PublicKey,
) ([]byte, error) {
	dhLen := k.dh.sizeDH()
	dh := make([]byte, 2*dhLen)
	kemCtx, err := k.coreDecap(dh[:dhLen], skR, ct)
	if err != nil {
		return nil, err
	}

	err = k.dh.calcDH(dh[dhLen:], skR, pkS)
	if err != nil {
		return nil, err
	}

	pkSm, err := pkS.MarshalBinary()
	if err != nil {
		return nil, err
	}
	kemCtx = append(kemCtx, pkSm...)
	return k.extractExpand(dh, kemCtx), nil
}

func (k kemBase) coreDecap(
	dh []byte,
	skR kem.PrivateKey,
	ct []byte,
) ([]byte, error) {
	pkE, err := k.dh.UnmarshalBinaryPublicKey(ct)
	if err != nil {
		return nil, err
	}

	err = k.dh.calcDH(dh, skR, pkE)
	if err != nil {
		return nil, err
	}

	pkR := skR.Public()
	pkRm, err := pkR.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return append(append([]byte{}, ct...), pkRm...), nil
}
