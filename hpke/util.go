package hpke

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/short"
	"golang.org/x/crypto/hkdf"
)

func (s state) keySchedule(ss, info, psk, pskID []byte) (*encdecCxt, error) {
	if err := s.verifyPSKInputs(psk, pskID); err != nil {
		return nil, err
	}

	pskIDHash := s.labeledExtract(nil, []byte("psk_id_hash"), pskID)
	infoHash := s.labeledExtract(nil, []byte("info_hash"), info)
	keySchCtx := append([]byte{s.modeID}, pskIDHash...)
	keySchCtx = append(keySchCtx, infoHash...)

	secret := s.labeledExtract(ss, []byte("secret"), psk)

	aeadPar := aeadParams[s.AeadID]
	key := s.labeledExpand(secret, []byte("key"), keySchCtx, aeadPar.Nk)
	baseNonce := s.labeledExpand(secret, []byte("base_nonce"), keySchCtx, aeadPar.Nn)
	exporterSecret := s.labeledExpand(secret, []byte("exp"), keySchCtx, aeadPar.Nn)

	return s.aeadCtx(key, baseNonce, exporterSecret)
}

func (s state) verifyPSKInputs(psk, pskID []byte) error {
	gotPSK := psk != nil
	gotPSKID := pskID != nil
	if gotPSK != gotPSKID {
		return errors.New("inconsistent psk inputs")
	}
	switch s.modeID {
	case Base | Auth:
		if gotPSK {
			return errors.New("psk input provided when not needed")
		}
	case PSK | AuthPSK:
		if !gotPSK {
			return errors.New("missing required psk input")
		}
	}
	return nil
}

func (s Suite) String() string {
	return fmt.Sprintf("kem_id: %v kdf_id: %v aead_id: %v", s.KemID, s.KdfID, s.AeadID)
}

func (s Suite) getSuiteID() (id [10]byte) {
	copy(id[:], "HPKE")
	binary.BigEndian.PutUint16(id[4:6], s.KemID)
	binary.BigEndian.PutUint16(id[6:8], s.KdfID)
	binary.BigEndian.PutUint16(id[8:10], s.AeadID)
	return
}

func (s Suite) validate() error {
	if _, ok := kemParams[s.KemID]; !ok {
		return errors.New("kdfID not supported")
	}
	if _, ok := kdfParams[s.KdfID]; !ok {
		return errors.New("kemID not supported")
	}
	if _, ok := aeadParams[s.AeadID]; !ok {
		return errors.New("aeadID not supported")
	}
	return nil
}

func (s Suite) labeledExtract(salt, label, ikm []byte) []byte {
	suiteID := s.getSuiteID()
	labeledIKM := append(append(append(append(
		make([]byte, 0, len(versionLabel)+len(suiteID)+len(label)+len(ikm)),
		versionLabel...),
		suiteID[:]...),
		label...),
		ikm...)
	return hkdf.Extract(kdfParams[s.KdfID].H.New, labeledIKM, salt)
}

func (s Suite) labeledExpand(prk, label, info []byte, l uint16) []byte {
	suiteID := s.getSuiteID()
	labeledInfo := make([]byte, 2, 2+len(versionLabel)+len(suiteID)+len(label)+len(info))
	binary.BigEndian.PutUint16(labeledInfo[0:2], l)
	labeledInfo = append(append(append(append(labeledInfo,
		versionLabel...),
		suiteID[:]...),
		label...),
		info...)
	b := make([]byte, l)
	rd := hkdf.Expand(kdfParams[s.KdfID].H.New, prk, labeledInfo)
	_, _ = io.ReadFull(rd, b)
	return b
}

func (s Suite) GetKem() (kem.Scheme, error) {
	var dhkem kem.Scheme

	switch s.KemID {
	case KemP256Sha256, KemP384Sha384, KemP521Sha512:
		dhkem = short.New(s.KemID, []byte(versionLabel))
	case KemX25519Sha256, KemX448Sha512:
		panic("not implemented yet")
	default:
		return nil, errors.New("wrong kemID")
	}
	return dhkem, nil
}
