package hpke

import (
	"crypto"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

func (s state) keySchedule(ss, info, psk, pskID []byte) (*encdecCtx, error) {
	if err := s.verifyPSKInputs(psk, pskID); err != nil {
		return nil, err
	}

	pskIDHash := s.labeledExtract(nil, []byte("psk_id_hash"), pskID)
	infoHash := s.labeledExtract(nil, []byte("info_hash"), info)
	keySchCtx := append([]byte{s.modeID}, pskIDHash...)
	keySchCtx = append(keySchCtx, infoHash...)

	secret := s.labeledExtract(ss, []byte("secret"), psk)

	Nk := uint16(s.AeadID.KeySize())
	key := s.labeledExpand(secret, []byte("key"), keySchCtx, Nk)

	aead, err := s.AeadID.New(key)
	if err != nil {
		return nil, err
	}

	Nn := uint16(aead.NonceSize())
	baseNonce := s.labeledExpand(secret, []byte("base_nonce"), keySchCtx, Nn)
	exporterSecret := s.labeledExpand(
		secret,
		[]byte("exp"),
		keySchCtx,
		uint16(s.KdfID.Hash().Size()),
	)

	return &encdecCtx{
		aead,
		s.Suite,
		baseNonce,
		make([]byte, Nn),
		exporterSecret,
	}, nil
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
	return fmt.Sprintf(
		"kem_id: %v kdf_id: %v aead_id: %v",
		s.KemID,
		s.KdfID,
		s.AeadID,
	)
}

func (s Suite) getSuiteID() (id [10]byte) {
	id[0], id[1], id[2], id[3] = 'H', 'P', 'K', 'E'
	binary.BigEndian.PutUint16(id[4:6], uint16(s.KemID))
	binary.BigEndian.PutUint16(id[6:8], uint16(s.KdfID))
	binary.BigEndian.PutUint16(id[8:10], uint16(s.AeadID))
	return
}

func (s Suite) IsValid() bool {
	return s.KemID.Scheme() != nil &&
		s.KdfID.Hash() != crypto.Hash(0) &&
		s.AeadID.KeySize() != 0
}

func (s Suite) labeledExtract(salt, label, ikm []byte) []byte {
	suiteID := s.getSuiteID()
	labeledIKM := append(append(append(append(
		make([]byte, 0, len(versionLabel)+len(suiteID)+len(label)+len(ikm)),
		versionLabel...),
		suiteID[:]...),
		label...),
		ikm...)
	return hkdf.Extract(s.KdfID.Hash().New, labeledIKM, salt)
}

func (s Suite) labeledExpand(prk, label, info []byte, l uint16) []byte {
	suiteID := s.getSuiteID()
	labeledInfo := make([]byte,
		2, 2+len(versionLabel)+len(suiteID)+len(label)+len(info))
	binary.BigEndian.PutUint16(labeledInfo[0:2], l)
	labeledInfo = append(append(append(append(labeledInfo,
		versionLabel...),
		suiteID[:]...),
		label...),
		info...)
	b := make([]byte, l)
	rd := hkdf.Expand(s.KdfID.Hash().New, prk, labeledInfo)
	_, _ = io.ReadFull(rd, b)
	return b
}
