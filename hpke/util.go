package hpke

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const versionLabel = "HPKE-06"

func (m Mode) String() string {
	return fmt.Sprintf("mode: %v\nkem_id: %v\nkdf_id: %v\naead_id: %v",
		m.ModeID, m.KemInfo, m.HkdfInfo, m.AeadInfo)
}

func (m Mode) keySchedule(ss, info, psk, pskID []byte) (*encdecCxt, error) {
	if err := m.verifyPSKInputs(psk, pskID); err != nil {
		panic(err)
	}

	pskIDHash := m.labeledExtract(nil, []byte("psk_id_hash"), pskID)
	infoHash := m.labeledExtract(nil, []byte("info_hash"), info)
	keySchCtx := append([]byte{byte(m.ModeID)}, pskIDHash...)
	keySchCtx = append(keySchCtx, infoHash...)

	secret := m.labeledExtract(ss, []byte("secret"), psk)

	aeadPar := aeadParams[m.AeadInfo]
	key := m.labeledExpand(secret, []byte("key"), keySchCtx, aeadPar.Nk)
	baseNonce := m.labeledExpand(secret, []byte("base_nonce"), keySchCtx, aeadPar.Nn)
	exporterSecret := m.labeledExpand(secret, []byte("exp"), keySchCtx, aeadPar.Nn)

	return aeadPar.newCtx(key, baseNonce, exporterSecret)
}

func (m Mode) verifyPSKInputs(psk, pskID []byte) error {
	gotPSK := psk != nil
	gotPSKID := pskID != nil
	if gotPSK != gotPSKID {
		return errors.New("inconsistent psk inputs")
	}
	switch m.ModeID {
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

func (m Mode) getSuiteID() (id [10]byte) {
	copy(id[:], "HPKE")
	binary.BigEndian.PutUint16(id[4:6], uint16(m.KemInfo))
	binary.BigEndian.PutUint16(id[6:8], uint16(m.HkdfInfo))
	binary.BigEndian.PutUint16(id[8:10], uint16(m.AeadInfo))
	return
}

func (m Mode) labeledExtract(salt, label, ikm []byte) []byte {
	suiteID := m.getSuiteID()
	labeledIKM := make([]byte, 0, len(versionLabel)+len(suiteID)+len(label)+len(ikm))
	labeledIKM = append(labeledIKM, []byte(versionLabel)...)
	labeledIKM = append(labeledIKM, suiteID[:]...)
	labeledIKM = append(labeledIKM, label...)
	labeledIKM = append(labeledIKM, ikm...)
	return hkdf.Extract(hkdfParams[m.HkdfInfo].H.New, labeledIKM, salt)
}

func (m Mode) labeledExpand(prk, label, info []byte, l uint16) []byte {
	suiteID := m.getSuiteID()
	labeledInfo := make([]byte, 2, 2+len(versionLabel)+len(suiteID)+len(label)+len(info))
	binary.BigEndian.PutUint16(labeledInfo[0:2], l)
	labeledInfo = append(labeledInfo, []byte(versionLabel)...)
	labeledInfo = append(labeledInfo, suiteID[:]...)
	labeledInfo = append(labeledInfo, label...)
	labeledInfo = append(labeledInfo, info...)
	b := make([]byte, l)
	rd := hkdf.Expand(hkdfParams[m.HkdfInfo].H.New, prk, labeledInfo)
	_, _ = io.ReadFull(rd, b)
	return b
}
