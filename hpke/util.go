package hpke

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

func (st state) keySchedule(ss, info, psk, pskID []byte) (*encdecContext, error) {
	if err := st.verifyPSKInputs(psk, pskID); err != nil {
		return nil, err
	}

	pskIDHash := st.labeledExtract(nil, []byte("psk_id_hash"), pskID)
	infoHash := st.labeledExtract(nil, []byte("info_hash"), info)
	keySchCtx := append(append(
		[]byte{st.modeID},
		pskIDHash...),
		infoHash...)

	secret := st.labeledExtract(ss, []byte("secret"), psk)

	Nk := uint16(st.AeadID.KeySize())
	key := st.labeledExpand(secret, []byte("key"), keySchCtx, Nk)

	aead, err := st.AeadID.New(key)
	if err != nil {
		return nil, err
	}

	Nn := uint16(aead.NonceSize())
	baseNonce := st.labeledExpand(secret, []byte("base_nonce"), keySchCtx, Nn)
	exporterSecret := st.labeledExpand(
		secret,
		[]byte("exp"),
		keySchCtx,
		uint16(st.KdfID.Hash().Size()),
	)

	return &encdecContext{
		aead,
		st.Suite,
		exporterSecret,
		key,
		baseNonce,
		make([]byte, Nn),
	}, nil
}

func (st state) verifyPSKInputs(psk, pskID []byte) error {
	gotPSK := psk != nil
	gotPSKID := pskID != nil
	if gotPSK != gotPSKID {
		return errors.New("inconsistent PSK inputs")
	}
	switch st.modeID {
	case modeBase | modeAuth:
		if gotPSK {
			return errors.New("PSK input provided when not needed")
		}
	case modePSK | modeAuthPSK:
		if !gotPSK {
			return errors.New("missing required PSK input")
		}
	}
	return nil
}

func (suite Suite) String() string {
	return fmt.Sprintf(
		"kem: %v kdf: %v aead: %v",
		suite.KemID, suite.KdfID, suite.AeadID,
	)
}

func (suite Suite) getSuiteID() (id [10]byte) {
	id[0], id[1], id[2], id[3] = 'H', 'P', 'K', 'E'
	binary.BigEndian.PutUint16(id[4:6], suite.KemID.uint16)
	binary.BigEndian.PutUint16(id[6:8], suite.KdfID.uint16)
	binary.BigEndian.PutUint16(id[8:10], suite.AeadID.uint16)
	return
}

func (suite Suite) labeledExtract(salt, label, ikm []byte) []byte {
	suiteID := suite.getSuiteID()
	labeledIKM := append(append(append(append(
		make([]byte, 0, len(versionLabel)+len(suiteID)+len(label)+len(ikm)),
		versionLabel...),
		suiteID[:]...),
		label...),
		ikm...)
	return hkdf.Extract(suite.KdfID.Hash().New, labeledIKM, salt)
}

func (suite Suite) labeledExpand(prk, label, info []byte, l uint16) []byte {
	suiteID := suite.getSuiteID()
	labeledInfo := make([]byte,
		2, 2+len(versionLabel)+len(suiteID)+len(label)+len(info))
	binary.BigEndian.PutUint16(labeledInfo[0:2], l)
	labeledInfo = append(append(append(append(labeledInfo,
		versionLabel...),
		suiteID[:]...),
		label...),
		info...)
	b := make([]byte, l)
	rd := hkdf.Expand(suite.KdfID.Hash().New, prk, labeledInfo)
	_, _ = io.ReadFull(rd, b)
	return b
}
