package hpke

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/kem"
)

func (st state) keySchedule(ss, info, psk, pskID []byte) (*encdecContext, error) {
	if err := st.verifyPSKInputs(psk, pskID); err != nil {
		return nil, err
	}

	Nk := uint16(st.aeadID.KeySize())
	Nn := uint16(st.aeadID.NonceSize())
	Nh := uint16(st.kdfID.ExtractSize())

	var key, secret, baseNonce, exporterSecret, context []byte

	if st.kdfID.IsTwoStage() {
		pskIDHash := st.labeledExtract(nil, []byte("psk_id_hash"), pskID)
		infoHash := st.labeledExtract(nil, []byte("info_hash"), info)
		context = concat(
			[]byte{st.modeID},
			pskIDHash,
			infoHash,
		)

		secret = st.labeledExtract(ss, []byte("secret"), psk)
		key = st.labeledExpand(secret, []byte("key"), context, Nk)

		baseNonce = st.labeledExpand(secret, []byte("base_nonce"), context, Nn)
		exporterSecret = st.labeledExpand(
			secret,
			[]byte("exp"),
			context,
			uint16(st.kdfID.ExtractSize()),
		)
	} else {
		secrets := concat(
			lengthPrefixed(psk),
			lengthPrefixed(ss),
		)
		context = concat(
			[]byte{st.modeID},
			lengthPrefixed(pskID),
			lengthPrefixed(info),
		)
		secret = st.labeledDerive(secrets, []byte("secret"), context, Nk+Nn+Nh)
		key = secret[:Nk]
		baseNonce = secret[Nk : Nk+Nn]
		exporterSecret = secret[Nk+Nn:]
	}

	aead, err := st.aeadID.New(key)
	if err != nil {
		return nil, err
	}

	return &encdecContext{
		st.Suite,
		ss,
		secret,
		context,
		exporterSecret,
		key,
		baseNonce,
		make([]byte, Nn),
		aead,
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

func (suite Suite) UnmarshalBinaryPrivateKey(xs []byte) (kem.PrivateKey, error) {
	return suite.kemID.UnmarshalBinaryPrivateKey(xs)
}

// Params returns the codepoints for the algorithms comprising the suite.
func (suite Suite) Params() (KEM, KDF, AEAD) {
	return suite.kemID, suite.kdfID, suite.aeadID
}

func (suite Suite) String() string {
	return fmt.Sprintf(
		"kem_id: %v kdf_id: %v aead_id: %v",
		suite.kemID, suite.kdfID, suite.aeadID,
	)
}

func (suite Suite) getSuiteID() (id [10]byte) {
	id[0], id[1], id[2], id[3] = 'H', 'P', 'K', 'E'
	binary.BigEndian.PutUint16(id[4:6], uint16(suite.kemID))
	binary.BigEndian.PutUint16(id[6:8], uint16(suite.kdfID))
	binary.BigEndian.PutUint16(id[8:10], uint16(suite.aeadID))
	return
}

func (suite Suite) isValid() bool {
	return suite.kemID.IsValid() &&
		suite.kdfID.IsValid() &&
		suite.aeadID.IsValid()
}

func (suite Suite) labeledExtract(salt, label, ikm []byte) []byte {
	suiteID := suite.getSuiteID()
	labeledIKM := concat(
		[]byte(versionLabel),
		suiteID[:],
		label,
		ikm,
	)
	return suite.kdfID.Extract(labeledIKM, salt)
}

func (suite Suite) labeledExpand(prk, label, info []byte, l uint16) []byte {
	suiteID := suite.getSuiteID()
	var packedL [2]byte
	binary.BigEndian.PutUint16(packedL[:], l)
	labeledInfo := concat(
		packedL[:],
		[]byte(versionLabel),
		suiteID[:],
		label,
		info,
	)
	return suite.kdfID.Expand(prk, labeledInfo, uint(l))
}

func (suite Suite) labeledDerive(ikm, label, context []byte, l uint16) []byte {
	suiteID := suite.getSuiteID()
	var labelLen, packedL [2]byte
	binary.BigEndian.PutUint16(labelLen[:], uint16(len(label)))
	binary.BigEndian.PutUint16(packedL[:], l)
	labeledIKM := concat(
		ikm,
		[]byte(versionLabel),
		suiteID[:],
		labelLen[:],
		label,
		packedL[:],
		context,
	)
	return suite.kdfID.Derive(labeledIKM, uint(l))
}

func concat(xs ...[]byte) []byte {
	cap := 0
	for _, x := range xs {
		cap += len(x)
	}
	ret := make([]byte, 0, cap)
	for _, x := range xs {
		ret = append(ret, x...)
	}
	return ret
}

func lengthPrefixed(x []byte) []byte {
	var packedL [2]byte
	l := len(x)
	if l > 65535 {
		panic("buffer too long for uint16 length prefix")
	}
	binary.BigEndian.PutUint16(packedL[:], uint16(l))
	return append(packedL[:], x...)
}
