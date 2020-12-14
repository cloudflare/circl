package hpke

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func contextEqual(a, b *encdecContext) bool {
	an := make([]byte, a.NonceSize())
	bn := make([]byte, b.NonceSize())
	ac := a.AEAD.Seal(nil, an, nil, nil)
	bc := b.AEAD.Seal(nil, bn, nil, nil)
	return a.suite == b.suite &&
		bytes.Equal(a.exporterSecret, b.exporterSecret) &&
		bytes.Equal(a.key, b.key) &&
		bytes.Equal(a.baseNonce, b.baseNonce) &&
		bytes.Equal(a.sequenceNumber, b.sequenceNumber) &&
		bytes.Equal(ac, bc) &&
		len(a.nonce) == len(b.nonce) &&
		len(a.nonce) == len(a.baseNonce)
}

func TestContextSerialization(t *testing.T) {
	s := NewSuite(KEM_P384_HKDF_SHA384, KDF_HKDF_SHA384, AEAD_AES256GCM)
	info := []byte("some info string")

	pk, sk, err := s.kemID.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := s.NewReceiver(sk, info)
	if err != nil {
		t.Fatal(err)
	}
	sender, err := s.NewSender(pk, info)
	if err != nil {
		t.Fatal(err)
	}
	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	opener, err := receiver.Setup(enc)
	if err != nil {
		t.Fatal(err)
	}

	rawSealer, err := sealer.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	parsedSealer, err := UnmarshalSealer(rawSealer)
	if err != nil {
		t.Fatal(err)
	}
	if !contextEqual(
		sealer.(*sealContext).encdecContext,
		parsedSealer.(*sealContext).encdecContext) {
		t.Error("parsed sealer does not match original")
	}
	_, err = UnmarshalOpener(rawSealer)
	if err == nil {
		t.Error("parsing a sealer as an opener succeeded; want failure")
	}

	rawOpener, err := opener.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	parsedOpener, err := UnmarshalOpener(rawOpener)
	if err != nil {
		t.Fatal(err)
	}
	if !contextEqual(
		opener.(*openContext).encdecContext,
		parsedOpener.(*openContext).encdecContext) {
		t.Error("parsed opener does not match original")
	}
	_, err = UnmarshalSealer(rawOpener)
	if err == nil {
		t.Error("parsing an opener as a sealer succeeded; want failure")
	}
}
