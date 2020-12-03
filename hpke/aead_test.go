package hpke

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func TestAeadExporter(t *testing.T) {
	suite := Suite{KdfID: HkdfSha256, AeadID: AeadAes128Gcm}
	exporter := &encdecCtx{suite: suite}
	maxLength := uint(255 * suite.KdfID.Hash().Size())

	err := test.CheckPanic(func() {
		exporter.Export([]byte("exporter"), maxLength+1)
	})
	test.CheckNoErr(t, err, "exporter max size")
}

func TestAeadSeqOverflow(t *testing.T) {
	suite := Suite{AeadID: AeadAes128Gcm}

	key := make([]byte, suite.AeadID.KeySize())
	_, _ = rand.Read(key)
	aead, err := suite.AeadID.New(key)
	test.CheckNoErr(t, err, "bad key")

	Nn := aead.NonceSize()
	nonce := make([]byte, Nn)
	_, _ = rand.Read(nonce)
	sealer := &sealCtx{
		nil,
		&encdecCtx{nil, suite, nil, nil, nonce, make([]byte, Nn), aead},
	}
	opener := &openCtx{
		nil,
		&encdecCtx{nil, suite, nil, nil, nonce, make([]byte, Nn), aead},
	}

	pt := []byte("plaintext")
	aad := []byte("aad")

	// Sets sequence number to 256 before its max value = 0xFF...FF.
	for i := 0; i < Nn; i++ {
		sealer.seq[i] = 0xFF
		opener.seq[i] = 0xFF
	}
	sealer.seq[Nn-1] = 0x00
	opener.seq[Nn-1] = 0x00

	numAttempts := 260
	wantCorrect := 2 * 255
	wantIncorrect := 2*numAttempts - wantCorrect
	gotCorrect := 0
	gotIncorrect := 0

	for i := 0; i < numAttempts; i++ {
		ct, err := sealer.Seal(pt, aad)
		switch true {
		case ct != nil && err == nil:
			gotCorrect++
		case ct == nil && err != nil:
			gotIncorrect++
		default:
			t.FailNow()
		}

		pt2, err := opener.Open(ct, aad)
		switch true {
		case pt2 != nil && err == nil:
			gotCorrect++
		case pt2 == nil && err != nil:
			gotIncorrect++
		default:
			t.FailNow()
		}
	}

	if gotCorrect != wantCorrect {
		test.ReportError(t, gotCorrect, wantCorrect)
	}
	if gotIncorrect != wantIncorrect {
		test.ReportError(t, gotIncorrect, wantIncorrect)
	}
}

func contextEqual(a, b *encdecCtx) bool {
	an := make([]byte, a.NonceSize())
	bn := make([]byte, b.NonceSize())
	ac := a.AEAD.Seal(nil, an, nil, nil)
	bc := b.AEAD.Seal(nil, bn, nil, nil)
	return bytes.Equal(a.raw, b.raw) &&
		a.suite == b.suite &&
		bytes.Equal(a.exporterSecret, b.exporterSecret) &&
		bytes.Equal(a.key, b.key) &&
		bytes.Equal(a.baseNonce, b.baseNonce) &&
		bytes.Equal(a.seq, b.seq) &&
		bytes.Equal(ac, bc)
}

func TestContextSerialization(t *testing.T) {
	s := Suite{
		DHKemP384HkdfSha384,
		HkdfSha384,
		AeadAes256Gcm,
	}
	info := []byte("some info string")

	pk, sk, err := s.KemID.Scheme().GenerateKey()
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

	rawSealer, err := sealer.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	rawOpener, err := opener.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	parsedSealer, err := UnmarshalSealer(rawSealer)
	if err != nil {
		t.Fatal(err)
	}

	if !contextEqual(
		sealer.(*sealCtx).encdecCtx,
		parsedSealer.(*sealCtx).encdecCtx) {
		t.Error("parsed sealer does not match original")
	}

	parsedOpener, err := UnmarshalOpener(rawOpener)
	if err != nil {
		t.Fatal(err)
	}

	if !contextEqual(
		opener.(*openCtx).encdecCtx,
		parsedOpener.(*openCtx).encdecCtx) {
		t.Error("parsed opener does not match original")
	}
}
