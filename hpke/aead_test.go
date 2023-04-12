package hpke

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func TestAeadExporter(t *testing.T) {
	suite := Suite{kdfID: KDF_HKDF_SHA256, aeadID: AEAD_AES128GCM}
	exporter := &encdecContext{suite: suite}
	maxLength := uint(255 * suite.kdfID.ExtractSize())

	err := test.CheckPanic(func() {
		exporter.Export([]byte("exporter"), maxLength+1)
	})
	test.CheckNoErr(t, err, "exporter max size")
}

func setupAeadTest() (*sealContext, *openContext, error) {
	suite := Suite{aeadID: AEAD_AES128GCM}
	key := make([]byte, suite.aeadID.KeySize())
	if n, err := rand.Read(key); err != nil {
		return nil, nil, err
	} else if n != len(key) {
		return nil, nil, fmt.Errorf("unexpected key size: got %d; want %d", n, len(key))
	}

	aead, err := suite.aeadID.New(key)
	if err != nil {
		return nil, nil, err
	}

	Nn := suite.aeadID.NonceSize()
	baseNonce := make([]byte, Nn)
	if n, err := rand.Read(baseNonce); err != nil {
		return nil, nil, err
	} else if n != len(baseNonce) {
		return nil, nil, fmt.Errorf("unexpected base nonce size: got %d; want %d", n, len(baseNonce))
	}

	sealer := &sealContext{
		&encdecContext{
			suite, nil, nil, nil, nil, nil, baseNonce, make([]byte, Nn), aead, make([]byte, Nn),
		},
	}
	opener := &openContext{
		&encdecContext{
			suite, nil, nil, nil, nil, nil, baseNonce, make([]byte, Nn), aead, make([]byte, Nn),
		},
	}
	return sealer, opener, nil
}

func TestAeadNonceUpdate(t *testing.T) {
	sealer, opener, err := setupAeadTest()
	test.CheckNoErr(t, err, "setup failed")

	pt := []byte("plaintext")
	aad := []byte("aad")

	numAttempts := 2
	var prevCt []byte
	for i := 0; i < numAttempts; i++ {
		ct, err := sealer.Seal(pt, aad)
		if err != nil {
			t.Fatalf("encryption failed: %s", err)
		}

		if prevCt != nil && bytes.Equal(ct, prevCt) {
			t.Error("ciphertext matches the previous (nonce not updated)")
		}

		_, err = opener.Open(ct, aad)
		if err != nil {
			t.Errorf("decryption failed: %s", err)
		}

		prevCt = ct
	}
}

func TestOpenPhaseMismatch(t *testing.T) {
	sealer, opener, err := setupAeadTest()
	test.CheckNoErr(t, err, "setup failed")

	pt := []byte("plaintext")
	aad := []byte("aad")

	ct, err := sealer.Seal(pt, aad)
	if err != nil {
		t.Fatalf("encryption failed: %s", err)
	}

	recovered, err := opener.Open(ct, aad)
	if err != nil {
		t.Fatalf("decryption failed: %s", err)
	}

	if !bytes.Equal(pt, recovered) {
		t.Fatal("Plaintext mismatch")
	}

	_, err = opener.Open(ct, aad)
	if err == nil {
		t.Fatal("decryption succeeded when it should have failed")
	}
}

func TestSealPhaseMismatch(t *testing.T) {
	sealer, opener, err := setupAeadTest()
	test.CheckNoErr(t, err, "setup failed")

	pt := []byte("plaintext")
	aad := []byte("aad")

	_, err = sealer.Seal(pt, aad)
	if err != nil {
		t.Fatalf("encryption failed: %s", err)
	}

	ct, err := sealer.Seal(pt, aad)
	if err != nil {
		t.Fatalf("encryption failed: %s", err)
	}

	_, err = opener.Open(ct, aad)
	if err == nil {
		t.Fatal("decryption succeeded when it should have failed")
	}
}

func TestAeadSeqOverflow(t *testing.T) {
	sealer, opener, err := setupAeadTest()
	test.CheckNoErr(t, err, "setup failed")

	Nn := len(sealer.baseNonce)
	pt := []byte("plaintext")
	aad := []byte("aad")

	// Sets sequence number to 256 before its max value = 0xFF...FF.
	for i := 0; i < Nn; i++ {
		sealer.sequenceNumber[i] = 0xFF
		opener.sequenceNumber[i] = 0xFF
	}
	sealer.sequenceNumber[Nn-1] = 0x00
	opener.sequenceNumber[Nn-1] = 0x00

	numAttempts := 260
	wantCorrect := 2 * 255
	wantIncorrect := 2*numAttempts - wantCorrect
	gotCorrect := 0
	gotIncorrect := 0

	for i := 0; i < numAttempts; i++ {
		ct, err := sealer.Seal(pt, aad)
		switch {
		case ct != nil && err == nil:
			gotCorrect++
		case ct == nil && err != nil:
			gotIncorrect++
		default:
			t.FailNow()
		}

		pt2, err := opener.Open(ct, aad)
		switch {
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
