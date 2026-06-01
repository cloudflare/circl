package hpke

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func TestPSKModeRejectsMissingPSK(t *testing.T) {
	kemID := KEM_X25519_HKDF_SHA256
	kdfID := KDF_HKDF_SHA256
	aeadID := AEAD_AES128GCM
	suite := NewSuite(kemID, kdfID, aeadID)
	info := []byte("info")

	pkR, skR, err := kemID.Scheme().GenerateKeyPair()
	test.CheckNoErr(t, err, "keygen")

	sender, err := suite.NewSender(pkR, info)
	test.CheckNoErr(t, err, "sender")
	receiver, err := suite.NewReceiver(skR, info)
	test.CheckNoErr(t, err, "receiver")

	// modePSK with nil PSK must fail.
	_, _, err = sender.SetupPSK(rand.Reader, nil, nil)
	if err == nil {
		t.Error("modePSK: expected error for nil PSK, got nil")
	}

	// modePSK with empty (but non-nil) PSK must fail.
	_, _, err = sender.SetupPSK(rand.Reader, []byte{}, []byte{})
	if err == nil {
		t.Error("modePSK: expected error for empty PSK, got nil")
	}

	// modeAuthPSK with nil PSK must fail.
	_, skA, err := kemID.Scheme().GenerateKeyPair()
	test.CheckNoErr(t, err, "auth keygen")
	_, _, err = sender.SetupAuthPSK(rand.Reader, skA, nil, nil)
	if err == nil {
		t.Error("modeAuthPSK: expected error for nil PSK, got nil")
	}

	// modeAuthPSK with empty (but non-nil) PSK must fail.
	_, _, err = sender.SetupAuthPSK(rand.Reader, skA, []byte{}, []byte{})
	if err == nil {
		t.Error("modeAuthPSK: expected error for empty PSK, got nil")
	}

	// Receiver side: modePSK with nil PSK must fail.
	enc, _, err := sender.SetupPSK(rand.Reader, []byte("psk"), []byte("pskID"))
	test.CheckNoErr(t, err, "sender setup with valid PSK")

	_, err = receiver.SetupPSK(enc, nil, nil)
	if err == nil {
		t.Error("receiver modePSK: expected error for nil PSK, got nil")
	}

	_, err = receiver.SetupPSK(enc, []byte{}, []byte{})
	if err == nil {
		t.Error("receiver modePSK: expected error for empty PSK, got nil")
	}
}

func TestBaseModeRejectsUnwantedPSK(t *testing.T) {
	kemID := KEM_X25519_HKDF_SHA256
	kdfID := KDF_HKDF_SHA256
	aeadID := AEAD_AES128GCM
	suite := NewSuite(kemID, kdfID, aeadID)
	info := []byte("info")

	pkR, skR, err := kemID.Scheme().GenerateKeyPair()
	test.CheckNoErr(t, err, "keygen")

	// modeBase with a PSK provided must fail.
	_, err = suite.NewSender(pkR, info)
	test.CheckNoErr(t, err, "sender")

	// We need to smuggle a PSK into the base setup. Since the public API
	// doesn't accept PSK for base mode, we construct the state manually.
	st := state{Suite: suite, modeID: modeBase, info: info, psk: []byte("psk"), pskID: []byte("pskID")}
	badSender := &Sender{state: st, pkR: pkR}
	_, _, err = badSender.allSetup(rand.Reader)
	if err == nil {
		t.Error("modeBase: expected error for unwanted PSK, got nil")
	}

	// modeAuth with a PSK provided must fail.
	st.modeID = modeAuth
	st.skS = skR // reuse skR as auth key for simplicity
	badAuthSender := &Sender{state: st, pkR: pkR}
	_, _, err = badAuthSender.allSetup(rand.Reader)
	if err == nil {
		t.Error("modeAuth: expected error for unwanted PSK, got nil")
	}

	// Receiver side: modeBase with a PSK provided must fail.
	enc := []byte("dummy")
	st.modeID = modeBase
	badReceiver := &Receiver{state: st, skR: skR, enc: enc}
	_, err = badReceiver.allSetup()
	if err == nil {
		t.Error("receiver modeBase: expected error for unwanted PSK, got nil")
	}

	// Receiver side: modeAuth with a PSK provided must fail.
	st.modeID = modeAuth
	badAuthReceiver := &Receiver{state: st, skR: skR, enc: enc}
	_, err = badAuthReceiver.allSetup()
	if err == nil {
		t.Error("receiver modeAuth: expected error for unwanted PSK, got nil")
	}
}

func TestVerifyPSKInputsDirectly(t *testing.T) {
	st := state{Suite: NewSuite(KEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES128GCM)}

	// modeBase: unwanted non-empty PSK should fail.
	st.modeID = modeBase
	if err := st.verifyPSKInputs([]byte("psk"), []byte("pskID")); err == nil {
		t.Error("modeBase: expected error for non-empty PSK")
	}
	// modeBase: nil PSK should succeed.
	if err := st.verifyPSKInputs(nil, nil); err != nil {
		t.Errorf("modeBase: unexpected error for nil PSK: %v", err)
	}
	// modeBase: empty PSK should succeed.
	if err := st.verifyPSKInputs([]byte{}, []byte{}); err != nil {
		t.Errorf("modeBase: unexpected error for empty PSK: %v", err)
	}

	// modeAuth: unwanted non-empty PSK should fail.
	st.modeID = modeAuth
	if err := st.verifyPSKInputs([]byte("psk"), []byte("pskID")); err == nil {
		t.Error("modeAuth: expected error for non-empty PSK")
	}
	// modeAuth: nil PSK should succeed.
	if err := st.verifyPSKInputs(nil, nil); err != nil {
		t.Errorf("modeAuth: unexpected error for nil PSK: %v", err)
	}

	// modePSK: missing nil PSK should fail.
	st.modeID = modePSK
	if err := st.verifyPSKInputs(nil, nil); err == nil {
		t.Error("modePSK: expected error for nil PSK")
	}
	// modePSK: missing empty PSK should fail.
	if err := st.verifyPSKInputs([]byte{}, []byte{}); err == nil {
		t.Error("modePSK: expected error for empty PSK")
	}
	// modePSK: non-empty PSK should succeed.
	if err := st.verifyPSKInputs([]byte("psk"), []byte("pskID")); err != nil {
		t.Errorf("modePSK: unexpected error for valid PSK: %v", err)
	}

	// modeAuthPSK: missing nil PSK should fail.
	st.modeID = modeAuthPSK
	if err := st.verifyPSKInputs(nil, nil); err == nil {
		t.Error("modeAuthPSK: expected error for nil PSK")
	}
	// modeAuthPSK: missing empty PSK should fail.
	if err := st.verifyPSKInputs([]byte{}, []byte{}); err == nil {
		t.Error("modeAuthPSK: expected error for empty PSK")
	}
	// modeAuthPSK: non-empty PSK should succeed.
	if err := st.verifyPSKInputs([]byte("psk"), []byte("pskID")); err != nil {
		t.Errorf("modeAuthPSK: unexpected error for valid PSK: %v", err)
	}

	// Mismatched PSK / PskID must fail in all modes.
	for _, m := range []modeID{modeBase, modeAuth, modePSK, modeAuthPSK} {
		st.modeID = m
		if err := st.verifyPSKInputs([]byte("psk"), nil); err == nil {
			t.Errorf("mode %d: expected error for mismatched PSK inputs", m)
		}
		if err := st.verifyPSKInputs(nil, []byte("pskID")); err == nil {
			t.Errorf("mode %d: expected error for mismatched PSK inputs", m)
		}
	}
}
