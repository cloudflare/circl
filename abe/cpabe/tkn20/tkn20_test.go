package tkn20

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

type TestCase struct {
	Policy  string
	Success bool
	Attrs   map[string]string `json:"attributes"`
}

func TestConcurrentDecryption(t *testing.T) {
	var tests []TestCase
	buf, _ := os.ReadFile("testdata/policies.json")
	err := json.Unmarshal(buf, &tests)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("must have the precious")
	for i, test := range tests {
		t.Run(fmt.Sprintf("TestConcurrentDecryption:#%d", i), func(t *testing.T) {
			pk, msk, err := Setup(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			policy := Policy{}
			err = policy.FromString(test.Policy)
			if err != nil {
				t.Fatal(err)
			}
			ct, err := pk.Encrypt(rand.Reader, policy, msg)
			if err != nil {
				t.Fatalf("encryption failed: %s", err)
			}
			attrs := Attributes{}
			attrs.FromMap(test.Attrs)
			sk, err := msk.KeyGen(rand.Reader, attrs)
			if err != nil {
				t.Fatalf("key generation failed: %s", err)
			}
			checkResults := func(ct []byte, sk AttributeKey, i int) {
				pt, err := sk.Decrypt(ct)
				if tests[i].Success {
					if err != nil {
						t.Errorf("decryption failed: %s", err)
					}
					if !bytes.Equal(pt, msg) {
						t.Errorf("expected %v, received %v", pt, msg)
					}
				} else {
					if err == nil {
						t.Errorf("decryption should have failed")
					}
				}
			}
			go checkResults(ct, sk, i)
			go checkResults(ct, sk, i)
		})
	}
}

func TestEndToEndEncryption(t *testing.T) {
	var tests []TestCase
	buf, _ := os.ReadFile("testdata/policies.json")
	err := json.Unmarshal(buf, &tests)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("must have the precious")
	for i, test := range tests {
		t.Run(fmt.Sprintf("TestEndToEndEncryption:#%d", i), func(t *testing.T) {
			pk, msk, err := Setup(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			policy := Policy{}
			err = policy.FromString(test.Policy)
			if err != nil {
				t.Fatal(err)
			}
			ct, err := pk.Encrypt(rand.Reader, policy, msg)
			if err != nil {
				t.Fatalf("encryption failed: %s", err)
			}
			attrs := Attributes{}
			attrs.FromMap(test.Attrs)
			sk, err := msk.KeyGen(rand.Reader, attrs)
			if err != nil {
				t.Fatalf("key generation failed: %s", err)
			}
			npol := &Policy{}
			if err = npol.ExtractFromCiphertext(ct); err != nil {
				t.Fatalf("extraction failed: %s", err)
			}
			strpol := npol.String()
			npol2 := &Policy{}
			if err = npol2.FromString(strpol); err != nil {
				t.Fatalf("string %s didn't parse: %s", strpol, err)
			}
			sat := policy.Satisfaction(attrs)
			if sat != npol.Satisfaction(attrs) {
				t.Fatalf("extracted policy doesn't match original")
			}
			if sat != npol2.Satisfaction(attrs) {
				t.Fatalf("round tripped policy doesn't match original")
			}
			ctSat := attrs.CouldDecrypt(ct)
			pt, err := sk.Decrypt(ct)
			if test.Success {
				// test case should succeed
				if !sat {
					t.Fatalf("satisfaction failed")
				}
				if !ctSat {
					t.Fatalf("ciphertext satisfaction failed")
				}
				if err != nil {
					t.Fatalf("decryption failed: %s", err)
				}
				if !bytes.Equal(pt, msg) {
					t.Fatalf("expected %v, received %v", pt, msg)
				}
			} else {
				// test case should fail
				if sat {
					t.Fatal("satisfaction should have failed")
				}
				if ctSat {
					t.Fatal("ciphertext satisfaction should have failed")
				}
				if err == nil {
					t.Fatal("decryption should have failed")
				}
			}
		})
	}
}

func TestMarshal(t *testing.T) {
	pk, msk, err := Setup(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	data, err := pk.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	b := &PublicKey{}
	err = b.UnmarshalBinary(data)
	if err != nil {
		t.Fatal(err)
	}
	if !pk.Equal(b) {
		t.Fatal("PublicKey: failure to roundtrip")
	}

	data, err = msk.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	c := &SystemSecretKey{}
	err = c.UnmarshalBinary(data)
	if err != nil {
		t.Fatal(err)
	}
	if !msk.Equal(c) {
		t.Fatal("MasterSecretKey: failure to roundtrip")
	}

	attrs := Attributes{}
	attrs.FromMap(map[string]string{"occupation": "doctor", "country": "US", "age": "16"})
	sk, err := msk.KeyGen(rand.Reader, attrs)
	if err != nil {
		t.Fatal(err)
	}

	data, err = sk.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	d := AttributeKey{} // don't use pointer to verify unmarshal works with both pointer and not
	err = d.UnmarshalBinary(data)
	if err != nil {
		t.Fatal(err)
	}
	if !sk.Equal(&d) {
		t.Fatal("SecretKey: failure to roundtrip")
	}
}

func TestMalformedCiphertext(t *testing.T) {
	pk, msk, err := Setup(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := Policy{}
	err = policy.FromString("a:1")
	if err != nil {
		t.Fatal(err)
	}
	attrs := Attributes{}
	attrs.FromMap(map[string]string{"a": "1"})
	sk, err := msk.KeyGen(rand.Reader, attrs)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("test")
	validCT, err := pk.Encrypt(rand.Reader, policy, msg)
	if err != nil {
		t.Fatal(err)
	}

	// Empty ciphertext must not panic.
	emptyAttrs := Attributes{}
	emptyAttrs.FromMap(map[string]string{})
	_ = emptyAttrs.CouldDecrypt([]byte{})
	if _, err := sk.Decrypt([]byte{}); err == nil {
		t.Fatal("empty ciphertext should fail to decrypt")
	}
	badPolicy := &Policy{}
	if err := badPolicy.ExtractFromCiphertext([]byte{}); err == nil {
		t.Fatal("empty ciphertext should fail extraction")
	}

	// Truncate the valid ciphertext at every byte and ensure no panic.
	// DecryptCCA must return an error for any truncation because it needs
	// the authentication tag, but CouldDecrypt and ExtractFromCiphertext
	// only need the header and may succeed if the truncation is in the
	// trailing tag/mac region.
	for i := 1; i < len(validCT); i++ {
		truncated := validCT[:i]
		_ = attrs.CouldDecrypt(truncated)
		if _, err := sk.Decrypt(truncated); err == nil {
			t.Fatalf("truncated ciphertext (len=%d) should fail to decrypt", i)
		}
		badPolicy = &Policy{}
		_ = badPolicy.ExtractFromCiphertext(truncated)
	}

	// Legacy format (no version prefix) with minimal data.
	legacyTruncated := []byte{0x00, 0x00}
	_ = attrs.CouldDecrypt(legacyTruncated)
	if _, err := sk.Decrypt(legacyTruncated); err == nil {
		t.Fatal("legacy truncated ciphertext should fail to decrypt")
	}
	badPolicy = &Policy{}
	if err := badPolicy.ExtractFromCiphertext(legacyTruncated); err == nil {
		t.Fatal("legacy truncated ciphertext should fail extraction")
	}

	// Version prefix with truncated remainder.
	versionPrefixed := append([]byte("v1.3.8"), []byte{0x00, 0x00}...)
	_ = attrs.CouldDecrypt(versionPrefixed)
	if _, err := sk.Decrypt(versionPrefixed); err == nil {
		t.Fatal("version-prefixed truncated ciphertext should fail to decrypt")
	}
	badPolicy = &Policy{}
	if err := badPolicy.ExtractFromCiphertext(versionPrefixed); err == nil {
		t.Fatal("version-prefixed truncated ciphertext should fail extraction")
	}
}

func TestPolicyMethods(t *testing.T) {
	policyStr := "(season: fall or season: winter) or (region: alaska and season: summer)"
	policy := Policy{}
	err := policy.FromString(policyStr)
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string][]string{
		"season": {"fall", "winter", "summer"},
		"region": {"alaska"},
	}
	received := policy.ExtractAttributeValuePairs()
	if len(expected) != len(received) {
		t.Fatal("diff lengths")
	}
	for k, vs := range expected {
		vs2, ok := received[k]
		if !ok {
			t.Fatalf("key %s not found in received map", k)
		}
		if len(vs) != len(vs2) {
			t.Fatalf("expected len: %d, received len: %d, for key %s", len(vs), len(vs2), k)
		}
		// compare each value for given key, order doesn't matter
		for _, v := range vs {
			flag := false
			for _, v2 := range vs2 {
				if v == v2 {
					flag = true
					break
				}
			}
			if !flag {
				t.Fatalf("expected and received values differ")
			}
		}
	}
}

func TestPolicyFromStringStackOverflow(t *testing.T) {
	// Regression test: 4 MB of '(' used to drive ~4,000,000 levels of
	// expression->or->and->not->primary recursion, exhausting the goroutine
	// stack and aborting the process with a fatal "stack overflow" error that
	// no recover() can catch. The parser now bounds its recursion depth and
	// returns an error instead.
	var p Policy
	if err := p.FromString(strings.Repeat("(", 4_000_000)); err == nil {
		t.Fatal("expected an error for an excessively nested policy, got nil")
	}
}

func TestCouldDecryptPanicsOnOversizedWireList(t *testing.T) {
	le16 := func(n int) []byte {
		b := make([]byte, 2)
		binary.LittleEndian.PutUint16(b, uint16(n))
		return b
	}
	pre := func(b []byte) []byte { return append(le16(len(b)), b...) }

	// One serialized Wire: label "x", empty raw value, 32-byte zero scalar, positive.
	wire := append(pre([]byte("x")), pre([]byte{})...)
	wire = append(wire, le16(32)...)
	wire = append(wire, make([]byte, 32)...)
	wire = append(wire, 1)

	// Formula with zero gates (2 bytes: n=0).
	formula := le16(0)

	// Policy: 0-gate formula plus THREE wires. After the BK transform the formula
	// has one gate (wire slots 0,1,2) but the appended BK wire sits at index 3.
	policy := pre(formula)
	policy = append(policy, le16(3)...)
	for i := 0; i < 3; i++ {
		policy = append(policy, pre(wire)...)
	}

	// c1: an empty (0x0) matrixG2 -- 4 zero bytes, accepted by unmarshalBinary.
	c1 := []byte{0, 0, 0, 0}

	// Ciphertext header C1: lenPrefixed(policy) || lenPrefixed(c1) || c2Len=0 || c3Len=0
	c1Hdr := append(pre(policy), pre(c1)...)
	c1Hdr = append(c1Hdr, le16(0)...)
	c1Hdr = append(c1Hdr, le16(0)...)

	macData := pre(c1Hdr)
	macData = append(macData, pre(make([]byte, 100))...) // env (needed for the Decrypt path)

	// Legacy (pre-v1.3.8) outer format: lenPrefixed(id) || lenPrefixed(macData) || lenPrefixed(tag)
	ct := pre(make([]byte, 32))
	ct = append(ct, pre(macData)...)
	ct = append(ct, pre([]byte{})...)

	attrs := Attributes{}
	attrs.FromMap(map[string]string{"country": "US"})

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("CouldDecrypt panicked on attacker-controlled ciphertext: %v", r)
		}
	}()
	if attrs.CouldDecrypt(ct) {
		t.Fatal("malformed ciphertext should not be decryptable")
	}
}

// truncateCiphertextHeader takes a legitimate v1.3.8 ciphertext and surgically
// truncates the inner C1 header right after the (structurally valid) policy and
// c1 fields, dropping the c2 count and everything after it. The outer envelope
// is reassembled with corrected length prefixes. Such a header leaves zero bytes
// where ciphertextHeader.unmarshalBinary reads the c2 element count, which must
// be rejected with an error rather than an out-of-range panic.
func truncateCiphertextHeader(t *testing.T, ct []byte) []byte {
	t.Helper()

	// Ciphertext layout (v1.3.8):
	//   "v1.3.8" || len16(id) || len32(macData) || len16(tag)
	//   macData = len32(C1) || len32(env)
	//   C1      = len16(policy) || len16(c1) || u16(c2Len) || ... || u16(c3Len) || ...
	const version = "v1.3.8"
	rest := ct[len(version):]
	idLen := int(binary.LittleEndian.Uint16(rest))
	id := rest[2 : 2+idLen]
	rest = rest[2+idLen:]
	macLen := int(binary.LittleEndian.Uint32(rest))
	macData := rest[4 : 4+macLen]
	rest = rest[4+macLen:]
	tagLen := int(binary.LittleEndian.Uint16(rest))
	tag := rest[2 : 2+tagLen]

	c1Len := int(binary.LittleEndian.Uint32(macData))
	C1 := macData[4 : 4+c1Len]
	envWithPrefix := macData[4+c1Len:]

	// Truncate C1 right after the (still valid) policy and c1 fields,
	// dropping the c2 count and everything after it.
	pLen := int(binary.LittleEndian.Uint16(C1))
	off := 2 + pLen
	c1bLen := int(binary.LittleEndian.Uint16(C1[off:]))
	off += 2 + c1bLen
	truncC1 := C1[:off]

	// Reassemble the outer ciphertext around the truncated header.
	newMac := make([]byte, 4, 4+len(truncC1)+len(envWithPrefix))
	binary.LittleEndian.PutUint32(newMac, uint32(len(truncC1)))
	newMac = append(newMac, truncC1...)
	newMac = append(newMac, envWithPrefix...)

	evil := append([]byte{}, []byte(version)...)
	evil = append(evil, 0, 0)
	binary.LittleEndian.PutUint16(evil[len(evil)-2:], uint16(len(id)))
	evil = append(evil, id...)
	evil = append(evil, 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(evil[len(evil)-4:], uint32(len(newMac)))
	evil = append(evil, newMac...)
	evil = append(evil, 0, 0)
	binary.LittleEndian.PutUint16(evil[len(evil)-2:], uint16(len(tag)))
	evil = append(evil, tag...)
	return evil
}

// TestTruncatedCiphertextHeaderPanic guards against a denial-of-service in
// ciphertextHeader.unmarshalBinary: a ciphertext truncated right after the
// policy and c1 fields must fail gracefully (returning an error / false) on all
// three public entrypoints rather than panicking.
func TestTruncatedCiphertextHeaderPanic(t *testing.T) {
	pk, msk, err := Setup(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := Policy{}
	if err = policy.FromString("(country: US) and (top: secret)"); err != nil {
		t.Fatal(err)
	}
	ct, err := pk.Encrypt(rand.Reader, policy, []byte("hello world"))
	if err != nil {
		t.Fatal(err)
	}

	attrs := Attributes{}
	attrs.FromMap(map[string]string{"country": "US", "top": "secret"})
	key, err := msk.KeyGen(rand.Reader, attrs)
	if err != nil {
		t.Fatal(err)
	}

	evil := truncateCiphertextHeader(t, ct)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("truncated ciphertext header panicked instead of returning an error: %v", r)
		}
	}()

	// Policy.ExtractFromCiphertext must return an error, not panic.
	extracted := &Policy{}
	if err := extracted.ExtractFromCiphertext(evil); err == nil {
		t.Error("ExtractFromCiphertext accepted a malformed ciphertext")
	}

	// Attributes.CouldDecrypt must return false, not panic.
	if attrs.CouldDecrypt(evil) {
		t.Error("CouldDecrypt accepted a malformed ciphertext")
	}

	// AttributeKey.Decrypt must return an error, not panic.
	if _, err := key.Decrypt(evil); err == nil {
		t.Error("Decrypt accepted a malformed ciphertext")
	}
}
