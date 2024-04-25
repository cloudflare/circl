package tkn20

import (
	"os"
	"testing"
)

func TestPublicKeyFormat(t *testing.T) {
	paramsData, err := os.ReadFile("testdata/publicKey")
	if err != nil {
		t.Fatalf("Unable to read public key")
	}
	pp := &PublicKey{}
	err = pp.UnmarshalBinary(paramsData)
	if err != nil {
		t.Fatalf("unable to parse public key")
	}
}

func TestSystemSecretKeyFormat(t *testing.T) {
	secret, err := os.ReadFile("testdata/secretKey")
	if err != nil {
		t.Fatalf("Unable to read secret key")
	}
	sk := &SystemSecretKey{}
	err = sk.UnmarshalBinary(secret)
	if err != nil {
		t.Fatalf("unable to parse system secret key")
	}
}

func TestAttributeKeyFormat(t *testing.T) {
	attributeKey, err := os.ReadFile("testdata/attributeKey")
	if err != nil {
		t.Fatalf("Unable to read secret key")
	}
	sk := &AttributeKey{}
	err = sk.UnmarshalBinary(attributeKey)
	if err != nil {
		t.Fatalf("unable to parse secret key")
	}
}

func TestCiphertext_v137(t *testing.T) {
	// As of v1.3.8 ciphertext format changed to use wider prefixes.
	// Ciphertexts in the previous format are still decryptable.
	// The following functions are backwards-compatible:
	// - AttributeKey.Decrypt
	// - Attributes.CouldDecrypt
	// - Policy.ExtractFromCiphertext
	testCiphertext(t, "testdata/ciphertext_v137")
}

func TestCiphertext(t *testing.T) {
	testCiphertext(t, "testdata/ciphertext")
}

func testCiphertext(t *testing.T, ctName string) {
	t.Logf("Checking ciphertext: %v\n", ctName)
	ciphertext, err := os.ReadFile(ctName)
	if err != nil {
		t.Fatalf("Unable to read ciphertext data")
	}
	attributeKey, err := os.ReadFile("testdata/attributeKey")
	if err != nil {
		t.Fatalf("Unable to read secret key")
	}
	sk := AttributeKey{}
	err = sk.UnmarshalBinary(attributeKey)
	if err != nil {
		t.Fatalf("unable to parse secret key")
	}
	attrs := Attributes{}
	attrs.FromMap(map[string]string{"country": "NL", "EU": "true"})
	if !attrs.CouldDecrypt(ciphertext) {
		t.Fatal("these attributes will be unable to decrypt message")
	}
	policy := Policy{}
	err = policy.FromString("EU: true")
	if err != nil {
		t.Fatal("error creating policy from string")
	}
	gotPolicy := new(Policy)
	err = gotPolicy.ExtractFromCiphertext(ciphertext)
	if err != nil {
		t.Fatal("error extracting policy from ciphertext")
	}
	if !policy.Equal(gotPolicy) {
		t.Fatal("ciphertext's policy mismatches the original policy")
	}
	msg, err := sk.Decrypt(ciphertext)
	if err != nil {
		t.Fatal("unable to decrypt message")
	}
	if string(msg) != "Be sure to drink your ovaltine!" {
		t.Fatal("message incorrect")
	}
}
