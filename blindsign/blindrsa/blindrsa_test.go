package blindrsa

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"testing"

	"github.com/cloudflare/circl/blindsign"
)

// 4096-bit RSA private key
const testPrivateKey = `
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`

func loadPrivateKey(t *testing.T) *rsa.PrivateKey {
	block, _ := pem.Decode([]byte(testPrivateKey))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		t.Fatal("PEM private key decoding failed")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	return privateKey
}

func runSignatureProtocol(signer RSASigner, verifier blindsign.Verifier, message []byte, random io.Reader) ([]byte, error) {
	blindedMsg, state, err := verifier.Blind(random, message)
	if err != nil {
		return nil, err
	}

	kLen := (signer.sk.N.BitLen() + 7) / 8
	if len(blindedMsg) != kLen {
		return nil, fmt.Errorf("Protocol message (blind message) length mismatch, expected %d, got %d", kLen, len(blindedMsg))
	}

	blindedSig, err := signer.BlindSign(blindedMsg)
	if err != nil {
		return nil, err
	}

	if len(blindedSig) != kLen {
		return nil, fmt.Errorf("Protocol message (blind signature) length mismatch, expected %d, got %d", kLen, len(blindedMsg))
	}

	sig, err := state.Finalize(blindedSig)
	if err != nil {
		return nil, err
	}

	err = verifier.Verify(message, sig)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

func TestRoundTrip(t *testing.T) {
	message := []byte("hello world")
	key := loadPrivateKey(t)

	verifier := NewRSAVerifier(&key.PublicKey, crypto.SHA512)
	signer := NewRSASigner(key)

	sig, err := runSignatureProtocol(signer, verifier, message, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if sig == nil {
		t.Fatal("nil signature output")
	}
}

func TestDeterministicRoundTrip(t *testing.T) {
	message := []byte("hello world")
	key := loadPrivateKey(t)

	verifier := NewDeterministicRSAVerifier(&key.PublicKey, crypto.SHA512)
	signer := NewRSASigner(key)

	sig, err := runSignatureProtocol(signer, verifier, message, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if sig == nil {
		t.Fatal("nil signature output")
	}
}

func TestDeterministicBlindFailure(t *testing.T) {
	message := []byte("hello world")
	key := loadPrivateKey(t)

	verifier := NewDeterministicRSAVerifier(&key.PublicKey, crypto.SHA512)
	signer := NewRSASigner(key)

	_, err := runSignatureProtocol(signer, verifier, message, nil)
	if err == nil {
		t.Fatal("Expected signature generation to fail with empty randomness")
	}
}

func TestRandomSignVerify(t *testing.T) {
	message := []byte("hello world")
	key := loadPrivateKey(t)

	verifier := NewRSAVerifier(&key.PublicKey, crypto.SHA512)
	signer := NewRSASigner(key)

	sig1, err := runSignatureProtocol(signer, verifier, message, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sig2, err := runSignatureProtocol(signer, verifier, message, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if sig1 == nil || sig2 == nil {
		t.Fatal("nil signature output")
	}
	if bytes.Equal(sig1, sig2) {
		t.Fatal("random signatures matched when they should differ")
	}
}

type mockRandom struct {
	counter uint8
}

func (r *mockRandom) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = r.counter
		r.counter = r.counter + 1
	}
	return len(p), nil
}

func TestFixedRandomSignVerify(t *testing.T) {
	message := []byte("hello world")
	key := loadPrivateKey(t)

	verifier := NewRSAVerifier(&key.PublicKey, crypto.SHA512)
	signer := NewRSASigner(key)

	mockRand := &mockRandom{0}
	sig1, err := runSignatureProtocol(signer, verifier, message, mockRand)
	if err != nil {
		t.Fatal(err)
	}
	mockRand = &mockRandom{0}
	sig2, err := runSignatureProtocol(signer, verifier, message, mockRand)
	if err != nil {
		t.Fatal(err)
	}

	if sig1 == nil || sig2 == nil {
		t.Fatal("nil signature output")
	}
	if !bytes.Equal(sig1, sig2) {
		t.Fatal("random signatures with fixed random seeds differ when they should be equal")
	}
}

type rawTestVector struct {
	P              string `json:"p"`
	Q              string `json:"q"`
	N              string `json:"n"`
	E              string `json:"e"`
	D              string `json:"d"`
	Msg            string `json:"msg"`
	Salt           string `json:"salt"`
	Inv            string `json:"inv"`
	EncodedMsg     string `json:"encoded_msg"`
	BlindedMessage string `json:"blinded_message"`
	BlindSig       string `json:"blind_sig"`
	Sig            string `json:"sig"`
}

type testVector struct {
	t              *testing.T
	p              *big.Int
	q              *big.Int
	n              *big.Int
	e              int
	d              *big.Int
	msg            []byte
	salt           []byte
	blindInverse   *big.Int
	encodedMessage []byte
	blindedMessage []byte
	blindSig       []byte
	sig            []byte
}

type testVectorList struct {
	t       *testing.T
	vectors []testVector
}

func mustUnhexBigInt(number string) *big.Int {
	data, err := hex.DecodeString(number)
	if err != nil {
		panic(err)
	}

	value := new(big.Int)
	value.SetBytes(data)
	return value
}

func mustUnhex(value string) []byte {
	data, err := hex.DecodeString(value)
	if err != nil {
		panic(err)
	}

	return data
}

func mustUnhexInt(value string) int {
	number := mustUnhexBigInt(value)
	result := int(number.Int64())
	return result
}

func (tv *testVector) UnmarshalJSON(data []byte) error {
	raw := rawTestVector{}
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	tv.p = mustUnhexBigInt(raw.P)
	tv.q = mustUnhexBigInt(raw.Q)
	tv.n = mustUnhexBigInt(raw.N)
	tv.e = mustUnhexInt(raw.E)
	tv.d = mustUnhexBigInt(raw.D)
	tv.msg = mustUnhex(raw.Msg)
	tv.salt = mustUnhex(raw.Salt)
	tv.encodedMessage = mustUnhex(raw.EncodedMsg)
	tv.blindedMessage = mustUnhex(raw.BlindedMessage)
	tv.blindInverse = mustUnhexBigInt(raw.Inv)
	tv.blindSig = mustUnhex(raw.BlindSig)
	tv.sig = mustUnhex(raw.Sig)

	return nil
}

func (tvl testVectorList) MarshalJSON() ([]byte, error) {
	return json.Marshal(tvl.vectors)
}

func (tvl *testVectorList) UnmarshalJSON(data []byte) error {
	err := json.Unmarshal(data, &tvl.vectors)
	if err != nil {
		return err
	}

	for i := range tvl.vectors {
		tvl.vectors[i].t = tvl.t
	}

	return nil
}

func verifyTestVector(t *testing.T, vector testVector) {
	key := loadPrivateKey(t)
	key.PublicKey.N = vector.n
	key.PublicKey.E = vector.e
	key.D = vector.d
	key.Primes[0] = vector.p
	key.Primes[1] = vector.q
	key.Precomputed.Dp = nil // Remove precomputed CRT values

	// Recompute the original blind
	rInv := new(big.Int).Set(vector.blindInverse)
	r := new(big.Int).ModInverse(rInv, key.N)
	if r == nil {
		t.Fatal("Failed to compute blind inverse")
	}

	signer := NewRSASigner(key)
	verifier := NewRSAVerifier(&key.PublicKey, crypto.SHA384)

	blindedMsg, state, err := fixedBlind(vector.msg, vector.salt, r, rInv, verifier.pk, verifier.hash)
	if err != nil {
		t.Fatal(err)
	}

	blindSig, err := signer.BlindSign(blindedMsg)
	if err != nil {
		t.Fatal(err)
	}

	sig, err := state.Finalize(blindSig)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(state.(RSAVerifierState).encodedMsg, vector.encodedMessage) {
		t.Errorf("Encoded message mismatch: expected %x, got %x", state.(RSAVerifierState).encodedMsg, vector.encodedMessage)
	}

	if !bytes.Equal(sig, vector.sig) {
		t.Errorf("Signature mismatch: expected %x, got %x", sig, vector.sig)
	}
}

func TestVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/test_vectors.json")
	if err != nil {
		t.Fatal("Failed reading test vectors:", err)
	}

	tvl := &testVectorList{}
	err = tvl.UnmarshalJSON(data)
	if err != nil {
		t.Fatal("Failed deserializing test vectors:", err)
	}

	for _, vector := range tvl.vectors {
		verifyTestVector(t, vector)
	}
}
