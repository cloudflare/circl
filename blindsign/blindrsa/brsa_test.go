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
)

// 2048-bit RSA private key
const testPrivateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAyxrta2qV9bHOATpM/KsluUsuZKIwNOQlCn6rQ8DfOowSmTrx
KxEZCNS0cb7DHUtsmtnN2pBhKi7pA1I+beWiJNawLwnlw3TQz+Adj1KcUAp4ovZ5
CPpoK1orQwyB6vGvcte155T8mKMTknaHl1fORTtSbvm/bOuZl5uEI7kPRGGiKvN6
qwz1cz91l6vkTTHHMttooYHGy75gfYwOUuBlX9mZbcWE7KC+h6+814ozfRex26no
KLvYHikTFxROf/ifVWGXCbCWy7nqR0zq0mTCBz/kl0DAHwDhCRBgZpg9IeX4Pwhu
LoI8h5zUPO9wDSo1Kpur1hLQPK0C2xNLfiJaXwIDAQABAoIBAC8wm3c4tYz3efDJ
Ffgi38n0kNvq3x5636xXj/1XA8a7otqdWklyWIm3uhEvjG/zBVHZRz4AC8NcUOFn
q3+nOgwrIZZcS1klfBrAbL3PKOhj9nGOqMKQQ8HG2oRilJD9BJG/UtFyyVnBkhuW
lJxyV0e4p8eHGZX6C56xEHuoVMbDKm9HR8XRwwTHRn1VsICqIzo6Uv/fJhFMu1Qf
+mtpa3oJb43P9pygirWO+w+3U6pRhccwAWlrvOjAmeP0Ndy7/gXn26rSPbKmWcI6
3VIUB/FQsa8tkFTEFkIp1oQLejKk+EgUk66JWc8K6o3vDDyfdbmjTHVxi3ByyNur
F87+ykkCgYEA73MLD1FLwPWdmV/V+ZiMTEwTXRBc1W1D7iigNclp9VDAzXFI6ofs
3v+5N8hcZIdEBd9W6utHi/dBiEogDuSjljPRCqPsQENm2itTHzmNRvvI8wV1KQbP
eJOd0vPMl5iup8nYL+9ASfGYeX5FKlttKEm4ZIY0XUsx9pERoq4PlEsCgYEA2STJ
68thMWv9xKuz26LMQDzImJ5OSQD0hsts9Ge01G/rh0Dv/sTzO5wtLsiyDA/ZWkzB
8J+rO/y2xqBD9VkYKaGB/wdeJP0Z+n7sETetiKPbXPfgAi7VAe77Rmst/oEcGLUg
tm+XnfJSInoLU5HmtIdLg0kcQLVbN5+ZMmtkPb0CgYBSbhczmbfrYGJ1p0FBIFvD
9DiCRBzBOFE3TnMAsSqx0a/dyY7hdhN8HSqE4ouz68DmCKGiU4aYz3CW23W3ysvp
7EKdWBr/cHSazGlcCXLyKcFer9VKX1bS2nZtZZJb6arOhjTPI5zNF8d2o5pp33lv
chlxOaYTK8yyZfRdPXCNiwKBgQDV77oFV66dm7E9aJHerkmgbIKSYz3sDUXd3GSv
c9Gkj9Q0wNTzZKXkMB4P/un0mlTh88gMQ7PYeUa28UWjX7E/qwFB+8dUmA1VUGFT
IVEW06GXuhv46p0wt3zXx1dcbWX6LdJaDB4MHqevkiDAqHntmXLbmVd9pXCGn/a2
xznO3QKBgHkPJPEiCzRugzgN9UxOT5tNQCSGMOwJUd7qP0TWgvsWHT1N07JLgC8c
Yg0f1rCxEAQo5BVppiQFp0FA7W52DUnMEfBtiehZ6xArW7crO91gFRqKBWZ3Jjyz
/JcS8m5UgQxC8mmb/2wLD5TDvWw+XCfjUgWmvqIi5dcJgmuTAn5X
-----END RSA PRIVATE KEY-----`

func loadPrivateKey() (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(testPrivateKey))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("PEM private key decoding failed")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func runSignatureProtocol(signer BRSASigner, verifier BRSAVerifier, message []byte, random io.Reader) ([]byte, error) {
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
	key, err := loadPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	verifier := NewBRSAVerifier(&key.PublicKey, crypto.SHA512)
	signer := NewBRSASigner(key)

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
	key, err := loadPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	verifier := NewDeterministicBRSAVerifier(&key.PublicKey, crypto.SHA512)
	signer := NewBRSASigner(key)

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
	key, err := loadPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	verifier := NewDeterministicBRSAVerifier(&key.PublicKey, crypto.SHA512)
	signer := NewBRSASigner(key)

	_, err = runSignatureProtocol(signer, verifier, message, nil)
	if err == nil {
		t.Fatal("Expected signature generation to fail with empty randomness")
	}
}

func TestRandomSignVerify(t *testing.T) {
	message := []byte("hello world")
	key, err := loadPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	verifier := NewBRSAVerifier(&key.PublicKey, crypto.SHA512)
	signer := NewBRSASigner(key)

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
	key, err := loadPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	verifier := NewBRSAVerifier(&key.PublicKey, crypto.SHA512)
	signer := NewBRSASigner(key)

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
	key, err := loadPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

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

	signer := NewBRSASigner(key)
	verifier := NewBRSAVerifier(&key.PublicKey, crypto.SHA384)

	blindedMsg, state, err := fixedBlind(vector.msg, vector.salt, r, rInv, verifier.PublicKey(), verifier.Hash())
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

	if !bytes.Equal(state.encodedMsg, vector.encodedMessage) {
		t.Errorf("Encoded message mismatch: expected %x, got %x", state.encodedMsg, vector.encodedMessage)
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

func BenchmarkBRSA(b *testing.B) {
	message := []byte("hello world")
	key, err := loadStrongRSAKey()
	if err != nil {
		b.Fatal(err)
	}

	verifier := NewBRSAVerifier(&key.PublicKey, crypto.SHA512)
	signer := NewBRSASigner(key)

	var blindedMsg []byte
	var state BRSAVerifierState
	b.Run("Blind", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			blindedMsg, state, err = verifier.Blind(rand.Reader, message)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	var blindedSig []byte
	b.Run("BlindSign", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			blindedSig, err = signer.BlindSign(blindedMsg)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	var sig []byte
	b.Run("Finalize", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			sig, err = state.Finalize(blindedSig)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	err = verifier.Verify(message, sig)
	if err != nil {
		b.Fatal(err)
	}
}
