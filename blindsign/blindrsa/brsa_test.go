package blindrsa

import (
	"bytes"
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
	"strings"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func loadPrivateKey() (*rsa.PrivateKey, error) {
	file, err := os.ReadFile("./testdata/testRSA2048.rfc9500.pem")
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(file)
	if block == nil || block.Type != "RSA TESTING KEY" {
		return nil, fmt.Errorf("PEM private key decoding failed")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func mustDecodeHex(h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	return b
}

func loadStrongRSAKey() *rsa.PrivateKey {
	// https://gist.github.com/chris-wood/b77536febb25a5a11af428afff77820a
	pEnc := "dcd90af1be463632c0d5ea555256a20605af3db667475e190e3af12a34a3324c46a3094062c59fb4b249e0ee6afba8bee14e0276d126c99f4784b23009bf6168ff628ac1486e5ae8e23ce4d362889de4df63109cbd90ef93db5ae64372bfe1c55f832766f21e94ea3322eb2182f10a891546536ba907ad74b8d72469bea396f3"
	qEnc := "f8ba5c89bd068f57234a3cf54a1c89d5b4cd0194f2633ca7c60b91a795a56fa8c8686c0e37b1c4498b851e3420d08bea29f71d195cfbd3671c6ddc49cf4c1db5b478231ea9d91377ffa98fe95685fca20ba4623212b2f2def4da5b281ed0100b651f6db32112e4017d831c0da668768afa7141d45bbc279f1e0f8735d74395b3"
	NEnc := "d6930820f71fe517bf3259d14d40209b02a5c0d3d61991c731dd7da39f8d69821552e2318d6c9ad897e603887a476ea3162c1205da9ac96f02edf31df049bd55f142134c17d4382a0e78e275345f165fbe8e49cdca6cf5c726c599dd39e09e75e0f330a33121e73976e4facba9cfa001c28b7c96f8134f9981db6750b43a41710f51da4240fe03106c12acb1e7bb53d75ec7256da3fddd0718b89c365410fce61bc7c99b115fb4c3c318081fa7e1b65a37774e8e50c96e8ce2b2cc6b3b367982366a2bf9924c4bafdb3ff5e722258ab705c76d43e5f1f121b984814e98ea2b2b8725cd9bc905c0bc3d75c2a8db70a7153213c39ae371b2b5dc1dafcb19d6fae9"
	eEnc := "010001"
	dEnc := "4e21356983722aa1adedb084a483401c1127b781aac89eab103e1cfc52215494981d18dd8028566d9d499469c25476358de23821c78a6ae43005e26b394e3051b5ca206aa9968d68cae23b5affd9cbb4cb16d64ac7754b3cdba241b72ad6ddfc000facdb0f0dd03abd4efcfee1730748fcc47b7621182ef8af2eeb7c985349f62ce96ab373d2689baeaea0e28ea7d45f2d605451920ca4ea1f0c08b0f1f6711eaa4b7cca66d58a6b916f9985480f90aca97210685ac7b12d2ec3e30a1c7b97b65a18d38a93189258aa346bf2bc572cd7e7359605c20221b8909d599ed9d38164c9c4abf396f897b9993c1e805e574d704649985b600fa0ced8e5427071d7049d"

	p := new(big.Int).SetBytes(mustDecodeHex(pEnc))
	q := new(big.Int).SetBytes(mustDecodeHex(qEnc))
	N := new(big.Int).SetBytes(mustDecodeHex(NEnc))
	e := new(big.Int).SetBytes(mustDecodeHex(eEnc))
	d := new(big.Int).SetBytes(mustDecodeHex(dEnc))

	primes := make([]*big.Int, 2)
	primes[0] = p
	primes[1] = q

	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: N,
			E: int(e.Int64()),
		},
		D:      d,
		Primes: primes,
	}

	return key
}

func runSignatureProtocol(signer Signer, client Client, message []byte, random io.Reader) ([]byte, error) {
	inputMsg, err := client.Prepare(random, message)
	if err != nil {
		return nil, fmt.Errorf("prepare failed: %w", err)
	}

	blindedMsg, state, err := client.Blind(random, inputMsg)
	if err != nil {
		return nil, fmt.Errorf("blind failed: %w", err)
	}

	kLen := (signer.sk.N.BitLen() + 7) / 8
	if len(blindedMsg) != kLen {
		return nil, fmt.Errorf("Protocol message (blind message) length mismatch, expected %d, got %d", kLen, len(blindedMsg))
	}

	blindedSig, err := signer.BlindSign(blindedMsg)
	if err != nil {
		return nil, fmt.Errorf("blindSign failed: %w", err)
	}

	if len(blindedSig) != kLen {
		return nil, fmt.Errorf("Protocol message (blind signature) length mismatch, expected %d, got %d", kLen, len(blindedMsg))
	}

	sig, err := client.Finalize(state, blindedSig)
	if err != nil {
		return nil, fmt.Errorf("finalize failed: %w", err)
	}

	err = client.Verify(inputMsg, sig)
	if err != nil {
		return nil, fmt.Errorf("verification failed: %w", err)
	}

	return sig, nil
}

func TestRoundTrip(t *testing.T) {
	message := []byte("hello world")
	key, err := loadPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	for _, variant := range []Variant{
		SHA384PSSDeterministic,
		SHA384PSSZeroDeterministic,
		SHA384PSSRandomized,
		SHA384PSSZeroRandomized,
	} {
		t.Run(variant.String(), func(tt *testing.T) {
			client, err := NewClient(variant, &key.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			signer := NewSigner(key)

			sig, err := runSignatureProtocol(signer, client, message, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			if sig == nil {
				t.Fatal("nil signature output")
			}
		})
	}
}

func TestDeterministicRoundTrip(t *testing.T) {
	message := []byte("hello world")
	key, err := loadPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	client, err := NewClient(SHA384PSSDeterministic, &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	signer := NewSigner(key)

	sig, err := runSignatureProtocol(signer, client, message, rand.Reader)
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

	client, err := NewClient(SHA384PSSDeterministic, &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	signer := NewSigner(key)

	_, err = runSignatureProtocol(signer, client, message, nil)
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

	client, err := NewClient(SHA384PSSRandomized, &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	signer := NewSigner(key)

	sig1, err := runSignatureProtocol(signer, client, message, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sig2, err := runSignatureProtocol(signer, client, message, rand.Reader)
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

	client, err := NewClient(SHA384PSSRandomized, &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	signer := NewSigner(key)

	mockRand := &mockRandom{0}
	sig1, err := runSignatureProtocol(signer, client, message, mockRand)
	if err != nil {
		t.Fatal(err)
	}
	mockRand = &mockRandom{0}
	sig2, err := runSignatureProtocol(signer, client, message, mockRand)
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
	Name           string `json:"name"`
	P              string `json:"p"`
	Q              string `json:"q"`
	N              string `json:"n"`
	E              string `json:"e"`
	D              string `json:"d"`
	Msg            string `json:"msg"`
	MsgPrefix      string `json:"msg_prefix"`
	InputMsg       string `json:"input_msg"`
	Salt           string `json:"salt"`
	SaltLen        string `json:"sLen"`
	IsRandomized   string `json:"is_randomized"`
	Inv            string `json:"inv"`
	BlindedMessage string `json:"blinded_msg"`
	BlindSig       string `json:"blind_sig"`
	Sig            string `json:"sig"`
}

type testVector struct {
	t              *testing.T
	name           string
	p              *big.Int
	q              *big.Int
	n              *big.Int
	e              int
	d              *big.Int
	msg            []byte
	msgPrefix      []byte
	inputMsg       []byte
	salt           []byte
	saltLen        int
	isRandomized   bool
	blindInverse   *big.Int
	blindedMessage []byte
	blindSig       []byte
	sig            []byte
}

type testVectorList struct {
	t       *testing.T
	vectors []testVector
}

func mustUnhexBigInt(number string) *big.Int {
	data := mustUnhex(number)
	value := new(big.Int)
	value.SetBytes(data)
	return value
}

func mustUnhex(value string) []byte {
	value = strings.TrimPrefix(value, "0x")
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

	tv.name = raw.Name
	tv.p = mustUnhexBigInt(raw.P)
	tv.q = mustUnhexBigInt(raw.Q)
	tv.n = mustUnhexBigInt(raw.N)
	tv.e = mustUnhexInt(raw.E)
	tv.d = mustUnhexBigInt(raw.D)
	tv.msg = mustUnhex(raw.Msg)
	tv.msgPrefix = mustUnhex(raw.MsgPrefix)
	tv.inputMsg = mustUnhex(raw.InputMsg)
	tv.salt = mustUnhex(raw.Salt)
	tv.saltLen = mustUnhexInt(raw.SaltLen)
	tv.isRandomized = mustUnhexInt(raw.IsRandomized) != 0
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
	key := new(rsa.PrivateKey)
	key.PublicKey.N = vector.n
	key.PublicKey.E = vector.e
	key.D = vector.d
	key.Primes = []*big.Int{vector.p, vector.q}
	key.Precomputed.Dp = nil // Remove precomputed CRT values

	// Recompute the original blind
	rInv := new(big.Int).Set(vector.blindInverse)
	r := new(big.Int).ModInverse(rInv, key.N)
	if r == nil {
		t.Fatal("Failed to compute blind inverse")
	}

	var variant Variant
	switch vector.name {
	case "RSABSSA-SHA384-PSS-Deterministic":
		variant = SHA384PSSDeterministic
	case "RSABSSA-SHA384-PSSZERO-Deterministic":
		variant = SHA384PSSZeroDeterministic
	case "RSABSSA-SHA384-PSS-Randomized":
		variant = SHA384PSSRandomized
	case "RSABSSA-SHA384-PSSZERO-Randomized":
		variant = SHA384PSSZeroRandomized
	default:
		t.Fatal("variant not supported")
	}

	signer := NewSigner(key)

	client, err := NewClient(variant, &key.PublicKey)
	test.CheckNoErr(t, err, "new client failed")

	blindedMsg, state, err := client.fixedBlind(vector.inputMsg, vector.salt, r, rInv)
	test.CheckNoErr(t, err, "fixedBlind failed")
	got := hex.EncodeToString(blindedMsg)
	want := hex.EncodeToString(vector.blindedMessage)
	if got != want {
		test.ReportError(t, got, want)
	}

	blindSig, err := signer.BlindSign(blindedMsg)
	test.CheckNoErr(t, err, "blindSign failed")
	got = hex.EncodeToString(blindSig)
	want = hex.EncodeToString(vector.blindSig)
	if got != want {
		test.ReportError(t, got, want)
	}

	sig, err := client.Finalize(state, blindSig)
	test.CheckNoErr(t, err, "finalize failed")
	got = hex.EncodeToString(sig)
	want = hex.EncodeToString(vector.sig)
	if got != want {
		test.ReportError(t, got, want)
	}

	verifier, err := NewVerifier(variant, &key.PublicKey)
	test.CheckNoErr(t, err, "new verifier failed")

	test.CheckNoErr(t, verifier.Verify(vector.inputMsg, sig), "verification failed")
}

func TestVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/test_vectors_rfc9474.json")
	if err != nil {
		t.Fatal("Failed reading test vectors:", err)
	}

	tvl := &testVectorList{}
	err = tvl.UnmarshalJSON(data)
	if err != nil {
		t.Fatal("Failed deserializing test vectors:", err)
	}

	for _, vector := range tvl.vectors {
		t.Run(vector.name, func(tt *testing.T) {
			verifyTestVector(tt, vector)
		})
	}
}

func BenchmarkBRSA(b *testing.B) {
	message := []byte("hello world")
	key := loadStrongRSAKey()
	server := NewSigner(key)

	client, err := NewClient(SHA384PSSRandomized, &key.PublicKey)
	if err != nil {
		b.Fatal(err)
	}

	inputMsg, err := client.Prepare(rand.Reader, message)
	if err != nil {
		b.Errorf("prepare failed: %v", err)
	}

	blindedMsg, state, err := client.Blind(rand.Reader, inputMsg)
	if err != nil {
		b.Errorf("blind failed: %v", err)
	}

	blindedSig, err := server.BlindSign(blindedMsg)
	if err != nil {
		b.Errorf("blindSign failed: %v", err)
	}

	sig, err := client.Finalize(state, blindedSig)
	if err != nil {
		b.Errorf("finalize failed: %v", err)
	}

	err = client.Verify(inputMsg, sig)
	if err != nil {
		b.Errorf("verification failed: %v", err)
	}

	b.Run("Blind", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, _, err := client.Blind(rand.Reader, inputMsg)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("BlindSign", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, err := server.BlindSign(blindedMsg)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Finalize", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, err := client.Finalize(state, blindedSig)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Verify", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			err := client.Verify(inputMsg, sig)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func Example_blindrsa() {
	// Setup (offline)

	// Server: generate an RSA keypair.
	sk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("failed to generate RSA key: %v", err)
		return
	}
	pk := &sk.PublicKey
	server := NewSigner(sk)

	// Client: stores Server's public key.
	client, err := NewClient(SHA384PSSRandomized, pk)
	if err != nil {
		fmt.Printf("failed to invoke a client: %v", err)
		return
	}

	// Protocol (online)

	// Client prepares the message to be signed.
	msg := []byte("alice and bob")
	preparedMessage, err := client.Prepare(rand.Reader, msg)
	if err != nil {
		fmt.Printf("client failed to prepare the message: %v", err)
		return
	}

	// Client blinds a message.
	blindedMsg, state, err := client.Blind(rand.Reader, preparedMessage)
	if err != nil {
		fmt.Printf("client failed to generate blinded message: %v", err)
		return
	}

	// Server signs a blinded message, and produces a blinded signature.
	blindedSignature, err := server.BlindSign(blindedMsg)
	if err != nil {
		fmt.Printf("server failed to sign: %v", err)
		return
	}

	// Client build a signature from the previous state and blinded signature.
	signature, err := client.Finalize(state, blindedSignature)
	if err != nil {
		fmt.Printf("client failed to obtain signature: %v", err)
		return
	}

	// Client build a signature from the previous state and blinded signature.
	ok := client.Verify(preparedMessage, signature)

	fmt.Printf("Valid signature: %v", ok == nil)
	// Output: Valid signature: true
}
