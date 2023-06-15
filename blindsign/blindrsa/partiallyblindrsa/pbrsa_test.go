package partiallyblindrsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"testing"

	"github.com/cloudflare/circl/blindsign/blindrsa/internal/keys"
)

const (
	pbrsaTestVectorOutEnvironmentKey = "PBRSA_TEST_VECTORS_OUT"
	pbrsaTestVectorInEnvironmentKey  = "PBRSA_TEST_VECTORS_IN"
)

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

func runPBRSA(signer Signer, verifier Verifier, message, metadata []byte, random io.Reader) ([]byte, error) {
	blindedMsg, state, err := verifier.Blind(random, message, metadata)
	if err != nil {
		return nil, err
	}

	kLen := (signer.sk.Pk.N.BitLen() + 7) / 8
	if len(blindedMsg) != kLen {
		return nil, fmt.Errorf("Protocol message (blind message) length mismatch, expected %d, got %d", kLen, len(blindedMsg))
	}

	blindedSig, err := signer.BlindSign(blindedMsg, metadata)
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

	err = verifier.Verify(message, metadata, sig)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

func mustDecodeHex(h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	return b
}

func TestPBRSARoundTrip(t *testing.T) {
	message := []byte("hello world")
	metadata := []byte("metadata")
	key := loadStrongRSAKey()

	hash := crypto.SHA384
	verifier := NewVerifier(&key.PublicKey, hash)
	signer, err := NewSigner(key, hash)
	if err != nil {
		t.Fatal(err)
	}

	sig, err := runPBRSA(signer, verifier, message, metadata, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if sig == nil {
		t.Fatal("nil signature output")
	}
}

type encodedPBRSATestVector struct {
	Message   string `json:"msg"`
	Metadata  string `json:"metadata"`
	P         string `json:"p"`
	Q         string `json:"q"`
	D         string `json:"d"`
	E         string `json:"e"`
	N         string `json:"N"`
	Eprime    string `json:"eprime"`
	Rand      string `json:"rand"`
	Blind     string `json:"blind"`
	Salt      string `json:"salt"`
	Request   string `json:"blinded_msg"`
	Response  string `json:"blinded_sig"`
	Signature string `json:"sig"`
}

type rawPBRSATestVector struct {
	privateKey  *rsa.PrivateKey
	message     []byte
	metadata    []byte
	metadataKey []byte
	rand        []byte
	blind       []byte
	salt        []byte
	request     []byte
	response    []byte
	signature   []byte
}

func mustHex(d []byte) string {
	return hex.EncodeToString(d)
}

func (tv rawPBRSATestVector) MarshalJSON() ([]byte, error) {
	pEnc := mustHex(tv.privateKey.Primes[0].Bytes())
	qEnc := mustHex(tv.privateKey.Primes[1].Bytes())
	nEnc := mustHex(tv.privateKey.N.Bytes())
	e := new(big.Int).SetInt64(int64(tv.privateKey.PublicKey.E))
	eEnc := mustHex(e.Bytes())
	dEnc := mustHex(tv.privateKey.D.Bytes())
	ePrimeEnc := mustHex(tv.metadataKey)
	return json.Marshal(encodedPBRSATestVector{
		P:         pEnc,
		Q:         qEnc,
		D:         dEnc,
		E:         eEnc,
		N:         nEnc,
		Eprime:    ePrimeEnc,
		Message:   mustHex(tv.message),
		Metadata:  mustHex(tv.metadata),
		Rand:      mustHex(tv.rand),
		Blind:     mustHex(tv.blind),
		Salt:      mustHex(tv.salt),
		Request:   mustHex(tv.request),
		Response:  mustHex(tv.response),
		Signature: mustHex(tv.signature),
	})
}

func generatePBRSATestVector(t *testing.T, msg, metadata []byte) rawPBRSATestVector {
	key := loadStrongRSAKey()

	hash := crypto.SHA384
	verifier := NewVerifier(&key.PublicKey, hash)
	signer, err := NewSigner(key, hash)
	if err != nil {
		t.Fatal(err)
	}

	publicKey := keys.NewBigPublicKey(&key.PublicKey)
	metadataKey := augmentPublicKey(hash, publicKey, metadata)

	blindedMsg, state, err := verifier.Blind(rand.Reader, msg, metadata)
	if err != nil {
		t.Fatal(err)
	}

	blindedSig, err := signer.BlindSign(blindedMsg, metadata)
	if err != nil {
		t.Fatal(err)
	}

	sig, err := state.Finalize(blindedSig)
	if err != nil {
		t.Fatal(err)
	}

	err = verifier.Verify(msg, metadata, sig)
	if err != nil {
		t.Fatal(err)
	}

	return rawPBRSATestVector{
		message:     msg,
		metadata:    metadata,
		privateKey:  key,
		metadataKey: metadataKey.Marshal(),
		salt:        state.CopySalt(),
		blind:       state.CopyBlind(),
		request:     blindedMsg,
		response:    blindedSig,
		signature:   sig,
	}
}

func TestPBRSAGenerateTestVector(t *testing.T) {
	testCases := []struct {
		msg      []byte
		metadata []byte
	}{
		{
			[]byte("hello world"),
			[]byte("metadata"),
		},
		{
			[]byte("hello world"),
			[]byte(""),
		},
		{
			[]byte(""),
			[]byte("metadata"),
		},
		{
			[]byte(""),
			[]byte(""),
		},
	}

	vectors := []rawPBRSATestVector{}
	for _, testCase := range testCases {
		vectors = append(vectors, generatePBRSATestVector(t, testCase.msg, testCase.metadata))
	}

	// Encode the test vectors
	encoded, err := json.Marshal(vectors)
	if err != nil {
		t.Fatalf("Error producing test vectors: %v", err)
	}

	// TODO(caw): verify that we process them correctly
	// verifyPBRSATestVectors(t, encoded)

	var outputFile string
	if outputFile = os.Getenv(pbrsaTestVectorOutEnvironmentKey); len(outputFile) > 0 {
		err := os.WriteFile(outputFile, encoded, 0600)
		if err != nil {
			t.Fatalf("Error writing test vectors: %v", err)
		}
	}
}

func BenchmarkPBRSA(b *testing.B) {
	message := []byte("hello world")
	metadata := []byte("good doggo")
	key := loadStrongRSAKey()

	hash := crypto.SHA384
	verifier := NewVerifier(&key.PublicKey, hash)
	signer, err := NewSigner(key, hash)
	if err != nil {
		b.Fatal(err)
	}

	var blindedMsg []byte
	var state VerifierState
	b.Run("Blind", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			blindedMsg, state, err = verifier.Blind(rand.Reader, message, metadata)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	var blindedSig []byte
	b.Run("BlindSign", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			blindedSig, err = signer.BlindSign(blindedMsg, metadata)
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

	err = verifier.Verify(message, metadata, sig)
	if err != nil {
		b.Fatal(err)
	}
}
