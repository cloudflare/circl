package tkn20

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

type abeTestCase struct {
	desc   string
	attrs  Attributes
	policy Policy
	msk    SystemSecretKey
	pk     PublicKey
}

var testCases []abeTestCase

var (
	msg     = []byte("drink your ovaltine now")
	longMsg = []byte(strings.Repeat("a", 10000))
)

func generateAttrs() Attributes {
	benchableAttrs := make(map[string]string, 50)
	for i := 0; i < 50; i++ {
		benchableAttrs["k"+strconv.Itoa(i)] = "v" + strconv.Itoa(i)
	}
	attrs := Attributes{}
	attrs.FromMap(benchableAttrs)
	return attrs
}

func generatePolicy() string {
	var policyBuilder strings.Builder
	for i := 0; i < 50; i++ {
		policyBuilder.WriteString("k")
		policyBuilder.WriteString(strconv.Itoa(i))
		policyBuilder.WriteString(":v")
		policyBuilder.WriteString(strconv.Itoa(i))
		if i != 49 {
			if i%2 == 0 {
				policyBuilder.WriteString(" and ")
			} else {
				policyBuilder.WriteString(" or ")
			}
		}
	}
	return policyBuilder.String()
}

func init() {
	smallPolicy := Policy{}
	_ = smallPolicy.FromString("(k1:v1 or k1:v2) and not k2:v3")
	smallAttrs := Attributes{}
	smallAttrs.FromMap(map[string]string{"k1": "v2", "k2": "v4"})
	longPolicy := Policy{}
	_ = longPolicy.FromString(generatePolicy())
	testCases = []abeTestCase{
		{
			desc:   "smallPolicy/Attrs",
			attrs:  smallAttrs,
			policy: smallPolicy,
		},
		{
			desc:   "longPolicy/Attrs",
			attrs:  generateAttrs(),
			policy: longPolicy,
		},
	}
	var err error
	for i := range testCases {
		testCases[i].pk, testCases[i].msk, err = Setup(rand.Reader)
		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkTKN20KeyGen(b *testing.B) {
	for _, tc := range testCases {
		b.Run(fmt.Sprintf("keygen:%s", tc.desc), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := tc.msk.KeyGen(rand.Reader, tc.attrs)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkRSAKeyGen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkX25519KeyGen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, err := box.GenerateKey(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTKN20Encrypt(b *testing.B) {
	for _, tc := range testCases {
		b.Run(fmt.Sprintf("encrypt:%s", tc.desc), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := tc.pk.Encrypt(rand.Reader, tc.policy, msg)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkRSAEncrypt(b *testing.B) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	pubKey := privKey.PublicKey
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := rsa.EncryptPKCS1v15(rand.Reader, &pubKey, msg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkX25519Encrypt(b *testing.B) {
	pubKey, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := box.SealAnonymous(nil, msg, pubKey, rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTKN20Decrypt(b *testing.B) {
	for _, tc := range testCases {
		b.Run(fmt.Sprintf("decrypt:%s", tc.desc), func(b *testing.B) {
			userKey, err := tc.msk.KeyGen(rand.Reader, tc.attrs)
			if err != nil {
				b.Fatal(err)
			}
			ciphertext, err := tc.pk.Encrypt(rand.Reader, tc.policy, msg)
			if err != nil {
				b.Fatal(err)
			}
			keyBytes, _ := userKey.MarshalBinary()
			pubKeyBytes, _ := tc.pk.MarshalBinary()
			// longCt is only benchmarked to measure size overhead
			longCt, err := tc.pk.Encrypt(rand.Reader, tc.policy, longMsg)
			if err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err = userKey.Decrypt(ciphertext)
				if err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(len(pubKeyBytes)), "public_key_size")
			b.ReportMetric(float64(len(keyBytes)), "attribute_secret_key_size")
			b.ReportMetric(float64(len(ciphertext)-len(msg)), "ciphertext_bytes_overhead_32b_msg")
			b.ReportMetric(float64(len(longCt)-len(longMsg)), "ciphertext_bytes_overhead_10kb_msg")
		})
	}
}

func BenchmarkRSADecrypt(b *testing.B) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	pubKey := privKey.PublicKey
	ct, err := rsa.EncryptPKCS1v15(rand.Reader, &pubKey, msg)
	if err != nil {
		b.Fatal(err)
	}
	// longCt is only benchmarked to measure size overhead
	longCt, err := rsaEncrypt(longMsg, &privKey.PublicKey)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := rsa.DecryptPKCS1v15(rand.Reader, privKey, ct)
		if err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(privKey.PublicKey.Size()), "public_key_size")
	b.ReportMetric(float64(len(x509.MarshalPKCS1PrivateKey(privKey))), "secret_key_size")
	b.ReportMetric(float64(len(ct)-len(msg)), "ciphertext_bytes_overhead")
	b.ReportMetric(float64(len(longCt)-len(longMsg)), "ciphertext_bytes_overhead_10kb_msg")
}

func BenchmarkX25519Decrypt(b *testing.B) {
	pubKey, privKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	ct, err := box.SealAnonymous(nil, msg, pubKey, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	// longCt is only benchmarked to measure size overhead
	longCt, err := box.SealAnonymous(nil, longMsg, pubKey, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, ok := box.OpenAnonymous(nil, ct, pubKey, privKey)
		if !ok {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(len(pubKey)), "public_key_size")
	b.ReportMetric(float64(len(privKey)), "secret_key_size")
	b.ReportMetric(float64(len(ct)-len(msg)), "ciphertext_bytes_overhead_32b_msg")
	b.ReportMetric(float64(len(longCt)-len(longMsg)), "ciphertext_bytes_overhead_10kb_msg")
}

func rsaEncrypt(data []byte, pubKey *rsa.PublicKey) ([]byte, error) {
	chunkSize := 245 // Max chunk size for 2048 bit key with PKCS1v15 padding
	var ct []byte
	for len(data) > 0 {
		if len(data) < chunkSize {
			chunkSize = len(data)
		}
		chunk := data[:chunkSize]
		data = data[chunkSize:]
		encryptedChunk, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, chunk)
		if err != nil {
			return nil, err
		}
		ct = append(ct, encryptedChunk...)
	}
	return ct, nil
}
