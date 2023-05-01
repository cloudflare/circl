package hpke_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/hpke"
)

func Example() {
	// import "github.com/cloudflare/circl/hpke"
	// import "crypto/rand"

	// HPKE suite is a domain parameter.
	kemID := hpke.KEM_P384_HKDF_SHA384
	kdfID := hpke.KDF_HKDF_SHA384
	aeadID := hpke.AEAD_AES256GCM
	suite := hpke.NewSuite(kemID, kdfID, aeadID)
	info := []byte("public info string, known to both Alice and Bob")

	// Bob prepares to receive messages and announces his public key.
	publicBob, privateBob, err := kemID.Scheme().GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	Bob, err := suite.NewReceiver(privateBob, info)
	if err != nil {
		panic(err)
	}

	// Alice gets Bob's public key.
	Alice, err := suite.NewSender(publicBob, info)
	if err != nil {
		panic(err)
	}
	enc, sealer, err := Alice.Setup(rand.Reader)
	if err != nil {
		panic(err)
	}

	// Alice encrypts some plaintext and sends the ciphertext to Bob.
	ptAlice := []byte("text encrypted to Bob's public key")
	aad := []byte("additional public data")
	ct, err := sealer.Seal(ptAlice, aad)
	if err != nil {
		panic(err)
	}

	// Bob decrypts the ciphertext.
	opener, err := Bob.Setup(enc)
	if err != nil {
		panic(err)
	}
	ptBob, err := opener.Open(ct, aad)
	if err != nil {
		panic(err)
	}

	// Plaintext was sent successfully.
	fmt.Println(bytes.Equal(ptAlice, ptBob))
	// Output: true
}

func runHpkeBenchmark(b *testing.B, kem hpke.KEM, kdf hpke.KDF, aead hpke.AEAD) {
	suite := hpke.NewSuite(kem, kdf, aead)

	pkR, skR, err := kem.Scheme().GenerateKeyPair()
	if err != nil {
		b.Fatal(err)
	}

	info := []byte("public info string")
	sender, err := suite.NewSender(pkR, info)
	if err != nil {
		b.Fatal(err)
	}

	b.Run(fmt.Sprintf("SetupSender-%04x-%04x-%04x", kem, kdf, aead), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err = sender.Setup(rand.Reader)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	enc, _, err := sender.Setup(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	receiver, err := suite.NewReceiver(skR, info)
	if err != nil {
		b.Fatal(err)
	}

	b.Run(fmt.Sprintf("SetupReceiver-%04x-%04x-%04x", kem, kdf, aead), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := receiver.Setup(enc)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run(fmt.Sprintf("Encrypt-%04x-%04x-%04x", kem, kdf, aead), func(b *testing.B) {
		pt := []byte("plaintext")
		aad := []byte("additional authenticated data")
		cts := make([][]byte, b.N)
		_, sealer, err := sender.Setup(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			cts[i], err = sealer.Seal(pt, aad)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run(fmt.Sprintf("Decrypt-%04x-%04x-%04x", kem, kdf, aead), func(b *testing.B) {
		pt := []byte("plaintext")
		aad := []byte("additional authenticated data")
		cts := make([][]byte, b.N)
		enc, sealer, err := sender.Setup(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
		opener, err := receiver.Setup(enc)
		if err != nil {
			b.Fatal(err)
		}
		for i := 0; i < b.N; i++ {
			cts[i], err = sealer.Seal(pt, aad)
			if err != nil {
				b.Fatal(err)
			}
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err = opener.Open(cts[i], aad)
			if err != nil {
				b.Log(i)
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkHpkeRoundTrip(b *testing.B) {
	tests := []struct {
		kem  hpke.KEM
		kdf  hpke.KDF
		aead hpke.AEAD
	}{
		{hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM},
		{hpke.KEM_X25519_KYBER768_DRAFT00, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM},
	}
	for _, test := range tests {
		runHpkeBenchmark(b, test.kem, test.kdf, test.aead)
	}
}
