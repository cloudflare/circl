package hpke_test

import (
	"bytes"
	"fmt"

	"github.com/cloudflare/circl/hpke"
)

func Example_hpke() {
	// import "github.com/cloudflare/circl/hpke"

	// HPKE suite is a domain parameter.
	s := hpke.Suite{
		hpke.DHKemP256HkdfSha256,
		hpke.HkdfSha256,
		hpke.AeadAES128GCM,
	}
	info := []byte("public info string, known to both Alice and Bob")

	// Bob prepares to receive messages and announces his public key.
	k := s.KemID.Scheme()
	publicBob, privateBob, _ := k.GenerateKey()
	Bob, err := s.NewReceiver(privateBob, info)
	if err != nil {
		panic(err)
	}

	// Alice gets Bob's public key.
	Alice, err := s.NewSender(publicBob, info)
	if err != nil {
		panic(err)
	}

	seed := make([]byte, k.SeedSize())
	enc, sealer, err := Alice.Setup(seed)
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
