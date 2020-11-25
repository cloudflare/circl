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
	Bob, _ := s.NewReceiver(privateBob, info)

	// Alice gets Bob's public key.
	seed := make([]byte, k.SeedSize())
	Alice, _ := s.NewSender(publicBob, info)
	enc, sealer, _ := Alice.Setup(seed)

	// Alice encrypts some plaintext and sends the ciphertext to Bob.
	ptAlice := []byte("text encrypted to Bob's public key")
	aad := []byte("additional public data")
	ct, _ := sealer.Seal(ptAlice, aad)

	// Bob decrypts the ciphertext.
	opener, _ := Bob.Setup(enc)
	ptBob, _ := opener.Open(ct, aad)

	// Plaintext was sent successfully.
	fmt.Println(bytes.Equal(ptAlice, ptBob))
	// Output: true
}
