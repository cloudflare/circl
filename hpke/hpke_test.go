package hpke_test

import (
	"bytes"
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/hpke"
)

func Example() {
	// import "github.com/cloudflare/circl/hpke"
	// import "crypto/rand"

	// HPKE suite is a domain parameter.
	s := hpke.Suite{
		hpke.KEM.P384.HKDF.SHA384,
		hpke.KDF.HKDF.SHA384,
		hpke.AEAD.AES256GCM,
	}
	info := []byte("public info string, known to both Alice and Bob")

	// Bob prepares to receive messages and announces his public key.
	k := s.KemID.Scheme()
	publicBob, privateBob, err := k.GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	Bob, err := s.NewReceiver(privateBob, info)
	if err != nil {
		panic(err)
	}

	// Alice gets Bob's public key.
	Alice, err := s.NewSender(publicBob, info)
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

func Example_kEMID() {
	id, err := hpke.KEM.Parse(0x10)
	if err != nil {
		fmt.Print(err)
	}
	fmt.Print(*id == hpke.KEM.P256.HKDF.SHA256)
	// Outputs: true
}

func Example_kDFID() {
	id, err := hpke.KDF.Parse(0x1)
	if err != nil {
		fmt.Print(err)
	}
	fmt.Print(*id == hpke.KDF.HKDF.SHA256)
	// Outputs: true
}

func Example_aEADID() {
	id, err := hpke.AEAD.Parse(1)
	if err != nil {
		fmt.Print(err)
	}
	fmt.Print(*id == hpke.AEAD.AES128GCM)
	// Outputs: true
}
