package eddilithium4_test

import (
	"fmt"

	"github.com/cloudflare/circl/sign/eddilithium4"
)

func Example() {
	// Generates a keypair.
	pk, sk, err := eddilithium4.GenerateKey(nil)
	if err != nil {
		panic(err)
	}

	// (Alternatively one can derive a keypair from a seed,
	// see NewKeyFromSeed().)

	// Packs public and private key
	var packedSk [eddilithium4.PrivateKeySize]byte
	var packedPk [eddilithium4.PublicKeySize]byte
	sk.Pack(&packedSk)
	pk.Pack(&packedPk)

	// Load it again
	var sk2 eddilithium4.PrivateKey
	var pk2 eddilithium4.PublicKey
	sk2.Unpack(&packedSk)
	pk2.Unpack(&packedPk)

	// Creates a signature on our message with the generated private key.
	msg := []byte("Some message")
	var signature [eddilithium4.SignatureSize]byte
	eddilithium4.SignTo(&sk2, msg, signature[:])

	// Checks whether a signature is correct
	if !eddilithium4.Verify(&pk2, msg, signature[:]) {
		panic("incorrect signature")
	}

	fmt.Printf("O.K.")

	// Output:
	// O.K.
}
