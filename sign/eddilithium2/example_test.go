package eddilithium2_test

import (
	"fmt"

	"github.com/cloudflare/circl/sign/eddilithium2"
)

func Example() {
	// Generates a keypair.
	pk, sk, err := eddilithium2.GenerateKey(nil)
	if err != nil {
		panic(err)
	}

	// (Alternatively one can derive a keypair from a seed,
	// see NewKeyFromSeed().)

	// Packs public and private key
	var packedSk [eddilithium2.PrivateKeySize]byte
	var packedPk [eddilithium2.PublicKeySize]byte
	sk.Pack(&packedSk)
	pk.Pack(&packedPk)

	// Load it again
	var sk2 eddilithium2.PrivateKey
	var pk2 eddilithium2.PublicKey
	sk2.Unpack(&packedSk)
	pk2.Unpack(&packedPk)

	// Creates a signature on our message with the generated private key.
	msg := []byte("Some message")
	var signature [eddilithium2.SignatureSize]byte
	eddilithium2.SignTo(&sk2, msg, signature[:])

	// Checks whether a signature is correct
	if !eddilithium2.Verify(&pk2, msg, signature[:]) {
		panic("incorrect signature")
	}

	fmt.Printf("O.K.")

	// Output:
	// O.K.
}
