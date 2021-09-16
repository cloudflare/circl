package dilithium_test

import (
	"fmt"
	"sort"

	"github.com/cloudflare/circl/sign/dilithium"
)

func Example() {
	// Check supported modes
	modes := dilithium.ModeNames()
	sort.Strings(modes)
	fmt.Printf("Supported modes: %v\n", modes)

	// Pick Dilithium mode III.
	mode := dilithium.ModeByName("Dilithium3")
	if mode == nil {
		panic("Mode3 not supported")
	}

	// Alternatively one could simply write
	//
	//  mode := dilithium.Mode3

	// Generates a keypair.
	pk, sk, err := mode.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	// (Alternatively one can derive a keypair from a seed,
	// see mode.NewKeyFromSeed().)

	// Packs public and private key
	packedSk := sk.Bytes()
	packedPk := pk.Bytes()

	// Load it again
	sk2 := mode.PrivateKeyFromBytes(packedSk)
	pk2 := mode.PublicKeyFromBytes(packedPk)

	// Creates a signature on our message with the generated private key.
	msg := []byte("Some message")
	signature := mode.Sign(sk2, msg)

	// Checks whether a signature is correct
	if !mode.Verify(pk2, msg, signature) {
		panic("incorrect signature")
	}

	fmt.Printf("O.K.")

	// Output:
	// Supported modes: [Dilithium2 Dilithium2-AES Dilithium3 Dilithium3-AES Dilithium5 Dilithium5-AES]
	// O.K.
}
