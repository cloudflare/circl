package mayo_test

import (
	"fmt"
	"sort"

	"github.com/cloudflare/circl/sign/mayo"
)

func Example() {
	// Check supported modes
	modes := mayo.ModeNames()
	sort.Strings(modes)
	fmt.Printf("Supported modes: %v\n", modes)

	// Pick MAYO mode 3.
	mode := mayo.ModeByName("MAYO_3")
	if mode == nil {
		panic("Mode3 not supported")
	}

	// Alternatively one could simply write
	//
	//  mode := MAYO.Mode3

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
	signature, _ := mode.Sign(sk2, msg, nil)

	// Checks whether a signature is correct
	if !mode.Verify(pk2, msg, signature) {
		panic("incorrect signature")
	}

	fmt.Printf("O.K.")

	// Output:
	// Supported modes: [MAYO_1 MAYO_2 MAYO_3 MAYO_5]
	// O.K.
}
