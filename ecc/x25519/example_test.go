// @author Armando Faz

package x25519

import (
	"crypto/rand"
	"fmt"
)

// This example shows how Alice and Bob can generate a shared secret.
func Examplex25519() {
	var aliceSecret, bobSecret Key
	var alicePublic, bobPublic Key
	var aliceShared, bobShared Key

	_, err := rand.Read(aliceSecret[:])
	if err != nil {
		fmt.Println("rand error:", err)
		return
	}

	ScalarBaseMult(&alicePublic, &aliceSecret)
	_, err = rand.Read(bobSecret[:])
	if err != nil {
		fmt.Println("rand error:", err)
		return
	}

	ScalarBaseMult(&bobPublic, &bobSecret)

	ScalarMult(&bobShared, &bobSecret, &alicePublic)
	ScalarMult(&aliceShared, &aliceSecret, &bobPublic)

	fmt.Println(aliceShared == bobShared)
	// Output: true
}
