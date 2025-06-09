package bbs_test

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/sign/bbs"
)

const Suite = bbs.SuiteBLS12381Shake256

var (
	sOpts = bbs.SignOptions{ID: Suite}
	pOpts = bbs.ProveOptions{SignOptions: sOpts}
)

func ExampleSign() {
	var keyMaterial [bbs.KeyMaterialMinSize]byte
	_, _ = rand.Read(keyMaterial[:])
	key, _ := bbs.KeyGen(Suite, keyMaterial[:], nil, nil)
	pub := key.PublicKey()

	msg0 := []byte("Document")
	msg1 := []byte("Picture")
	msg2 := []byte("Table")
	sig := bbs.Sign(key, [][]byte{msg0, msg1, msg2}, sOpts)

	valid := bbs.Verify(pub, &sig, [][]byte{msg0, msg1, msg2}, sOpts)
	fmt.Println(valid)

	// Fails because messages are in a wrong order.
	invalid := bbs.Verify(pub, &sig, [][]byte{msg1, msg2, msg0}, sOpts)
	fmt.Println(invalid)
	// Output: true
	// false
}

func ExampleProve() {
	var keyMaterial [bbs.KeyMaterialMinSize]byte
	_, _ = rand.Read(keyMaterial[:])
	key, _ := bbs.KeyGen(Suite, keyMaterial[:], nil, nil)
	pub := key.PublicKey()

	allMsgs := [][]byte{[]byte("Document"), []byte("Picture"), []byte("Table")}
	sig := bbs.Sign(key, allMsgs, sOpts)

	// Disclose the second and third messages.
	// Equivalently:
	//   msgsProve, _ := bbs.Disclose(allMsgs, []uint{1, 2})
	// or
	//   msgsProve, _ := bbs.Conceal(allMsgs, []uint{0})
	msgsProve := []bbs.Msg{
		bbs.Concealed(allMsgs[0]),
		bbs.Disclosed(allMsgs[1]),
		bbs.Disclosed(allMsgs[2]),
	}

	for i, m := range msgsProve {
		fmt.Printf("[%v] %T: %s\n", i, m, m)
	}

	proof, disclosed, _ := bbs.Prove(rand.Reader, pub, &sig, msgsProve, pOpts)

	// Only disclosed messages.
	for _, m := range disclosed {
		fmt.Printf("[%v] %T: %s\n", m.Index, m.Message, m.Message)
	}

	valid := bbs.VerifyProof(pub, proof, disclosed, pOpts)
	fmt.Println(valid)

	// Fails because the disclosed messages are incomplete.
	invalid := bbs.VerifyProof(pub, proof, disclosed[1:], pOpts)
	fmt.Println(invalid)
	// Output:
	// [0] bbs.Concealed: Document
	// [1] bbs.Disclosed: Picture
	// [2] bbs.Disclosed: Table
	// [1] bbs.Disclosed: Picture
	// [2] bbs.Disclosed: Table
	// true
	// false
}
