package bbs

import (
	"testing"
)

func TestDifference(t *testing.T) {
	N := 10
	skipped := []int{0, 1, 5}
	expected := []int{2, 3, 4, 6, 7, 8, 9}
	diff := difference(skipped, N)
	if len(expected) != len(diff) {
		t.Fatal("mismatch difference")
	}
	for i := 0; i < len(diff); i++ {
		if expected[i] != diff[i] {
			t.Fatal("mismatch difference")
		}
	}
}

func TestRoundTrip(t *testing.T) {
	ikm := make([]byte, 32)
	keyInfo := []byte{}
	keyDst := []byte{}

	sk, err := keyGen(ikm, keyInfo, keyDst)
	if err != nil {
		t.Fatal(err)
	}

	header := []byte("test header")
	ph := []byte("presentation header")

	messages := make([][]byte, 5)
	messages[0] = []byte("hello")
	messages[1] = []byte("world")
	messages[1] = []byte("foo")
	messages[1] = []byte("bar")
	messages[1] = []byte("baz")

	sig, err := rawSign(sk, publicKey(sk), header, messages)
	if err != nil {
		t.Fatal(err)
	}

	err = rawVerify(publicKey(sk), sig, header, messages)
	if err != nil {
		t.Fatal(err)
	}

	disclosedIndexes := []int{0, 1}
	disclosedMessages := make([][]byte, len(disclosedIndexes))
	for i := 0; i < len(disclosedIndexes); i++ {
		disclosedMessages[i] = messages[disclosedIndexes[i]]
	}
	proof, err := rawProofGen(publicKey(sk), sig, header, ph, messages, disclosedIndexes)
	if err != nil {
		t.Fatal(err)
	}

	err = rawProofVerify(publicKey(sk), proof, header, ph, disclosedMessages, disclosedIndexes)
	if err != nil {
		t.Fatal(err)
	}
}
