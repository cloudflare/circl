// Reference: https://eprint.iacr.org/2015/267.pdf (1 out of 2 OT case)
// Sender has 2 messages m0, m1
// Receiver receives mc based on the choice bit c

package simot

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/group"
)

const testSimOTCount = 100

func simOT(myGroup group.Group, sender *Sender, receiver *Receiver, m0, m1 []byte, choice, index int) error {
	// Initialization
	A := sender.InitSender(myGroup, m0, m1, index)

	// Round 1
	// Sender sends A to receiver
	B := receiver.Round1Receiver(myGroup, choice, index, A)

	// Round 2
	// Receiver sends B to sender
	e0, e1 := sender.Round2Sender(B)

	// Round 3
	// Sender sends e0 e1 to receiver
	errDec := receiver.Round3Receiver(e0, e1, receiver.c)
	if errDec != nil {
		return errDec
	}

	return nil
}

func testNegativeSimOT(t *testing.T, myGroup group.Group, choice int) {
	var sender Sender
	var receiver Receiver
	m0 := make([]byte, myGroup.Params().ScalarLength)
	m1 := make([]byte, myGroup.Params().ScalarLength)
	_, errRand := rand.Read(m0)
	if errRand != nil {
		panic(errRand)
	}
	_, errRand = rand.Read(m1)
	if errRand != nil {
		panic(errRand)
	}

	// Initialization
	A := sender.InitSender(myGroup, m0, m1, 0)

	// Round 1
	B := receiver.Round1Receiver(myGroup, choice, 0, A)

	// Round 2
	e0, e1 := sender.Round2Sender(B)
	// Round 3

	// Here we pass in the flipped choice bit, to prove the decryption will fail
	// The receiver will not learn anything about m_{1-c}
	errDec := receiver.Round3Receiver(e0, e1, 1-choice)
	if errDec == nil {
		t.Error("SimOT decryption failed", errDec)
	}

	if choice == 0 {
		equal0 := bytes.Compare(sender.m0, receiver.mc)
		if equal0 == 0 {
			t.Error("Receiver decryption should fail")
		}
		equal1 := bytes.Compare(sender.m1, receiver.mc)
		if equal1 == 0 {
			t.Error("Receiver decryption should fail")
		}
	} else {
		equal0 := bytes.Compare(sender.m0, receiver.mc)
		if equal0 == 0 {
			t.Error("Receiver decryption should fail")
		}
		equal1 := bytes.Compare(sender.m1, receiver.mc)
		if equal1 == 0 {
			t.Error("Receiver decryption should fail")
		}
	}
}

// Input: myGroup, the group we operate in
func testSimOT(t *testing.T, myGroup group.Group, choice int) {
	var sender Sender
	var receiver Receiver

	m0 := make([]byte, myGroup.Params().ScalarLength)
	m1 := make([]byte, myGroup.Params().ScalarLength)
	_, errRand := rand.Read(m0)
	if errRand != nil {
		panic(errRand)
	}
	_, errRand = rand.Read(m1)
	if errRand != nil {
		panic(errRand)
	}

	errDec := simOT(myGroup, &sender, &receiver, m0, m1, choice, 0)
	if errDec != nil {
		t.Error("AES GCM Decryption failed")
	}

	if choice == 0 {
		equal0 := bytes.Compare(sender.m0, receiver.mc)
		if equal0 != 0 {
			t.Error("Receiver decryption failed")
		}
	} else {
		equal1 := bytes.Compare(sender.m1, receiver.mc)
		if equal1 != 0 {
			t.Error("Receiver decryption failed")
		}
	}
}

func benchmarSimOT(b *testing.B, myGroup group.Group) {
	var sender Sender
	var receiver Receiver
	m0 := make([]byte, myGroup.Params().ScalarLength)
	m1 := make([]byte, myGroup.Params().ScalarLength)
	_, errRand := rand.Read(m0)
	if errRand != nil {
		panic(errRand)
	}
	_, errRand = rand.Read(m1)
	if errRand != nil {
		panic(errRand)
	}

	for iter := 0; iter < b.N; iter++ {
		errDec := simOT(myGroup, &sender, &receiver, m0, m1, iter%2, 0)
		if errDec != nil {
			b.Error("AES GCM Decryption failed")
		}
	}
}

func benchmarkSimOTRound(b *testing.B, myGroup group.Group) {
	var sender Sender
	var receiver Receiver
	m0 := make([]byte, myGroup.Params().ScalarLength)
	m1 := make([]byte, myGroup.Params().ScalarLength)
	_, errRand := rand.Read(m0)
	if errRand != nil {
		panic(errRand)
	}
	_, errRand = rand.Read(m1)
	if errRand != nil {
		panic(errRand)
	}

	b.Run("Sender-Initialization", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			sender.InitSender(myGroup, m0, m1, 0)
		}
	})

	A := sender.InitSender(myGroup, m0, m1, 0)

	b.Run("Receiver-Round1", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			receiver.Round1Receiver(myGroup, 0, 0, A)
		}
	})

	B := receiver.Round1Receiver(myGroup, 0, 0, A)

	b.Run("Sender-Round2", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			sender.Round2Sender(B)
		}
	})

	e0, e1 := sender.Round2Sender(B)

	b.Run("Receiver-Round3", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			errDec := receiver.Round3Receiver(e0, e1, receiver.c)
			if errDec != nil {
				b.Error("Receiver-Round3 decryption failed")
			}
		}
	})

	errDec := receiver.Round3Receiver(e0, e1, receiver.c)
	if errDec != nil {
		b.Error("Receiver-Round3 decryption failed")
	}

	// Confirm
	equal0 := bytes.Compare(sender.m0, receiver.mc)
	if equal0 != 0 {
		b.Error("Receiver decryption failed")
	}
}

func TestSimOT(t *testing.T) {
	t.Run("SimOT", func(t *testing.T) {
		for i := 0; i < testSimOTCount; i++ {
			currGroup := group.P256
			choice := i % 2
			testSimOT(t, currGroup, choice)
		}
	})
	t.Run("SimOTNegative", func(t *testing.T) {
		for i := 0; i < testSimOTCount; i++ {
			currGroup := group.P256
			choice := i % 2
			testNegativeSimOT(t, currGroup, choice)
		}
	})
}

func BenchmarkSimOT(b *testing.B) {
	currGroup := group.P256
	benchmarSimOT(b, currGroup)
}

func BenchmarkSimOTRound(b *testing.B) {
	currGroup := group.P256
	benchmarkSimOTRound(b, currGroup)
}
