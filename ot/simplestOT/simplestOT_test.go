package simplestOT

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/cloudflare/circl/group"
)

const TestBaseOTCount = 100

func testNegativeBaseOT(t *testing.T, myGroup group.Group, choice int) {
	var sender SenderSimOT
	var receiver ReceiverSimOT
	m0 := make([]byte, myGroup.Params().ScalarLength)
	m1 := make([]byte, myGroup.Params().ScalarLength)
	rand.Read(m0)
	rand.Read(m1)

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
		t.Error("BaseOT decryption failed", errDec)
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
func testBaseOT(t *testing.T, myGroup group.Group, choice int) {
	var sender SenderSimOT
	var receiver ReceiverSimOT

	m0 := make([]byte, myGroup.Params().ScalarLength)
	m1 := make([]byte, myGroup.Params().ScalarLength)
	rand.Read(m0)
	rand.Read(m1)
	err := BaseOT(myGroup, &sender, &receiver, m0, m1, choice, 0)
	if err != nil {
		t.Error("BaseOT failed", err)
	}
	//Confirm
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

func benchmarBaseOT(b *testing.B, myGroup group.Group) {
	var sender SenderSimOT
	var receiver ReceiverSimOT
	m0 := make([]byte, myGroup.Params().ScalarLength)
	m1 := make([]byte, myGroup.Params().ScalarLength)
	rand.Read(m0)
	rand.Read(m1)

	for iter := 0; iter < b.N; iter++ {
		err := BaseOT(myGroup, &sender, &receiver, m0, m1, iter%2, 0)
		if err != nil {
			b.Error("BaseOT failed")
		}
	}
}

func benchmarkBaseOTRound(b *testing.B, myGroup group.Group) {
	var sender SenderSimOT
	var receiver ReceiverSimOT
	m0 := make([]byte, myGroup.Params().ScalarLength)
	m1 := make([]byte, myGroup.Params().ScalarLength)
	rand.Read(m0)
	rand.Read(m1)

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

func TestBaseOT(t *testing.T) {

	t.Run("BaseOT", func(t *testing.T) {
		for i := 0; i < TestBaseOTCount; i++ {
			currGroup := group.P256
			choice := i % 2
			testBaseOT(t, currGroup, choice)
		}
	})
	t.Run("BaseOTNegative", func(t *testing.T) {
		for i := 0; i < TestBaseOTCount; i++ {
			currGroup := group.P256
			choice := i % 2
			testNegativeBaseOT(t, currGroup, choice)
		}
	})

}

func BenchmarkBaseOT(b *testing.B) {
	currGroup := group.P256
	benchmarBaseOT(b, currGroup)
}

func BenchmarkBaseOTRound(b *testing.B) {
	currGroup := group.P256
	benchmarkBaseOTRound(b, currGroup)
}
