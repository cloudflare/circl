// Reference: https://eprint.iacr.org/2021/1373.pdf
// Sender and receiver has private input a and b
// Sender and receiver get s1 and s2 such that a*b = s1+s2 from Fmul
// This scheme based on pure OT but not OT extension

package fmul

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/group"
)

const testFmulCount = 50

// Input: aInput, bInput, the private input from both sender and receiver
// Input: myGroup, the group we operate in
// Input: n, the total number of SimOT
func fmul(sender *SenderFmul, receiver *ReceiverFmul, aInput, bInput group.Scalar, myGroup group.Group, n int) error {
	// Sender Initialization
	As := sender.SenderInit(myGroup, aInput, n)

	// ---- Round1: Sender sends As to receiver ----

	Bs := receiver.ReceiverRound1(myGroup, As, bInput, n)

	// ---- Round 2: Receiver sends Bs = [bi]G or Ai+[bi]G to sender ----

	e0s, e1s := sender.SenderRound2(Bs, n)

	// ---- Round 3: Sender sends e0s, e1s to receiver ----

	sigma, vs, errDec := receiver.ReceiverRound3(e0s, e1s, n)
	if errDec != nil {
		return errDec
	}

	// ---- Round 4: receiver sends sigma as well as vs to sender ----

	sender.SenderRound4(vs, sigma, n)

	return nil
}

func testFmul(t *testing.T, myGroup group.Group) {
	n := DecideNumOT(myGroup, 128)
	var sender SenderFmul
	var receiver ReceiverFmul
	aSender := myGroup.RandomNonZeroScalar(rand.Reader)
	bReceiver := myGroup.RandomNonZeroScalar(rand.Reader)

	err := fmul(&sender, &receiver, aSender, bReceiver, myGroup, n)
	if err != nil {
		t.Error("Fmul decryption fail", err)
	}

	mul := myGroup.NewScalar()
	add := myGroup.NewScalar()

	add.Add(sender.s1, receiver.s2)
	mul.Mul(aSender, bReceiver)

	if add.IsEqual(mul) == false {
		t.Error("Fmul reconstruction failed")
	}
}

// Note the receiver has no space to cheat in the protocol.
// The only way receiver can cheat is by making up incorrect vs which is the same as entering a different private input b
// So we will only test the case where sender deviate from the protocol
// Where sender exchanges one pair of e0 and e1.
func testFmulNegative(t *testing.T, myGroup group.Group) {
	n := DecideNumOT(myGroup, 128)
	var sender SenderFmul
	var receiver ReceiverFmul
	aSender := myGroup.RandomNonZeroScalar(rand.Reader)
	bReceiver := myGroup.RandomNonZeroScalar(rand.Reader)

	// Sender Initialization
	As := sender.SenderInit(myGroup, aSender, n)

	// ---- Round1: Sender sends As to receiver ----

	Bs := receiver.ReceiverRound1(myGroup, As, bReceiver, n)

	// ---- Round 2: Receiver sends Bs = [bi]G or Ai+[bi]G to sender ----

	e0s, e1s := sender.SenderRound2(Bs, n)

	// exchange one pair of e0 and e1
	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		panic(err)
	}
	randomIndex := int(nBig.Int64())
	savee0 := make([]byte, len(e0s[randomIndex]))
	copy(savee0, e0s[randomIndex])
	e0s[randomIndex] = e1s[randomIndex]
	e1s[randomIndex] = savee0

	// ---- Round 3: Sender sends e0s, e1s to receiver ----

	_, _, err = receiver.ReceiverRound3(e0s, e1s, n)
	if err == nil {
		t.Error("Fmul decryption should fail", err)
	}
}

func benchmarFmul(b *testing.B, myGroup group.Group) {
	n := DecideNumOT(myGroup, 128)
	for iter := 0; iter < b.N; iter++ {
		var sender SenderFmul
		var receiver ReceiverFmul
		aSender := myGroup.RandomNonZeroScalar(rand.Reader)
		bReceiver := myGroup.RandomNonZeroScalar(rand.Reader)

		err := fmul(&sender, &receiver, aSender, bReceiver, myGroup, n)
		if err != nil {
			b.Error("Fmul reconstruction failed")
		}
	}
}

func benchmarFmulRound(b *testing.B, myGroup group.Group) {
	n := DecideNumOT(myGroup, 128)

	var sender SenderFmul
	var receiver ReceiverFmul
	aSender := myGroup.RandomNonZeroScalar(rand.Reader)
	bReceiver := myGroup.RandomNonZeroScalar(rand.Reader)

	b.Run("Sender-Initialization", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			sender.SenderInit(myGroup, aSender, n)
		}
	})

	As := sender.SenderInit(myGroup, aSender, n)

	b.Run("Receiver-Round1", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			receiver.ReceiverRound1(myGroup, As, bReceiver, n)
		}
	})

	Bs := receiver.ReceiverRound1(myGroup, As, bReceiver, n)

	b.Run("Sender-Round2", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			sender.SenderRound2(Bs, n)
		}
	})

	e0s, e1s := sender.SenderRound2(Bs, n)

	b.Run("Receiver-Round3", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := receiver.ReceiverRound3(e0s, e1s, n)
			if err != nil {
				b.Error("Receiver-Round3 decryption failed")
			}
		}
	})

	sigma, vs, err := receiver.ReceiverRound3(e0s, e1s, n)
	if err != nil {
		b.Error("Receiver-Round3 decryption failed")
	}

	b.Run("Sender-Round4", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			sender.SenderRound4(vs, sigma, n)
		}
	})

	sender.SenderRound4(vs, sigma, n)

	add := myGroup.NewScalar()
	mul := myGroup.NewScalar()

	add.Add(sender.s1, receiver.s2)
	mul.Mul(aSender, bReceiver)

	if add.IsEqual(mul) == false {
		b.Error("Fmul reconstruction failed")
	}
}

func TestFmul(t *testing.T) {
	t.Run("fmul", func(t *testing.T) {
		for i := 0; i < testFmulCount; i++ {
			currGroup := group.P256
			testFmul(t, currGroup)
		}
	})
	t.Run("fmulNegative", func(t *testing.T) {
		for i := 0; i < testFmulCount; i++ {
			currGroup := group.P256
			testFmulNegative(t, currGroup)
		}
	})
}

func BenchmarkFmul(b *testing.B) {
	currGroup := group.P256
	benchmarFmul(b, currGroup)
}

func BenchmarkFmulRound(b *testing.B) {
	currGroup := group.P256
	benchmarFmulRound(b, currGroup)
}
