package simot

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"io"

	"github.com/cloudflare/circl/group"
	"golang.org/x/crypto/sha3"
)

const keyLength = 16

// AES GCM encryption, we don't need to pad because our input is fixed length
// Need to use authenticated encryption to defend against tampering on ciphertext
// Input: key, plaintext message
// Output: ciphertext
func aesEncGCM(key, plaintext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}

	ciphertext := aesgcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext
}

// AES GCM decryption
// Input: key, ciphertext message
// Output: plaintext
func aesDecGCM(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := aesgcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, encryptedMessage := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := aesgcm.Open(nil, nonce, encryptedMessage, nil)

	return plaintext, err
}

// Initialization

// Input: myGroup, the group we operate in
// Input: m0, m1 the 2 message of the sender
// Input: index, the index of this SimOT
// Output: A = [a]G, a the sender randomness
func (sender *Sender) InitSender(myGroup group.Group, m0, m1 []byte, index int) group.Element {
	sender.a = myGroup.RandomNonZeroScalar(rand.Reader)
	sender.k0 = make([]byte, keyLength)
	sender.k1 = make([]byte, keyLength)
	sender.m0 = m0
	sender.m1 = m1
	sender.index = index
	sender.A = myGroup.NewElement()
	sender.A.MulGen(sender.a)
	sender.myGroup = myGroup
	return sender.A.Copy()
}

// Round 1

// ---- sender should send A to receiver ----

// Input: myGroup, the group we operate in
// Input: choice, the receiver choice bit
// Input: index, the index of this SimOT
// Input: A, from sender
// Output: B = [b]G if c == 0, B = A+[b]G if c == 1 (Implementation in constant time). b, the receiver randomness
func (receiver *Receiver) Round1Receiver(myGroup group.Group, choice int, index int, A group.Element) group.Element {
	receiver.b = myGroup.RandomNonZeroScalar(rand.Reader)
	receiver.c = choice
	receiver.kR = make([]byte, keyLength)
	receiver.index = index
	receiver.A = A
	receiver.myGroup = myGroup

	bG := myGroup.NewElement()
	bG.MulGen(receiver.b)
	AorI := myGroup.NewElement()
	AorI.CMov(choice, A)
	receiver.B = myGroup.NewElement()
	receiver.B.Add(bG, AorI)

	return receiver.B.Copy()
}

// Round 2

// ---- receiver should send B to sender ----

// Input: B from the receiver
// Output: e0, e1, encryption of m0 and m1 under key k0, k1
func (sender *Sender) Round2Sender(B group.Element) ([]byte, []byte) {
	sender.B = B

	aB := sender.myGroup.NewElement()
	aB.Mul(sender.B, sender.a)
	maA := sender.myGroup.NewElement()
	maA.Mul(sender.A, sender.a)
	maA.Neg(maA)
	aBaA := sender.myGroup.NewElement()
	aBaA.Add(aB, maA)

	// Hash the whole transcript A|B|...
	AByte, errByte := sender.A.MarshalBinary()
	if errByte != nil {
		panic(errByte)
	}
	BByte, errByte := sender.B.MarshalBinary()
	if errByte != nil {
		panic(errByte)
	}
	aBByte, errByte := aB.MarshalBinary()
	if errByte != nil {
		panic(errByte)
	}
	hashByte0 := append(AByte, BByte...)
	hashByte0 = append(hashByte0, aBByte...)

	s := sha3.NewShake128()
	_, errWrite := s.Write(hashByte0)
	if errWrite != nil {
		panic(errWrite)
	}
	_, errRead := s.Read(sender.k0)
	if errRead != nil {
		panic(errRead)
	}

	aBaAByte, errByte := aBaA.MarshalBinary()
	if errByte != nil {
		panic(errByte)
	}
	hashByte1 := append(AByte, BByte...)
	hashByte1 = append(hashByte1, aBaAByte...)
	s = sha3.NewShake128()
	_, errWrite = s.Write(hashByte1)
	if errWrite != nil {
		panic(errWrite)
	}
	_, errRead = s.Read(sender.k1)
	if errRead != nil {
		panic(errRead)
	}

	e0 := aesEncGCM(sender.k0, sender.m0)
	sender.e0 = e0

	e1 := aesEncGCM(sender.k1, sender.m1)
	sender.e1 = e1

	return sender.e0, sender.e1
}

// Round 3

// ---- sender should send e0, e1 to receiver ----

// Input: e0, e1: encryption of m0 and m1 from the sender
// Input: choice, choice bit of receiver
// Choose e0 or e1 based on choice bit in constant time
func (receiver *Receiver) Round3Receiver(e0, e1 []byte, choice int) error {
	receiver.ec = make([]byte, len(e1))
	// If c == 1, copy e1
	subtle.ConstantTimeCopy(choice, receiver.ec, e1)
	// If c == 0, copy e0
	subtle.ConstantTimeCopy(1-choice, receiver.ec, e0)

	AByte, errByte := receiver.A.MarshalBinary()
	if errByte != nil {
		panic(errByte)
	}
	BByte, errByte := receiver.B.MarshalBinary()
	if errByte != nil {
		panic(errByte)
	}
	bA := receiver.myGroup.NewElement()
	bA.Mul(receiver.A, receiver.b)
	bAByte, errByte := bA.MarshalBinary()
	if errByte != nil {
		panic(errByte)
	}
	// Hash the whole transcript so far
	hashByte := append(AByte, BByte...)
	hashByte = append(hashByte, bAByte...)

	s := sha3.NewShake128()
	_, errWrite := s.Write(hashByte)
	if errWrite != nil {
		panic(errWrite)
	}
	_, errRead := s.Read(receiver.kR) // kR, decryption key of mc
	if errRead != nil {
		panic(errRead)
	}
	mc, errDec := aesDecGCM(receiver.kR, receiver.ec)
	if errDec != nil {
		return errDec
	}
	receiver.mc = mc
	return nil
}

func (receiver *Receiver) Returnmc() []byte {
	return receiver.mc
}

func (sender *Sender) Returne0e1() ([]byte, []byte) {
	return sender.e0, sender.e1
}

func (sender *Sender) Returnm0m1() ([]byte, []byte) {
	return sender.m0, sender.m1
}
