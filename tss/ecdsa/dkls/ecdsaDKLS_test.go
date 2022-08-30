// Reference: https://eprint.iacr.org/2018/499.pdf
// 2 out of 2 party threhsold signature scheme
// Figure 1 and Protocol 1 and 2

package dkls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/group"
)

const testECDSAOTCount = 10

func genKey(myGroup group.Group, curve elliptic.Curve) (group.Scalar, *ecdsa.PublicKey) {
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}

	if privateKey == nil {
		panic(err)
	}

	publicKey := &privateKey.PublicKey

	if publicKey == nil {
		panic(err)
	}

	secretByte := privateKey.D.Bytes()
	secretScalar := myGroup.NewScalar()
	err = secretScalar.UnmarshalBinary(secretByte)
	if err != nil {
		panic(err)
	}
	return secretScalar, publicKey
}

// Input: myGroup, the group we operate in
// Output: precomputation information for signature generation
func precomputation(myGroup group.Group, alice *AlicePre, bob *BobPre, Alice *Alice, Bob *Bob) error {
	// Initialization
	DB, bAs, kBInvAs := bob.BobInit(myGroup)

	// Round 1
	// bob sends DB, bAs, kBInvAs, to alice
	V, r, RPrime, aBs, kAInvBs := alice.AliceRound1(myGroup, DB, bAs, kBInvAs, alice.label, bob.label)

	// Round 2
	// alice sends a proof (V, r) of she knows the kA for R=[kA]DB as well as R' to bob
	// alice sends aBs, kAInvBs, to bob
	e0b, e1b, e0kBInv, e1kBInv, err := bob.BobRound2(V, r, RPrime, aBs, kAInvBs, alice.label, bob.label)
	if err != nil {
		return err
	}

	// Round 3
	// bob sends e0b, e1b, e0kBInv, e1kBInv, to alice
	sigmaa, vsa, sigmakAInv, vskAInv, err := alice.AliceRound3(e0b, e1b, e0kBInv, e1kBInv)
	if err != nil {
		return err
	}

	// Round 4
	// alice sends sigmaa, vsa, sigmakAInv, vskAInv to bob
	bob.BobRound4(sigmaa, sigmakAInv, vsa, vskAInv)

	Alice.SetParamters(alice)
	Bob.SetParamters(bob)

	return nil
}

// Input: myGroup, the group we operate in
// Input: Alice and Bob
// Input: hash, the hash of the message we want to sign
// Input: curve, the curve we operate in
func sigGen(myGroup group.Group, Alice *Alice, Bob *Bob, hash []byte, curve elliptic.Curve) group.Scalar {
	// Convert hash to scalar
	hashBig := hashToInt(hash, curve)
	hashByte := hashBig.Bytes()

	hashScalar := myGroup.NewScalar()
	errByte := hashScalar.UnmarshalBinary(hashByte)
	if errByte != nil {
		panic(errByte)
	}
	beaverAlice := Alice.SigGenInit()
	beaverBob := Bob.SigGenInit()

	// Round 1
	// Alice and Bob sends beaverAlice: skA/(kA*a), beaverBob: skB/(kB*b) to each other
	sigAlice := Alice.SigGenRound1(beaverBob, hashScalar)
	sigBob := Bob.SigGenRound1(beaverAlice, hashScalar)

	// Round 2
	// Either Alice or Bob can send the signature share to the other one and then combine
	signature := SigGenRound2(myGroup, sigAlice, sigBob)
	return signature
}

func testECDSAOT(t *testing.T, myGroup group.Group, curve elliptic.Curve) {
	var AliceSign Alice
	var BobSign Bob

	// Precomputation
	var alicePre AlicePre
	var bobPre BobPre
	// Set alice and bob label
	alicePre.label = []byte("alice")
	bobPre.label = []byte("bob")
	errPre := precomputation(myGroup, &alicePre, &bobPre, &AliceSign, &BobSign)
	if errPre != nil {
		t.Error("Precomputation fail")
	}

	// Generate key shares (precomputation is separate from key shares)
	prvScalar, pub := genKey(myGroup, curve)
	share1, share2 := KeyShareGen(myGroup, prvScalar)
	AliceSign.SetKeyShare(share1)
	BobSign.SetKeyShare(share2)

	// Online signature generation
	hash := []byte("Cloudflare: meow meow")
	signature := sigGen(myGroup, &AliceSign, &BobSign, hash, curve)

	// Verify the signature
	errVerify := Verify(AliceSign.Rx, signature, hash, pub)
	if errVerify != nil {
		t.Error("Signature verification fail")
	}
}

func TestECDSAOT(t *testing.T) {
	t.Run("ECDSAOT", func(t *testing.T) {
		for i := 0; i < testECDSAOTCount; i++ {
			currGroup := group.P256
			currCurve := elliptic.P256()
			testECDSAOT(t, currGroup, currCurve)
		}
	})
}

func benchECDSAOTPRE(b *testing.B, myGroup group.Group, curve elliptic.Curve) {
	var AliceSign Alice
	var BobSign Bob

	// Precomputation
	var alicePre AlicePre
	var bobPre BobPre
	// Set alice and bob label
	alicePre.label = []byte("alice")
	bobPre.label = []byte("bob")

	b.Run(curve.Params().Name+"-PreInit", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bobPre.BobInit(myGroup)
		}
	})

	DB, bAs, kBInvAs := bobPre.BobInit(myGroup)

	b.Run(curve.Params().Name+"-PreRound1", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			alicePre.AliceRound1(myGroup, DB, bAs, kBInvAs, alicePre.label, bobPre.label)
		}
	})

	V, r, RPrime, aBs, kAInvBs := alicePre.AliceRound1(myGroup, DB, bAs, kBInvAs, alicePre.label, bobPre.label)

	b.Run(curve.Params().Name+"-PreRound2", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, _, _, err := bobPre.BobRound2(V, r, RPrime, aBs, kAInvBs, alicePre.label, bobPre.label)
			if err != nil {
				b.Error("PreRound2 zk verification fail")
			}
		}
	})

	e0b, e1b, e0kBInv, e1kBInv, err := bobPre.BobRound2(V, r, RPrime, aBs, kAInvBs, alicePre.label, bobPre.label)
	if err != nil {
		b.Error("PreRound2 zk verification fail")
	}

	b.Run(curve.Params().Name+"-PreRound3", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, _, _, err = alicePre.AliceRound3(e0b, e1b, e0kBInv, e1kBInv)
			if err != nil {
				b.Error("PreRound3 decryption fail")
			}
		}
	})

	sigmaa, vsa, sigmakAInv, vskAInv, err := alicePre.AliceRound3(e0b, e1b, e0kBInv, e1kBInv)
	if err != nil {
		b.Error("PreRound3 decryption fail")
	}

	b.Run(curve.Params().Name+"-PreRound4", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bobPre.BobRound4(sigmaa, sigmakAInv, vsa, vskAInv)
		}
	})

	bobPre.BobRound4(sigmaa, sigmakAInv, vsa, vskAInv)

	AliceSign.SetParamters(&alicePre)
	BobSign.SetParamters(&bobPre)

	// Generate key shares
	prvScalar, pub := genKey(myGroup, curve)
	share1, share2 := KeyShareGen(myGroup, prvScalar)
	AliceSign.SetKeyShare(share1)
	BobSign.SetKeyShare(share2)

	// Online signature generation
	hash := []byte("Cloudflare: meow meow")
	signature := sigGen(myGroup, &AliceSign, &BobSign, hash, curve)

	// Verify the signature
	errVerify := Verify(AliceSign.Rx, signature, hash, pub)
	if errVerify != nil {
		b.Error("Signature verification fail")
	}
}

func benchECDSAOTSign(b *testing.B, myGroup group.Group, curve elliptic.Curve) {
	var AliceSign Alice
	var BobSign Bob

	// Precomputation
	var alicePre AlicePre
	var bobPre BobPre
	// Set alice and bob label
	alicePre.label = []byte("alice")
	bobPre.label = []byte("bob")
	err := precomputation(myGroup, &alicePre, &bobPre, &AliceSign, &BobSign)
	if err != nil {
		b.Error("Precomputation fail")
	}

	// Generate key shares
	prvScalar, pub := genKey(myGroup, curve)
	share1, share2 := KeyShareGen(myGroup, prvScalar)
	AliceSign.SetKeyShare(share1)
	BobSign.SetKeyShare(share2)

	// Online signature generation
	hash := []byte("Cloudflare: meow meow")
	hashBig := hashToInt(hash, curve)
	hashByte := hashBig.Bytes()

	hashScalar := myGroup.NewScalar()
	errByte := hashScalar.UnmarshalBinary(hashByte)
	if errByte != nil {
		panic(errByte)
	}

	b.Run(curve.Params().Name+"-SignInit", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			AliceSign.SigGenInit()
			BobSign.SigGenInit()
		}
	})

	beaverAlice := AliceSign.SigGenInit()
	beaverBob := BobSign.SigGenInit()

	b.Run(curve.Params().Name+"-SignRound1", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			AliceSign.SigGenRound1(beaverBob, hashScalar)
			BobSign.SigGenRound1(beaverAlice, hashScalar)
		}
	})

	sigAlice := AliceSign.SigGenRound1(beaverBob, hashScalar)
	sigBob := BobSign.SigGenRound1(beaverAlice, hashScalar)

	b.Run(curve.Params().Name+"-SignRound2", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			SigGenRound2(myGroup, sigAlice, sigBob)
		}
	})

	signature := SigGenRound2(myGroup, sigAlice, sigBob)

	// Verify the signature
	errVerify := Verify(AliceSign.Rx, signature, hash, pub)
	if errVerify != nil {
		b.Error("Signature verification fail")
	}
}

func BenchmarkECDSAOTPRE(b *testing.B) {
	pubkeyCurve := elliptic.P256()
	currGroup := group.P256
	benchECDSAOTPRE(b, currGroup, pubkeyCurve)
}

func BenchmarkECDSAOTSign(b *testing.B) {
	pubkeyCurve := elliptic.P256()
	currGroup := group.P256
	benchECDSAOTSign(b, currGroup, pubkeyCurve)
}
