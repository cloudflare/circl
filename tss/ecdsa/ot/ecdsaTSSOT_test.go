package ECDSAOT

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/group"
)

const TestECDSAOTCount = 10

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

func testECDSAOT(t *testing.T, myGroup group.Group, curve elliptic.Curve) {
	var Alice Alice
	var Bob Bob

	// Precomputation
	var alice AlicePre
	var bob BobPre
	// Set alice and bob label
	alice.label = []byte("alice")
	bob.label = []byte("bob")
	errPre := Precomputation(myGroup, &alice, &bob, &Alice, &Bob)
	if errPre != nil {
		t.Error("Precomputation fail")
	}

	// Generate key shares (precomputation is separate from key shares)
	prvScalar, pub := genKey(myGroup, curve)
	share1, share2 := KeyShareGen(myGroup, prvScalar)
	Alice.SetKeyShare(share1)
	Bob.SetKeyShare(share2)

	// Online signature generation
	hash := []byte("Cloudflare: meow meow")
	signature := SigGen(myGroup, &Alice, &Bob, hash, curve)

	// Verify the signature
	errVerify := Verify(Alice.Rx, signature, hash, pub)
	if errVerify != nil {
		t.Error("Signature verification fail")
	}
}

func TestECDSAOT(t *testing.T) {
	t.Run("ECDSAOT", func(t *testing.T) {
		for i := 0; i < TestECDSAOTCount; i++ {
			currGroup := group.P256
			currCurve := elliptic.P256()
			testECDSAOT(t, currGroup, currCurve)
		}
	})
}

func benchECDSAOTPRE(b *testing.B, myGroup group.Group, curve elliptic.Curve) {

	var Alice Alice
	var Bob Bob

	// Precomputation
	var alice AlicePre
	var bob BobPre
	// Set alice and bob label
	alice.label = []byte("alice")
	bob.label = []byte("bob")

	b.Run(curve.Params().Name+"-PreInit", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bob.BobInit(myGroup)
		}
	})

	DB, bAs, kBInvAs := bob.BobInit(myGroup)

	b.Run(curve.Params().Name+"-PreRound1", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			alice.AliceRound1(myGroup, DB, bAs, kBInvAs, alice.label, bob.label)
		}
	})

	V, r, RPrime, aBs, kAInvBs := alice.AliceRound1(myGroup, DB, bAs, kBInvAs, alice.label, bob.label)

	b.Run(curve.Params().Name+"-PreRound2", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, _, _, err := bob.BobRound2(V, r, RPrime, aBs, kAInvBs, alice.label, bob.label)
			if err != nil {
				b.Error("PreRound2 zk verification fail")
			}
		}
	})

	e0b, e1b, e0kBInv, e1kBInv, err := bob.BobRound2(V, r, RPrime, aBs, kAInvBs, alice.label, bob.label)
	if err != nil {
		b.Error("PreRound2 zk verification fail")
	}

	b.Run(curve.Params().Name+"-PreRound3", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, _, _, err := alice.AliceRound3(e0b, e1b, e0kBInv, e1kBInv)
			if err != nil {
				b.Error("PreRound3 decryption fail")
			}
		}
	})

	sigmaa, vsa, sigmakAInv, vskAInv, err := alice.AliceRound3(e0b, e1b, e0kBInv, e1kBInv)
	if err != nil {
		b.Error("PreRound3 decryption fail")
	}

	b.Run(curve.Params().Name+"-PreRound4", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bob.BobRound4(sigmaa, sigmakAInv, vsa, vskAInv)
		}
	})

	bob.BobRound4(sigmaa, sigmakAInv, vsa, vskAInv)

	Alice.SetParamters(&alice)
	Bob.SetParamters(&bob)

	// Generate key shares
	prvScalar, pub := genKey(myGroup, curve)
	share1, share2 := KeyShareGen(myGroup, prvScalar)
	Alice.SetKeyShare(share1)
	Bob.SetKeyShare(share2)

	// Online signature generation
	hash := []byte("Cloudflare: meow meow")
	signature := SigGen(myGroup, &Alice, &Bob, hash, curve)

	// Verify the signature
	errVerify := Verify(Alice.Rx, signature, hash, pub)
	if errVerify != nil {
		b.Error("Signature verification fail")
	}

}

func benchECDSAOTSign(b *testing.B, myGroup group.Group, curve elliptic.Curve) {
	var Alice Alice
	var Bob Bob

	// Precomputation
	var alice AlicePre
	var bob BobPre
	// Set alice and bob label
	alice.label = []byte("alice")
	bob.label = []byte("bob")
	err := Precomputation(myGroup, &alice, &bob, &Alice, &Bob)
	if err != nil {
		b.Error("Precomputation fail")
	}

	// Generate key shares
	prvScalar, pub := genKey(myGroup, curve)
	share1, share2 := KeyShareGen(myGroup, prvScalar)
	Alice.SetKeyShare(share1)
	Bob.SetKeyShare(share2)

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
			Alice.SigGenInit()
			Bob.SigGenInit()
		}
	})

	beaverAlice := Alice.SigGenInit()
	beaverBob := Bob.SigGenInit()

	b.Run(curve.Params().Name+"-SignRound1", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Alice.SigGenRound1(beaverBob, hashScalar)
			Bob.SigGenRound1(beaverAlice, hashScalar)
		}
	})

	sigAlice := Alice.SigGenRound1(beaverBob, hashScalar)
	sigBob := Bob.SigGenRound1(beaverAlice, hashScalar)

	b.Run(curve.Params().Name+"-SignRound2", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			SigGenRound2(myGroup, sigAlice, sigBob)
		}
	})

	signature := SigGenRound2(myGroup, sigAlice, sigBob)

	// Verify the signature
	errVerify := Verify(Alice.Rx, signature, hash, pub)
	if errVerify != nil {
		b.Error("Signature verification fail")
	}

}

func BenchmarkECDSAOTPRE(b *testing.B) {
	pubkeyCurve := elliptic.P256()
	curr_group := group.P256
	benchECDSAOTPRE(b, curr_group, pubkeyCurve)

}

func BenchmarkECDSAOTSign(b *testing.B) {
	pubkeyCurve := elliptic.P256()
	curr_group := group.P256
	benchECDSAOTSign(b, curr_group, pubkeyCurve)
}
