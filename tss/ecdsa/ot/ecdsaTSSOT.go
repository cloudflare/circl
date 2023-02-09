// Reference: https://eprint.iacr.org/2018/499.pdf
// 2 out of 2 party threhsold signature scheme
// Figure 1 and Protocol 1 and 2

package ECDSAOT

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/cloudflare/circl/group"
)

// Input: myGroup, the group we operate in
// Input: sk, the real secret key
// Output: share1, share2 the multiplicative secret key shares for 2 parties.
func KeyShareGen(myGroup group.Group, sk group.Scalar) (group.Scalar, group.Scalar) {
	share1 := myGroup.RandomNonZeroScalar(rand.Reader)
	share1Inv := myGroup.NewScalar()
	share1Inv.Inv(share1)

	share2 := myGroup.NewScalar()
	share2.Mul(share1Inv, sk)

	return share1, share2
}

// Input: myGroup, the group we operate in
// Output: precomputation information for signature generation
func Precomputation(myGroup group.Group, alice *AlicePre, bob *BobPre, Alice *Alice, Bob *Bob) error {

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
func SigGen(myGroup group.Group, Alice *Alice, Bob *Bob, hash []byte, curve elliptic.Curve) group.Scalar {
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

func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

// ECDSA threshold signature verification
// Input: (r,s), the signature
// Input: hashMSG, the message
// Input: publicKey, the ECDSA public key
// Output: verification passed or not
func Verify(r, s group.Scalar, hashMSG []byte, publicKey *ecdsa.PublicKey) error {
	rBig := new(big.Int)
	sBig := new(big.Int)

	rByte, errByte := r.MarshalBinary()
	if errByte != nil {
		panic(errByte)
	}
	rBig.SetBytes(rByte)

	sByte, errByte := s.MarshalBinary()
	if errByte != nil {
		panic(errByte)
	}
	sBig.SetBytes(sByte)

	verify := ecdsa.Verify(publicKey, hashMSG, rBig, sBig)
	if !verify {
		return errors.New("ECDSA threshold verification failed")
	}
	return nil
}
