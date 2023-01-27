// Package dl provides a Schnorr NIZK discrete-log proof.
//
// This package implements a Schnorr NIZK discrete-log proof obtained from the
// interactive Schnorr identification scheme through a Fiat-Shamir transformation.
//
// Given (k,G,kG) the Prove function returns a Proof struct attesting that
// kG = [k]G, which can be validated using the Verify function.
//
// The userID label is a unique identifier for the prover.
//
// The otherInfo label is defined to allow flexible inclusion of contextual
// information in the Schnorr NIZK proof.
// The otherInfo is also used as a domain separation tag (dst) for the hash
// to scalar function.
//
// Reference: https://datatracker.ietf.org/doc/html/rfc8235
package dl

import (
	"encoding/binary"
	"io"

	"github.com/cloudflare/circl/group"
)

type Proof struct {
	V group.Element
	R group.Scalar
}

func calcChallenge(myGroup group.Group, G, V, A group.Element, userID, otherInfo []byte) group.Scalar {
	// Hash transcript (G | V | A | UserID | OtherInfo) to get the random coin.
	GByte, errByte := G.MarshalBinary()
	if errByte != nil {
		panic(errByte)
	}
	VByte, errByte := V.MarshalBinary()
	if errByte != nil {
		panic(errByte)
	}
	AByte, errByte := A.MarshalBinary()
	if errByte != nil {
		panic(errByte)
	}

	uPrefix := [4]byte{}
	binary.BigEndian.PutUint32(uPrefix[:], uint32(len(userID)))
	oPrefix := [4]byte{}
	binary.BigEndian.PutUint32(oPrefix[:], uint32(len(otherInfo)))

	hashByte := append(append(append(append(append(append(
		GByte, VByte...), AByte...),
		uPrefix[:]...), userID...),
		oPrefix[:]...), otherInfo...)

	return myGroup.HashToScalar(hashByte, otherInfo)
}

// Prove returns a proof attesting that kG = [k]G.
func Prove(myGroup group.Group, G, kG group.Element, k group.Scalar, userID, otherInfo []byte, rnd io.Reader) Proof {
	v := myGroup.RandomNonZeroScalar(rnd)
	V := myGroup.NewElement()
	V.Mul(G, v)

	c := calcChallenge(myGroup, G, V, kG, userID, otherInfo)

	r := myGroup.NewScalar()
	r.Sub(v, myGroup.NewScalar().Mul(k, c))

	return Proof{V, r}
}

// Verify checks whether the proof attests that kG = [k]G.
func Verify(myGroup group.Group, G, kG group.Element, p Proof, userID, otherInfo []byte) bool {
	c := calcChallenge(myGroup, G, p.V, kG, userID, otherInfo)

	rG := myGroup.NewElement()
	rG.Mul(G, p.R)

	ckG := myGroup.NewElement()
	ckG.Mul(kG, c)

	rG.Add(rG, ckG)

	return p.V.IsEqual(rG)
}
