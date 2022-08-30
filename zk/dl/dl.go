// Reference: https://datatracker.ietf.org/doc/html/rfc8235#page-6
// Prove the knowledge of [k] given [k]G, G and the curve where the points reside
package dl

import (
	"io"

	"github.com/cloudflare/circl/group"
)

// Input: myGroup, the group we operate in
// Input: R = [kA]DB
// Input: proverLabel, verifierLabel labels of prover and verifier
// Ouptput: (V,r), the prove such that we know kA without revealing kA
func ProveGen(myGroup group.Group, DB, R group.Element, kA group.Scalar, proverLabel, verifierLabel, dst []byte, rnd io.Reader) (group.Element, group.Scalar) {
	v := myGroup.RandomNonZeroScalar(rnd)
	V := myGroup.NewElement()
	V.Mul(DB, v)

	// Hash transcript (D_B | V | R | proverLabel | verifierLabel) to get the random coin
	DBByte, errByte := DB.MarshalBinary()
	if errByte != nil {
		panic(errByte)
	}
	VByte, errByte := V.MarshalBinary()
	if errByte != nil {
		panic(errByte)
	}

	RByte, errByte := R.MarshalBinary()
	if errByte != nil {
		panic(errByte)
	}

	hashByte := append(DBByte, VByte...)
	hashByte = append(hashByte, RByte...)
	hashByte = append(hashByte, proverLabel...)
	hashByte = append(hashByte, verifierLabel...)

	c := myGroup.HashToScalar(hashByte, dst)

	kAc := myGroup.NewScalar()
	kAc.Mul(c, kA)
	r := v.Copy()
	r.Sub(r, kAc)

	return V, r
}

// Input: myGroup, the group we operate in
// Input: R = [kA]DB
// Input: (V,r), the prove such that the prover knows kA
// Input: proverLabel, verifierLabel labels of prover and verifier
// Output: V ?= [r]D_B +[c]R
func Verify(myGroup group.Group, DB, R group.Element, V group.Element, r group.Scalar, proverLabel, verifierLabel, dst []byte) bool {
	// Hash the transcript (D_B | V | R | proverLabel | verifierLabel) to get the random coin
	DBByte, errByte := DB.MarshalBinary()
	if errByte != nil {
		panic(errByte)
	}
	VByte, errByte := V.MarshalBinary()
	if errByte != nil {
		panic(errByte)
	}

	RByte, errByte := R.MarshalBinary()
	if errByte != nil {
		panic(errByte)
	}
	hashByte := append(DBByte, VByte...)
	hashByte = append(hashByte, RByte...)
	hashByte = append(hashByte, proverLabel...)
	hashByte = append(hashByte, verifierLabel...)

	c := myGroup.HashToScalar(hashByte, dst)

	rDB := myGroup.NewElement()
	rDB.Mul(DB, r)

	cR := myGroup.NewElement()
	cR.Mul(R, c)

	rDB.Add(rDB, cR)

	return V.IsEqual(rDB)
}
