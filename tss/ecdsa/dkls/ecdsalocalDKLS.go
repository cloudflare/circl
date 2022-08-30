package dkls

import (
	"crypto/rand"
	"errors"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/tss/ecdsa/dkls/fmul"
	zkRDL "github.com/cloudflare/circl/zk/dl"
	"golang.org/x/crypto/sha3"
)

// ---- Precomputation ----

// ---- Precomputation Initialization ----

// Input: myGroup, the group we operate in
// Output: DB for random nonce generation
// Output: bAs, kBInvAs for Fmul of a*b and 1/kA*1/kB
func (bob *BobPre) BobInit(myGroup group.Group) (group.Element, []group.Element, []group.Element) {
	bob.myGroup = myGroup
	// Generate multiplicative share of random nonce k
	DB := bob.initRandomNonce(myGroup)

	// Initialize Fmul of a*b and 1/kA*1/kB
	bAs, kBInvAs := bob.addShareGenInit(myGroup)

	return DB, bAs, kBInvAs
}

// ---- Precomputation Round 1 ----
// bob sends DB, bAs, kBInvAs, to alice

// Input: myGroup, the group we operate in
// Input: DB, from bob for random nonce generation
// Input: bAs, kBInvAs from Bob for Fmul of a*b and 1/kA*1/kB
// Output: Proof (V, r) that alice knows kA, where R=[kA]DB, and RPrime
// Output: aBs, kAInvBs for Fmul of a*b and 1/kA*1/kB
func (alice *AlicePre) AliceRound1(myGroup group.Group, DB group.Element, bAs, kBInvAs []group.Element, aliceLabel, bobLabel []byte) (group.Element, group.Scalar, group.Element, []group.Element, []group.Element) {
	alice.myGroup = myGroup
	// Generate multiplicative share of random nonce k
	V, r, RPrime := alice.initRandomNonce(myGroup, DB, aliceLabel, bobLabel)

	// Round 1 Fmul of a*b and 1/kA*1/kB
	aBs, kAInvBs := alice.addShareGenRound1(myGroup, bAs, kBInvAs)
	return V, r, RPrime, aBs, kAInvBs
}

// ---- Precomputation Round 2 ----
// alice sends V, r, RPrime, aBs, kAInvBs, to bob

// Input: Proof (V, r) that alice knows kA, where R=[kA]DB, and RPrime
// Input: aBs, kAInvBs for Fmul of a*b and 1/kA*1/kB
// Output: e0b, e1b, e0kBInv, e1kBInv, encryption of m0s and m1s for a*b and 1/kA*1/kB
func (bob *BobPre) BobRound2(V group.Element, r group.Scalar, RPrime group.Element, aBs, kAInvBs []group.Element, aliceLabel, bobLabel []byte) ([][]byte, [][]byte, [][]byte, [][]byte, error) {
	// Generate R and verify proof from alice
	err := bob.getRandomNonce(V, RPrime, r, aliceLabel, bobLabel)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Round 2 Fmul of a*b and 1/kA*1/kB
	e0b, e1b, e0kBInv, e1kBInv := bob.addShareGenRound2(aBs, kAInvBs)

	return e0b, e1b, e0kBInv, e1kBInv, nil
}

// ---- Precomputation Round 3 ----
// bob sends e0b, e1b, e0kBInv, e1kBInv, to alice

// Input: e0b, e1b, e0kBInv, e1kBInv, encryption of m0s and m1s for a*b and 1/kA*1/kB
// Output: sigmaa, vsa, sigmakAInv, vskAInv, Blinding sigma and Array of v for (a and kAInv)
func (alice *AlicePre) AliceRound3(e0b, e1b, e0kBInv, e1kBInv [][]byte) (group.Scalar, []group.Scalar, group.Scalar, []group.Scalar, error) {
	sigmaa, vsa, sigmakAInv, vskAInv, errDec := alice.addShareGenRound3(e0b, e1b, e0kBInv, e1kBInv)
	if errDec != nil {
		return nil, nil, nil, nil, errDec
	}
	alice.ta = alice.receivera.Returns2().Copy()
	alice.tkA = alice.receiverkAInv.Returns2().Copy()
	return sigmaa, vsa, sigmakAInv, vskAInv, nil
}

// ---- Precomputation Round 4 ----
// alice sends sigmaa, vsa, sigmakAInv, vskAInv to bob

// Input: sigmaa, vsa, sigmakAInv, vskAInv, Blinding sigma and Array of v for (a and kAInv), from alice
func (bob *BobPre) BobRound4(sigmaa, sigmakAInv group.Scalar, vsa, vskAInv []group.Scalar) {
	bob.addShareGenRound4(sigmaa, sigmakAInv, vsa, vskAInv)
	bob.tb = bob.senderb.Returns1().Copy()
	bob.tkB = bob.senderkBInv.Returns1().Copy()
}

// ---- Helper functions for precomputation ----

// ---- Negotiate random nonce k ----

// Input: myGroup, the group we operate in
// Output: DB
func (bob *BobPre) initRandomNonce(myGroup group.Group) group.Element {
	bob.kB = myGroup.RandomNonZeroScalar(rand.Reader)
	bob.kBInv = myGroup.NewScalar()
	bob.kBInv.Inv(bob.kB)
	bob.DB = myGroup.NewElement()
	bob.DB.MulGen(bob.kB)
	return bob.DB.Copy()
}

// bob sends DB to alice

// Input: myGroup, the group we operate in
// Input: DB, from bob
// Output: Proof that alice knows kA, where R=[kA]DB, and RPrime
func (alice *AlicePre) initRandomNonce(myGroup group.Group, DB group.Element, aliceLabel, bobLabel []byte) (group.Element, group.Scalar, group.Element) {
	alice.DB = DB.Copy()
	alice.kAPrime = myGroup.RandomNonZeroScalar(rand.Reader)
	alice.RPrime = myGroup.NewElement()
	alice.RPrime.Mul(alice.DB, alice.kAPrime)

	RPrimeByte, errByte := alice.RPrime.MarshalBinary()
	if errByte != nil {
		panic(errByte)
	}
	hashResult := make([]byte, myGroup.Params().ScalarLength)
	s := sha3.NewShake128()
	_, errWrite := s.Write(RPrimeByte)
	if errWrite != nil {
		panic(errWrite)
	}
	_, errRead := s.Read(hashResult)
	if errRead != nil {
		panic(errRead)
	}

	hashRPrimeScalar := myGroup.NewScalar()
	errByte = hashRPrimeScalar.UnmarshalBinary(hashResult)
	if errByte != nil {
		panic(errByte)
	}

	alice.kA = myGroup.NewScalar()
	alice.kA.Add(hashRPrimeScalar, alice.kAPrime)

	alice.kAInv = myGroup.NewScalar()
	alice.kAInv.Inv(alice.kA)

	alice.R = myGroup.NewElement()
	alice.R.Mul(alice.DB, alice.kA)
	// get Rx as the x coordinate of R
	RBinary, errByte := alice.R.MarshalBinary()
	if errByte != nil {
		panic(errByte)
	}

	xCoor := RBinary[1 : myGroup.Params().ScalarLength+1]
	alice.Rx = myGroup.NewScalar()
	errByte = alice.Rx.UnmarshalBinary(xCoor)
	if errByte != nil {
		panic(errByte)
	}

	// Construct zero knowledge proof that alice knows kA where R=[kA]DB
	dst := "zeroknowledge"
	rnd := rand.Reader
	V, r := zkRDL.ProveGen(myGroup, alice.DB, alice.R, alice.kA, aliceLabel, bobLabel, []byte(dst), rnd)

	return V, r, alice.RPrime
}

// alice sends a proof of she knows the kA for R=[kA]DB as well as R' to bob

// Input: RPrime, from alice
// Input: V, r a proof from alice that she knows kA where R=[kA]DB
func (bob *BobPre) getRandomNonce(V, RPrime group.Element, r group.Scalar, aliceLabel, bobLabel []byte) error {
	RPrimeByte, errByte := RPrime.MarshalBinary()
	if errByte != nil {
		panic(errByte)
	}

	hashResult := make([]byte, bob.myGroup.Params().ScalarLength)
	s := sha3.NewShake128()
	_, errWrite := s.Write(RPrimeByte)
	if errWrite != nil {
		panic(errWrite)
	}
	_, errRead := s.Read(hashResult)
	if errRead != nil {
		panic(errRead)
	}

	hashRPrimeScalar := bob.myGroup.NewScalar()
	errByte = hashRPrimeScalar.UnmarshalBinary(hashResult)
	if errByte != nil {
		panic(errByte)
	}

	bob.R = bob.myGroup.NewElement()
	bob.R.Mul(bob.DB, hashRPrimeScalar)
	bob.R.Add(bob.R, RPrime)

	// get Rx as the x coordinate of R
	RBinary, errByte := bob.R.MarshalBinary()
	if errByte != nil {
		panic(errByte)
	}

	xCoor := RBinary[1 : bob.myGroup.Params().ScalarLength+1]
	bob.Rx = bob.myGroup.NewScalar()
	errByte = bob.Rx.UnmarshalBinary(xCoor)
	if errByte != nil {
		panic(errByte)
	}

	// Verify the proof
	dst := "zeroknowledge"

	verify := zkRDL.Verify(bob.myGroup, bob.DB, bob.R, V, r, aliceLabel, bobLabel, []byte(dst))
	if !verify {
		return errors.New("zero knowledge proof verification fails")
	}
	return nil
}

// Now alice and bob have kA and kB
// Generate additive share of 1/kA*1/kB and random blinding a*b (For beaver's triple)
// t_kA + t_kB = 1/kA*1/kB = 1/k
// t_a + t_b = a*b
// Use Fmul subprotocol to realize this.
// bob as the sender of Fmul, alice as the receiver of Fmul

// ---- Additive shares generation Initialization ----

// Input: myGroup, the group we operate in
// Output: bAs, kBInvAs for Fmul of a*b and 1/kA*1/kB
func (bob *BobPre) addShareGenInit(myGroup group.Group) ([]group.Element, []group.Element) {
	bob.b = myGroup.RandomNonZeroScalar(rand.Reader)

	n := fmul.DecideNumOT(myGroup, 128)
	bAs := bob.senderb.SenderInit(myGroup, bob.b, n)

	kBInvAs := bob.senderkBInv.SenderInit(myGroup, bob.kBInv, n)

	return bAs, kBInvAs
}

// ---- Additive shares generation Round1 ----
// bob sends bAs, kBInvAs to alice

// Input: myGroup, the group we operate in
// Input: bAs, kBInvAs from bob
// Output: aBs, kAInvBs for Fmul of a*b and 1/kA*1/kB
func (alice *AlicePre) addShareGenRound1(myGroup group.Group, bAs, kBInvAs []group.Element) ([]group.Element, []group.Element) {
	alice.a = myGroup.RandomNonZeroScalar(rand.Reader)

	n := fmul.DecideNumOT(myGroup, 128)

	aBs := alice.receivera.ReceiverRound1(myGroup, bAs, alice.a, n)
	kAInvBs := alice.receiverkAInv.ReceiverRound1(myGroup, kBInvAs, alice.kAInv, n)

	return aBs, kAInvBs
}

// ---- Additive shares generation Round2 ----
// alice sends aBs, kAInvBs to bob

// Input: aBs, kAInvBs from alice
// Output: e0b, e1b, e0kBInv, e1kBInv, encryption of m0s and m1s for a*b and 1/kA*1/kB
func (bob *BobPre) addShareGenRound2(aBs, kAInvBs []group.Element) ([][]byte, [][]byte, [][]byte, [][]byte) {
	n := fmul.DecideNumOT(bob.myGroup, 128)
	e0b, e1b := bob.senderb.SenderRound2(aBs, n)
	e0kBInv, e1kBInv := bob.senderkBInv.SenderRound2(kAInvBs, n)

	return e0b, e1b, e0kBInv, e1kBInv
}

// ---- Additive shares generation Round3 ----
// bob sends e0b, e1b, e0kBInv, e1kBInv, to alice

// Input: e0b, e1b, e0kBInv, e1kBInv, encryption of m0s and m1s for a*b and 1/kA*1/kB
// Output: sigmaa, vsa, sigmakAInv, vskAInv, Blinding sigma and Array of v for (a and kAInv)
func (alice *AlicePre) addShareGenRound3(e0b, e1b, e0kBInv, e1kBInv [][]byte) (group.Scalar, []group.Scalar, group.Scalar, []group.Scalar, error) {
	n := fmul.DecideNumOT(alice.myGroup, 128)

	sigmaa, vsa, errDec := alice.receivera.ReceiverRound3(e0b, e1b, n)
	if errDec != nil {
		return nil, nil, nil, nil, errDec
	}
	sigmakAInv, vskAInv, errDec := alice.receiverkAInv.ReceiverRound3(e0kBInv, e1kBInv, n)
	if errDec != nil {
		return nil, nil, nil, nil, errDec
	}
	return sigmaa, vsa, sigmakAInv, vskAInv, nil
}

// ---- Additive shares generation Round4 ----
// alice sends sigmaa, vsa, sigmakAInv, vskAInv to bob

// Input: sigmaa, vsa, sigmakAInv, vskAInv, Blinding sigma and Array of v for (a and kAInv), from alice
func (bob *BobPre) addShareGenRound4(sigmaa, sigmakAInv group.Scalar, vsa, vskAInv []group.Scalar) {
	n := fmul.DecideNumOT(bob.myGroup, 128)

	bob.senderb.SenderRound4(vsa, sigmaa, n)
	bob.senderkBInv.SenderRound4(vskAInv, sigmakAInv, n)
}

// ---- Set useful parameter from AlicePre and BobPre to Alice and Bob ----

func (alice *Alice) SetParamters(alicePre *AlicePre) {
	alice.myGroup = alicePre.myGroup
	alice.a = alicePre.a.Copy()
	alice.kA = alicePre.kA.Copy()
	alice.ta = alicePre.ta.Copy()
	alice.tkA = alicePre.tkA.Copy()
	alice.Rx = alicePre.Rx.Copy()
}

func (bob *Bob) SetParamters(bobPre *BobPre) {
	bob.myGroup = bobPre.myGroup
	bob.b = bobPre.b.Copy()
	bob.kB = bobPre.kB.Copy()
	bob.tb = bobPre.tb.Copy()
	bob.tkB = bobPre.tkB.Copy()
	bob.Rx = bobPre.Rx.Copy()
}

// Receive key shares from the core

func (bob *Bob) SetKeyShare(share group.Scalar) {
	bob.keyShare = share
}

func (alice *Alice) SetKeyShare(share group.Scalar) {
	alice.keyShare = share
}

// ---- Online phase ----

// Online Round 1

// Output: skA/(kA*a), skA/kA blinded by a
func (alice *Alice) SigGenInit() group.Scalar {
	alice.beaver = alice.myGroup.NewScalar() // skA/(kA*a)
	aInv := alice.myGroup.NewScalar()
	aInv.Inv(alice.a)
	kAInv := alice.myGroup.NewScalar()
	kAInv.Inv(alice.kA)

	alice.beaver.Mul(alice.keyShare, aInv)
	alice.beaver.Mul(alice.beaver, kAInv)
	return alice.beaver.Copy()
}

// Output: skB/(kB*b), skB/kB blinded by b
func (bob *Bob) SigGenInit() group.Scalar {
	bob.beaver = bob.myGroup.NewScalar() // skB/(kB*b)
	bInv := bob.myGroup.NewScalar()
	bInv.Inv(bob.b)
	kBInv := bob.myGroup.NewScalar()
	kBInv.Inv(bob.kB)

	bob.beaver.Mul(bob.keyShare, bInv)
	bob.beaver.Mul(bob.beaver, kBInv)
	return bob.beaver.Copy()
}

// Alice and Bob sends skA/(kA*a), skB/(kB*b) to each other

// Online Round 2
// Input: beaver, skB/(kB*b)
// Input: hashScalar, the hash message as a scalar
// Output: sigShare the additive share of the final signature
func (alice *Alice) SigGenRound1(beaver group.Scalar, hashScalar group.Scalar) group.Scalar {
	askk := alice.myGroup.NewScalar() // Additive share of sk/k
	askk.Mul(alice.ta, alice.beaver)
	askk.Mul(askk, beaver)

	askk.Mul(askk, alice.Rx) // Rx * Additive share of sk/k

	sigShare := alice.myGroup.NewScalar() // Final signature share
	sigShare.Mul(hashScalar, alice.tkA)
	sigShare.Add(sigShare, askk)
	return sigShare
}

// Input: beaver, skA/(kA*a)
// Input: hashScalar, the hash message as a scalar
// Output: sigShare the additive share of the final signature
func (bob *Bob) SigGenRound1(beaver group.Scalar, hashScalar group.Scalar) group.Scalar {
	askk := bob.myGroup.NewScalar() // Additive share of sk/k
	askk.Mul(bob.tb, bob.beaver)
	askk.Mul(askk, beaver)

	askk.Mul(askk, bob.Rx) // Rx * Additive share of sk/k

	sigShare := bob.myGroup.NewScalar() // Final signature share
	sigShare.Mul(hashScalar, bob.tkB)
	sigShare.Add(sigShare, askk)
	return sigShare
}

// Either Alice or Bob can send the signature share to the other one and then combine

// Input: myGroup, the group we operate in
// Input: sigShare1, sigShare2 the 2 signature share from alice and bob
// Output: the final signature s
func SigGenRound2(myGroup group.Group, sigShare1, sigShare2 group.Scalar) group.Scalar {
	signature := myGroup.NewScalar() // Additive share of sk/k
	signature.Add(sigShare1, sigShare2)
	return signature
}
