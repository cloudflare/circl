// Assumptions and Terminology
// 1. There are n parties: p_1...p_n
// 2. Every party has a label and receives a share of the secret key from the core.
// 3. Elliptic curve E(Z_p) of order q is defined as: y^2=x^3 + ax + b (mod p)
//     where a, b in Z_p and Z_p is the underlying finite field for E.
// 4. We use Feldman TSS because every party needs to verify the msg from any other party.

package ecdsaTSS

import (
	"crypto/rand"
	"errors"

	"github.com/cloudflare/circl/secretsharing"

	"github.com/cloudflare/circl/group"
)

// Local Sign functions

// During online round, the metals will construct their own signature share upon receiving the message
// Input: currParty, the local party
func (currParty *partySign) LocalGenSignatureShare() {
	currParty.sharesig.Share.Mul(currParty.r, currParty.sharesk.Share)
	currParty.sharesig.Share.Add(currParty.sharesig.Share, currParty.hashMSG)
	currParty.sharesig.Share.Mul(currParty.sharesig.Share, currParty.sharekInv.Share)
}

// Initiate local party parameters for final round of signature generation
// Input: i, this party index
// Input: currParty, the local party
// Input: preSign, the same party with preSign informations
// Input: myGroup, the group we operate in
func (currParty *partySign) LocalInit(i uint, myGroup group.Group, preSign partyPreSign) {
	currParty.myGroup = preSign.myGroup
	currParty.index = i
	currParty.sharekInv.ID = i
	currParty.sharekInv.Share = preSign.sharekInv.Share.Copy()
	currParty.r = myGroup.NewScalar()
	currParty.r = preSign.r.Copy()
	currParty.sharesk.ID = i
	currParty.sharesk.Share = myGroup.NewScalar()
	currParty.sharesk.Share.SetUint64(uint64(0))
	currParty.sharesig.ID = i
	currParty.sharesig.Share = myGroup.NewScalar()
	currParty.sharesig.Share.SetUint64(uint64(0))
	currParty.hashMSG = myGroup.NewScalar()
}

// Input: currParty, the local party
// Input: sssk, the share of secret key
func (currParty *partySign) Setss(sssk group.Scalar) {
	currParty.sharesk.Share = sssk.Copy()
}

func (currParty *partySign) SetMSG(hashMSG group.Scalar) {
	currParty.hashMSG = hashMSG.Copy()
}

// Local Pre computation functions

// Initiate local party parameters for preComputation
// Input: i, this party index
// Input: n, the number of parties
// Input: currParty, the local party
// Input: myGroup, the group we operate in
func (currParty *partyPreSign) LocalInit(i, n uint, myGroup group.Group) {
	currParty.index = i
	currParty.myGroup = myGroup
	currParty.sharek.ID = i
	currParty.sharek.Share = myGroup.NewScalar()
	currParty.sharek.Share.SetUint64(uint64(0))
	currParty.shareb.ID = i
	currParty.shareb.Share = myGroup.NewScalar()
	currParty.shareb.Share.SetUint64(uint64(0))
	currParty.sharekb.ID = i
	currParty.sharekb.Share = myGroup.NewScalar()
	currParty.sharekb.Share.SetUint64(uint64(0))
	currParty.sharekInv.ID = i
	currParty.sharekInv.Share = myGroup.NewScalar()
	currParty.sharekInv.Share.SetUint64(uint64(0))
	currParty.sharekG = myGroup.NewElement()
	currParty.obfCoefks = make([][]group.Element, n)
	currParty.obfCoefbs = make([][]group.Element, n)
}

// Generate the local party information for nonce k and blinding b,
// later will be used in Feldman secret sharing to construct shares of the nonce k and k^{-1}
// Input: t, the threshold parameter
// Input: n, the number of parties
// Input: currParty, the local party
func (currParty *partyPreSign) LocalGenkb(t, n uint) {

	// first coefficient of secret polynomial k_i for this party i
	currParty.polyki = currParty.myGroup.RandomNonZeroScalar(rand.Reader)
	vs, err := secretsharing.NewVerifiable(currParty.myGroup, t, n)
	if err != nil {
		panic(err)
	}
	currParty.sski, currParty.obfCoefki = vs.Shard(rand.Reader, currParty.polyki)

	// secret polynomial b_i for this party i
	currParty.polybi = currParty.myGroup.RandomNonZeroScalar(rand.Reader)
	vs, err = secretsharing.NewVerifiable(currParty.myGroup, t, n)
	if err != nil {
		panic(err)
	}
	// the shares of polynomial b_i for every single party in the game and the obfuscated coefficient for proving correctness
	currParty.ssbi, currParty.obfCoefbi = vs.Shard(rand.Reader, currParty.polybi)

	currParty.sharek = currParty.sski[currParty.index-1]
	currParty.shareb = currParty.ssbi[currParty.index-1]
}

// Update local shares of k and b
// Input: t, the threshold parameter
// Input: n, the number of parties
// Input: sharekUpdate, update for nonce k share from other party
// Input: sharebUpdate, update for blinding b share from other party
// Input: obfCoefk, the obfuscated coefficient (commitment) as for proving correctness of sharekUpdate
// Input: obfCoefb, the obfuscated coefficient (commitment) as for proving correctness of sharebUpdate
// Input: currParty, the local party
// Input: fromIndex, the index of the party who sends this update
// Output: fromIndex if Feldman check fails, otherwise 0
func (currParty *partyPreSign) LocalUpdatekb(t, n uint, sharekUpdate, sharebUpdate secretsharing.Share, obfCoefk, obfCoefb []group.Element, fromIndex uint) uint {
	currParty.sharek.Share.Add(currParty.sharek.Share, sharekUpdate.Share)
	vs, err := secretsharing.NewVerifiable(currParty.myGroup, t, n)
	if err != nil {
		panic(err)
	}
	check := vs.Verify(sharekUpdate, obfCoefk)
	if !check {
		return fromIndex
	}

	currParty.shareb.Share.Add(currParty.shareb.Share, sharebUpdate.Share)
	vs, err = secretsharing.NewVerifiable(currParty.myGroup, t, n)
	if err != nil {
		panic(err)
	}
	check = vs.Verify(sharebUpdate, obfCoefb)
	if !check {
		return fromIndex
	}

	return 0
}

// Compute shares for k*b as sharek*shareb
// Input: currParty, the local party
func (currParty *partyPreSign) LocalSharekb() {
	currParty.sharekb.Share.Mul(currParty.sharek.Share, currParty.shareb.Share)
}

// Compute [sharek]G
// Input: currParty, the local party
func (currParty *partyPreSign) LocalkG() {
	currParty.sharekG.MulGen(currParty.sharek.Share)
}

// Local party as a combiner collects shares for kb and computes kb^{-1}
// Input: t, the threshold parameter
// Input: n, the number of parties
// Input: currParty, the local party
// Input: shareskb, the shares for kb from other parties
// Output: kb^{-1} and possible error
func (currParty *partyPreSign) CombinerCompkbInv(t, n uint, shareskb []secretsharing.Share) (group.Scalar, error) {
	s, err := secretsharing.New(currParty.myGroup, t, n)
	if err != nil {
		panic(err)
	}
	kb, err := s.Recover(shareskb)
	kbInv := currParty.myGroup.NewScalar()
	kbInv.Inv(kb)
	return kbInv, err
}

// Local party as a combiner collects shares for [sharek]G and computes [k]G
// Input: t, the threshold parameter
// Input: n, the number of parties
// Input: currParty, the local party
// Input: shareskG, the shares for [k]G from other parties
// Input: indexes, the indexes for all other parties
// Output: x coordinate of [k]G and possible error
func (currParty *partyPreSign) CombinerCompkG(t, n uint, shareskG []group.Element, indexes []group.Scalar) (group.Scalar, error) {
	resultkG, errkG := lagrangeInterpolatePoint(t, currParty.myGroup, shareskG, indexes)
	if errkG != nil {
		return nil, errkG
	}

	kGBinary, errBinary := resultkG.MarshalBinary()
	if errBinary != nil {
		panic(errBinary)
	}

	xCoor := kGBinary[1 : currParty.myGroup.Params().ScalarLength+1]
	xScalar := currParty.myGroup.NewScalar()
	errBinary = xScalar.UnmarshalBinary(xCoor)
	if errBinary != nil {
		panic(errBinary)
	}
	return xScalar, nil
}

// Set the x coordinate of [k]G as r
// Input: currParty, the local party
// Input: xCoor, the x coordinate of [k]G
func (currParty *partyPreSign) Setr(xCoor group.Scalar) {
	currParty.r = xCoor.Copy()
}

// Compute share of k^{-1} as (kb)^{-1}*shareb
// Input: currParty, the local party
// Input: kbInv, the (kb)^{-1}
func (currParty *partyPreSign) LocalSharekInv(kbInv group.Scalar) {
	currParty.kbInv = kbInv.Copy()
	currParty.sharekInv.Share.Mul(currParty.kbInv, currParty.shareb.Share)
}

// Helper functions

// Check everyone receives the same coefficient for Feldman
// Input: t, the threshold parameter
// Input: obfCoefj, the obfuscated coefficient for f_i send to party j
// Input: obfCoefk, the obfuscated coefficient for f_i send to party k
// Ouput: true if obfCoefj == obfCoefk, false otherwise.
func checkObf(t uint, obfCoefj []group.Element, obfCoefk []group.Element) bool {
	check := true
	for i := uint(0); i < t+1; i++ {
		if !(obfCoefj[i].IsEqual(obfCoefk[i])) {
			check = false
		}
	}
	return check
}

// Lagrange Interpolation of y as element but not scalar

// Input: myGroup, the group we operate in
// Input: targetIndex, the i
// Input: currShare, the [y_i]G
// Input: indexes, the indexes for each party
// Output: Compute a single [f_i(0)]G
func lagrangeSinglePoint(myGroup group.Group, targetIndex int, currShare group.Element, indexes []group.Scalar) group.Element {
	// f_i(0) = y_i[G]
	result := currShare.Copy()

	// x_i
	targetLabel := (indexes)[targetIndex].Copy()

	interValue := myGroup.NewScalar()
	invValue := myGroup.NewScalar()

	for k := 0; k < len(indexes); k++ {
		//f_i(0) = f_i(0) * (0-x_k)/(x_i-x_k)
		if k != targetIndex {
			// x_k
			currLabel := (indexes)[k].Copy()

			// f_i(0) * (0-x_k)
			interValue.SetUint64(uint64(0))
			interValue.Sub(interValue, currLabel)
			result.Mul(result, interValue)

			// (x_i-x_k)
			invValue.Sub(targetLabel, currLabel)
			invValue.Inv(invValue)
			result.Mul(result, invValue)

		}
	}
	return result
}

// Input: t, the threshold, we need at least t+1 points for Lagrange Interpolation
// Input: myGroup, the group we operate in
// Input: ss, the secret shares multiplied by generator G
// Input: indexes, the indexes for each party
// Ouput: the re-constructed secret [f(0)]G
func lagrangeInterpolatePoint(t uint, myGroup group.Group, ss []group.Element, indexes []group.Scalar) (group.Element, error) {
	if uint(len(ss)) < t+1 {
		return nil, errors.New("need at least t+1 points to do Lagrange Interpolation")
	}

	secret := myGroup.NewElement()
	for i := 0; i < len(ss); i++ {
		fi := lagrangeSinglePoint(myGroup, i, ss[i], indexes)
		if i == 0 {
			secret.Set(fi)
		} else {
			secret.Add(secret, fi)
		}
	}

	return secret, nil
}
