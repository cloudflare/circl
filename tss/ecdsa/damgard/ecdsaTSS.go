// Assumptions and Terminology
// 1. There are n parties: p_1...p_n
// 2. Every party has a label and receives a share of the secret key from the core.
// 3. Elliptic curve E(Z_p) of order q is defined as: y^2=x^3 + ax + b (mod p)
//     where a, b in Z_p and Z_p is the underlying finite field for E.
// 4. We use Feldman TSS because every party needs to verify the msg from any other party.

// Background:
// ECDSA signing: Input secret key sk
// 1. Generate a random nonce k.
// 2. Compute k[G] and get its x coordinate as r. Back to step 1 if r = 0.
// 3. Compute s = k^{-1}(H(m)+sk*r). Back to step 1 if s = 0.
// 4. Signature is (r,s).

// ECDSA Threshold Signature with Feldman secret sharing
// 1. Every party p_i has a share of the secret key, sharesk, and a share of the public key, shareskG: [sharesk]G.
// 2. Round 1: Parties use Feldman to jointly get shares, sharek, for nonce k.
//             Parties use Feldman to jointly get shares, shareb, for a blinding b, which is used to derived k^{-1}.
//             Party j needs to broadcast Feldman Coefficients received from Party i to all other parties and make sure everyone receives the same.
//             Local: Parties compute shares, sharekb, for k*b locally.
// 3. Round 2: A combiner is responsible for collect sharekb and compute kb and (kb)^{-1} and broadcast `kb` to all parties.
//             A combiner is responsible for collect [sharek]G and compute [k]G and broadcasts x coordinate of [k]G to all parties.
//             All parties upon receiving (kb)^{-1}, compute (kb)^{-1}*shareb as share of k^{-1}
// 4. Online round 3: message hash arrived.
//                    To finish the online round for signature generation, we need:
//                        a. sharesk, shares for the secret key (core gave us).
//                        b. r, xoordinate of [k]G (Step3).
//                        c. hashMSG, the hash of message to be signed (Just arrived).
//                        d. sharekInv, shares of the k^{-1} (Step3).
//                    All above are ready, parties can locally compute the signature share, sharesig, as sharekInv*(hashMSG+sharesk*r)
//                    A combiner is responsible for collect sharesig and compute the final signature sig = (r, s) and verify it with the public key.
//
//
//
// Security:
// 1. Note this scheme has a major drawback: leaking of t+1 shares is enough to compromise the secret key.,
//    but 2t+1 parties are required to reconstruct the signature in step 3.
// 2. Any party fails to pass Feldman check in Round 1 should be marked as malicious.
// 3. Any party caught broadcasting different Feldman Coefficients should be marked as malicious.
//
// Limitation: Require at least 3 parties in the pre-computation phase and recontruction phase
package ecdsaTSS

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/secretsharing"
)

// Upon receiving the secret key, f0, from customer,
// Dealer/Core generates a secret polynomial, f, for further generating party shares.
// Input: t, the threshold parameter
// Input: n, the number of parties
// Input: myGroup, the group we operate in
// Input: f0, the secret key also will be the first coefficient of polynomial f
// Output: shares of the secret key for n parties
func genSecretShare(t, n uint, myGroup group.Group, f0 group.Scalar) []secretsharing.Share {

	s, err := secretsharing.New(myGroup, t, n)
	if err != nil {
		panic(err)
	}

	shares := s.Shard(rand.Reader, f0)

	return shares
}

// Jointly and sequentially compute shares for the nonce k , k^{-1} as well as x coordinate of [k]G
// Input: t, the threshold parameter
// Input: n, the number of parties
// Input: myGroup, the group we operate in
// Input: parties, the parties of size n
func PreSign(t, n uint, myGroup group.Group, parties []partyPreSign) error {
	// Local: Parties initiate the parameters
	for i := uint(0); i < n; i++ {
		parties[i].LocalInit(i+1, n, myGroup)
	}

	// Local: Parties generate their local information for nonce k and blinding b
	for i := uint(0); i < n; i++ {
		parties[i].LocalGenkb(t, n)
	}

	// Round 1
	// Parties broadcast their local information for nonce k and blinding b
	// From party i to party j
	for i := uint(0); i < n; i++ {
		for j := uint(0); j < n; j++ {
			if i != j {
				errorLable := parties[j].LocalUpdatekb(t, n, parties[i].sski[j], parties[i].ssbi[j], parties[i].obfCoefki, parties[i].obfCoefbi, i)
				if errorLable != 0 {
					return errors.New("feldman verification failed")
				}
			}
			parties[j].obfCoefks[i] = parties[i].obfCoefki
			parties[j].obfCoefbs[i] = parties[i].obfCoefbi
		}
	}

	// Party j broadcast feldman coefficient received from party i to all other parties and everyone confirm they receive the same
	for j := uint(0); j < n; j++ {
		for i := uint(0); i < n; i++ {
			// party j sends feldman coefficient received from party i to party l!=i or j
			if i != j {
				for l := uint(0); l < n; l++ {
					if (l != i) && (l != j) {
						check := checkObf(t, parties[j].obfCoefbs[i], parties[l].obfCoefbs[i])
						if !check {
							return errors.New("broadcasting feldman coefficient failed")
						}
						check = checkObf(t, parties[j].obfCoefks[i], parties[l].obfCoefks[i])
						if !check {
							return errors.New("broadcasting feldman coefficient failed")
						}
					}
				}
			}

		}
	}

	// Local: Parties compute shares for k*b and [sharek]G
	sskb := make([]secretsharing.Share, n)
	for i := uint(0); i < n; i++ {
		parties[i].LocalSharekb()
		parties[i].LocalkG()
		sskb[i].ID = parties[i].sharekb.ID
		sskb[i].Share = parties[i].sharekb.Share.Copy()
	}

	// Round 2
	// A combiner, assume party 0, combines shares for kb and compute (kb)^{-1}
	if n < (2*t + 1) {
		return errors.New("at least 2t+1 parties are required for computing multiplication")
	}

	kbInv, err := parties[0].CombinerCompkbInv(t, n, sskb)
	if err != nil {
		return err
	}

	// A combiner, assume party 0, combines shares for [sharek]G, compute [k]G
	sskG := make([]group.Element, n)
	indexes := make([]group.Scalar, n)
	for i := uint(0); i < n; i++ {
		sskG[i] = parties[i].sharekG
		indexes[i] = myGroup.NewScalar()
		indexes[i].SetUint64(uint64(parties[i].index))
	}

	xCoor, err := parties[0].CombinerCompkG(t, n, sskG, indexes)
	if err != nil {
		return err
	}

	// Combiner informs all other party of (kb)^{-1}, and all party computes (kb)^{-1}*shareb as share of k^{-1}
	// Combiner broadcasts x coordinate of [k]G
	for i := uint(0); i < n; i++ {
		parties[i].Setr(xCoor)
	}

	for i := uint(0); i < n; i++ {
		parties[i].LocalSharekInv(kbInv)
	}

	return nil
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

// During online round, all metals construct their own signature share upon receiving the message
// Input: n, the number of parties
// Input: myGroup, the group we operate in
func genSignatureShare(n uint, myGroup group.Group, parties []partySign) {
	for i := uint(0); i < n; i++ {
		parties[i].LocalGenSignatureShare()
	}
}

// ECDSA threshold signature generation
// Input: t, the threshold parameter
// Input: nPrime, the number of parties involved in the final signature generation
// Input: myGroup, the group we operate in
// Input: parties, the parties of size n
// Input: msg, the message hash
// curve: curve, the curve we operate in
// Output: signature (r,s) or possible error
func Sign(t, nPrime uint, myGroup group.Group, sharesk []secretsharing.Share, parties []partySign, preParties []partyPreSign, msg []byte, curve elliptic.Curve) (group.Scalar, group.Scalar, error) {

	// Local: Parties initiate the parameters
	for i := uint(0); i < nPrime; i++ {
		parties[i].LocalInit(i+1, myGroup, preParties[i])
		parties[i].Setss(sharesk[i].Share)
	}

	msgBig := hashToInt(msg, curve)
	msgByte := msgBig.Bytes()

	hashScalar := myGroup.NewScalar()
	errBinary := hashScalar.UnmarshalBinary(msgByte)
	if errBinary != nil {
		panic(errBinary)
	}
	// Every party gets the hash Scalar
	for i := uint(0); i < nPrime; i++ {
		parties[i].SetMSG(hashScalar)
	}

	// Parties generate signature online round 3
	genSignatureShare(nPrime, myGroup, parties)

	// A combiner interpolate the signature
	sigShares := make([]secretsharing.Share, nPrime)
	for i := uint(0); i < nPrime; i++ {
		sigShares[i].ID = parties[i].sharesig.ID
		sigShares[i].Share = parties[i].sharesig.Share.Copy()
	}
	s, err := secretsharing.New(parties[0].myGroup, t, nPrime)
	if err != nil {
		panic(err)
	}
	signature, err := s.Recover(sigShares)
	if err != nil {
		return nil, nil, err
	}
	return parties[0].r, signature, nil
}

// ECDSA threshold signature verification
// Input: (r,s), the signature
// Input: hashMSG, the message
// Input: publicKey, the ECDSA public key
// Output: verification passed or not
func Verify(r, s group.Scalar, hashMSG []byte, publicKey *ecdsa.PublicKey) error {
	rBig := new(big.Int)
	sBig := new(big.Int)

	rByte, errBinary := r.MarshalBinary()
	if errBinary != nil {
		panic(errBinary)
	}
	rBig.SetBytes(rByte)

	sByte, errBinary := s.MarshalBinary()
	if errBinary != nil {
		panic(errBinary)
	}
	sBig.SetBytes(sByte)

	verify := ecdsa.Verify(publicKey, hashMSG, rBig, sBig)
	if !verify {
		return errors.New("ECDSA threshold verification failed")
	}
	return nil
}
