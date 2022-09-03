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
//  1. Every party p_i has a share of the secret key, sharesk, and a share of the public key, shareskG: [sharesk]G.
//  2. Round 1: Parties use Feldman to jointly get shares, sharek, for nonce k.
//     Parties use Feldman to jointly get shares, shareb, for a blinding b, which is used to derived k^{-1}.
//     Party j needs to broadcast Feldman Coefficients received from Party i to all other parties and make sure everyone receives the same.
//     Local: Parties compute shares, sharekb, for k*b locally.
//  3. Round 2: A combiner is responsible for collect sharekb and compute kb and (kb)^{-1} and broadcast `kb` to all parties.
//     A combiner is responsible for collect [sharek]G and compute [k]G and broadcasts x coordinate of [k]G to all parties.
//     All parties upon receiving (kb)^{-1}, compute (kb)^{-1}*shareb as share of k^{-1}
//  4. Online round 3: message hash arrived.
//     To finish the online round for signature generation, we need:
//     a. sharesk, shares for the secret key (core gave us).
//     b. r, xoordinate of [k]G (Step3).
//     c. hashMSG, the hash of message to be signed (Just arrived).
//     d. sharekInv, shares of the k^{-1} (Step3).
//     All above are ready, parties can locally compute the signature share, sharesig, as sharekInv*(hashMSG+sharesk*r)
//     A combiner is responsible for collect sharesig and compute the final signature sig = (r, s) and verify it with the public key.
//
// Security:
//  1. Note this scheme has a major drawback: leaking of t+1 shares is enough to compromise the secret key.,
//     but 2t+1 parties are required to reconstruct the signature in step 3.
//  2. Any party fails to pass Feldman check in Round 1 should be marked as malicious.
//  3. Any party caught broadcasting different Feldman Coefficients should be marked as malicious.
//
// Limitation: Require at least 3 parties in the pre-computation phase and recontruction phase
package hstmaj

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
