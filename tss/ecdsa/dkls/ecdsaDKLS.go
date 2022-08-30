// Reference: https://eprint.iacr.org/2018/499.pdf
// 2 out of 2 party threhsold signature scheme
// Figure 1 and Protocol 1 and 2

package dkls

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
