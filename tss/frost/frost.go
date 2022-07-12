// Package frost provides the FROST threshold signature scheme for Schnorr signatures.
//
// References
//
//	FROST paper: https://eprint.iacr.org/2020/852
//	draft-irtf-cfrg-frost: https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost
//
// Version supported: v11
package frost

import (
	"io"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/secretsharing"
)

type PrivateKey struct {
	Suite
	key    group.Scalar
	pubKey *PublicKey
}

type PublicKey struct {
	Suite
	key group.Element
}

func GenerateKey(s Suite, rnd io.Reader) *PrivateKey {
	return &PrivateKey{s, s.g.RandomNonZeroScalar(rnd), nil}
}

func (k *PrivateKey) Public() *PublicKey {
	return &PublicKey{k.Suite, k.Suite.g.NewElement().MulGen(k.key)}
}

func (k *PrivateKey) Split(rnd io.Reader, threshold, maxSigners uint) (
	[]PeerSigner, secretsharing.SecretCommitment, error,
) {
	ss := secretsharing.New(rnd, threshold, k.key)
	shares := ss.Share(maxSigners)

	peers := make([]PeerSigner, len(shares))
	for i := range shares {
		peers[i] = PeerSigner{
			Suite:      k.Suite,
			threshold:  uint16(threshold),
			maxSigners: uint16(maxSigners),
			keyShare: secretsharing.Share{
				ID:    shares[i].ID,
				Value: shares[i].Value,
			},
			myPubKey: nil,
		}
	}

	return peers, ss.CommitSecret(), nil
}

func Verify(s Suite, pubKey *PublicKey, msg, signature []byte) bool {
	params := s.g.Params()
	Ne, Ns := params.CompressedElementLength, params.ScalarLength
	if len(signature) < int(Ne+Ns) {
		return false
	}

	REnc := signature[:Ne]
	R := s.g.NewElement()
	err := R.UnmarshalBinary(REnc)
	if err != nil {
		return false
	}

	zEnc := signature[Ne : Ne+Ns]
	z := s.g.NewScalar()
	err = z.UnmarshalBinary(zEnc)
	if err != nil {
		return false
	}

	pubKeyEnc, err := pubKey.key.MarshalBinaryCompress()
	if err != nil {
		return false
	}

	chInput := append(append(append([]byte{}, REnc...), pubKeyEnc...), msg...)
	c := s.hasher.h2(chInput)

	l := s.g.NewElement().MulGen(z)
	r := s.g.NewElement().Mul(pubKey.key, c)
	r.Add(r, R)

	return l.IsEqual(r)
}
