// Package frost provides the FROST threshold signature scheme for Schnorr signatures.
//
// FROST paper: https://eprint.iacr.org/2020/852
// RFC 9519: https://www.rfc-editor.org/rfc/rfc9591
package frost

import (
	"io"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/secretsharing"
)

type PrivateKey struct {
	Suite
	key       group.Scalar
	publicKey *PublicKey
}

type PublicKey struct {
	Suite
	key group.Element
}

func GenerateKey(s Suite, rnd io.Reader) PrivateKey {
	g := s.getParams().group()
	return PrivateKey{s, g.RandomNonZeroScalar(rnd), nil}
}

func (k *PrivateKey) PublicKey() PublicKey {
	if k.publicKey == nil {
		g := k.Suite.getParams().group()
		k.publicKey = &PublicKey{k.Suite, g.NewElement().MulGen(k.key)}
	}

	return *k.publicKey
}

func (k *PrivateKey) Split(rnd io.Reader, threshold, maxSigners uint) (
	peers []PeerSigner, groupPublicKey PublicKey, comm secretsharing.SecretCommitment,
) {
	ss := secretsharing.New(rnd, threshold, k.key)
	shares := ss.Share(maxSigners)
	comm = ss.CommitSecret()
	groupPublicKey = PublicKey{k.Suite, comm[0]}

	peers = make([]PeerSigner, len(shares))
	for i := range shares {
		peers[i] = PeerSigner{
			Suite:          k.Suite,
			threshold:      uint16(threshold),
			maxSigners:     uint16(maxSigners),
			keyShare:       shares[i],
			groupPublicKey: groupPublicKey,
			myPublicKey:    nil,
		}
	}

	return peers, groupPublicKey, comm
}

func Verify(msg []byte, pubKey PublicKey, signature []byte) bool {
	p := pubKey.Suite.getParams()
	g := p.group()
	params := g.Params()
	Ne, Ns := params.CompressedElementLength, params.ScalarLength
	if len(signature) < int(Ne+Ns) {
		return false
	}

	REnc := signature[:Ne]
	R := g.NewElement()
	err := R.UnmarshalBinary(REnc)
	if err != nil {
		return false
	}

	zEnc := signature[Ne : Ne+Ns]
	z := g.NewScalar()
	err = z.UnmarshalBinary(zEnc)
	if err != nil {
		return false
	}

	pubKeyEnc, err := pubKey.key.MarshalBinaryCompress()
	if err != nil {
		return false
	}

	chInput := append(append(append([]byte{}, REnc...), pubKeyEnc...), msg...)
	c := p.h2(chInput)

	l := g.NewElement().MulGen(z)
	r := g.NewElement().Mul(pubKey.key, c)
	r.Add(r, R)

	return l.IsEqual(r)
}
