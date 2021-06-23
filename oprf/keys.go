package oprf

import (
	"io"

	"github.com/cloudflare/circl/group"
)

type PrivateKey struct {
	s SuiteID
	k group.Scalar
}
type PublicKey struct {
	s SuiteID
	e group.Element
}

func (k *PrivateKey) Serialize() ([]byte, error) { return k.k.MarshalBinary() }
func (k *PublicKey) Serialize() ([]byte, error)  { return k.e.MarshalBinaryCompress() }

func (k *PrivateKey) Deserialize(id SuiteID, data []byte) error {
	suite, err := suiteFromID(id, BaseMode)
	if err != nil {
		return err
	}
	k.s = id
	k.k = suite.Group.NewScalar()
	return k.k.UnmarshalBinary(data)
}

func (k *PublicKey) Deserialize(id SuiteID, data []byte) error {
	suite, err := suiteFromID(id, BaseMode)
	if err != nil {
		return err
	}
	k.s = id
	k.e = suite.Group.NewElement()
	return k.e.UnmarshalBinary(data)
}

func (k *PrivateKey) Public() *PublicKey {
	suite, _ := suiteFromID(k.s, BaseMode)
	publicKey := suite.Group.NewElement()
	publicKey.MulGen(k.k)
	return &PublicKey{k.s, publicKey}
}

// GenerateKey generates a pair of keys in accordance with the suite. Panics if
// rnd is nil.
func GenerateKey(id SuiteID, rnd io.Reader) (*PrivateKey, error) {
	suite, err := suiteFromID(id, BaseMode)
	if err != nil {
		return nil, err
	}
	if rnd == nil {
		panic("rnd must be an non-nil io.Reader")
	}
	privateKey := suite.Group.RandomScalar(rnd)
	return &PrivateKey{suite.SuiteID, privateKey}, nil
}

// DeriveKey derives a pair of keys given a seed and in accordance with the suite and mode.
func DeriveKey(id SuiteID, mode Mode, seed []byte) (*PrivateKey, error) {
	suite, err := suiteFromID(id, mode)
	if err != nil {
		return nil, err
	}
	privateKey := suite.Group.HashToScalar(seed, suite.getDST(hashToScalarDST))
	return &PrivateKey{suite.SuiteID, privateKey}, nil
}
