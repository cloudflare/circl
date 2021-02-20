package oprf

import (
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

// GenerateKey generates a pair of keys in accordance with the suite.
func GenerateKey(id SuiteID) (*PrivateKey, error) {
	suite, err := suiteFromID(id, BaseMode)
	if err != nil {
		return nil, err
	}
	return suite.generateKey(), nil
}
