package oprf

import (
	"github.com/cloudflare/circl/group"
)

type PrivateKey struct {
	SuiteID
	group.Scalar
}
type PublicKey struct {
	SuiteID
	group.Element
}

func (k *PrivateKey) Serialize() ([]byte, error) { return k.Scalar.MarshalBinary() }
func (k *PublicKey) Serialize() ([]byte, error)  { return k.Element.MarshalBinary() }

func (k *PrivateKey) Deserialize(id SuiteID, data []byte) error {
	suite, err := suiteFromID(id, BaseMode)
	if err != nil {
		return err
	}
	k.SuiteID = id
	k.Scalar = suite.Group.NewScalar()
	return k.Scalar.UnmarshalBinary(data)
}

func (k *PublicKey) Deserialize(id SuiteID, data []byte) error {
	suite, err := suiteFromID(id, BaseMode)
	if err != nil {
		return err
	}
	k.SuiteID = id
	k.Element = suite.Group.NewElement()
	return k.Element.UnmarshalBinary(data)
}

func (k *PrivateKey) Public() *PublicKey {
	suite, _ := suiteFromID(k.SuiteID, BaseMode)
	publicKey := suite.Group.NewElement()
	publicKey.MulGen(k.Scalar)
	return &PublicKey{k.SuiteID, publicKey}
}

// GenerateKey generates a pair of keys in accordance with the suite.
func GenerateKey(id SuiteID) (*PrivateKey, error) {
	suite, err := suiteFromID(id, BaseMode)
	if err != nil {
		return nil, err
	}
	return suite.generateKey(), nil
}
