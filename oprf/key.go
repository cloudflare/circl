package oprf

import "github.com/cloudflare/circl/group"

// KeyPair is an struct containing a public and private key.
type KeyPair struct {
	id         SuiteID
	publicKey  group.Element
	privateKey group.Scalar
}

// Serialize serializes a KeyPair elements into byte arrays.
func (kp *KeyPair) Serialize() ([]byte, error) { return kp.privateKey.MarshalBinary() }

// Deserialize deserializes a KeyPair into an element and field element of the group.
func (kp *KeyPair) Deserialize(id SuiteID, encoded []byte) error {
	suite, err := suiteFromID(id, BaseMode)
	if err != nil {
		return err
	}
	privateKey := suite.NewScl()
	err = privateKey.UnmarshalBinary(encoded)
	if err != nil {
		return err
	}
	publicKey := suite.NewElt()
	publicKey.MulGen(privateKey)

	kp.id = id
	kp.publicKey = publicKey
	kp.privateKey = privateKey

	return nil
}

// GenerateKeyPair generates a KeyPair in accordance with the group.
func GenerateKeyPair(id SuiteID) (*KeyPair, error) {
	suite, err := suiteFromID(id, BaseMode)
	if err != nil {
		return nil, err
	}
	return suite.generateKeyPair(), nil
}
