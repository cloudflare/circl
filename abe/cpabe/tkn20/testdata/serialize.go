//go:build exclude

package main

import (
	"log"
	"os"

	"code.cfops.it/crypto/cpabe"
)

func main() {
	publicParams, secretParams, err := cpabe.Setup()
	ppData, err := publicParams.MarshalBinary()
	if err != nil {
		log.Fatal(err)
	}
	err = os.WriteFile("publicKey", ppData, 0o400)
	if err != nil {
		log.Fatal(err)
	}
	spData, err := secretParams.MarshalBinary()
	if err != nil {
		log.Fatal(err)
	}
	err = os.WriteFile("secretKey", spData, 0o400)
	if err != nil {
		log.Fatal(err)
	}
	attrs := cpabe.Attributes{}
	attrs.FromMap(map[string]string{"country": "NL", "EU": "true"})

	policy := cpabe.Policy{}
	err = policy.FromString("EU: true")
	if err != nil {
		log.Fatal(err)
	}
	ciphertext, err := publicParams.Encrypt(policy, []byte("Be sure to drink your ovaltine!"))
	if err != nil {
		log.Fatal(err)
	}
	err = os.WriteFile("ciphertext", ciphertext, 0o400)
	if err != nil {
		log.Fatal(err)
	}
	key, err := secretParams.KeyGen(attrs)
	if err != nil {
		log.Fatal(err)
	}
	keyData, err := key.MarshalBinary()
	err = os.WriteFile("attributeKey", keyData, 0o400)
	if err != nil {
		log.Fatal(err)
	}
}
