package main

import (
	"crypto/rand"
	"log"
	"os"

	cpabe "github.com/cloudflare/circl/abe/cpabe/tkn20"
)

func main() {
	publicParams, secretParams, err := cpabe.Setup(rand.Reader)
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
	attrs := cpabe.NewAttributes([]cpabe.Attribute{
		{"country", "NL", true},
		{"region", "EU", false},
	})

	policy := cpabe.Policy{}
	err = policy.FromString("region: EU")
	if err != nil {
		log.Fatal(err)
	}

	ciphertext, err := publicParams.Encrypt(rand.Reader, policy, []byte("Be sure to drink your ovaltine!"))
	if err != nil {
		log.Fatal(err)
	}
	err = os.WriteFile("ciphertext", ciphertext, 0o400)
	if err != nil {
		log.Fatal(err)
	}
	key, err := secretParams.KeyGen(rand.Reader, attrs)
	if err != nil {
		log.Fatal(err)
	}
	keyData, err := key.MarshalBinary()
	err = os.WriteFile("attributeKey", keyData, 0o400)
	if err != nil {
		log.Fatal(err)
	}
}
