//go:build ignore
// +build ignore

// Generates golden files for tests.
package main

import (
	"encoding"
	"os"

	cpabe "github.com/cloudflare/circl/abe/cpabe/tkn20"
	"github.com/cloudflare/circl/xof"
)

func writeToFile(name string, data []byte) {
	err := os.WriteFile("testdata/"+name, data, 0o644)
	if err != nil {
		panic(err)
	}
}

func dumpToFile(name string, m encoding.BinaryMarshaler) {
	data, err := m.MarshalBinary()
	if err != nil {
		panic(err)
	}
	writeToFile(name, data)
}

func main() {
	// Using fixed PRNG for reproducibility,
	prng := xof.SHAKE128.New()

	err := os.MkdirAll("testdata", 0o755)
	if err != nil {
		panic(err)
	}

	publicParams, secretParams, err := cpabe.Setup(prng)
	if err != nil {
		panic(err)
	}

	dumpToFile("publicKey", &publicParams)
	dumpToFile("secretKey", &secretParams)

	attrs := cpabe.Attributes{}
	attrs.FromMap(map[string]string{"country": "NL", "EU": "true"})

	policy := cpabe.Policy{}
	err = policy.FromString("EU: true")
	if err != nil {
		panic(err)
	}
	msg := []byte("Be sure to drink your ovaltine!")
	ciphertext, err := publicParams.Encrypt(prng, policy, msg)
	if err != nil {
		panic(err)
	}
	writeToFile("ciphertext", ciphertext)

	key, err := secretParams.KeyGen(prng, attrs)
	if err != nil {
		panic(err)
	}
	dumpToFile("attributeKey", &key)
}
