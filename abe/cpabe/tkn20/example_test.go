package tkn20_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"log"
	"strconv"

	cpabe "github.com/cloudflare/circl/abe/cpabe/tkn20"
)

func checkPolicy(in map[string][]string) bool {
	possiblePairs := map[string][]string{
		"occupation": {"wizard", "doctor", "ghost"},
		"country":    {"US", "croatia"},
		"age":        {},
	}
	isValid := func(key string, value string) bool {
		vs, ok := possiblePairs[key]
		if !ok {
			return false
		}
		if key == "age" {
			age, err := strconv.Atoi(value)
			if err != nil {
				return false
			}
			if age < 13 || age > 100 {
				return false
			}
		} else {
			for _, v := range vs {
				if value == v {
					return true
				}
			}
		}
		return false
	}
	for k, v := range in {
		for _, value := range v {
			if !isValid(k, value) {
				return false
			}
		}
	}
	return true
}

func Example() {
	policyStr := `(occupation: doctor) and (country: US)`
	invalidPolicyStr := `(ocupation: doctor) and (country: pacific)`
	msgStr := `must have the precious 🎃`
	wrongAttrsMap := map[string]string{"occupation": "doctor", "country": "croatia"}
	rightAttrsMap := map[string]string{"occupation": "doctor", "country": "US", "age": "16"}

	publicKey, systemSecretKey, err := cpabe.Setup(rand.Reader)
	if err != nil {
		log.Fatalf("%s", err)
	}

	policy := cpabe.Policy{}
	err = policy.FromString(policyStr)
	if err != nil {
		log.Fatal(err)
	}
	if !checkPolicy(policy.ExtractAttributeValuePairs()) {
		log.Fatalf("policy check failed for valid policy")
	}

	fmt.Println(policy.String())
	invalidPolicy := cpabe.Policy{}
	err = invalidPolicy.FromString(invalidPolicyStr)
	if err != nil {
		log.Fatal(err)
	}
	if checkPolicy(invalidPolicy.ExtractAttributeValuePairs()) {
		log.Fatalf("policy check should fail for invalid policy")
	}

	// encrypt the secret message for a given policy
	ct, err := publicKey.Encrypt(rand.Reader, policy, []byte(msgStr))
	if err != nil {
		log.Fatalf("%s", err)
	}

	// generate secret key for certain set of attributes
	wrongAttrs := cpabe.Attributes{}
	wrongAttrs.FromMap(wrongAttrsMap)
	rightAttrs := cpabe.Attributes{}
	rightAttrs.FromMap(rightAttrsMap)

	wrongSecretKey, _ := systemSecretKey.KeyGen(rand.Reader, wrongAttrs)
	rightSecretKey, _ := systemSecretKey.KeyGen(rand.Reader, rightAttrs)

	wrongSat := policy.Satisfaction(wrongAttrs)
	if wrongSat {
		log.Fatalf("wrong attributes should not satisfy policy")
	}
	rightSat := policy.Satisfaction(rightAttrs)
	if !rightSat {
		log.Fatalf("right attributes should satisfy policy")
	}

	// wrong attrs should not satisfy ciphertext
	wrongCtSat := wrongAttrs.CouldDecrypt(ct)
	if wrongCtSat {
		log.Fatalf("wrong attrs should not satisfy ciphertext")
	}
	rightCtSat := rightAttrs.CouldDecrypt(ct)
	if rightCtSat == false {
		log.Fatalf("right attrs should satisfy ciphertext")
	}

	// attempt to decrypt with wrong attributes should fail
	pt, err := wrongSecretKey.Decrypt(ct)
	if err == nil {
		log.Fatalf("decryption using wrong attrs should have failed, plaintext: %s", pt)
	}

	pt, err = rightSecretKey.Decrypt(ct)
	if err != nil {
		log.Fatalf("decryption using right attrs should have succeeded, plaintext: %s", pt)
	}
	if !bytes.Equal(pt, []byte(msgStr)) {
		log.Fatalf("recoverd plaintext: %s is not equal to original msg: %s", pt, msgStr)
	}
	fmt.Println("Successfully recovered plaintext")
	// Output: (occupation:doctor and country:US)
	// Successfully recovered plaintext
}
