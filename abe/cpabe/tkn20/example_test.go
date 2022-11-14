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
		"Occupation":             {"Wizard", "Doctor", "Ghost"},
		"SecurityClearanceLevel": {"low", "medium", "high", "*"},
		"Country":                {"US", "Croatia"},
		"Age":                    {},
	}
	isValid := func(key string, value string) bool {
		vs, ok := possiblePairs[key]
		if !ok {
			return false
		}
		if key == "Age" {
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
	policyStr := `(Occupation: Doctor) and (Country: US)`
	policyWithWildcardsStr := `(Occupation: Doctor) or (SecurityClearanceLevel: *)`
	invalidPolicyStr := `(Occupation: Doctor) and (Country: Pacific)`
	msgStr := `must have the precious 🎃`

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
	wildPolicy := cpabe.Policy{}
	err = wildPolicy.FromString(policyWithWildcardsStr)
	if err != nil {
		log.Fatal(err)
	}

	if !checkPolicy(wildPolicy.ExtractAttributeValuePairs()) {
		log.Fatalf("policy check failed for valid policy")
	}

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

	ctWild, err := publicKey.Encrypt(rand.Reader, wildPolicy, []byte(msgStr))
	if err != nil {
		log.Fatalf("%s", err)
	}

	// generate secret key for certain set of attributes
	wrongAttrs := cpabe.NewAttributes([]cpabe.Attribute{
		{"Occupation", "Doctor", false},
		{"Country", "Croatia", false},
	})
	rightAttrs := cpabe.NewAttributes([]cpabe.Attribute{
		{"Occupation", "Doctor", false},
		{"Country", "US", false},
		{"Age", "16", false},
	})
	wildAttrs := cpabe.NewAttributes([]cpabe.Attribute{
		{"SecurityClearanceLevel", "high", true},
		{"Occupation", "President", false},
	})

	wrongSecretKey, _ := systemSecretKey.KeyGen(rand.Reader, wrongAttrs)
	rightSecretKey, _ := systemSecretKey.KeyGen(rand.Reader, rightAttrs)
	wildSecretKey, _ := systemSecretKey.KeyGen(rand.Reader, wildAttrs)

	wrongSat := policy.Satisfaction(wrongAttrs)
	if wrongSat {
		log.Fatalf("wrong attributes should not satisfy policy")
	}
	rightSat := policy.Satisfaction(rightAttrs)
	if !rightSat {
		log.Fatalf("right attributes should satisfy policy")
	}
	wildSat := wildPolicy.Satisfaction(wildAttrs)
	if !wildSat {
		log.Fatalf("attributes should satisfy policy")
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
	wildCtSat := wildAttrs.CouldDecrypt(ctWild)
	if !wildCtSat {
		log.Fatalf("attrs should satisfy ciphertext")
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

	ptWild, err := wildSecretKey.Decrypt(ctWild)
	if err != nil {
		log.Fatalf("decryption should have succeeded")
	}
	if !bytes.Equal(ptWild, []byte(msgStr)) {
		log.Fatalf("recoverd plaintext: %s is not equal to original msg: %s", ptWild, msgStr)
	}

	fmt.Println("Successfully recovered plaintext")
	// Output: (Occupation:Doctor and Country:US)
	// Successfully recovered plaintext
}
