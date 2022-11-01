package tkn20

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/cloudflare/circl/abe/cpabe/tkn20/internal/dsl"
	"github.com/cloudflare/circl/abe/cpabe/tkn20/internal/tkn"
)

type TestAttribute struct {
	Fail  bool              // if this test case should fail
	Attrs map[string]string `json:"attributes"`
}

func loadTestCases(t *testing.T) ([]Policy, []TestAttribute, []Attributes) {
	testFile, err := os.Open("testdata/policies")
	if err != nil {
		t.Fatal(err)
	}
	defer testFile.Close()

	scanner := bufio.NewScanner(testFile)
	var policies []Policy
	var testAttrs []TestAttribute
	i := 0
	for scanner.Scan() {
		if i%3 == 0 {
			p := Policy{}
			err := p.FromString(scanner.Text())
			if err != nil {
				t.Fatal(err)
			}
			policies = append(policies, p)
		} else if i%3 == 1 {
			testAttrs = append(testAttrs, parseTestAttr(t, scanner.Text()))
		}
		i++
	}

	attrs := make([]Attributes, len(testAttrs))
	for i, testAttr := range testAttrs {
		currAttrMap := make(map[string]tkn.Attribute, len(testAttr.Attrs))
		for k, v := range testAttr.Attrs {
			currAttrMap[k] = tkn.Attribute{
				Value: tkn.HashStringToScalar(dsl.AttrHashKey, v),
			}
		}
		attrs[i] = Attributes{currAttrMap}
	}
	return policies, testAttrs, attrs
}

func TestConcurrentDecryption(t *testing.T) {
	policies, testAttrs, attrs := loadTestCases(t)
	msg := []byte("must have the precious")
	for i, policy := range policies {
		t.Run(fmt.Sprintf("TestConcurrentDecryption:#%d", i), func(t *testing.T) {
			pk, msk, err := Setup(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			ct, err := pk.Encrypt(rand.Reader, policy, msg)
			if err != nil {
				t.Fatalf("encryption failed: %s", err)
			}
			sk, err := msk.KeyGen(rand.Reader, attrs[i])
			if err != nil {
				t.Fatalf("key generation failed: %s", err)
			}
			checkResults := func(ct []byte, sk AttributeKey, i int) {
				pt, err := sk.Decrypt(ct)
				if !testAttrs[i].Fail {
					if err != nil {
						t.Errorf("decryption failed: %s", err)
					}
					if !bytes.Equal(pt, msg) {
						t.Errorf("expected %v, received %v", pt, msg)
					}
				} else {
					if err == nil {
						t.Errorf("decryption should have failed")
					}
				}
			}
			go checkResults(ct, sk, i)
			go checkResults(ct, sk, i)
		})
	}
}

func TestEndToEndEncryption(t *testing.T) {
	policies, testAttrs, attrs := loadTestCases(t)
	msg := []byte("must have the precious")
	for i, policy := range policies {
		t.Run(fmt.Sprintf("TestEndToEndEncryption:#%d", i), func(t *testing.T) {
			pk, msk, err := Setup(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			ct, err := pk.Encrypt(rand.Reader, policy, msg)
			if err != nil {
				t.Fatalf("encryption failed: %s", err)
			}
			sk, err := msk.KeyGen(rand.Reader, attrs[i])
			if err != nil {
				t.Fatalf("key generation failed: %s", err)
			}
			npol := &Policy{}
			if err = npol.ExtractFromCiphertext(ct); err != nil {
				t.Fatalf("extraction failed: %s", err)
			}
			strpol := npol.String()
			npol2 := &Policy{}
			if err = npol2.FromString(strpol); err != nil {
				t.Fatalf("string %s didn't parse: %s", strpol, err)
			}
			sat := policy.Satisfaction(attrs[i])
			if sat != npol.Satisfaction(attrs[i]) {
				t.Fatalf("extracted policy doesn't match original")
			}
			if sat != npol2.Satisfaction(attrs[i]) {
				t.Fatalf("round triped policy doesn't match original")
			}
			ctSat := attrs[i].CouldDecrypt(ct)
			pt, err := sk.Decrypt(ct)
			if !testAttrs[i].Fail {
				// test case should succeed
				if !sat {
					t.Fatalf("satisfaction failed")
				}
				if !ctSat {
					t.Fatalf("ciphertext satisfaction failed")
				}
				if err != nil {
					t.Fatalf("decryption failed: %s", err)
				}
				if !bytes.Equal(pt, msg) {
					t.Fatalf("expected %v, received %v", pt, msg)
				}
			} else {
				// test case should fail
				if sat {
					t.Fatal("satisfaction should have failed")
				}
				if ctSat {
					t.Fatal("ciphertext satisfaction should have failed")
				}
				if err == nil {
					t.Fatal("decryption should have failed")
				}
			}
		})
	}
}

func TestMarshal(t *testing.T) {
	pk, msk, err := Setup(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	data, err := pk.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	b := &PublicKey{}
	err = b.UnmarshalBinary(data)
	if err != nil {
		t.Fatal(err)
	}
	if !pk.Equal(b) {
		t.Fatal("PublicKey: failure to roundtrip")
	}

	data, err = msk.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	c := &SystemSecretKey{}
	err = c.UnmarshalBinary(data)
	if err != nil {
		t.Fatal(err)
	}
	if !msk.Equal(c) {
		t.Fatal("MasterSecretKey: failure to roundtrip")
	}

	attrs := Attributes{}
	attrs.FromMap(map[string]string{"occupation": "doctor", "country": "US", "age": "16"})
	sk, err := msk.KeyGen(rand.Reader, attrs)
	if err != nil {
		t.Fatal(err)
	}

	data, err = sk.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	d := AttributeKey{} // don't use pointer to verify unmarshal works with both pointer and not
	err = d.UnmarshalBinary(data)
	if err != nil {
		t.Fatal(err)
	}
	if !sk.Equal(&d) {
		t.Fatal("SecretKey: failure to roundtrip")
	}
}

func TestPolicyMethods(t *testing.T) {
	policyStr := "(season: fall or season: winter) or (region: alaska and season: summer)"
	policy := Policy{}
	err := policy.FromString(policyStr)
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string][]string{
		"season": {"fall", "winter", "summer"},
		"region": {"alaska"},
	}
	received := policy.ExtractAttributeValuePairs()
	if len(expected) != len(received) {
		t.Fatal("diff lengths")
	}
	for k, vs := range expected {
		vs2, ok := received[k]
		if !ok {
			t.Fatalf("key %s not found in received map", k)
		}
		if len(vs) != len(vs2) {
			t.Fatalf("expected len: %d, received len: %d, for key %s", len(vs), len(vs2), k)
		}
		// compare each value for given key, order doesn't matter
		for _, v := range vs {
			flag := false
			for _, v2 := range vs2 {
				if v == v2 {
					flag = true
					break
				}
			}
			if !flag {
				t.Fatalf("expected and received values differ")
			}
		}
	}
}

func parseTestAttr(t *testing.T, buf string) TestAttribute {
	var testAttr TestAttribute
	err := json.Unmarshal([]byte("{"+buf+"}"), &testAttr)
	if err != nil {
		t.Fatalf("invalid attributes %s, parse error: %s\n", buf, err)
	}
	return testAttr
}
