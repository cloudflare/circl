package tkn

import (
	"crypto/rand"
	"fmt"
	"testing"
)

func TestEncryptionSimple(t *testing.T) {
	for i, suite := range encTestCases {
		t.Run(fmt.Sprintf("test %d", i), func(t *testing.T) {
			public, secret, err := GenerateParams(rand.Reader)
			if err != nil {
				t.Fatalf("error generating parameters: %s", err)
			}
			userKey, err := deriveAttributeKeys(rand.Reader, secret, suite.a)
			if err != nil {
				t.Fatalf("error generating attribute keys: %s", err)
			}

			header, shared, err := encapsulate(rand.Reader, public, suite.p)
			if err != nil {
				t.Fatalf("error encrypting message: %s", err)
			}
			headerSerialized, err := header.marshalBinary()
			if err != nil {
				t.Fatalf("cannot serialize: %s", err)
			}
			newHeader := &ciphertextHeader{}
			err = newHeader.unmarshalBinary(headerSerialized)
			if err != nil {
				t.Fatalf("unmarshaling failed: %s", err)
			}

			recovered, err := decapsulate(newHeader, userKey)
			if err != nil {
				t.Fatalf("error decrypting message: %s", err)
			}
			if !recovered.IsEqual(shared) {
				t.Fatalf("decryption is incorrect")
			}
		})
	}
}

func TestMarshalPublicParams(t *testing.T) {
	a, _, err := GenerateParams(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data, err := a.MarshalBinary()
	if err != nil {
		t.Fatalf("failure to serialize: %s", err)
	}
	b := &PublicParams{}
	err = b.UnmarshalBinary(data)
	if err != nil {
		t.Fatalf("failure to deserialize: %s", err)
	}
	if !a.Equal(b) {
		t.Fatal("failure to roundtrip")
	}
}

func TestMarshalSecretParams(t *testing.T) {
	_, a, err := GenerateParams(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data, err := a.MarshalBinary()
	if err != nil {
		t.Fatalf("failure to serialize: %s", err)
	}
	b := &SecretParams{}
	err = b.UnmarshalBinary(data)
	if err != nil {
		t.Fatalf("failure to deserialize: %s", err)
	}
	if !a.Equal(b) {
		t.Fatal("failure to roundtrip")
	}
}

func TestMarshalAttributesKey(t *testing.T) {
	_, sp, err := GenerateParams(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	attrs := &Attributes{
		"d": {
			wild:  false,
			Value: ToScalar(4),
		},
		"c": {
			wild:  true,
			Value: ToScalar(3),
		},
		"b": {
			wild:  false,
			Value: ToScalar(2),
		},
		"a": {
			wild:  true,
			Value: ToScalar(2),
		},
	}
	a, err := deriveAttributeKeys(rand.Reader, sp, attrs)
	if err != nil {
		t.Fatalf("error generating attribute keys: %s", err)
	}
	data, err := a.MarshalBinary()
	if err != nil {
		t.Fatalf("failure to serialize: %s", err)
	}
	b := &AttributesKey{}
	err = b.UnmarshalBinary(data)
	if err != nil {
		t.Fatalf("failure to deserialize: %s", err)
	}
	if !a.Equal(b) {
		t.Fatal("failure to roundtrip")
	}

	// ensure we can deserialize into non-empty struct
	cAttrs := &Attributes{
		"evil": {
			wild:  false,
			Value: ToScalar(0),
		},
	}
	c, err := deriveAttributeKeys(rand.Reader, sp, cAttrs)
	if err != nil {
		t.Fatalf("error generating attribute keys: %s", err)
	}
	err = c.UnmarshalBinary(data)
	if err != nil {
		t.Fatalf("failure to deserialize into non-empty struct: %s", err)
	}
	if !a.Equal(c) {
		t.Fatal("failure to roundtrip")
	}
}

func TestEqualAttributesKey(t *testing.T) {
	_, sp, err := GenerateParams(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	attrs := &Attributes{
		"d": {
			wild:  false,
			Value: ToScalar(4),
		},
	}
	a, err := deriveAttributeKeys(rand.Reader, sp, attrs)
	if err != nil {
		t.Fatalf("error generating attribute keys: %s", err)
	}

	_, sp2, err := GenerateParams(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	attrs2 := &Attributes{
		"k": {
			wild:  false,
			Value: ToScalar(4),
		},
	}
	b, err := deriveAttributeKeys(rand.Reader, sp2, attrs2)
	if err != nil {
		t.Fatalf("error generating attribute keys: %s", err)
	}
	if a.Equal(b) {
		t.Fatalf("shouldnt be equal")
	}

	// deep copy
	data, err := a.MarshalBinary()
	if err != nil {
		t.Fatalf("failure to serialize: %s", err)
	}
	c := &AttributesKey{}
	err = c.UnmarshalBinary(data)
	if err != nil {
		t.Fatalf("failure to deserialize: %s", err)
	}
	if !a.Equal(c) {
		t.Fatalf("failure to roundtrip")
	}

	for k, v := range a.k3 {
		c.k3[k], err = randomMatrixG1(rand.Reader, v.rows, v.cols)
		if err != nil {
			t.Fatal(err)
		}
		break
	}
	if a.Equal(c) {
		t.Fatalf("shouldnt be equal")
	}
}
