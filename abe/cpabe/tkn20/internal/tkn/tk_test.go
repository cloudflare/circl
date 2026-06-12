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

// buildSatisfiedHeaderAndKey produces a ciphertext header and a key whose
// attributes satisfy the policy, mirroring the state decapsulate is invoked in
// (header.p is the BK-transformed policy, and c2/c3/c3neg are sized to it).
func buildSatisfiedHeaderAndKey(t *testing.T) (*ciphertextHeader, *AttributesKey) {
	t.Helper()
	pp, sp, err := GenerateParams(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hashKey := []byte("decapsulate-bounds-test")
	policy := &Policy{
		Inputs: []Wire{
			{Label: "country", RawValue: "US", Value: HashStringToScalar(hashKey, "US"), Positive: true},
			{Label: "top", RawValue: "secret", Value: HashStringToScalar(hashKey, "secret"), Positive: true},
		},
		F: Formula{Gates: []Gate{{In0: 0, In1: 1, Out: 2, Class: Andgate}}},
	}
	attrs := Attributes{
		"country": {Value: HashStringToScalar(hashKey, "US")},
		"top":     {Value: HashStringToScalar(hashKey, "secret")},
	}
	key, err := DeriveAttributeKeysCCA(rand.Reader, sp, &attrs)
	if err != nil {
		t.Fatal(err)
	}
	// EncryptCCA encapsulates with the BK-transformed policy, so do the same to
	// obtain a header in the state decapsulate sees after DecryptCCA's transform.
	header, _, err := encapsulate(rand.Reader, pp, policy.transformBK(ToScalar(123)))
	if err != nil {
		t.Fatal(err)
	}
	return header, key
}

// TestDecapsulateRejectsShortArrays guards against out-of-range access in
// decapsulate: a structurally complete header that declares fewer c2/c3/c3neg
// entries than the policy requires must make decapsulate return an error rather
// than panic with an out-of-range index.
func TestDecapsulateRejectsShortArrays(t *testing.T) {
	// Sanity check: the untampered header decapsulates without error.
	header, key := buildSatisfiedHeaderAndKey(t)
	if _, err := decapsulate(header, key); err != nil {
		t.Fatalf("baseline decapsulate failed: %v", err)
	}

	t.Run("short c3", func(t *testing.T) {
		header, key := buildSatisfiedHeaderAndKey(t)
		header.c3 = header.c3[:len(header.c3)-1]
		assertDecapsulateErrors(t, header, key)
	})

	t.Run("short c3neg", func(t *testing.T) {
		header, key := buildSatisfiedHeaderAndKey(t)
		header.c3neg = header.c3neg[:len(header.c3neg)-1]
		assertDecapsulateErrors(t, header, key)
	})

	t.Run("empty c2", func(t *testing.T) {
		header, key := buildSatisfiedHeaderAndKey(t)
		header.c2 = nil
		assertDecapsulateErrors(t, header, key)
	})
}

func assertDecapsulateErrors(t *testing.T, header *ciphertextHeader, key *AttributesKey) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("decapsulate panicked instead of returning an error: %v", r)
		}
	}()
	if _, err := decapsulate(header, key); err == nil {
		t.Fatal("decapsulate accepted an inconsistent header without error")
	}
}

// TestDecapsulateDegeneratePolicyNoPanic checks that decapsulate fails
// gracefully (rather than panicking) when no policy wire contributes to the
// pairing -- e.g. an empty policy, or a key that does not satisfy the policy.
// Satisfaction rejects these inputs with an error, and decapsulate additionally
// guards the resulting nil accumulator before it reaches pairAccum.addDuals.
func TestDecapsulateDegeneratePolicyNoPanic(t *testing.T) {
	pp, sp, err := GenerateParams(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("empty policy", func(t *testing.T) {
		attrs := Attributes{}
		key, err := DeriveAttributeKeysCCA(rand.Reader, sp, &attrs)
		if err != nil {
			t.Fatal(err)
		}
		header, _, err := encapsulate(rand.Reader, pp, &Policy{Inputs: []Wire{}, F: Formula{Gates: []Gate{}}})
		if err != nil {
			t.Fatal(err)
		}
		assertDecapsulateErrors(t, header, key)
	})

	t.Run("non-satisfying key", func(t *testing.T) {
		hashKey := []byte("degenerate")
		policy := &Policy{
			Inputs: []Wire{
				{Label: "country", RawValue: "US", Value: HashStringToScalar(hashKey, "US"), Positive: true},
			},
			F: Formula{Gates: []Gate{}},
		}
		attrs := Attributes{"other": {Value: HashStringToScalar(hashKey, "nope")}}
		key, err := DeriveAttributeKeysCCA(rand.Reader, sp, &attrs)
		if err != nil {
			t.Fatal(err)
		}
		header, _, err := encapsulate(rand.Reader, pp, policy.transformBK(ToScalar(7)))
		if err != nil {
			t.Fatal(err)
		}
		assertDecapsulateErrors(t, header, key)
	})
}

// TestDecapsulateRejectsNilC3neg guards against a nil-pointer dereference in the
// negative-wire path of decapsulate. unmarshalBinary leaves c3neg[i] nil when
// its serialized entry is empty, which is legitimate for positive wires but not
// for negative ones. A malicious ciphertext can mark a wire negative while
// leaving its c3neg empty; if a satisfying key matches that wire, decapsulate
// must return an error rather than dereferencing nil at header.c3neg[mt.wire]
// (which runs before the MAC check in DecryptCCA).
func TestDecapsulateRejectsNilC3neg(t *testing.T) {
	pp, sp, err := GenerateParams(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hashKey := []byte("nil-c3neg")
	// A single negative wire on "country".
	policy := &Policy{
		Inputs: []Wire{
			{Label: "country", RawValue: "US", Value: HashStringToScalar(hashKey, "US"), Positive: false},
		},
		F: Formula{Gates: []Gate{}},
	}
	// The key has "country" with a different value, so the negative wire matches.
	attrs := Attributes{"country": {Value: HashStringToScalar(hashKey, "CA")}}
	key, err := DeriveAttributeKeysCCA(rand.Reader, sp, &attrs)
	if err != nil {
		t.Fatal(err)
	}
	header, _, err := encapsulate(rand.Reader, pp, policy.transformBK(ToScalar(99)))
	if err != nil {
		t.Fatal(err)
	}
	if header.c3neg[0] == nil {
		t.Fatal("expected c3neg[0] to be set for the negative wire")
	}

	// Drop the negative wire's c3neg entry and round-trip through the wire
	// format, mimicking an attacker-serialized header with an empty c3neg entry;
	// unmarshalBinary leaves c3neg[0] nil.
	header.c3neg[0] = nil
	raw, err := header.marshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	tampered := &ciphertextHeader{}
	if err := tampered.unmarshalBinary(raw); err != nil {
		t.Fatal(err)
	}
	if tampered.c3neg[0] != nil {
		t.Fatal("expected unmarshalBinary to leave c3neg[0] nil")
	}

	assertDecapsulateErrors(t, tampered, key)
}
