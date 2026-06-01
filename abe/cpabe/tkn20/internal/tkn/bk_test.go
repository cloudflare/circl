package tkn

import (
	"crypto/rand"
	"encoding/binary"
	"testing"
)

var encTestCases = []TestCase{
	{
		&Policy{
			Inputs: []Wire{
				{"a", "", ToScalar(0), true},
			},
			F: Formula{
				Gates: []Gate{},
			},
		},
		&Attributes{
			"a": {
				wild:  false,
				Value: ToScalar(0),
			},
		},
	},
	{
		&Policy{
			Inputs: []Wire{
				{"a", "", ToScalar(1), true},
				{"b", "", ToScalar(2), true},
				{"c", "", ToScalar(3), true},
			},
			F: Formula{
				Gates: []Gate{
					{Andgate, 0, 1, 3},
					{Andgate, 2, 3, 4},
				},
			},
		},
		&Attributes{
			"d": {
				wild:  false,
				Value: ToScalar(4),
			},
			"c": {
				wild:  false,
				Value: ToScalar(3),
			},
			"b": {
				wild:  false,
				Value: ToScalar(2),
			},
			"a": {
				wild:  false,
				Value: ToScalar(1),
			},
		},
	},
	{
		&Policy{
			Inputs: []Wire{
				{"a", "", ToScalar(1), false},
				{"b", "", ToScalar(2), true},
				{"c", "", ToScalar(3), true},
			},
			F: Formula{
				Gates: []Gate{
					{Andgate, 0, 1, 3},
					{Andgate, 2, 3, 4},
				},
			},
		},
		&Attributes{
			"d": {
				wild:  false,
				Value: ToScalar(4),
			},
			"c": {
				wild:  false,
				Value: ToScalar(3),
			},
			"b": {
				wild:  false,
				Value: ToScalar(2),
			},
			"a": {
				wild:  false,
				Value: ToScalar(2),
			},
		},
	},
	{
		&Policy{
			Inputs: []Wire{
				{"a", "", ToScalar(1), false},
				{"c", "", ToScalar(4), true},
			},
			F: Formula{
				Gates: []Gate{
					{Andgate, 0, 1, 2},
				},
			},
		},
		&Attributes{
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
		},
	},
	{
		&Policy{
			Inputs: []Wire{
				{"a", "", ToScalar(1), true},
				{"b", "", ToScalar(2), true},
				{"c", "", ToScalar(3), true},
			},
			F: Formula{
				Gates: []Gate{
					{Andgate, 0, 1, 3},
					{Orgate, 2, 3, 4},
				},
			},
		},
		&Attributes{
			"d": {
				wild:  false,
				Value: ToScalar(4),
			},
			"c": {
				wild:  false,
				Value: ToScalar(3),
			},
			"b": {
				wild:  false,
				Value: ToScalar(2),
			},
			"a": {
				wild:  false,
				Value: ToScalar(1),
			},
		},
	},
	{
		&Policy{
			Inputs: []Wire{
				{"blocked", "", ToScalar(1), false},
				{"secure", "", ToScalar(1), true},
				{"eu", "", ToScalar(1), true},
				{"us", "", ToScalar(1), true},
			},
			F: Formula{
				Gates: []Gate{
					{Orgate, 2, 3, 4},
					{Andgate, 0, 4, 5},
					{Andgate, 1, 5, 6},
				},
			},
		},
		&Attributes{
			"blocked": {
				wild:  false,
				Value: ToScalar(0),
			},
			"secure": {
				wild:  false,
				Value: ToScalar(1),
			},
			"us": {
				wild:  false,
				Value: ToScalar(1),
			},
			"irrelevantAttr": {
				wild:  false,
				Value: ToScalar(1),
			},
		},
	},
	{
		&Policy{
			Inputs: []Wire{
				{"a", "", ToScalar(1), true},
				{"a", "", ToScalar(2), true},
			},
			F: Formula{
				Gates: []Gate{
					{Orgate, 0, 1, 2},
				},
			},
		},
		&Attributes{
			"a": {
				false,
				ToScalar(1),
			},
		},
	},
	{
		&Policy{
			Inputs: []Wire{
				{"a", "", ToScalar(1), true},
				{"a", "", ToScalar(2), true},
			},
			F: Formula{
				Gates: []Gate{
					{Orgate, 0, 1, 2},
				},
			},
		},
		&Attributes{
			"a": {
				false,
				ToScalar(2),
			},
		},
	},
}

func TestEncryptionBk(t *testing.T) {
	msg := []byte("drink your ovaltine")

	for _, suite := range encTestCases {
		public, secret, err := GenerateParams(rand.Reader)
		if err != nil {
			t.Fatalf("error generating parameters: %s", err)
		}
		userKey, err := DeriveAttributeKeysCCA(rand.Reader, secret, suite.a)
		if err != nil {
			t.Fatalf("error generating Attribute keys: %s", err)
		}

		ciphertext, err := EncryptCCA(rand.Reader, public, suite.p, msg)
		if err != nil {
			t.Fatalf("error encrypting: %s", err)
		}
		recovered, err := DecryptCCA(ciphertext, userKey)
		if err != nil {
			t.Fatalf("error decrypting: %s", err)
		}
		if string(recovered) != string(msg) {
			t.Fatalf("expected: %s, got %s", string(recovered), string(msg))
		}
	}
}

var benchPolicy = &Policy{
	Inputs: []Wire{
		{"blocked", "", ToScalar(1), false},
		{"secure", "", ToScalar(1), true},
		{"eu", "", ToScalar(1), true},
		{"us", "", ToScalar(1), true},
	},
	F: Formula{
		Gates: []Gate{
			{Orgate, 2, 3, 4},
			{Andgate, 0, 4, 5},
			{Andgate, 1, 5, 6},
		},
	},
}

var benchAttrs = &Attributes{
	"blocked": {
		wild:  false,
		Value: ToScalar(0),
	},
	"secure": {
		wild:  false,
		Value: ToScalar(1),
	},
	"us": {
		wild:  false,
		Value: ToScalar(1),
	},
	"irrelevantAttr": {
		wild:  false,
		Value: ToScalar(1),
	},
}

func TestMalformedCiphertextInternal(t *testing.T) {
	public, secret, err := GenerateParams(rand.Reader)
	if err != nil {
		t.Fatalf("error generating parameters: %s", err)
	}
	policy := &Policy{
		Inputs: []Wire{
			{"a", "", ToScalar(1), true},
		},
		F: Formula{
			Gates: []Gate{},
		},
	}
	attrs := &Attributes{
		"a": {
			wild:  false,
			Value: ToScalar(1),
		},
	}
	userKey, err := DeriveAttributeKeysCCA(rand.Reader, secret, attrs)
	if err != nil {
		t.Fatalf("error generating Attribute keys: %s", err)
	}

	msg := []byte("drink your ovaltine")
	ciphertext, err := EncryptCCA(rand.Reader, public, policy, msg)
	if err != nil {
		t.Fatalf("error encrypting: %s", err)
	}

	// Empty ciphertext must not panic.
	if CouldDecrypt([]byte{}, attrs) {
		t.Fatal("empty ciphertext should not be decryptable")
	}
	if _, err := DecryptCCA([]byte{}, userKey); err == nil {
		t.Fatal("empty ciphertext should fail to decrypt")
	}
	badPolicy := &Policy{}
	if err := badPolicy.ExtractFromCiphertext([]byte{}); err == nil {
		t.Fatal("empty ciphertext should fail extraction")
	}

	// Truncated ciphertexts must not panic.
	// DecryptCCA must return an error for any truncation because it needs
	// the authentication tag, but CouldDecrypt and ExtractFromCiphertext
	// only need the header and may succeed if the truncation is in the
	// trailing tag/mac region.
	for i := 1; i < len(ciphertext); i++ {
		truncated := ciphertext[:i]
		_ = CouldDecrypt(truncated, attrs)
		if _, err := DecryptCCA(truncated, userKey); err == nil {
			t.Fatalf("truncated ciphertext (len=%d) should fail to decrypt", i)
		}
		badPolicy := &Policy{}
		_ = badPolicy.ExtractFromCiphertext(truncated)
	}

	// Manipulated lengths to create inconsistent data.
	// Corrupt the macData length field in a v1.3.8 ciphertext.
	if len(ciphertext) > len(CiphertextVersion)+4 {
		corrupted := make([]byte, len(ciphertext))
		copy(corrupted, ciphertext)
		// The layout is: version | id (len-prefixed) | macData (len32-prefixed) | tag (len-prefixed)
		// Corrupt the 32-bit length prefix of macData to claim a huge size.
		idx := len(CiphertextVersion)
		// Skip id length-prefixed field
		_, rem, err := removeLenPrefixed(corrupted[idx:])
		if err == nil {
			// rem now starts with the 32-bit length prefix for macData
			binary.LittleEndian.PutUint32(rem, 0xFFFFFFFF)
			if CouldDecrypt(corrupted, attrs) {
				t.Fatal("corrupted-length ciphertext should not be decryptable")
			}
			if _, err := DecryptCCA(corrupted, userKey); err == nil {
				t.Fatal("corrupted-length ciphertext should fail to decrypt")
			}
			badPolicy := &Policy{}
			if err := badPolicy.ExtractFromCiphertext(corrupted); err == nil {
				t.Fatal("corrupted-length ciphertext should fail extraction")
			}
		}
	}
}

func BenchmarkTkDecryption(b *testing.B) {
	msg := []byte("drink your ovaltine")

	public, secret, err := GenerateParams(rand.Reader)
	if err != nil {
		b.Fatalf("error generating parameters: %s", err)
	}
	userKey, err := DeriveAttributeKeysCCA(rand.Reader, secret, benchAttrs)
	if err != nil {
		b.Fatalf("error generating Attribute keys: %s", err)
	}

	ciphertext, err := EncryptCCA(rand.Reader, public, benchPolicy, msg)
	if err != nil {
		b.Fatalf("error encrypting: %s", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err = DecryptCCA(ciphertext, userKey)
		if err != nil {
			b.Fatalf("mismatch: %s", err)
		}
	}
}

func BenchmarkTkEncryption(b *testing.B) {
	msg := []byte("drink your ovaltine")
	public, _, err := GenerateParams(rand.Reader)
	if err != nil {
		b.Fatalf("error generating parameters: %s", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := EncryptCCA(rand.Reader, public, benchPolicy, msg)
		if err != nil {
			b.Fatalf("error encrypting: %s", err)
		}
	}
}

func BenchmarkTkDerivation(b *testing.B) {
	_, secret, err := GenerateParams(rand.Reader)
	if err != nil {
		b.Fatalf("error generating parameters: %s", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := DeriveAttributeKeysCCA(rand.Reader, secret, benchAttrs)
		if err != nil {
			b.Fatalf("error generating Attribute keys: %s", err)
		}
	}
}
