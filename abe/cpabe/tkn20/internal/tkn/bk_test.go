package tkn

import (
	"crypto/rand"
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
