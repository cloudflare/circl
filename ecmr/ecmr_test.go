package ecmr

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/cloudflare/circl/group"
)

func TestProvisionAndRecover(t *testing.T) {
	serverKey, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	server, err := NewServer(serverKey)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	client := NewClient()

	provisionResult, err := client.Provision(server.PublicKey(), rand.Reader)
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	if len(provisionResult.ClientPublic) != PublicKeySize {
		t.Errorf("ClientPublic size = %d, want %d", len(provisionResult.ClientPublic), PublicKeySize)
	}
	if len(provisionResult.SharedPoint) != SharedPointSize {
		t.Errorf("SharedPoint size = %d, want %d", len(provisionResult.SharedPoint), SharedPointSize)
	}

	request, state, err := client.CreateRecoveryRequest(
		provisionResult.ClientPublic,
		server.PublicKey(),
		rand.Reader,
	)
	if err != nil {
		t.Fatalf("CreateRecoveryRequest failed: %v", err)
	}

	if len(request.BlindedPoint) != PublicKeySize {
		t.Errorf("BlindedPoint size = %d, want %d", len(request.BlindedPoint), PublicKeySize)
	}

	response, err := server.ProcessRecoveryRequest(request)
	if err != nil {
		t.Fatalf("ProcessRecoveryRequest failed: %v", err)
	}

	if len(response.ProcessedPoint) != SharedPointSize {
		t.Errorf("ProcessedPoint size = %d, want %d", len(response.ProcessedPoint), SharedPointSize)
	}

	recoveredPoint, err := client.RecoverKey(state, response)
	if err != nil {
		t.Fatalf("RecoverKey failed: %v", err)
	}

	if !bytes.Equal(recoveredPoint, provisionResult.SharedPoint) {
		t.Error("Recovered point does not match original shared point")
	}
}

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	if key.scalar == nil {
		t.Error("Generated key has nil scalar")
	}

	pub := key.Public()
	if pub == nil || pub.element == nil {
		t.Error("Public key is nil or has nil element")
	}

	keyBytes, err := key.MarshalBinary()
	if err != nil {
		t.Fatalf("PrivateKey.MarshalBinary failed: %v", err)
	}
	if len(keyBytes) != PrivateKeySize {
		t.Errorf("PrivateKey size = %d, want %d", len(keyBytes), PrivateKeySize)
	}

	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		t.Fatalf("PublicKey.MarshalBinary failed: %v", err)
	}
	if len(pubBytes) != PublicKeySize {
		t.Errorf("PublicKey size = %d, want %d", len(pubBytes), PublicKeySize)
	}
}

func TestMarshalUnmarshal(t *testing.T) {
	key, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	keyBytes, err := key.MarshalBinary()
	if err != nil {
		t.Fatalf("PrivateKey.MarshalBinary failed: %v", err)
	}

	var key2 PrivateKey
	err = key2.UnmarshalBinary(keyBytes)
	if err != nil {
		t.Fatalf("PrivateKey.UnmarshalBinary failed: %v", err)
	}

	keyBytes2, err := key2.MarshalBinary()
	if err != nil {
		t.Fatalf("PrivateKey.MarshalBinary (2) failed: %v", err)
	}
	if !bytes.Equal(keyBytes, keyBytes2) {
		t.Error("Private key round-trip failed")
	}

	pub := key.Public()
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		t.Fatalf("PublicKey.MarshalBinary failed: %v", err)
	}

	var pub2 PublicKey
	err = pub2.UnmarshalBinary(pubBytes)
	if err != nil {
		t.Fatalf("PublicKey.UnmarshalBinary failed: %v", err)
	}

	pubBytes2, err := pub2.MarshalBinary()
	if err != nil {
		t.Fatalf("PublicKey.MarshalBinary (2) failed: %v", err)
	}
	if !bytes.Equal(pubBytes, pubBytes2) {
		t.Error("Public key round-trip failed")
	}
}

func TestExtractX(t *testing.T) {
	key, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	pubBytes, err := key.Public().MarshalBinary()
	if err != nil {
		t.Fatalf("PublicKey.MarshalBinary failed: %v", err)
	}

	x, err := ExtractX(pubBytes)
	if err != nil {
		t.Fatalf("ExtractX failed: %v", err)
	}

	if len(x) != XCoordinateSize {
		t.Errorf("x-coordinate size = %d, want %d", len(x), XCoordinateSize)
	}

	expectedX := pubBytes[1 : 1+XCoordinateSize]
	if !bytes.Equal(x, expectedX) {
		t.Error("ExtractX returned incorrect x-coordinate")
	}
}

func TestExtractXWrongLength(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"too short", make([]byte, 100)},
		{"too long", make([]byte, 200)},
		{"one byte", []byte{0x04}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ExtractX(tc.data)
			if !errors.Is(err, ErrMalformedPoint) {
				t.Errorf("ExtractX(%s) error = %v, want ErrMalformedPoint", tc.name, err)
			}
		})
	}
}

func TestExtractXWrongPrefix(t *testing.T) {
	data := make([]byte, UncompressedPointSize)
	data[0] = 0x02
	_, err := ExtractX(data)
	if !errors.Is(err, ErrMalformedPoint) {
		t.Errorf("ExtractX(wrong prefix) error = %v, want ErrMalformedPoint", err)
	}
}

func TestExtractXIdentity(t *testing.T) {
	identity := []byte{0x00}

	_, err := ExtractX(identity)
	if !errors.Is(err, ErrIdentityPoint) {
		t.Errorf("ExtractX(identity) error = %v, want ErrIdentityPoint", err)
	}
}

func TestExtractXOffCurve(t *testing.T) {
	data := make([]byte, UncompressedPointSize)
	data[0] = 0x04
	for i := 1; i < len(data); i++ {
		data[i] = 0xFF
	}

	_, err := ExtractX(data)
	if !errors.Is(err, ErrMalformedPoint) {
		t.Errorf("ExtractX(off-curve) error = %v, want ErrMalformedPoint", err)
	}
}

func TestNilKeyErrors(t *testing.T) {
	validKey, _ := GenerateKey(rand.Reader)
	validPub := validKey.Public()
	validPubBytes, _ := validPub.MarshalBinary()

	t.Run("Provision nil serverPub", func(t *testing.T) {
		_, err := NewClient().Provision(nil, rand.Reader)
		assertError(t, err, ErrNilKey, ErrNilReader, ErrMalformedPoint)
	})
	t.Run("Provision zero serverPub", func(t *testing.T) {
		_, err := NewClient().Provision(&PublicKey{}, rand.Reader)
		assertError(t, err, ErrNilKey, ErrNilReader, ErrMalformedPoint)
	})
	t.Run("Provision nil reader", func(t *testing.T) {
		_, err := NewClient().Provision(validPub, nil)
		assertError(t, err, ErrNilKey, ErrNilReader, ErrMalformedPoint)
	})
	t.Run("CreateRecoveryRequest nil serverPub", func(t *testing.T) {
		_, _, err := NewClient().CreateRecoveryRequest(validPubBytes, nil, rand.Reader)
		assertError(t, err, ErrNilKey, ErrNilReader, ErrMalformedPoint)
	})
	t.Run("CreateRecoveryRequest zero serverPub", func(t *testing.T) {
		_, _, err := NewClient().CreateRecoveryRequest(validPubBytes, &PublicKey{}, rand.Reader)
		assertError(t, err, ErrNilKey, ErrNilReader, ErrMalformedPoint)
	})
	t.Run("CreateRecoveryRequest nil reader", func(t *testing.T) {
		_, _, err := NewClient().CreateRecoveryRequest(validPubBytes, validPub, nil)
		assertError(t, err, ErrNilKey, ErrNilReader, ErrMalformedPoint)
	})
	t.Run("RecoverKey nil state", func(t *testing.T) {
		_, err := NewClient().RecoverKey(nil, &RecoveryResponse{ProcessedPoint: validPubBytes})
		assertError(t, err, ErrNilKey, ErrNilReader, ErrMalformedPoint)
	})
	t.Run("RecoverKey zero state", func(t *testing.T) {
		_, err := NewClient().RecoverKey(&RecoveryState{}, &RecoveryResponse{ProcessedPoint: validPubBytes})
		assertError(t, err, ErrNilKey, ErrNilReader, ErrMalformedPoint)
	})
	t.Run("NewServer nil key", func(t *testing.T) {
		_, err := NewServer(nil)
		assertError(t, err, ErrNilKey, ErrNilReader, ErrMalformedPoint)
	})
	t.Run("NewServer zero key", func(t *testing.T) {
		_, err := NewServer(&PrivateKey{})
		assertError(t, err, ErrNilKey, ErrNilReader, ErrMalformedPoint)
	})
	t.Run("ProcessRecoveryRequest nil request", func(t *testing.T) {
		server, _ := NewServer(validKey)
		_, err := server.ProcessRecoveryRequest(nil)
		assertError(t, err, ErrNilKey, ErrNilReader, ErrMalformedPoint)
	})
	t.Run("GenerateKey nil reader", func(t *testing.T) {
		_, err := GenerateKey(nil)
		assertError(t, err, ErrNilKey, ErrNilReader, ErrMalformedPoint)
	})
	t.Run("PrivateKey.MarshalBinary zero value", func(t *testing.T) {
		k := &PrivateKey{}
		_, err := k.MarshalBinary()
		assertError(t, err, ErrNilKey, ErrNilReader, ErrMalformedPoint)
	})
	t.Run("PublicKey.MarshalBinary zero value", func(t *testing.T) {
		k := &PublicKey{}
		_, err := k.MarshalBinary()
		assertError(t, err, ErrNilKey, ErrNilReader, ErrMalformedPoint)
	})
}

func assertError(t *testing.T, err error, expected ...error) {
	t.Helper()
	if err == nil {
		t.Error("expected error, got nil")
		return
	}
	for _, e := range expected {
		if errors.Is(err, e) {
			return
		}
	}
	t.Errorf("unexpected error type: %v", err)
}

func TestZeroScalar(t *testing.T) {
	zeroBytes := make([]byte, PrivateKeySize)

	var key PrivateKey
	err := key.UnmarshalBinary(zeroBytes)
	if !errors.Is(err, ErrZeroScalar) {
		t.Errorf("UnmarshalBinary(zero) error = %v, want ErrZeroScalar", err)
	}
}

func TestMalformedBytes(t *testing.T) {
	tests := []struct {
		name string
		fn   func() error
	}{
		{
			name: "PrivateKey.UnmarshalBinary too short",
			fn: func() error {
				var k PrivateKey
				return k.UnmarshalBinary(make([]byte, 10))
			},
		},
		{
			name: "PrivateKey.UnmarshalBinary too long",
			fn: func() error {
				var k PrivateKey
				return k.UnmarshalBinary(make([]byte, 100))
			},
		},
		{
			name: "PublicKey.UnmarshalBinary too short",
			fn: func() error {
				var k PublicKey
				return k.UnmarshalBinary(make([]byte, 10))
			},
		},
		{
			name: "PublicKey.UnmarshalBinary too long",
			fn: func() error {
				var k PublicKey
				return k.UnmarshalBinary(make([]byte, 200))
			},
		},
		{
			name: "PublicKey.UnmarshalBinary wrong prefix",
			fn: func() error {
				var k PublicKey
				data := make([]byte, PublicKeySize)
				data[0] = 0x02
				return k.UnmarshalBinary(data)
			},
		},
		{
			name: "CreateRecoveryRequest wrong clientPublic size",
			fn: func() error {
				key, _ := GenerateKey(rand.Reader)
				_, _, err := NewClient().CreateRecoveryRequest(
					make([]byte, 10),
					key.Public(),
					rand.Reader,
				)
				return err
			},
		},
		{
			name: "CreateRecoveryRequest wrong clientPublic prefix",
			fn: func() error {
				key, _ := GenerateKey(rand.Reader)
				data := make([]byte, PublicKeySize)
				data[0] = 0x02
				_, _, err := NewClient().CreateRecoveryRequest(
					data,
					key.Public(),
					rand.Reader,
				)
				return err
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.fn()
			if err == nil {
				t.Errorf("%s: expected error, got nil", tc.name)
			}
		})
	}
}

func TestMultipleRecoveries(t *testing.T) {
	serverKey, _ := GenerateKey(rand.Reader)
	server, _ := NewServer(serverKey)
	client := NewClient()

	provisionResult, err := client.Provision(server.PublicKey(), rand.Reader)
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	for i := 0; i < 3; i++ {
		request, state, err := client.CreateRecoveryRequest(
			provisionResult.ClientPublic,
			server.PublicKey(),
			rand.Reader,
		)
		if err != nil {
			t.Fatalf("CreateRecoveryRequest %d failed: %v", i, err)
		}

		response, err := server.ProcessRecoveryRequest(request)
		if err != nil {
			t.Fatalf("ProcessRecoveryRequest %d failed: %v", i, err)
		}

		recoveredPoint, err := client.RecoverKey(state, response)
		if err != nil {
			t.Fatalf("RecoverKey %d failed: %v", i, err)
		}

		if !bytes.Equal(recoveredPoint, provisionResult.SharedPoint) {
			t.Errorf("Recovery %d: point mismatch", i)
		}
	}
}

func TestRecoveryStateInvalidatedAfterUse(t *testing.T) {
	serverKey, _ := GenerateKey(rand.Reader)
	server, _ := NewServer(serverKey)
	client := NewClient()

	provisionResult, _ := client.Provision(server.PublicKey(), rand.Reader)

	request, state, _ := client.CreateRecoveryRequest(
		provisionResult.ClientPublic,
		server.PublicKey(),
		rand.Reader,
	)
	response, _ := server.ProcessRecoveryRequest(request)

	_, err := client.RecoverKey(state, response)
	if err != nil {
		t.Fatalf("First RecoverKey failed: %v", err)
	}

	_, err = client.RecoverKey(state, response)
	if !errors.Is(err, ErrNilKey) {
		t.Errorf("Reusing state: got %v, want ErrNilKey", err)
	}
}

func TestExtractXConsistency(t *testing.T) {
	for i := 0; i < 10; i++ {
		key, _ := GenerateKey(rand.Reader)
		pubBytes, _ := key.Public().MarshalBinary()

		x, err := ExtractX(pubBytes)
		if err != nil {
			t.Fatalf("ExtractX failed: %v", err)
		}

		expectedX := pubBytes[1 : 1+XCoordinateSize]
		if !bytes.Equal(x, expectedX) {
			t.Errorf("Iteration %d: x-coordinate mismatch", i)
		}
	}
}

func BenchmarkProvision(b *testing.B) {
	serverKey, _ := GenerateKey(rand.Reader)
	server, _ := NewServer(serverKey)
	client := NewClient()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := client.Provision(server.PublicKey(), rand.Reader)
		if err != nil {
			b.Fatalf("Provision failed: %v", err)
		}
	}
}

func BenchmarkRecover(b *testing.B) {
	serverKey, _ := GenerateKey(rand.Reader)
	server, _ := NewServer(serverKey)
	client := NewClient()

	provisionResult, _ := client.Provision(server.PublicKey(), rand.Reader)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		request, state, err := client.CreateRecoveryRequest(
			provisionResult.ClientPublic,
			server.PublicKey(),
			rand.Reader,
		)
		if err != nil {
			b.Fatalf("CreateRecoveryRequest failed: %v", err)
		}

		response, err := server.ProcessRecoveryRequest(request)
		if err != nil {
			b.Fatalf("ProcessRecoveryRequest failed: %v", err)
		}

		_, err = client.RecoverKey(state, response)
		if err != nil {
			b.Fatalf("RecoverKey failed: %v", err)
		}
	}
}

func BenchmarkExtractX(b *testing.B) {
	key, _ := GenerateKey(rand.Reader)
	pubBytes, _ := key.Public().MarshalBinary()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ExtractX(pubBytes)
		if err != nil {
			b.Fatalf("ExtractX failed: %v", err)
		}
	}
}

func BenchmarkGenerateKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GenerateKey(rand.Reader)
		if err != nil {
			b.Fatalf("GenerateKey failed: %v", err)
		}
	}
}

func TestIdentityPointRejection(t *testing.T) {
	identity := group.P521.Identity()
	identityBytes, _ := identity.MarshalBinary()

	t.Run("PublicKey.UnmarshalBinary rejects identity", func(t *testing.T) {
		var k PublicKey
		err := k.UnmarshalBinary(identityBytes)
		if err == nil {
			t.Error("Expected error for identity point")
		}
	})

	t.Run("Server.ProcessRecoveryRequest validates input", func(t *testing.T) {
		serverKey, _ := GenerateKey(rand.Reader)
		server, _ := NewServer(serverKey)

		_, err := server.ProcessRecoveryRequest(&RecoveryRequest{
			BlindedPoint: identityBytes,
		})
		if err == nil {
			t.Error("Expected error for identity point in request")
		}
	})
}
