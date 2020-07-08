package eddilithium4_test

import (
	"github.com/cloudflare/circl/sign/eddilithium4"

	"encoding/binary"
	"testing"
)

func BenchmarkVerify(b *testing.B) {
	// Note that Dilithium precomputes quite a bit during Unpacking/Keygen
	// instead of at the moment of verification (as compared to the reference
	// implementation.  A fair comparison thus should sum verification
	// times with unpacking times.)
	var seed [57]byte
	var msg [8]byte
	var sig [eddilithium4.SignatureSize]byte
	pk, sk := eddilithium4.NewKeyFromSeed(&seed)
	eddilithium4.SignTo(sk, msg[:], sig[:])
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// We should generate a new signature for every verify attempt,
		// as this influences the time a little bit.  This difference, however,
		// is small and generating a new signature in between creates a lot
		// pressure on the allocator which makes an accurate measurement hard.
		eddilithium4.Verify(pk, msg[:], sig[:])
	}
}

func BenchmarkSign(b *testing.B) {
	// Note that Dilithium precomputes quite a bit during Unpacking/Keygen
	// instead of at the moment of signing (as compared to the reference
	// implementation.  A fair comparison thus should sum sign times with
	// unpacking times.)
	var seed [57]byte
	var msg [8]byte
	var sig [eddilithium4.SignatureSize]byte
	_, sk := eddilithium4.NewKeyFromSeed(&seed)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		binary.LittleEndian.PutUint64(msg[:], uint64(i))
		eddilithium4.SignTo(sk, msg[:], sig[:])
	}
}

func BenchmarkGenerateKey(b *testing.B) {
	var seed [57]byte
	for i := 0; i < b.N; i++ {
		binary.LittleEndian.PutUint64(seed[:], uint64(i))
		eddilithium4.NewKeyFromSeed(&seed)
	}
}

func BenchmarkPublicFromPrivate(b *testing.B) {
	var seed [57]byte
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		binary.LittleEndian.PutUint64(seed[:], uint64(i))
		_, sk := eddilithium4.NewKeyFromSeed(&seed)
		b.StartTimer()
		sk.Public()
	}
}

func TestSignThenVerifyAndPkSkPacking(t *testing.T) {
	var seed [eddilithium4.SeedSize]byte
	var sig [eddilithium4.SignatureSize]byte
	var msg [8]byte
	var pkb1, pkb2 [eddilithium4.PublicKeySize]byte
	var skb1, skb2 [eddilithium4.PrivateKeySize]byte
	var pk2 eddilithium4.PublicKey
	var sk2 eddilithium4.PrivateKey
	for i := uint64(0); i < 100; i++ {
		binary.LittleEndian.PutUint64(seed[:], i)
		pk, sk := eddilithium4.NewKeyFromSeed(&seed)
		for j := uint64(0); j < 10; j++ {
			binary.LittleEndian.PutUint64(msg[:], j)
			eddilithium4.SignTo(sk, msg[:], sig[:])
			if !eddilithium4.Verify(pk, msg[:], sig[:]) {
				t.Fatal()
			}
		}
		pk.Pack(&pkb1)
		pk2.Unpack(&pkb1)
		pk2.Pack(&pkb2)
		if pkb1 != pkb2 {
			t.Fatal()
		}
		sk.Pack(&skb1)
		sk2.Unpack(&skb1)
		sk2.Pack(&skb2)
		if skb1 != skb2 {
			t.Fatal()
		}
	}
}

func TestPublicFromPrivate(t *testing.T) {
	var seed [eddilithium4.SeedSize]byte
	for i := uint64(0); i < 100; i++ {
		binary.LittleEndian.PutUint64(seed[:], i)
		pk, sk := eddilithium4.NewKeyFromSeed(&seed)
		pk2 := sk.Public().(*eddilithium4.PublicKey)
		var pkb1, pkb2 [eddilithium4.PublicKeySize]byte
		pk.Pack(&pkb1)
		pk2.Pack(&pkb2)
		if pkb1 != pkb2 {
			t.Fatal()
		}
	}
}
