package classicmceliece

import (
	"bytes"
	"testing"
)

func BenchmarkDeriveKeyPair(b *testing.B) {
	for _, v := range publicVariants {
		b.Run(v.katName, func(b *testing.B) {
			seed := bytes.Repeat([]byte{0x42}, v.scheme.SeedSize())
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				seed[0] = byte(i)
				pk, sk := v.scheme.DeriveKeyPair(seed)
				if pk == nil || sk == nil {
					b.Fatal("nil key")
				}
			}
		})
	}
}

func BenchmarkEncapsulateDeterministically(b *testing.B) {
	for _, v := range publicVariants {
		b.Run(v.katName, func(b *testing.B) {
			pk, _ := v.scheme.DeriveKeyPair(bytes.Repeat([]byte{0x42}, v.scheme.SeedSize()))
			seed := bytes.Repeat([]byte{0x24}, v.scheme.EncapsulationSeedSize())
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				seed[0] = byte(i)
				ct, ss, err := v.scheme.EncapsulateDeterministically(pk, seed)
				if err != nil {
					b.Fatal(err)
				}
				if len(ct) != v.scheme.CiphertextSize() || len(ss) != v.scheme.SharedKeySize() {
					b.Fatal("bad output size")
				}
			}
		})
	}
}

func BenchmarkDecapsulate(b *testing.B) {
	for _, v := range publicVariants {
		b.Run(v.katName, func(b *testing.B) {
			pk, sk := v.scheme.DeriveKeyPair(bytes.Repeat([]byte{0x42}, v.scheme.SeedSize()))
			ct, _, err := v.scheme.EncapsulateDeterministically(pk, bytes.Repeat([]byte{0x24}, v.scheme.EncapsulationSeedSize()))
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ss, err := v.scheme.Decapsulate(sk, ct)
				if err != nil {
					b.Fatal(err)
				}
				if len(ss) != v.scheme.SharedKeySize() {
					b.Fatal("bad shared-secret size")
				}
			}
		})
	}
}

func BenchmarkMarshalPublicKey(b *testing.B) {
	for _, v := range publicVariants {
		b.Run(v.katName, func(b *testing.B) {
			pk, _ := v.scheme.DeriveKeyPair(bytes.Repeat([]byte{0x42}, v.scheme.SeedSize()))
			b.ReportAllocs()
			b.SetBytes(int64(v.scheme.PublicKeySize()))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				out, err := pk.MarshalBinary()
				if err != nil {
					b.Fatal(err)
				}
				if len(out) != v.scheme.PublicKeySize() {
					b.Fatal("bad public-key size")
				}
			}
		})
	}
}

func BenchmarkUnmarshalPublicKey(b *testing.B) {
	for _, v := range publicVariants {
		b.Run(v.katName, func(b *testing.B) {
			pk, _ := v.scheme.DeriveKeyPair(bytes.Repeat([]byte{0x42}, v.scheme.SeedSize()))
			buf, err := pk.MarshalBinary()
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.SetBytes(int64(v.scheme.PublicKeySize()))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				out, err := v.scheme.UnmarshalBinaryPublicKey(buf)
				if err != nil {
					b.Fatal(err)
				}
				if out == nil {
					b.Fatal("nil public key")
				}
			}
		})
	}
}

func BenchmarkMarshalPrivateKey(b *testing.B) {
	for _, v := range publicVariants {
		b.Run(v.katName, func(b *testing.B) {
			_, sk := v.scheme.DeriveKeyPair(bytes.Repeat([]byte{0x42}, v.scheme.SeedSize()))
			b.ReportAllocs()
			b.SetBytes(int64(v.scheme.PrivateKeySize()))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				out, err := sk.MarshalBinary()
				if err != nil {
					b.Fatal(err)
				}
				if len(out) != v.scheme.PrivateKeySize() {
					b.Fatal("bad private-key size")
				}
			}
		})
	}
}

func BenchmarkUnmarshalPrivateKeyRecoverPublic(b *testing.B) {
	for _, v := range publicVariants {
		b.Run(v.katName, func(b *testing.B) {
			_, sk := v.scheme.DeriveKeyPair(bytes.Repeat([]byte{0x42}, v.scheme.SeedSize()))
			buf, err := sk.MarshalBinary()
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.SetBytes(int64(v.scheme.PrivateKeySize()))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				out, err := v.scheme.UnmarshalBinaryPrivateKey(buf)
				if err != nil {
					b.Fatal(err)
				}
				if out == nil {
					b.Fatal("nil private key")
				}
			}
		})
	}
}

func BenchmarkPrivateKeyPublic(b *testing.B) {
	for _, v := range publicVariants {
		b.Run(v.katName, func(b *testing.B) {
			pk, sk := v.scheme.DeriveKeyPair(bytes.Repeat([]byte{0x42}, v.scheme.SeedSize()))
			b.ReportAllocs()
			b.SetBytes(int64(v.scheme.PublicKeySize()))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				out := sk.Public()
				if !pk.Equal(out) {
					b.Fatal("public key mismatch")
				}
			}
		})
	}
}
