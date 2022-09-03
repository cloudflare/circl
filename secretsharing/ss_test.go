package secretsharing_test

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/secretsharing"
)

func TestSecretSharing(tt *testing.T) {
	g := group.P256
	t := uint(3)
	n := uint(5)

	s, err := secretsharing.New(g, t, n)
	test.CheckNoErr(tt, err, "failed to create ShamirSS")

	want := g.RandomScalar(rand.Reader)
	shares := s.Shard(rand.Reader, want)
	test.CheckOk(len(shares) == int(n), "bad num shares", tt)

	tt.Run("subsetSize", func(ttt *testing.T) {
		// Test any possible subset size.
		for k := 0; k < int(n); k++ {
			got, err := s.Recover(shares[:k])
			if k <= int(t) {
				test.CheckIsErr(ttt, err, "should not recover secret")
				test.CheckOk(got == nil, "not nil secret", ttt)
			} else {
				test.CheckNoErr(ttt, err, "should recover secret")
				if !got.IsEqual(want) {
					test.ReportError(ttt, got, want, t, k, n)
				}
			}
		}
	})
}

func TestVerifiableSecretSharing(tt *testing.T) {
	g := group.P256
	t := uint(3)
	n := uint(5)

	vs, err := secretsharing.NewVerifiable(g, t, n)
	test.CheckNoErr(tt, err, "failed to create ShamirSS")

	want := g.RandomScalar(rand.Reader)
	shares, com := vs.Shard(rand.Reader, want)
	test.CheckOk(len(shares) == int(n), "bad num shares", tt)
	test.CheckOk(len(com) == int(t+1), "bad num commitments", tt)

	tt.Run("verifyShares", func(ttt *testing.T) {
		for i := range shares {
			test.CheckOk(vs.Verify(shares[i], com) == true, "failed one share", ttt)
		}
	})

	tt.Run("subsetSize", func(ttt *testing.T) {
		// Test any possible subset size.
		for k := 0; k < int(n); k++ {
			got, err := vs.Recover(shares[:k])
			if k <= int(t) {
				test.CheckIsErr(ttt, err, "should not recover secret")
				test.CheckOk(got == nil, "not nil secret", ttt)
			} else {
				test.CheckNoErr(ttt, err, "should recover secret")
				if !got.IsEqual(want) {
					test.ReportError(ttt, got, want, t, k, n)
				}
			}
		}
	})

	tt.Run("badShares", func(ttt *testing.T) {
		badShares := make([]secretsharing.Share, len(shares))
		for i := range shares {
			badShares[i].Share = shares[i].Share.Copy()
			badShares[i].Share.SetUint64(9)
		}

		for i := range badShares {
			test.CheckOk(vs.Verify(badShares[i], com) == false, "verify must fail due to bad shares", ttt)
		}
	})

	tt.Run("badCommitments", func(ttt *testing.T) {
		badCom := make(secretsharing.SharesCommitment, len(com))
		for i := range com {
			badCom[i] = com[i].Copy()
			badCom[i].Dbl(badCom[i])
		}

		for i := range shares {
			test.CheckOk(vs.Verify(shares[i], badCom) == false, "verify must fail due to bad commitment", ttt)
		}
	})
}

func BenchmarkSecretSharing(b *testing.B) {
	g := group.P256
	t := uint(3)
	n := uint(5)

	s, _ := secretsharing.New(g, t, n)
	want := g.RandomScalar(rand.Reader)
	shares := s.Shard(rand.Reader, want)

	b.Run("Shard", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			s.Shard(rand.Reader, want)
		}
	})

	b.Run("Recover", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = s.Recover(shares)
		}
	})
}

func BenchmarkVerifiableSecretSharing(b *testing.B) {
	g := group.P256
	t := uint(3)
	n := uint(5)

	vs, _ := secretsharing.NewVerifiable(g, t, n)
	want := g.RandomScalar(rand.Reader)
	shares, com := vs.Shard(rand.Reader, want)

	b.Run("Shard", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			vs.Shard(rand.Reader, want)
		}
	})

	b.Run("Recover", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = vs.Recover(shares)
		}
	})

	b.Run("Verify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			vs.Verify(shares[0], com)
		}
	})
}
