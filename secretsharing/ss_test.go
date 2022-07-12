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
	t := uint(2)
	n := uint(5)

	secret := g.RandomScalar(rand.Reader)
	ss := secretsharing.New(rand.Reader, t, secret)
	shares := ss.Share(n)
	test.CheckOk(len(shares) == int(n), "bad num shares", tt)
	coms := ss.CommitSecret()

	tt.Run("subsetSize", func(ttt *testing.T) {
		// Test any possible subset size.
		for k := 0; k <= int(n); k++ {
			got, err := secretsharing.Recover(t, shares[:k])
			if !(int(t) < k && k <= int(n)) {
				test.CheckIsErr(ttt, err, "should not recover secret")
				test.CheckOk(got == nil, "not nil secret", ttt)
			} else {
				test.CheckNoErr(ttt, err, "should recover secret")
				want := secret
				if !got.IsEqual(want) {
					test.ReportError(ttt, got, want, t, k, n)
				}
			}
		}
	})

	tt.Run("verifyShares", func(ttt *testing.T) {
		for i := range shares {
			test.CheckOk(secretsharing.Verify(t, shares[i], coms) == true, "failed one share", ttt)
		}
	})

	tt.Run("badShares", func(ttt *testing.T) {
		badShares := make([]secretsharing.Share, len(shares))
		for i := range shares {
			badShares[i].ID = shares[i].ID.Copy()
			badShares[i].Value = shares[i].Value.Copy()
			badShares[i].Value.SetUint64(9)
		}

		for i := range badShares {
			test.CheckOk(secretsharing.Verify(t, badShares[i], coms) == false, "verify must fail due to bad shares", ttt)
		}
	})

	tt.Run("badCommitments", func(ttt *testing.T) {
		badComs := make(secretsharing.SecretCommitment, len(coms))
		for i := range coms {
			badComs[i] = coms[i].Copy()
			badComs[i].Dbl(badComs[i])
		}

		for i := range shares {
			test.CheckOk(secretsharing.Verify(t, shares[i], badComs) == false, "verify must fail due to bad commitment", ttt)
		}
	})
}

func TestShareWithID(tt *testing.T) {
	g := group.P256
	t := uint(2)
	n := uint(5)
	secret := g.RandomScalar(rand.Reader)
	ss := secretsharing.New(rand.Reader, t, secret)

	tt.Run("recoverOk", func(ttt *testing.T) {
		// SecretSharing can create shares at will, not exactly n many.
		shares := []secretsharing.Share{
			ss.ShareWithID(g.RandomScalar(rand.Reader)),
			ss.ShareWithID(g.RandomScalar(rand.Reader)),
			ss.ShareWithID(g.RandomScalar(rand.Reader)),
		}
		got, err := secretsharing.Recover(t, shares)
		test.CheckNoErr(tt, err, "failed to recover the secret")
		want := secret
		if !got.IsEqual(want) {
			test.ReportError(tt, got, want, t, n)
		}
	})

	tt.Run("duplicatedFail", func(ttt *testing.T) {
		// Panics if trying to recover duplicated shares.
		share := ss.ShareWithID(g.RandomScalar(rand.Reader))
		sameShares := []secretsharing.Share{share, share, share}
		err := test.CheckPanic(func() {
			got, err := secretsharing.Recover(t, sameShares)
			test.CheckIsErr(tt, err, "must fail to recover the secret")
			test.CheckOk(got == nil, "must not recover", tt)
		})
		test.CheckOk(err == nil, "must panic", tt)
	})
}

func BenchmarkSecretSharing(b *testing.B) {
	g := group.P256
	t := uint(3)
	n := uint(5)

	secret := g.RandomScalar(rand.Reader)
	ss := secretsharing.New(rand.Reader, t, secret)
	shares := ss.Share(n)
	coms := ss.CommitSecret()

	b.Run("New", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			secretsharing.New(rand.Reader, t, secret)
		}
	})

	b.Run("Share", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ss.Share(n)
		}
	})

	b.Run("Recover", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = secretsharing.Recover(t, shares)
		}
	})

	b.Run("CommitSecret", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ss.CommitSecret()
		}
	})

	b.Run("Verify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			secretsharing.Verify(t, shares[0], coms)
		}
	})
}
