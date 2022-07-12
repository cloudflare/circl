package frost_test

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/tss/frost"
)

func TestFrost(t *testing.T) {
	for _, si := range []frost.Suite{frost.Ristretto255, frost.P256} {
		t.Run(fmt.Sprintf("%v", si), func(tt *testing.T) { testFrost(tt, si) })
	}
}

func testFrost(tt *testing.T, suite frost.Suite) {
	t, n := uint(3), uint(5)

	privKey := frost.GenerateKey(suite, rand.Reader)
	pubKeyGroup := privKey.Public()
	peers, keyShareCommits, err := privKey.Split(rand.Reader, t, n)
	test.CheckNoErr(tt, err, "failed to split secret")

	// every peer can validate its own keyShare.
	for i := range peers {
		valid := peers[i].CheckKeyShare(keyShareCommits)
		test.CheckOk(valid == true, "invalid key share", tt)
	}

	// Only k peers try to generate a signature.
	for k := uint(0); k < n; k++ {
		// round 1
		nonces := make([]*frost.Nonce, k)
		commits := make([]*frost.Commitment, k)
		pkSigners := make([]*frost.PublicKey, k)
		for i := range peers[:k] {
			nonces[i], commits[i], err = peers[i].Commit(rand.Reader)
			test.CheckNoErr(tt, err, "failed to commit")
			pkSigners[i] = peers[i].Public()
		}

		// round 2
		msg := []byte("it's cold here")
		signShares := make([]*frost.SignShare, k)
		for i := range peers[:k] {
			signShares[i], err = peers[i].Sign(msg, pubKeyGroup, nonces[i], commits)
			test.CheckNoErr(tt, err, "failed to create a sign share")
		}

		// Combiner
		combiner, err := frost.NewCombiner(suite, t, n)
		test.CheckNoErr(tt, err, "failed to create combiner")

		valid := combiner.CheckSignShares(signShares, pkSigners, commits, pubKeyGroup, msg)
		if k > t {
			test.CheckOk(valid == true, "invalid sign shares", tt)
		} else {
			test.CheckOk(valid == false, "must be invalid sign shares", tt)
		}

		signature, err := combiner.Sign(msg, commits, signShares)
		if k > t {
			test.CheckNoErr(tt, err, "failed to produce signature")
			// anyone can verify
			valid := frost.Verify(suite, pubKeyGroup, msg, signature)
			test.CheckOk(valid == true, "invalid signature", tt)
		} else {
			test.CheckIsErr(tt, err, "should not produce a signature")
			test.CheckOk(signature == nil, "not nil signature", tt)
		}
	}
}

func BenchmarkFrost(b *testing.B) {
	for _, si := range []frost.Suite{frost.Ristretto255, frost.P256} {
		b.Run(fmt.Sprintf("%v", si), func(bb *testing.B) { benchmarkFrost(bb, si) })
	}
}

func benchmarkFrost(b *testing.B, suite frost.Suite) {
	t, n := uint(3), uint(5)

	privKey := frost.GenerateKey(suite, rand.Reader)
	peers, keyShareCommits, err := privKey.Split(rand.Reader, t, n)
	test.CheckNoErr(b, err, "failed to split secret")

	b.Run("SplitKey", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, _ = privKey.Split(rand.Reader, t, n)
		}
	})

	pubKeyGroup := privKey.Public()
	msg := []byte("it's cold here")

	nonces := make([]*frost.Nonce, len(peers))
	commits := make([]*frost.Commitment, len(peers))
	pkSigners := make([]*frost.PublicKey, len(peers))
	for i := range peers {
		nonces[i], commits[i], err = peers[i].Commit(rand.Reader)
		test.CheckNoErr(b, err, "failed to commit")
		pkSigners[i] = peers[i].Public()
	}

	b.Run("CheckKeyShare", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = peers[0].CheckKeyShare(keyShareCommits)
		}
	})

	b.Run("Commit", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, _ = peers[0].Commit(rand.Reader)
		}
	})

	b.Run("SignShare", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = peers[0].Sign(msg, pubKeyGroup, nonces[0], commits)
		}
	})

	signShares := make([]*frost.SignShare, len(peers))
	for i := range peers {
		signShares[i], err = peers[i].Sign(msg, pubKeyGroup, nonces[i], commits)
		test.CheckNoErr(b, err, "failed to create a sign share")
	}

	combiner, err := frost.NewCombiner(suite, t, n)
	test.CheckNoErr(b, err, "failed to create combiner")

	b.Run("CheckSignShares", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = combiner.CheckSignShares(signShares, pkSigners, commits, pubKeyGroup, msg)
		}
	})

	b.Run("Sign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = combiner.Sign(msg, commits, signShares)
		}
	})

	b.Run("Verify", func(b *testing.B) {
		signature, _ := combiner.Sign(msg, commits, signShares)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = frost.Verify(suite, pubKeyGroup, msg, signature)
		}
	})
}
