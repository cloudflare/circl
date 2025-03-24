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
	peers, groupPublicKey, keyShareCommits := privKey.Split(rand.Reader, t, n)

	// every peer can validate its own keyShare.
	for i := range peers {
		valid := peers[i].CheckKeyShare(keyShareCommits)
		test.CheckOk(valid == true, "invalid key share", tt)
	}

	// Only k peers try to generate a signature.
	for k := uint(0); k < n; k++ {
		// round 1
		nonces := make([]frost.Nonce, k)
		commits := make([]frost.Commitment, k)
		pkSigners := make([]frost.PublicKey, k)
		for i := range peers[:k] {
			nonce, commit, err := peers[i].Commit(rand.Reader)
			test.CheckNoErr(tt, err, "failed to commit")
			pkSigners[i] = peers[i].PublicKey()
			nonces[i] = *nonce
			commits[i] = *commit
		}

		// round 2
		msg := []byte("it's cold here")
		signShares := make([]frost.SignShare, k)
		for i := range peers[:k] {
			sigShare, err := peers[i].Sign(msg, groupPublicKey, nonces[i], commits)
			test.CheckNoErr(tt, err, "failed to create a sign share")
			signShares[i] = *sigShare
		}

		// Coordinator
		coordinator, err := frost.NewCoordinator(suite, t, n)
		test.CheckNoErr(tt, err, "failed to create combiner")

		valid := coordinator.CheckSignShares(msg, groupPublicKey, signShares, commits, pkSigners)
		if k > t {
			test.CheckOk(valid == true, "invalid sign shares", tt)
		} else {
			test.CheckOk(valid == false, "must be invalid sign shares", tt)
		}

		signature, err := coordinator.Aggregate(msg, groupPublicKey, signShares, commits)
		if k > t {
			test.CheckNoErr(tt, err, "failed to produce signature")
			// anyone can verify
			valid := frost.Verify(msg, groupPublicKey, signature)
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
	peers, groupPublicKey, keyShareCommits := privKey.Split(rand.Reader, t, n)

	msg := []byte("it's cold here")
	nonces := make([]frost.Nonce, len(peers))
	commits := make([]frost.Commitment, len(peers))
	pkSigners := make([]frost.PublicKey, len(peers))
	for i := range peers {
		nonce, commit, err := peers[i].Commit(rand.Reader)
		test.CheckNoErr(b, err, "failed to commit")
		pkSigners[i] = peers[i].PublicKey()
		nonces[i] = *nonce
		commits[i] = *commit
	}

	signShares := make([]frost.SignShare, len(peers))
	for i := range peers {
		sigShare, err := peers[i].Sign(msg, groupPublicKey, nonces[i], commits)
		test.CheckNoErr(b, err, "failed to create a sign share")
		signShares[i] = *sigShare
	}
	coordinator, err := frost.NewCoordinator(suite, t, n)
	test.CheckNoErr(b, err, "failed to create combiner")
	signature, err := coordinator.Aggregate(msg, groupPublicKey, signShares, commits)
	test.CheckNoErr(b, err, "failed to aggregate")
	valid := frost.Verify(msg, groupPublicKey, signature)
	test.CheckOk(valid, "failed to verify", b)

	b.Run("SplitKey", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, _ = privKey.Split(rand.Reader, t, n)
		}
	})

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
			_, _ = peers[0].Sign(msg, groupPublicKey, nonces[0], commits)
		}
	})

	b.Run("CheckSignShares", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = coordinator.CheckSignShares(msg, groupPublicKey, signShares, commits, pkSigners)
		}
	})

	b.Run("Aggregate", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = coordinator.Aggregate(msg, groupPublicKey, signShares, commits)
		}
	})

	b.Run("Verify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = frost.Verify(msg, groupPublicKey, signature)
		}
	})
}
