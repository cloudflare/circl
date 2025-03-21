package slhdsa

import (
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func testHyperTree(t *testing.T, p *params) {
	skSeed := mustRead(t, p.n)
	pkSeed := mustRead(t, p.n)
	msg := mustRead(t, p.n)

	state := p.NewStatePriv(skSeed, pkSeed)

	idxTree := [3]uint32{0, 0, 0}
	idxLeaf := uint32(0)

	addr := p.NewAddress()
	addr.SetLayerAddress(p.d - 1)
	stack := p.NewStack(p.hPrime)
	pkRoot := make([]byte, p.n)
	state.xmssNodeIter(stack, pkRoot, idxLeaf, p.hPrime, addr)

	var sig hyperTreeSignature
	curSig := cursor(make([]byte, p.hyperTreeSigSize()))
	sig.fromBytes(p, &curSig)
	state.htSign(sig, msg, idxTree, idxLeaf)

	valid := state.htVerify(msg, pkRoot, idxTree, idxLeaf, sig)
	test.CheckOk(valid, "hypertree signature verification failed", t)
}

func benchmarkHyperTree(b *testing.B, p *params) {
	skSeed := mustRead(b, p.n)
	pkSeed := mustRead(b, p.n)
	pkRoot := mustRead(b, p.n)
	msg := mustRead(b, p.n)

	state := p.NewStatePriv(skSeed, pkSeed)

	idxTree := [3]uint32{0, 0, 0}
	idxLeaf := uint32(0)

	var sig hyperTreeSignature
	curSig := cursor(make([]byte, p.hyperTreeSigSize()))
	sig.fromBytes(p, &curSig)
	state.htSign(sig, msg, idxTree, idxLeaf)

	b.Run("Sign", func(b *testing.B) {
		for range b.N {
			state.htSign(sig, msg, idxTree, idxLeaf)
		}
	})
	b.Run("Verify", func(b *testing.B) {
		for range b.N {
			_ = state.htVerify(msg, pkRoot, idxTree, idxLeaf, sig)
		}
	})
}
