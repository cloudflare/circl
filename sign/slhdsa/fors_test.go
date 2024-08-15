package slhdsa

import (
	"bytes"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

// See FIPS 205 -- Section 8.2 -- Algorithm 15 -- Recursive version.
func (s *statePriv) forsNodeRec(i, z uint32, addr address) (node []byte) {
	if !(z <= s.a && i < s.k<<(s.a-z)) {
		panic(ErrTree)
	}

	node = make([]byte, s.n)
	if z == 0 {
		sk := s.forsSkGen(addr, i)
		addr.SetTreeHeight(0)
		addr.SetTreeIndex(i)

		s.F.address.Set(addr)
		s.F.SetMessage(sk)
		copy(node, s.F.Final())
	} else {
		lnode := s.forsNodeRec(2*i, z-1, addr)
		rnode := s.forsNodeRec(2*i+1, z-1, addr)

		s.H.address.Set(addr)
		s.H.address.SetTreeHeight(z)
		s.H.address.SetTreeIndex(i)
		s.H.SetMsgs(lnode, rnode)
		copy(node, s.H.Final())
	}

	return
}

func testFors(t *testing.T, p *params) {
	skSeed := mustRead(t, p.n)
	pkSeed := mustRead(t, p.n)
	msg := mustRead(t, p.forsMsgSize())

	state := p.NewStatePriv(skSeed, pkSeed)

	idxTree := [3]uint32{0, 0, 0}
	idxLeaf := uint32(0)

	addr := p.NewAddress()
	addr.SetLayerAddress(p.d - 1)

	pkRoot := make([]byte, p.n)
	state.xmssNodeIter(p.NewStack(p.hPrime), pkRoot, idxLeaf, p.hPrime, addr)

	n0 := state.forsNodeRec(idxLeaf, p.a, addr)

	n1 := make([]byte, p.n)
	state.forsNodeIter(p.NewStack(p.a), n1, idxLeaf, p.a, addr)

	if !bytes.Equal(n0, n1) {
		test.ReportError(t, n0, n1)
	}

	var sig forsSignature
	curSig := cursor(make([]byte, p.forsSigSize()))
	sig.fromBytes(p, &curSig)
	state.forsSign(sig, msg, addr)

	pkFors := state.forsPkFromSig(msg, sig, addr)

	var htSig hyperTreeSignature
	curHtSig := cursor(make([]byte, p.hyperTreeSigSize()))
	htSig.fromBytes(p, &curHtSig)
	state.htSign(htSig, pkFors, idxTree, idxLeaf)

	valid := state.htVerify(pkFors, pkRoot, idxTree, idxLeaf, htSig)
	test.CheckOk(valid, "hypertree signature verification failed", t)
}

func benchmarkFors(b *testing.B, p *params) {
	skSeed := mustRead(b, p.n)
	pkSeed := mustRead(b, p.n)
	msg := mustRead(b, p.forsMsgSize())

	state := p.NewStatePriv(skSeed, pkSeed)

	addr := p.NewAddress()
	addr.SetLayerAddress(p.d - 1)

	var sig forsSignature
	curSig := cursor(make([]byte, p.forsSigSize()))
	sig.fromBytes(p, &curSig)
	state.forsSign(sig, msg, addr)

	b.Run("NodeRec", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = state.forsNodeRec(0, p.a, addr)
		}
	})
	b.Run("NodeIter", func(b *testing.B) {
		node := make([]byte, p.n)
		forsStack := p.NewStack(p.a)
		for i := 0; i < b.N; i++ {
			state.forsNodeIter(forsStack, node, 0, p.a, addr)
		}
	})
	b.Run("Sign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			state.forsSign(sig, msg, addr)
		}
	})
	b.Run("PkFromSig", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = state.forsPkFromSig(msg, sig, addr)
		}
	})
}
