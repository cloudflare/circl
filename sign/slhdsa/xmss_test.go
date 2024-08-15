package slhdsa

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

// See FIPS 205 -- Section 6.1 -- Algorithm 9 -- Recursive version.
func (s *statePriv) xmssNodeRec(i, z uint32, addr address) (node []byte) {
	if !(z <= s.hPrime && i < (1<<(s.hPrime-z))) {
		panic(ErrTree)
	}

	node = make([]byte, s.n)
	if z == 0 {
		addr.SetTypeAndClear(addressWotsHash)
		addr.SetKeyPairAddress(i)
		copy(node, s.wotsPkGen(addr))
	} else {
		lnode := s.xmssNodeRec(2*i, z-1, addr)
		rnode := s.xmssNodeRec(2*i+1, z-1, addr)

		s.H.address.Set(addr)
		s.H.address.SetTypeAndClear(addressTree)
		s.H.address.SetTreeHeight(z)
		s.H.address.SetTreeIndex(i)
		s.H.SetMsgs(lnode, rnode)
		copy(node, s.H.Final())
	}

	return
}

func testXmss(t *testing.T, p *params) {
	skSeed := mustRead(t, p.n)
	pkSeed := mustRead(t, p.n)
	msg := mustRead(t, p.n)

	state := p.NewStatePriv(skSeed, pkSeed)

	addr := p.NewAddress()
	addr.SetTypeAndClear(addressWotsHash)
	idx := uint32(0)

	rootRec := state.xmssNodeRec(idx, p.hPrime, addr)
	test.CheckOk(
		len(rootRec) == int(p.n),
		fmt.Sprintf("bad xmss rootRec length: %v", len(rootRec)),
		t,
	)

	stack := p.NewStack(p.hPrime)
	rootIter := make([]byte, p.n)
	state.xmssNodeIter(stack, rootIter, idx, p.hPrime, addr)

	if !bytes.Equal(rootRec, rootIter) {
		test.ReportError(t, rootRec, rootIter, skSeed, pkSeed, msg)
	}

	var sig xmssSignature
	curSig := cursor(make([]byte, p.xmssSigSize()))
	sig.fromBytes(p, &curSig)
	state.xmssSign(stack, sig, msg, idx, addr)

	node := make([]byte, p.xmssPkSize())
	state.xmssPkFromSig(node, msg, sig, idx, addr)

	if !bytes.Equal(rootRec, node) {
		test.ReportError(t, rootRec, node, skSeed, pkSeed, msg)
	}
}

func benchmarkXmss(b *testing.B, p *params) {
	skSeed := mustRead(b, p.n)
	pkSeed := mustRead(b, p.n)
	msg := mustRead(b, p.n)

	state := p.NewStatePriv(skSeed, pkSeed)

	addr := p.NewAddress()
	addr.SetTypeAndClear(addressWotsHash)
	idx := uint32(0)

	var sig xmssSignature
	curSig := cursor(make([]byte, p.xmssSigSize()))
	sig.fromBytes(p, &curSig)
	state.xmssSign(state.NewStack(p.hPrime), sig, msg, idx, addr)

	b.Run("NodeRec", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = state.xmssNodeRec(idx, p.hPrime, addr)
		}
	})
	b.Run("NodeIter", func(b *testing.B) {
		node := make([]byte, p.n)
		stack := state.NewStack(p.hPrime)
		for i := 0; i < b.N; i++ {
			state.xmssNodeIter(stack, node, idx, p.hPrime, addr)
		}
	})
	b.Run("Sign", func(b *testing.B) {
		stack := state.NewStack(p.hPrime)
		for i := 0; i < b.N; i++ {
			state.xmssSign(stack, sig, msg, idx, addr)
		}
	})
	b.Run("PkFromSig", func(b *testing.B) {
		node := make([]byte, p.xmssPkSize())
		for i := 0; i < b.N; i++ {
			state.xmssPkFromSig(node, msg, sig, idx, addr)
		}
	})
}
