package slhdsa

import (
	"bytes"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func testWotsPlus(t *testing.T, p *params) {
	skSeed := mustRead(t, p.n)
	pkSeed := mustRead(t, p.n)
	msg := mustRead(t, p.n)

	state := p.NewStatePriv(skSeed, pkSeed)

	addr := p.NewAddress()
	addr.SetTypeAndClear(addressWotsHash)

	pk0 := state.wotsPkGen(addr)

	var sig wotsSignature
	curSig := cursor(make([]byte, p.wotsSigSize()))
	sig.fromBytes(p, &curSig)
	state.wotsSign(sig, msg, addr)

	pk1 := state.wotsPkFromSig(sig, msg, addr)

	if !bytes.Equal(pk0, pk1) {
		test.ReportError(t, pk0, pk1, skSeed, pkSeed, msg)
	}
}

func benchmarkWotsPlus(b *testing.B, p *params) {
	skSeed := mustRead(b, p.n)
	pkSeed := mustRead(b, p.n)
	msg := mustRead(b, p.n)

	state := p.NewStatePriv(skSeed, pkSeed)

	addr := p.NewAddress()
	addr.SetTypeAndClear(addressWotsHash)

	var sig wotsSignature
	curSig := cursor(make([]byte, p.wotsSigSize()))
	sig.fromBytes(p, &curSig)
	state.wotsSign(sig, msg, addr)

	b.Run("PkGen", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = state.wotsPkGen(addr)
		}
	})
	b.Run("Sign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			state.wotsSign(sig, msg, addr)
		}
	})
	b.Run("PkFromSig", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = state.wotsPkFromSig(sig, msg, addr)
		}
	})
}
