package ed25519

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

// Previous versions of VerifyPh accepted a context longer than
// ContextMaxSize, encoding its length modulo 256 in dom2.
func TestVerifyBigContext(t *testing.T) {
	msg := []byte("message")
	ctx := make([]byte, ContextMaxSize+1)
	pub, priv, _ := GenerateKey(rand.Reader)

	// SignPh rejects this context, so build the signature with the
	// internal routine, which does not check its length.
	sig := make([]byte, SignatureSize)
	signAll(sig, priv, msg, ctx, true)

	got := VerifyPh(pub, msg, sig, string(ctx))
	want := false
	if got != want {
		test.ReportError(t, got, want)
	}
}
