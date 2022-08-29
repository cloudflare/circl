package dleq_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/zk/dleq"
)

func TestDLEQ(t *testing.T) {
	for _, g := range []group.Group{
		group.P256,
		group.P384,
		group.P521,
		group.Ristretto255,
	} {
		t.Run(g.(fmt.Stringer).String(), func(t *testing.T) {
			params := dleq.Params{g, crypto.SHA256, []byte("domain_sep_string")}
			Peggy := dleq.Prover{params}
			Victor := dleq.Verifier{params}

			k := g.RandomScalar(rand.Reader)
			A := g.RandomElement(rand.Reader)
			kA := g.NewElement().Mul(A, k)

			B := g.RandomElement(rand.Reader)
			kB := g.NewElement().Mul(B, k)

			proof, err := Peggy.Prove(k, A, kA, B, kB, rand.Reader)
			test.CheckNoErr(t, err, "wrong proof generation")
			test.CheckOk(Victor.Verify(A, kA, B, kB, proof), "proof must verify", t)

			rr := g.RandomScalar(rand.Reader)
			proof, err = Peggy.ProveWithRandomness(k, A, kA, B, kB, rr)
			test.CheckNoErr(t, err, "wrong proof generation")
			test.CheckOk(Victor.Verify(A, kA, B, kB, proof), "proof must verify", t)

			const N = 4
			C := make([]group.Element, N)
			kC := make([]group.Element, N)
			for i := 0; i < N; i++ {
				C[i] = g.RandomElement(rand.Reader)
				kC[i] = g.NewElement().Mul(C[i], k)
			}
			proof, err = Peggy.ProveBatch(k, A, kA, C, kC, rand.Reader)
			test.CheckNoErr(t, err, "wrong proof generation")
			test.CheckOk(Victor.VerifyBatch(A, kA, C, kC, proof), "proof must verify", t)

			testMarshal(t, g, proof)
			testErrors(t, &Peggy, &Victor, g, k, A, kA, B, kB)
		})
	}
}

func testMarshal(t *testing.T, g group.Group, proof *dleq.Proof) {
	t.Helper()

	wantProofBytes, err := proof.MarshalBinary()
	test.CheckNoErr(t, err, "error on marshaling proof")

	gotProof := new(dleq.Proof)
	err = gotProof.UnmarshalBinary(g, wantProofBytes)
	test.CheckNoErr(t, err, "error on unmarshaling proof")

	gotProofBytes, err := gotProof.MarshalBinary()
	test.CheckNoErr(t, err, "error on marshaling proof")

	if !bytes.Equal(gotProofBytes, wantProofBytes) {
		test.ReportError(t, gotProofBytes, wantProofBytes)
	}
}

func testErrors(
	t *testing.T,
	Peggy *dleq.Prover,
	Victor *dleq.Verifier,
	g group.Group,
	k group.Scalar, a, ka, b, kb group.Element,
) {
	goodProof, err := Peggy.Prove(k, a, ka, b, kb, rand.Reader)
	test.CheckNoErr(t, err, "wrong proof generation")

	proofBytes, err := goodProof.MarshalBinary()
	test.CheckNoErr(t, err, "error on marshaling proof")

	// Tamper proof (in transit)
	_, _ = rand.Read(proofBytes)

	tamperedProof := new(dleq.Proof)
	err = tamperedProof.UnmarshalBinary(g, proofBytes[:5])
	test.CheckIsErr(t, err, "unmarshal must fail")

	err = tamperedProof.UnmarshalBinary(g, proofBytes)
	test.CheckNoErr(t, err, "proof must be unmarshaled")
	test.CheckOk(false == Victor.Verify(a, ka, b, kb, tamperedProof), "proof must not verify", t)

	// Tamper elements
	bada := g.NewElement().Neg(a)
	test.CheckOk(false == Victor.Verify(bada, ka, b, kb, goodProof), "proof must not verify", t)
	badka := g.NewElement().Neg(ka)
	test.CheckOk(false == Victor.Verify(a, badka, b, kb, goodProof), "proof must not verify", t)
	badb := g.NewElement().Neg(b)
	test.CheckOk(false == Victor.Verify(a, ka, badb, kb, goodProof), "proof must not verify", t)
	badkb := g.NewElement().Neg(kb)
	test.CheckOk(false == Victor.Verify(a, ka, b, badkb, goodProof), "proof must not verify", t)
}

func BenchmarkDLEQ(b *testing.B) {
	g := group.P256
	params := dleq.Params{g, crypto.SHA256, []byte("domain_sep_string")}
	Peggy := dleq.Prover{params}
	Victor := dleq.Verifier{params}

	k := g.RandomScalar(rand.Reader)
	A := g.Generator()
	kA := g.NewElement().MulGen(k)

	B := g.RandomElement(rand.Reader)
	kB := g.NewElement().Mul(B, k)
	rr := g.RandomScalar(rand.Reader)

	proof, _ := Peggy.ProveWithRandomness(k, A, kA, B, kB, rr)

	const N = 4
	C := make([]group.Element, N)
	kC := make([]group.Element, N)
	for i := 0; i < N; i++ {
		C[i] = g.RandomElement(rand.Reader)
		kC[i] = g.NewElement().Mul(C[i], k)
	}

	proofBatched, _ := Peggy.ProveBatchWithRandomness(k, A, kA, C, kC, rr)

	b.Run("Prove", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = Peggy.ProveWithRandomness(k, A, kA, B, kB, rr)
		}
	})
	b.Run("Verify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = Victor.Verify(A, kA, B, kB, proof)
		}
	})
	b.Run(fmt.Sprint("ProveBatch=", N), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = Peggy.ProveBatchWithRandomness(k, A, kA, C, kC, rr)
		}
	})
	b.Run(fmt.Sprint("VerifyBatch=", N), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = Victor.VerifyBatch(A, kA, C, kC, proofBatched)
		}
	})
}
