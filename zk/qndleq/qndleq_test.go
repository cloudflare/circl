package qndleq_test

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/zk/qndleq"
)

func TestProve(t *testing.T) {
	const testTimes = 1 << 8
	const SecParam = 128
	one := big.NewInt(1)
	max := new(big.Int).Lsh(one, 256)

	for i := 0; i < testTimes; i++ {
		N, _ := rand.Int(rand.Reader, max)
		if N.Bit(0) == 0 {
			N.Add(N, one)
		}
		x, _ := rand.Int(rand.Reader, N)
		g, err := qndleq.SampleQn(rand.Reader, N)
		test.CheckNoErr(t, err, "failed to sampleQn")
		h, err := qndleq.SampleQn(rand.Reader, N)
		test.CheckNoErr(t, err, "failed to sampleQn")
		gx := new(big.Int).Exp(g, x, N)
		hx := new(big.Int).Exp(h, x, N)

		proof, err := qndleq.Prove(rand.Reader, x, g, gx, h, hx, N, SecParam)
		test.CheckNoErr(t, err, "failed to generate proof")
		test.CheckOk(proof.Verify(g, gx, h, hx, N), "failed to verify", t)
	}
}

func TestInvalidStatement(t *testing.T) {
	g, gx := big.NewInt(4), big.NewInt(16) // 4^2 == 16 mod 101
	h, hx := big.NewInt(9), big.NewInt(81) // 9^2 == 81 mod 101
	N := big.NewInt(101)
	incorrectX := big.NewInt(3)

	p, err := qndleq.Prove(rand.Reader, incorrectX, g, gx, h, hx, N, 128)
	test.CheckNoErr(t, err, "an alleged proof must be computed")
	isValid := p.Verify(g, gx, h, hx, N)
	test.CheckOk(isValid == false, "proof verification must fail", t)
}

func TestSampleQn(t *testing.T) {
	const testTimes = 1 << 7
	one := big.NewInt(1)
	max := new(big.Int).Lsh(one, 256)

	for i := 0; i < testTimes; i++ {
		N, _ := rand.Int(rand.Reader, max)
		if N.Bit(0) == 0 {
			N.Add(N, one)
		}
		a, err := qndleq.SampleQn(rand.Reader, N)
		test.CheckNoErr(t, err, "failed to sampleQn")
		jac := big.Jacobi(a, N)
		test.CheckOk(jac == 1, "Jacoby symbol should be one", t)
		gcd := new(big.Int).GCD(nil, nil, a, N)
		test.CheckOk(gcd.Cmp(one) == 0, "should be coprime to N", t)
	}
}

func Benchmark_qndleq(b *testing.B) {
	const SecParam = 128
	one := big.NewInt(1)
	max := new(big.Int).Lsh(one, 256)

	N, _ := rand.Int(rand.Reader, max)
	if N.Bit(0) == 0 {
		N.Add(N, one)
	}
	x, _ := rand.Int(rand.Reader, N)
	g, _ := qndleq.SampleQn(rand.Reader, N)
	h, _ := qndleq.SampleQn(rand.Reader, N)
	gx := new(big.Int).Exp(g, x, N)
	hx := new(big.Int).Exp(h, x, N)

	proof, _ := qndleq.Prove(rand.Reader, x, g, gx, h, hx, N, SecParam)

	b.Run("Prove", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = qndleq.Prove(rand.Reader, x, g, gx, h, hx, N, SecParam)
		}
	})

	b.Run("Verify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = proof.Verify(g, gx, h, hx, N)
		}
	})
}
