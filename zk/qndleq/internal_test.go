package qndleq

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func TestForgedProofSecParamZero(t *testing.T) {
	// Safe primes: https://oeis.org/A005385
	p, q := big.NewInt(1019), big.NewInt(1187)
	N := new(big.Int).Mul(p, q)

	g, err := SampleQn(rand.Reader, N)
	if err != nil {
		t.Fatal(err)
	}

	h, err := SampleQn(rand.Reader, N)
	if err != nil {
		t.Fatal(err)
	}

	// Use a real witness to create valid gx = g^x mod N, hx = h^x mod N.
	x := big.NewInt(42)
	gx := new(big.Int).Exp(g, x, N)
	hx := new(big.Int).Exp(h, x, N)

	// Check Prove cannot be invoked with a small security parameter.
	invalid, err := Prove(rand.Reader, x, g, gx, h, hx, N, 0)
	test.CheckIsErr(t, err, "Prove must fail")
	test.CheckOk(invalid == nil, "proof must be nil", t)

	// Verify that a legitimate proof works.
	legitimate, err := Prove(rand.Reader, x, g, gx, h, hx, N, 128)
	test.CheckNoErr(t, err, "prove must succeed")
	test.CheckOk(legitimate.Verify(g, gx, h, hx, N), "legitimate proof rejected", t)

	// Forge a proof constructed independently of the witness value.
	// SecParam=0 makes doChallenge return 0 deterministically,
	// so C=0 and any Z will be accepted.
	forged := &Proof{
		z:        big.NewInt(99999),
		c:        big.NewInt(0),
		secParam: 0,
	}

	test.CheckOk(!forged.Verify(g, gx, h, hx, N), "forged proof must be rejected", t)
}

func TestOutOfBounds(t *testing.T) {
	// Safe primes: https://oeis.org/A005385
	p, q := big.NewInt(1019), big.NewInt(1187)
	N := new(big.Int).Mul(p, q)

	x := big.NewInt(2)
	g, gx := big.NewInt(4), big.NewInt(16)
	h, hx := big.NewInt(9), big.NewInt(81)

	invalidValues := []*big.Int{
		new(big.Int).Neg(g),    // Negative
		big.NewInt(0),          // Zero
		new(big.Int).Set(N),    // N
		new(big.Int).Add(N, N), // bigger than N
	}

	t.Run("prove", func(t *testing.T) {
		for _, invalidValue := range invalidValues {
			p, err := Prove(rand.Reader, x, invalidValue, gx, h, hx, N, 128)
			test.CheckIsErr(t, err, "Prove must fail")
			test.CheckOk(p == nil, "proof must be nil", t)
		}
	})

	t.Run("verify", func(t *testing.T) {
		for _, invalidValue := range invalidValues {
			p, err := Prove(rand.Reader, x, g, gx, h, hx, N, 128)
			test.CheckNoErr(t, err, "Prove must succeed")

			isValid := p.Verify(invalidValue, gx, h, hx, N)
			test.CheckOk(isValid == false, "proof verification must return false", t)
		}
	})
}

func TestChallengeZero(t *testing.T) {
	// Safe primes: https://oeis.org/A005385
	p, q := big.NewInt(1019), big.NewInt(1187)
	N := new(big.Int).Mul(p, q)
	g, gx := big.NewInt(4), big.NewInt(16) // 4^2 == 16 mod N
	h, hx := big.NewInt(9), big.NewInt(81) // 9^2 == 81 mod N

	// Proof must fail as challenge is congruent to zero modulo m = (p-1)(q-1)/4 = 509*593.
	// c = m * 1079334709418571583321702591065767
	c, _ := new(big.Int).SetString("325783150686773390995072744979517913979", 10)
	z, _ := new(big.Int).SetString("909208770437996720153744987183938443953758507571077689625761350579371458087594451128", 10)
	invalidProof := Proof{z, c, 128}

	isValid := invalidProof.Verify(g, gx, h, hx, N)
	test.CheckOk(isValid == false, "proof verification must fail", t)
}
