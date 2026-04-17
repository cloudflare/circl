package rsa

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

var ONE = big.NewInt(1)

func TestGenerateKey(t *testing.T) {
	// [Warning]: this is only for tests, use a secure bitlen above 2048 bits.
	bitlen := 128
	key, err := GenerateKey(rand.Reader, bitlen)
	test.CheckNoErr(t, err, "failed to create key")
	test.CheckOk(key.Validate() == nil, fmt.Sprintf("key is not valid: %v", key), t)
}

func createPrivateKey(p, q *big.Int, e int) *rsa.PrivateKey {
	return &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			E: e,
		},
		D:           nil,
		Primes:      []*big.Int{p, q},
		Precomputed: rsa.PrecomputedValues{},
	}
}

func TestCalcN(t *testing.T) {
	TWO := big.NewInt(2)
	n := calcN(ONE, TWO)
	if n.Cmp(TWO) != 0 {
		t.Fatal("calcN failed: (1, 2)")
	}
	n = calcN(TWO, big.NewInt(4))
	if n.Cmp(big.NewInt(8)) != 0 {
		t.Fatal("calcN failed: (2, 4)")
	}
}

func TestComputePolynomial(t *testing.T) {
	m := big.NewInt(11)
	const k = 5
	a := make([]*big.Int, k)
	for i := 0; i < k; i++ {
		a[i] = big.NewInt(int64(i + 1))
	}
	// a = {1, 2, 3, 4, 5}

	x := uint(3)
	out := computePolynomial(a, x, m)
	// 1 * 3^0 = 1  = 1
	// 2 * 3^1 = 6  = 6
	// 3 * 3^2 = 27 = 5
	// 4 * 3^3 = 108 = 9
	// 5 * 3^4 = 405 = 9
	// 1 + 6 + 5 + 9 + 9 = 30 = 8
	if out.Cmp(big.NewInt(8)) != 0 {
		t.Fatal("compute polynomial failed")
	}
}

func TestComputePolynomialLarge(t *testing.T) {
	m, err := rand.Prime(rand.Reader, 64)
	if err != nil {
		t.Fatal(err)
	}

	const k = 100
	a := make([]*big.Int, k)
	t0 := big.NewInt(0)
	want := big.NewInt(0)
	for i := 0; i < k; i++ {
		a[i] = big.NewInt(int64(i + 1))
		t0.Lsh(a[i], uint(i)).Mod(t0, m)
		want.Add(want, t0)
	}
	want.Mod(want, m)

	got := computePolynomial(a, 2, m)
	if got.Cmp(want) != 0 {
		test.ReportError(t, got, want, m, a)
	}
}

func TestComputeLambda(t *testing.T) {
	// shares = {1, 2, 3, 4, 5}
	// l = 5
	// i = 0
	// ∆ = 5! = 120
	// j = 3
	//
	// num = (0 - 1) * (0 - 2) * (0 - 4) * (0 - 5) = 40
	// den = (3 - 1) * (3 - 2) * (3 - 4) * (3 - 5) = 4
	// num/den = 40/4 = 10
	// ∆ * 10 = 120 * 10 = 1200
	const l = 5
	shares := make([]SignShare, l)
	for i := uint(1); i <= l; i++ {
		shares[i-1].Index = i
	}
	i := int64(0)
	delta := calculateDelta(l)
	j := int64(3)

	lambda, err := computeLambda(delta, shares, i, j, l)
	if err != nil || lambda.Cmp(big.NewInt(1200)) != 0 {
		t.Fatal("computeLambda failed")
	}
}

func TestCheckIndices(t *testing.T) {
	type pairs []struct {
		i int64 // i must be in {0..l} but not in S
		j int64 // j must be in S
	}

	testCases := []struct {
		want bool
		pairs
	}{
		{true, pairs{{0, 1}, {0, 4}, {2, 1}, {2, 4}, {3, 1}, {3, 4}, {5, 1}, {5, 4}, {6, 1}, {6, 4}, {8, 1}, {8, 4}}},
		{false, pairs{{1, 1}, {1, 4}, {4, 1}, {4, 4}, {9, 1}, {9, 4}, {-1, 1}, {-1, 4}, {0, 0}, {0, 2}, {0, 3}}},
	}

	// S = {1,4}
	var shares [2]SignShare
	shares[0].Index = 1
	shares[1].Index = 4
	const l = 8

	for _, tc := range testCases {
		for _, p := range tc.pairs {
			got := checkIndices(p.i, p.j, l, shares[:])
			test.CheckOk(got == tc.want, fmt.Sprintf("i: %v j: %v", p.i, p.j), t)
		}
	}
}

func TestComputeLambdaLarge(t *testing.T) {
	/* Python3
	from math import prod, factorial
	S = [7,14,21]
	j = 7
	l = 32
	computeLambda = lambda i,j,l,S : (\
		factorial(l) * prod( i-jp for jp in S if jp!=j ) \
		) // prod( j-jp for jp in S if jp!=j )
	i= 0; computeLambda(i,j,l,S)
	i=12; computeLambda(i,j,l,S)
	i=19; computeLambda(i,j,l,S)
	i=32; computeLambda(i,j,l,S)
	*/

	// S = {7,14,21}
	var shares [3]SignShare
	shares[0].Index = 7
	shares[1].Index = 14
	shares[2].Index = 21

	const players = 32
	const j = 7
	delta := calculateDelta(players)
	testCases := []struct {
		i    int64
		want string
	}{
		{0, "789392510801080590501654036480000000"},
		{12, "48330153722515138193978818560000000"},
		{19, "-26850085401397298996654899200000000"},
		{32, "531631690947666520133767004160000000"},
	}

	var want big.Int
	for _, tc := range testCases {
		got, err := computeLambda(delta, shares[:], tc.i, j, players)
		test.CheckNoErr(t, err, "computeLambda failed")
		want.SetString(tc.want, 10)

		if got.Cmp(&want) != 0 {
			test.ReportError(t, got.String(), want.String(), tc.i)
		}
	}
}

func TestDeal(t *testing.T) {
	// Players = 3
	// Threshold = 2
	// e = 3
	// p' = 11
	// q' = 5
	// p = 2(11) + 1 = 23
	// q = 2(5) + 1 = 11
	// n = 253
	// m = 55
	// d = 37
	//
	// a[0] = 37
	// a[1] = 33
	//
	//
	// Index = 1
	// computePolynomial(k: 2, a: {37, 33}, x: 1, m: 55) :
	//  	37 * 1^0 = 37 * 1 = 37
	//  	33 * 1^1 = 33 * 1 = 33
	//      37 + 33 = 70 = 15
	//
	// shares[0].si = 15
	// shares[0].Index  = 1
	//
	// Index = 2
	// computePolynomial(k: 2, a: {37, 33}, x: 2, m: 55) :
	//  	37 * 2^0 = 37 * 1 = 37
	//  	33 * 2^1 = 33 * 2 = 66 = 11
	//      37 + 11 = 48
	//
	// shares[1].si = 48
	// shares[1].Index  = 2
	//
	//
	// Index = 3
	// computePolynomial(k: 2, a: {37, 33}, x: 3, m: 55) :
	//  	37 * 3^0 = 37 * 1 = 37
	//  	33 * 3^1 = 33 * 3 = 99 = 44
	//      37 + 44 = 81 = 26
	//
	// shares[2].si = 26
	// shares[2].Index  = 3
	//
	//
	//
	r := bytes.NewReader([]byte{33, 17})
	players := uint(3)
	threshold := uint(2)
	p := int64(23)
	q := int64(11)
	e := 3

	key := createPrivateKey(big.NewInt(p), big.NewInt(q), e)

	share, err := Deal(r, players, threshold, key, false)
	if err != nil {
		t.Fatal(err)
	}
	if share[0].si.Cmp(big.NewInt(15)) != 0 {
		t.Fatalf("share[0].si should have been 15 but was %d", share[0].si)
	}
	if share[1].si.Cmp(big.NewInt(48)) != 0 {
		t.Fatalf("share[1].si should have been 48 but was %d", share[1].si)
	}
	if share[2].si.Cmp(big.NewInt(26)) != 0 {
		t.Fatalf("share[2].si should have been 26 but was %d", share[2].si)
	}
}

const (
	PKS1v15 = 0
	PSS     = 1
)

func testIntegration(t *testing.T, algo crypto.Hash, priv *rsa.PrivateKey, threshold uint, keys []KeyShare, padScheme int) {
	msg := []byte("hello")
	pub := &priv.PublicKey

	var padder Padder
	if padScheme == PKS1v15 {
		padder = &PKCS1v15Padder{}
	} else if padScheme == PSS {
		padder = &PSSPadder{
			Rand: rand.Reader,
			Opts: nil,
		}
	} else {
		t.Fatal(errors.New("unknown padScheme"))
	}

	msgPH, err := PadHash(padder, algo, pub, msg)
	if err != nil {
		t.Fatal(err)
	}

	signshares := make([]SignShare, threshold)

	for i := uint(0); i < threshold; i++ {
		signshares[i], err = keys[i].Sign(rand.Reader, pub, msgPH, true)
		if err != nil {
			t.Fatal(err)
		}
	}

	sig, err := CombineSignShares(pub, signshares, msgPH)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != pub.Size() {
		t.Fatal("bad signature size")
	}

	h := algo.New()
	h.Write(msg)
	hashed := h.Sum(nil)

	if padScheme == PKS1v15 {
		err = rsa.VerifyPKCS1v15(pub, algo, hashed, sig)
	} else if padScheme == PSS {
		err = rsa.VerifyPSS(pub, algo, hashed, sig, padder.(*PSSPadder).Opts)
	} else {
		panic("logical error")
	}

	if err != nil {
		t.Logf("d: %v p: %v q: %v\n", priv.D.Text(16), priv.Primes[0].Text(16), priv.Primes[1].Text(16))
		for i, k := range keys {
			t.Logf("keys[%v]: %v\n", i, k)
		}
		for i, s := range signshares {
			t.Logf("signShares[%v]: %v\n", i, s)
		}
		t.Logf("sig: %x\n", sig)
		t.Fatal(err)
	}
}

func TestIntegrationStdRsaKeyGenerationPKS1v15(t *testing.T) {
	const players = 3
	const threshold = 2
	const bits = 2048
	const algo = crypto.SHA256

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := Deal(rand.Reader, players, threshold, key, false)
	if err != nil {
		t.Fatal(err)
	}
	testIntegration(t, algo, key, threshold, keys, PKS1v15)
}

func TestIntegrationStdRsaKeyGenerationPSS(t *testing.T) {
	const players = 3
	const threshold = 2
	const bits = 2048
	const algo = crypto.SHA256

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := Deal(rand.Reader, players, threshold, key, false)
	if err != nil {
		t.Fatal(err)
	}
	testIntegration(t, algo, key, threshold, keys, PSS)
}

// nolint: unparam
func benchmarkSignCombineHelper(randSource io.Reader, parallel bool, b *testing.B, players, threshold uint, bits int, algo crypto.Hash, padScheme int) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	pub := key.PublicKey
	if err != nil {
		panic(err)
	}

	keys, err := Deal(rand.Reader, players, threshold, key, true)
	if err != nil {
		b.Fatal(err)
	}

	msg := []byte("hello")
	var padder Padder
	if padScheme == PKS1v15 {
		padder = &PKCS1v15Padder{}
	} else if padScheme == PSS {
		padder = &PSSPadder{
			Rand: rand.Reader,
			Opts: nil,
		}
	} else {
		b.Fatal(errors.New("unknown padScheme"))
	}
	msgPH, err := PadHash(padder, algo, &pub, msg)
	if err != nil {
		b.Fatal(err)
	}

	signshares := make([]SignShare, threshold)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for i := uint(0); i < threshold; i++ {
			signshares[i], err = keys[i].Sign(randSource, &pub, msgPH, parallel)
			if err != nil {
				b.Fatal(err)
			}
		}
		_, err = CombineSignShares(&pub, signshares, msgPH)
		if err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
}

func BenchmarkBaselineRSA_SHA256_4096(b *testing.B) {
	const bits = 4096
	const algo = crypto.SHA256

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		b.Fatal(err)
	}
	h := algo.New()

	msg := []byte("hello")

	h.Write(msg)
	d := h.Sum(nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err = rsa.SignPKCS1v15(rand.Reader, key, algo, d)
		if err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
}

func BenchmarkBaselineRSA_SHA256_2048(b *testing.B) {
	const bits = 2048
	const algo = crypto.SHA256

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		b.Fatal(err)
	}
	h := algo.New()

	msg := []byte("hello")

	h.Write(msg)
	d := h.Sum(nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err = rsa.SignPKCS1v15(rand.Reader, key, algo, d)
		if err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
}

func BenchmarkSignCombine_SHA256_4096_3_2_Scheme(b *testing.B) {
	const players = 3
	const threshold = 2
	const bits = 4096
	const algo = crypto.SHA256
	benchmarkSignCombineHelper(nil, false, b, players, threshold, bits, algo, PKS1v15)
}

func BenchmarkSignCombine_SHA256_4096_3_2_Scheme_Blind(b *testing.B) {
	const players = 3
	const threshold = 2
	const bits = 4096
	const algo = crypto.SHA256
	benchmarkSignCombineHelper(rand.Reader, false, b, players, threshold, bits, algo, PKS1v15)
}

func BenchmarkSignCombine_SHA256_4096_3_2_Scheme_BlindParallel(b *testing.B) {
	const players = 3
	const threshold = 2
	const bits = 4096
	const algo = crypto.SHA256
	benchmarkSignCombineHelper(rand.Reader, true, b, players, threshold, bits, algo, PKS1v15)
}

func BenchmarkSignCombine_SHA256_2048_3_2_Scheme(b *testing.B) {
	const players = 3
	const threshold = 2
	const bits = 2048
	const algo = crypto.SHA256
	benchmarkSignCombineHelper(nil, false, b, players, threshold, bits, algo, PKS1v15)
}

func BenchmarkSignCombine_SHA256_2048_3_2_Scheme_Blind(b *testing.B) {
	const players = 3
	const threshold = 2
	const bits = 2048
	const algo = crypto.SHA256
	benchmarkSignCombineHelper(rand.Reader, false, b, players, threshold, bits, algo, PKS1v15)
}

func BenchmarkSignCombine_SHA256_2048_3_2_Scheme_BlindParallel(b *testing.B) {
	const players = 3
	const threshold = 2
	const bits = 2048
	const algo = crypto.SHA256
	benchmarkSignCombineHelper(rand.Reader, true, b, players, threshold, bits, algo, PKS1v15)
}

func BenchmarkSignCombine_SHA256_1024_3_2_Scheme(b *testing.B) {
	const players = 3
	const threshold = 2
	const bits = 1024
	const algo = crypto.SHA256
	benchmarkSignCombineHelper(nil, false, b, players, threshold, bits, algo, PKS1v15)
}

func BenchmarkDealGeneration(b *testing.B) {
	const players = 3
	const threshold = 2
	const bits = 2048
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		b.Fatal("could not generate key")
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Deal(rand.Reader, players, threshold, key, false)
		if err != nil {
			b.Fatal(err)
		}
	}
}
