package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
)

// l or `Players`, the total number of Players.
// t, the number of corrupted Players.
// k=t+1 or `Threshold`, the number of signature shares needed to obtain a signature.

func validateParams(players, threshold uint) error {
	if players <= 1 {
		return errors.New("rsa_threshold: Players (l) invalid: should be > 1")
	}
	if threshold < 1 || threshold > players {
		return fmt.Errorf("rsa_threshold: Threshold (k) invalid: %d < 1 || %d > %d", threshold, threshold, players)
	}
	return nil
}

// Deal takes in an existing RSA private key generated elsewhere. If cache is true, cached values are stored in KeyShare taking up more memory by reducing Sign time.
// See KeyShare documentation. Multi-prime RSA keys are unsupported.
func Deal(randSource io.Reader, players, threshold uint, key *rsa.PrivateKey, cache bool) ([]KeyShare, error) {
	err := validateParams(players, threshold)

	ONE := big.NewInt(1)

	if err != nil {
		return nil, err
	}

	if len(key.Primes) != 2 {
		return nil, errors.New("multiprime rsa keys are unsupported")
	}

	p := key.Primes[0]
	q := key.Primes[1]
	e := int64(key.E)

	// p = 2p' + 1
	// q = 2q' + 1
	// p' = (p - 1)/2
	// q' = (q - 1)/2
	// m = p'q' = (p - 1)(q - 1)/4

	var pprime big.Int
	// p - 1
	pprime.Sub(p, ONE)

	// q - 1
	var m big.Int
	m.Sub(q, ONE)
	// (p - 1)(q - 1)
	m.Mul(&m, &pprime)
	// >> 2 == / 4
	m.Rsh(&m, 2)

	// de ≡ 1
	var d big.Int
	_d := d.ModInverse(big.NewInt(e), &m)

	if _d == nil {
		return nil, errors.New("rsa_threshold: no ModInverse for e in Z/Zm")
	}

	// a_0...a_{k-1}
	a := make([]*big.Int, threshold)
	// a_0 = d
	a[0] = &d

	// a_0...a_{k-1} = rand from {0, ..., m - 1}
	for i := uint(1); i <= threshold-1; i++ {
		a[i], err = rand.Int(randSource, &m)
		if err != nil {
			return nil, errors.New("rsa_threshold: unable to generate an int within [0, m)")
		}
	}

	shares := make([]KeyShare, players)

	// 1 <= i <= l
	for i := uint(1); i <= players; i++ {
		shares[i-1].Players = players
		shares[i-1].Threshold = threshold
		// Σ^{k-1}_{i=0} | a_i * X^i (mod m)
		poly := computePolynomial(threshold, a, i, &m)
		shares[i-1].si = poly
		shares[i-1].Index = i
		if cache {
			shares[i-1].get2DeltaSi(int64(players))
		}
	}

	return shares, nil
}

func calcN(p, q *big.Int) big.Int {
	// n = pq
	var n big.Int
	n.Mul(p, q)
	return n
}

// f(X) = Σ^{k-1}_{i=0} | a_i * X^i (mod m)
func computePolynomial(k uint, a []*big.Int, x uint, m *big.Int) *big.Int {
	// TODO: use Horner's method here.
	sum := big.NewInt(0)
	//  Σ^{k-1}_{i=0}
	for i := uint(0); i <= k-1; i++ {
		// X^i
		// TODO optimize: we can compute x^{n+1} from the previous x^n
		xi := int64(math.Pow(float64(x), float64(i)))
		// a_i * X^i
		prod := big.Int{}
		prod.Mul(a[i], big.NewInt(xi))
		// (mod m)
		prod.Mod(&prod, m) // while not in the spec, we are eventually modding m, so we can mod here for efficiency
		// Σ
		sum.Add(sum, &prod)
	}

	sum.Mod(sum, m)

	return sum
}

// PadHash MUST be called before signing a message
func PadHash(padder Padder, hash crypto.Hash, pub *rsa.PublicKey, msg []byte) ([]byte, error) {
	// Sign(Pad(Hash(M)))

	hasher := hash.New()
	hasher.Write(msg)
	digest := hasher.Sum(nil)

	return padder.Pad(pub, hash, digest)
}

type Signature = []byte

// CombineSignShares combines t SignShare's to produce a valid signature
func CombineSignShares(pub *rsa.PublicKey, shares []SignShare, msg []byte) (Signature, error) {
	players := shares[0].Players
	threshold := shares[0].Threshold

	for i := range shares {
		if shares[i].Players != players {
			return nil, errors.New("rsa_threshold: shares didn't have consistent players")
		}
		if shares[i].Threshold != threshold {
			return nil, errors.New("rsa_threshold: shares didn't have consistent threshold")
		}
	}

	if uint(len(shares)) < threshold {
		return nil, errors.New("rsa_threshold: insufficient shares for the threshold")
	}

	w := big.NewInt(1)
	delta := calculateDelta(int64(players))
	// i_1 ... i_k
	for _, share := range shares {
		// λ(S, 0, i)
		lambda, err := computeLambda(delta, shares, 0, int64(share.Index))
		if err != nil {
			return nil, err
		}
		// 2λ
		var exp big.Int
		exp.Add(lambda, lambda) // faster than TWO * lambda

		// we need to handle negative λ's (aka inverse), so abs it, compare, and if necessary modinverse
		abslam := big.Int{}
		abslam.Abs(&exp)
		var tmp big.Int
		// x_i^{|2λ|}
		tmp.Exp(share.xi, &abslam, pub.N)
		if abslam.Cmp(&exp) == 1 {
			tmp.ModInverse(&tmp, pub.N)
		}
		// TODO  first compute all the powers for the negative exponents (but don't invert yet); multiply these together and then invert all at once. This is ok since (ab)^-1 = a^-1 b^-1

		w.Mul(w, &tmp).Mod(w, pub.N)
	}
	w.Mod(w, pub.N)

	// e′ = 4∆^2
	eprime := big.Int{}
	eprime.Mul(delta, delta)     // faster than delta^TWO
	eprime.Add(&eprime, &eprime) // faster than FOUR * eprime
	eprime.Add(&eprime, &eprime)

	// e′a + eb = 1
	a := big.Int{}
	b := big.Int{}
	e := big.NewInt(int64(pub.E))
	tmp := big.Int{}
	tmp.GCD(&a, &b, &eprime, e)

	// TODO You can compute a earlier and multiply a into the exponents used when computing w.
	// w^a
	wa := big.Int{}
	wa.Exp(w, &a, pub.N) // TODO justification
	// x^b
	x := big.Int{}
	x.SetBytes(msg)
	xb := big.Int{}
	xb.Exp(&x, &b, pub.N) // TODO justification
	// y = w^a * x^b
	y := big.Int{}
	y.Mul(&wa, &xb).Mod(&y, pub.N)

	// verify that signature is valid by checking x == y^e.
	ye := big.Int{}
	ye.Exp(&y, e, pub.N)
	if ye.Cmp(&x) != 0 {
		return nil, errors.New("rsa: internal error")
	}

	// ensure signature has the right size.
	sig := y.FillBytes(make([]byte, pub.Size()))

	return sig, nil
}

// computes lagrange Interpolation for the shares
// i must be an id 0..l but not in S
// j must be in S
func computeLambda(delta *big.Int, S []SignShare, i, j int64) (*big.Int, error) {
	if i == j {
		return nil, errors.New("rsa_threshold: i and j can't be equal by precondition")
	}
	// these are just to check preconditions
	foundi := false
	foundj := false

	// λ(s, i, j) = ∆( (  π{j'∈S\{j}} (i - j')  ) /  (  π{j'∈S\{j}} (j - j') ) )

	num := int64(1)
	den := int64(1)

	// ∈ S
	for _, s := range S {
		// j'
		jprime := int64(s.Index)
		// S\{j}
		if jprime == j {
			foundj = true
			continue
		}
		if jprime == i {
			foundi = false
			break
		}
		//  (i - j')
		num *= i - jprime
		// (j - j')
		den *= j - jprime
	}

	// ∆ * (num/den)
	var lambda big.Int
	// (num/den)
	lambda.Div(big.NewInt(num), big.NewInt(den))
	// ∆ * (num/den)
	lambda.Mul(delta, &lambda)

	if foundi {
		return nil, fmt.Errorf("rsa_threshold: i: %d should not be in S", i)
	}

	if !foundj {
		return nil, fmt.Errorf("rsa_threshold: j: %d should be in S", j)
	}

	return &lambda, nil
}
