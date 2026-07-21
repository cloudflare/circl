package math

import (
	"crypto/rand"
	"io"
	"math/big"
)

// IsSafePrime reports whether p is (probably) a safe prime.
// The prime p=2*q+1 is safe prime if both p and q are primes.
// Note that ProbablyPrime is not suitable for judging primes
// that an adversary may have crafted to fool the test.
func IsSafePrime(p *big.Int) bool {
	pdiv2 := new(big.Int).Rsh(p, 1)
	return p.ProbablyPrime(20) && pdiv2.ProbablyPrime(20)
}

// SafePrime returns a number of the given bit length that is a safe prime with high probability.
// The number returned p=2*q+1 is a safe prime if both p and q are primes.
// SafePrime will return error for any error returned by rand.Read or if bits < 2.
func SafePrime(random io.Reader, bits int) (*big.Int, error) {
	one := big.NewInt(1)
	p := new(big.Int)
	for {
		q, err := rand.Prime(random, bits-1)
		if err != nil {
			return nil, err
		}
		p.Lsh(q, 1).Add(p, one)
		if p.ProbablyPrime(20) {
			return p, nil
		}
	}
}

// SafePrimeConcurrent generates a safe prime concurrently.
func SafePrimeConcurrent(bits int, workers int) (*big.Int, error) {
	found := make(chan *big.Int, 1)
	errChan := make(chan error, workers)
	exitFlag := false

	worker := func() {
		defer func() {
			exitFlag = true
		}()
		for {
			if exitFlag {
				return
			}
			// Generate a candidate prime q
			q, err := rand.Prime(rand.Reader, bits-1)
			if err != nil {
				errChan <- err
				return
			}

			one := big.NewInt(1)
			p := new(big.Int)
			p.Lsh(q, 1).Add(p, one)

			// Check if p is prime
			if p.ProbablyPrime(20) {
				select {
				case found <- p:
					return
				default:
					return
				}
			}
		}
	}

	// Start worker goroutines
	for i := 0; i < workers; i++ {
		go worker()
	}

	// Return the first result from any worker
	for {
		select {
		case p := <-found:
			return p, nil
		case err := <-errChan:
			return nil, err
		}
	}
}
