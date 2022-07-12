package secretsharing_test

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/secretsharing"
)

func ExampleSecretSharing() {
	g := group.P256
	t := uint(2)
	n := uint(5)

	secret := g.RandomScalar(rand.Reader)
	ss := secretsharing.New(rand.Reader, t, secret)
	shares := ss.Share(n)

	got, err := secretsharing.Recover(t, shares[:t])
	fmt.Printf("Recover secret: %v\nError: %v\n", secret.IsEqual(got), err)

	got, err = secretsharing.Recover(t, shares[:t+1])
	fmt.Printf("Recover secret: %v\nError: %v\n", secret.IsEqual(got), err)
	// Output:
	// Recover secret: false
	// Error: secretsharing: number of shares (n=2) must be above the threshold (t=2)
	// Recover secret: true
	// Error: <nil>
}

func ExampleVerify() {
	g := group.P256
	t := uint(2)
	n := uint(5)

	secret := g.RandomScalar(rand.Reader)
	ss := secretsharing.New(rand.Reader, t, secret)
	shares := ss.Share(n)
	coms := ss.CommitSecret()

	for i := range shares {
		ok := secretsharing.Verify(t, shares[i], coms)
		fmt.Printf("Share %v is valid: %v\n", i, ok)
	}

	got, err := secretsharing.Recover(t, shares)
	fmt.Printf("Recover secret: %v\nError: %v\n", secret.IsEqual(got), err)
	// Output:
	// Share 0 is valid: true
	// Share 1 is valid: true
	// Share 2 is valid: true
	// Share 3 is valid: true
	// Share 4 is valid: true
	// Recover secret: true
	// Error: <nil>
}
