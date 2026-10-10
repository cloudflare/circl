package arc_test

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log"

	"github.com/cloudflare/circl/ac/arc"
)

var (
	requestContext      = []byte("Credential for Alice")
	presentationContext = []byte("Presentation for example.com")
)

func ExampleCredential() {
	priv, pub := getKeys(arc.SuiteP256)
	credential := getCredential(arc.SuiteP256, &priv, &pub)
	fmt.Print(credential != nil)
	// Output: true
}

func getKeys(id arc.SuiteID) (arc.PrivateKey, arc.PublicKey) {
	priv := arc.KeyGen(rand.Reader, id)
	pub := priv.PublicKey()
	return priv, pub
}

func getCredential(id arc.SuiteID, priv *arc.PrivateKey, pub *arc.PublicKey) *arc.Credential {
	// Client
	fin, credReq := arc.Request(rand.Reader, id, requestContext)

	// ----- credReq ---->

	// Server
	credRes, err := arc.Response(rand.Reader, priv, &credReq)
	if err != nil {
		log.Fatal(err)
	}

	// <----- credRes ----

	// Client
	credential, err := arc.Finalize(&fin, &credReq, credRes, pub)
	if err != nil {
		log.Fatal(err)
	}

	return credential
}

func ExamplePresentation() {
	priv, pub := getKeys(arc.SuiteP256)
	credential := getCredential(arc.SuiteP256, &priv, &pub)

	// Client
	const MaxPres = 3
	state, err0 := arc.NewState(credential, presentationContext, MaxPres)
	if err0 != nil {
		log.Fatal(err0)
	}

	// Valid presentations.
	for range MaxPres {
		// Client
		nonce, pres, err := state.Present(rand.Reader)
		if err != nil {
			log.Fatal(err)
		}

		// Server
		isValid := arc.Verify(&priv, pres, requestContext, presentationContext, *nonce, MaxPres)
		fmt.Println(isValid)
	}

	// Error after spending MaxPres presentations.
	nonce, pres, err := state.Present(rand.Reader)
	fmt.Println(nonce, pres, errors.Is(err, arc.ErrLimitExceeded))
	// Output:
	// true
	// true
	// true
	// <nil> <nil> true
}
