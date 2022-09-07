package dl

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/group"
)

const testzkDLCount = 10

func testzkDL(t *testing.T, myGroup group.Group) {
	kA := myGroup.RandomNonZeroScalar(rand.Reader)
	DB := myGroup.RandomElement(rand.Reader)

	R := myGroup.NewElement()
	R.Mul(DB, kA)

	dst := "zeroknowledge"
	rnd := rand.Reader
	V, r := ProveGen(myGroup, DB, R, kA, []byte("Prover"), []byte("Verifier"), []byte(dst), rnd)

	verify := Verify(myGroup, DB, R, V, r, []byte("Prover"), []byte("Verifier"), []byte(dst))
	if verify == false {
		t.Error("zkRDL verification failed")
	}
}

func testzkDLNegative(t *testing.T, myGroup group.Group) {
	kA := myGroup.RandomNonZeroScalar(rand.Reader)
	DB := myGroup.RandomElement(rand.Reader)

	R := myGroup.RandomElement(rand.Reader)

	dst := "zeroknowledge"
	rnd := rand.Reader
	V, r := ProveGen(myGroup, DB, R, kA, []byte("Prover"), []byte("Verifier"), []byte(dst), rnd)

	verify := Verify(myGroup, DB, R, V, r, []byte("Prover"), []byte("Verifier"), []byte(dst))
	if verify == true {
		t.Error("zkRDL verification should fail")
	}
}

func TestZKDL(t *testing.T) {
	t.Run("zkDL", func(t *testing.T) {
		for i := 0; i < testzkDLCount; i++ {
			currGroup := group.P256
			testzkDL(t, currGroup)
		}
	})

	t.Run("zkDLNegative", func(t *testing.T) {
		for i := 0; i < testzkDLCount; i++ {
			currGroup := group.P256
			testzkDLNegative(t, currGroup)
		}
	})
}
