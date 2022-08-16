package zkRDL

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/group"
)

const TestzkRDLCount = 10

func testzkRDL(t *testing.T, myGroup group.Group) {
	kA := myGroup.RandomNonZeroScalar(rand.Reader)
	DB := myGroup.RandomElement(rand.Reader)

	R := myGroup.NewElement()
	R.Mul(DB, kA)

	V, r := ProveGen(myGroup, DB, R, kA, []byte("Prover"), []byte("Verifier"))

	verify := Verify(myGroup, DB, R, V, r, []byte("Prover"), []byte("Verifier"))
	if verify == false {
		t.Error("zkRDL verification failed")
	}

}

func testzkRDLNegative(t *testing.T, myGroup group.Group) {
	kA := myGroup.RandomNonZeroScalar(rand.Reader)
	DB := myGroup.RandomElement(rand.Reader)

	R := myGroup.RandomElement(rand.Reader)

	V, r := ProveGen(myGroup, DB, R, kA, []byte("Prover"), []byte("Verifier"))

	verify := Verify(myGroup, DB, R, V, r, []byte("Prover"), []byte("Verifier"))
	if verify == true {
		t.Error("zkRDL verification should fail")
	}

}

func TestZKRDL(t *testing.T) {

	t.Run("zkRDL", func(t *testing.T) {
		for i := 0; i < TestzkRDLCount; i++ {
			currGroup := group.P256
			testzkRDL(t, currGroup)
		}
	})

	t.Run("zkRDLNegative", func(t *testing.T) {
		for i := 0; i < TestzkRDLCount; i++ {
			currGroup := group.P256
			testzkRDLNegative(t, currGroup)
		}
	})

}
