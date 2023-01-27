package dl_test

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/zk/dl"
)

const testzkDLCount = 1 << 8

func testzkDL(t *testing.T, myGroup group.Group) {
	kA := myGroup.RandomNonZeroScalar(rand.Reader)
	DB := myGroup.RandomElement(rand.Reader)

	R := myGroup.NewElement()
	R.Mul(DB, kA)

	dst := "zeroknowledge"
	rnd := rand.Reader
	proof := dl.Prove(myGroup, DB, R, kA, []byte("Prover"), []byte(dst), rnd)

	verify := dl.Verify(myGroup, DB, R, proof, []byte("Prover"), []byte(dst))
	if verify == false {
		t.Error("zk/dl verification failed")
	}
}

func testzkDLNegative(t *testing.T, myGroup group.Group) {
	kA := myGroup.RandomNonZeroScalar(rand.Reader)
	DB := myGroup.RandomElement(rand.Reader)

	R := myGroup.RandomElement(rand.Reader)

	dst := "zeroknowledge"
	rnd := rand.Reader
	proof := dl.Prove(myGroup, DB, R, kA, []byte("Prover"), []byte(dst), rnd)

	verify := dl.Verify(myGroup, DB, R, proof, []byte("Prover"), []byte(dst))
	if verify == true {
		t.Error("zk/dl verification should fail")
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
