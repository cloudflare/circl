package rsa

import (
	"math/big"
	"testing"
)

func TestCalculateDelta(t *testing.T) {
	ONE := big.NewInt(1)
	if calculateDelta(0).Cmp(ONE) != 0 {
		t.Fatal("calculateDelta failed on 0")
	}

	if calculateDelta(1).Cmp(ONE) != 0 {
		t.Fatal("calculateDelta failed on 1")
	}

	if calculateDelta(5).Cmp(big.NewInt(120)) != 0 {
		t.Fatal("calculateDelta failed on 5")
	}
}
