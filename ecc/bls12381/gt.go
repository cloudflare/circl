package bls12381

import (
	"fmt"

	"github.com/cloudflare/circl/ecc/bls12381/ff"
)

type Gt [2]ff.Fp6

func (z Gt) String() string { return fmt.Sprintf("\n0: %v\n1: %v", z[0], z[1]) }
