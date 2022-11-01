package tkn

import (
	"fmt"

	pairing "github.com/cloudflare/circl/ecc/bls12381"
)

type pairAccum struct {
	as      []*pairing.G1
	bs      []*pairing.G2
	scalars []int
}

func (pairs *pairAccum) addDuals(m1 *matrixG1, m2 *matrixG2, n int) {
	if m1.cols != 1 || m2.cols != 1 {
		panic(fmt.Sprintf("misuse of addDuals: m1: %d x %d m2: %d x %d\n", m1.rows, m1.cols, m2.rows, m2.cols))
	}
	for k := 0; k < m1.rows; k++ {
		pairs.as = append(pairs.as, &m1.entries[k])
		pairs.bs = append(pairs.bs, &m2.entries[k])
		pairs.scalars = append(pairs.scalars, n)
	}
}

func (pairs *pairAccum) eval() *pairing.Gt {
	return pairing.ProdPairFrac(pairs.as, pairs.bs, pairs.scalars)
}
