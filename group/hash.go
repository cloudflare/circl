package group

import "math/big"

// HashToField generates a set of elements {u1,..., uN} = Hash(b) where each
// u in GF(p) and L is the security parameter.
func HashToField(u []big.Int, b []byte, e Expander, p *big.Int, L uint) {
	count := uint(len(u))
	bytes := e.Expand(b, count*L)
	for i := range u {
		j := uint(i) * L
		u[i].Mod(u[i].SetBytes(bytes[j:j+L]), p)
	}
}
