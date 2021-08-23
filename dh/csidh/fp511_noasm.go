//go:build !amd64 || purego
// +build !amd64 purego

package csidh

func mul512(r, m1 *fp, m2 uint64)            { mul512Generic(r, m1, m2) }
func mul576(r *[9]uint64, m1 *fp, m2 uint64) { mul576Generic(r, m1, m2) }
func cswap512(x, y *fp, choice uint8)        { cswap512Generic(x, y, choice) }
func mulRdc(r, x, y *fp)                     { mulRdcGeneric(r, x, y) }
