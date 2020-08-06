package common

// Zetas lists precomputed powers of the primitive root of unity in
// Montgomery representation used for the NTT:
//
//  Zetas[i] = ζᵇʳᵛ⁽ⁱ⁾ R mod q
//
// where ζ = 17, brv(i) is the bitreversal of a 7-bit number and R=2¹⁶ mod q.
//
// The following Python code generates the Zetas (and InvZetas) arrays:
//
//    q = 13*2**8 + 1; zeta = 17
//    R = 2**16 % q # Montgomery const.
//    def brv(x): return int(''.join(reversed(bin(x)[2:].zfill(7))),2)
//    def inv(x): return pow(x, q-2, q) # inverse in F(q)
//    print([(pow(zeta, brv(i), q)*R)%q for i in range(128)])
//    print([(pow(inv(zeta), -(brv(127-i)-128), q)*R)%q for i in range(128)])
var Zetas = [128]int16{
	2285, 2571, 2970, 1812, 1493, 1422, 287, 202, 3158, 622, 1577, 182,
	962, 2127, 1855, 1468, 573, 2004, 264, 383, 2500, 1458, 1727, 3199,
	2648, 1017, 732, 608, 1787, 411, 3124, 1758, 1223, 652, 2777, 1015,
	2036, 1491, 3047, 1785, 516, 3321, 3009, 2663, 1711, 2167, 126,
	1469, 2476, 3239, 3058, 830, 107, 1908, 3082, 2378, 2931, 961, 1821,
	2604, 448, 2264, 677, 2054, 2226, 430, 555, 843, 2078, 871, 1550,
	105, 422, 587, 177, 3094, 3038, 2869, 1574, 1653, 3083, 778, 1159,
	3182, 2552, 1483, 2727, 1119, 1739, 644, 2457, 349, 418, 329, 3173,
	3254, 817, 1097, 603, 610, 1322, 2044, 1864, 384, 2114, 3193, 1218,
	1994, 2455, 220, 2142, 1670, 2144, 1799, 2051, 794, 1819, 2475,
	2459, 478, 3221, 3021, 996, 991, 958, 1869, 1522, 1628,
}

// InvZetas lists precomputed powers of the inverse root of unity in
// Montgomery representation used for the inverse NTT:
//
//  InvZetas[i] = ζᵇʳᵛ⁽¹²⁷⁻ⁱ⁾⁻¹²⁸ R mod q
//
// where ζ = 17, brv(i) is the bitreversal of a 7-bit number and R=2¹⁶ mod q.
// See Zetas for Python code that also generates this list.
var InvZetas = [128]int16{
	1701, 1807, 1460, 2371, 2338, 2333, 308, 108, 2851, 870,
	854, 1510, 2535, 1278, 1530, 1185, 1659, 1187, 3109, 874,
	1335, 2111, 136, 1215, 2945, 1465, 1285, 2007, 2719, 2726,
	2232, 2512, 75, 156, 3000, 2911, 2980, 872, 2685, 1590,
	2210, 602, 1846, 777, 147, 2170, 2551, 246, 1676, 1755,
	460, 291, 235, 3152, 2742, 2907, 3224, 1779, 2458, 1251,
	2486, 2774, 2899, 1103, 1275, 2652, 1065, 2881, 725, 1508,
	2368, 398, 951, 247, 1421, 3222, 2499, 271, 90, 853, 1860,
	3203, 1162, 1618, 666, 320, 8, 2813, 1544, 282, 1838, 1293,
	2314, 552, 2677, 2106, 1571, 205, 2918, 1542, 2721, 2597,
	2312, 681, 130, 1602, 1871, 829, 2946, 3065, 1325, 2756,
	1861, 1474, 1202, 2367, 3147, 1752, 2707, 171, 3127, 3042,
	1907, 1836, 1517, 359, 758, 1044,
}

// Executes an in-place forward "NTT" on p.
//
// Assumes the coefficients are in absolute value ≤q.  The resulting
// coefficients are in absolute value ≤7q.  If the input is in Montgomery
// form, then the result is in Montgomery form and so (by linearity of the NTT)
// if the input is in regular form, then the result is also in regular form.
func (p *Poly) NTT() {
	// Note that ℤ_q does not have a primitive 512ᵗʰ root of unity (as 512
	// does not divide into q) and so we cannot do a regular NTT.  ℤ_q
	// does have a primitive 256ᵗʰ root of unity, the smallest of which
	// is ζ := 17.
	//
	// Recall that our base ring R := ℤ_q[x] / (x²⁵⁶ + 1).  The polynomial
	// x²⁵⁶+1 will not split completely (as its roots would be 512ᵗʰ roots
	// of unity.)  However, it does split almost (using ζ¹²⁸ = -1):
	//
	// x²⁵⁶ + 1 = (x²)¹²⁸ - ζ¹²⁸
	//          = ((x²)⁶⁴ - ζ⁶⁴)((x²)⁶⁴ + ζ⁶⁴)
	//          = ((x²)³² - ζ³²)((x²)³² + ζ³²)((x²)³² - ζ⁹⁶)((x²)³² + ζ⁹⁶)
	//          ⋮
	//          = (x² - ζ)(x² + ζ)(x² - ζ⁶⁵)(x² + ζ⁶⁵) … (x² + ζ¹²⁷)
	//
	// Note that the powers of ζ that appear (from th second line down) are
	// in binary
	//
	// 010000 110000
	// 001000 101000 011000 111000
	// 000100 100100 010100 110100 001100 101100 011100 111100
	//         …
	//
	// That is: brv(2), brv(3), brv(4), …, where brv(x) denotes the 7-bit
	// bitreversal of x.  These powers of ζ are given by the Zetas array.
	//
	// The polynomials x² ± ζⁱ are irreducible and coprime, hence by
	// the Chinese Remainder Theorem we know
	//
	//  ℤ_q[x]/(x²⁵⁶+1) → ℤ_q[x]/(x²-ζ) x … x  ℤ_q[x]/(x²+ζ¹²⁷)
	//
	// given by a ↦ ( a mod x²-z, …, a mod x²+z¹²⁷ )
	// is an isomorphism, which is the "NTT".  It can be efficiently computed by
	//
	//
	//  a ↦ ( a mod (x²)⁶⁴ - ζ⁶⁴, a mod (x²)⁶⁴ + ζ⁶⁴ )
	//    ↦ ( a mod (x²)³² - ζ³², a mod (x²)³² + ζ³²,
	//        a mod (x²)⁹⁶ - ζ⁹⁶, a mod (x²)⁹⁶ + ζ⁹⁶ )
	//
	//	    et cetera
	//
	// If N was 8 then this can be pictured in the following diagram:
	//
	//  https://cnx.org/resources/17ee4dfe517a6adda05377b25a00bf6e6c93c334/File0026.png
	//
	// Each cross is a Cooley-Tukey butterfly: it's the map
	//
	//  (a, b) ↦ (a + ζ, a - ζ)
	//
	// for the appropriate power ζ for that column and row group.

	k := 0 // Index into Zetas

	// l runs effectively over the columns in the diagram above; it is half the
	// height of a row group, i.e. the number of butterflies in each row group.
	// In the diagram above it would be 4, 2, 1.
	for l := N / 2; l > 1; l >>= 1 {
		// On the nᵗʰ iteration of the l-loop, the absolute value of the
		// coefficients are bounded by nq.

		// offset effectively loops over the row groups in this column; it is
		// the first row in the row group.
		for offset := 0; offset < N-l; offset += 2 * l {
			k++
			zeta := int32(Zetas[k])

			// j loops over each butterfly in the row group.
			for j := offset; j < offset+l; j++ {
				t := montReduce(zeta * int32(p[j+l]))
				p[j+l] = p[j] - t
				p[j] += t
			}
		}
	}
}

// Executes an in-place inverse "NTT" on p and multiply by the Montgomery
// factor R.
//
// Assumes the coefficients are in absolute value ≤q.  The resulting
// coefficients are in absolute value ≤q.  If the input is in Montgomery
// form, then the result is in Montgomery form and so (by linearity)
// if the input is in regular form, then the result is also in regular form.
func (p *Poly) InvNTT() {
	k := 0 // Index into InvZetas

	// We basically do the oppposite of NTT, but postpone dividing by 2 in the
	// inverse of the Cooley-Tukey butterfly and accumulate that into a big
	// division by 2⁷ at the end.  See the comments in the NTT() function.

	for l := 2; l < N; l <<= 1 {
		// At the start of the nᵗʰ iteration of this loop, the coefficients
		// are bounded in absolute value by nq.

		// XXX Get rid of Barrett reduction?

		for offset := 0; offset < N-l; offset += 2 * l {
			zeta := int32(InvZetas[k])
			k++

			for j := offset; j < offset+l; j++ {
				t := barrettReduce(p[j]) // Gentleman-Sande butterfly
				p[j] = t + p[j+l]
				t -= p[j+l]
				p[j+l] = montReduce(zeta * int32(t))
			}
		}
	}

	for j := 0; j < N; j++ {
		// Note 1441 = (128)⁻¹ R².  The coefficients are bounded by 7q, so
		// as 1441 * 7 ≈ 2⁹ < 2¹⁵, we're within the required bounds
		// for montReduce().
		p[j] = montReduce(1441 * int32(p[j]))
	}
}
