package common

// Zetas lists precomputed powers of the root of unity in Montgomery
// representation used for the NTT:
//
//     Zetas[i] = zetaᵇʳᵛ⁽ⁱ⁾ R mod q,
//
// where zeta = 1753, brv(i) is the bitreversal of a 8-bit number
// and R=2³² mod q.
//
// The following Pari code generates the Zetas lists:
//
//  brv = [128, 64, 192, 32, 160, 96, 224, 16, 144, 80, 208, 48, 176, 112, 240, 8, 136, 72, 200, 40, 168, 104, 232, 24, 152, 88, 216, 56, 184, 120, 248, 4, 132, 68, 196, 36, 164, 100, 228, 20, 148, 84, 212, 52, 180, 116, 244, 12, 140, 76, 204, 44, 172, 108, 236, 28, 156, 92, 220, 60, 188, 124, 252, 2, 130, 66, 194, 34, 162, 98, 226, 18, 146, 82, 210, 50, 178, 114, 242, 10, 138, 74, 202, 42, 170, 106, 234, 26, 154, 90, 218, 58, 186, 122, 250, 6, 134, 70, 198, 38, 166, 102, 230, 22, 150, 86, 214, 54, 182, 118, 246, 14, 142, 78, 206, 46, 174, 110, 238, 30, 158, 94, 222, 62, 190, 126, 254, 1, 129, 65, 193, 33, 161, 97, 225, 17, 145, 81, 209, 49, 177, 113, 241, 9, 137, 73, 201, 41, 169, 105, 233, 25, 153, 89, 217, 57, 185, 121, 249, 5, 133, 69, 197, 37, 165, 101, 229, 21, 149, 85, 213, 53, 181, 117, 245, 13, 141, 77, 205, 45, 173, 109, 237, 29, 157, 93, 221, 61, 189, 125, 253, 3, 131, 67, 195, 35, 163, 99, 227, 19, 147, 83, 211, 51, 179, 115, 243, 11, 139, 75, 203, 43, 171, 107, 235, 27, 155, 91, 219, 59, 187, 123, 251, 7, 135, 71, 199, 39, 167, 103, 231, 23, 151, 87, 215, 55, 183, 119, 247, 15, 143, 79, 207, 47, 175, 111, 239, 31, 159, 95, 223, 63, 191, 127, 255];
//
//  q = 2^23 - 2^13 + 1;
//  qinv = Mod(1/q,2^32);
//  mont = Mod(2^32,q);
//
//  z = 0;
//  for(i = 1, q-1, z = Mod(i,q); if(znorder(z) == 512, break));
//  zetas = vector(255, i, centerlift(mont * z^(brv[i])));
//  return(zetas);
var Zetas = [N]int32{
	25847, -2608894, -518909, 237124, -777960, -876248, 466468, 1826347,
	2353451, -359251, -2091905, 3119733, -2884855, 3111497, 2680103, 2725464,
	1024112, -1079900, 3585928, -549488, -1119584, 2619752, -2108549, -2118186,
	-3859737, -1399561, -3277672, 1757237, -19422, 4010497, 280005, 2706023,
	95776, 3077325, 3530437, -1661693, -3592148, -2537516, 3915439, -3861115,
	-3043716, 3574422, -2867647, 3539968, -300467, 2348700, -539299, -1699267,
	-1643818, 3505694, -3821735, 3507263, -2140649, -1600420, 3699596, 811944,
	531354, 954230, 3881043, 3900724, -2556880, 2071892, -2797779, -3930395,
	-1528703, -3677745, -3041255, -1452451, 3475950, 2176455, -1585221, -1257611,
	1939314, -4083598, -1000202, -3190144, -3157330, -3632928, 126922, 3412210,
	-983419, 2147896, 2715295, -2967645, -3693493, -411027, -2477047, -671102,
	-1228525, -22981, -1308169, -381987, 1349076, 1852771, -1430430, -3343383,
	264944, 508951, 3097992, 44288, -1100098, 904516, 3958618, -3724342,
	-8578, 1653064, -3249728, 2389356, -210977, 759969, -1316856, 189548,
	-3553272, 3159746, -1851402, -2409325, -177440, 1315589, 1341330, 1285669,
	-1584928, -812732, -1439742, -3019102, -3881060, -3628969, 3839961, 2091667,
	3407706, 2316500, 3817976, -3342478, 2244091, -2446433, -3562462, 266997,
	2434439, -1235728, 3513181, -3520352, -3759364, -1197226, -3193378, 900702,
	1859098, 909542, 819034, 495491, -1613174, -43260, -522500, -655327,
	-3122442, 2031748, 3207046, -3556995, -525098, -768622, -3595838, 342297,
	286988, -2437823, 4108315, 3437287, -3342277, 1735879, 203044, 2842341,
	2691481, -2590150, 1265009, 4055324, 1247620, 2486353, 1595974, -3767016,
	1250494, 2635921, -3548272, -2994039, 1869119, 1903435, -1050970, -1333058,
	1237275, -3318210, -1430225, -451100, 1312455, 3306115, -1962642, -1279661,
	1917081, -2546312, -1374803, 1500165, 777191, 2235880, 3406031, -542412,
	-2831860, -1671176, -1846953, -2584293, -3724270, 594136, -3776993, -2013608,
	2432395, 2454455, -164721, 1957272, 3369112, 185531, -1207385, -3183426,
	162844, 1616392, 3014001, 810149, 1652634, -3694233, -1799107, -3038916,
	3523897, 3866901, 269760, 2213111, -975884, 1717735, 472078, -426683,
	1723600, -1803090, 1910376, -1667432, -1104333, -260646, -3833893, -2939036,
	-2235985, -420899, -2286327, 183443, -976891, 1612842, -3545687,
	-554416, 3919660, -48306, -1362209, 3937738, 1400424, -846154, 1976782,
}

// Execute an in-place forward NTT on as.
//
// Assumes the coefficients are in Montgomery representation and bounded
// by 2*Q.  The resulting coefficients are again in Montgomery representation,
// but are only bounded by 18*Q.
func (p *Poly) nttGeneric() {
	// Writing z := zeta for our root of unity zeta := 1753, note z²⁵⁶=-1
	// (otherwise the order of z wouldn't be 512) and so
	//
	//  x²⁵⁶ + 1 = x²⁵⁶ - z²⁵⁶
	//           = (x¹²⁸ - z¹²⁸)(x¹²⁸ + z¹²⁸)
	//           = (x⁶⁴ - z⁶⁴)(x⁶⁴ + z⁶⁴)(x⁶⁴ + z¹⁹²)(x⁶⁴ - z¹⁹²)
	//          ...
	//           = (x-z)(x+z)(x - z¹²⁹)(x + z¹²⁹) ... (x - z²⁵⁵)(x + z²⁵⁵)
	//
	// Note that the powers of z that appear (from the second line) are
	//  in binary
	//
	//  01000000 11000000
	//  00100000 10100000 01100000 11100000
	//  00010000 10010000 01010000 11010000 00110000 10110000 01110000 11110000
	//     ...
	//
	// i.e. brv(2), brv(3), brv(4), ... and these powers of z are given by
	// the Zetas array.
	//
	// The polynomials x ± zⁱ are irreducible and coprime, hence by the
	// Chinese Remainder Theorem we know
	//
	//  R[x]/(x²⁵⁶+1) → R[x] / (x-z) x ... x R[x] / (x+z²⁵⁵)
	//                      ~= ∏_i R
	//
	// given by
	//
	//  a ↦ ( a mod x-z, ..., a mod x+z²⁵⁵ )
	//    ~ ( a(z), a(-z), a(z¹²⁹), a(-z¹²⁹), ..., a(z²⁵⁵), a(-z²⁵⁵) )
	//
	// is an isomorphism, which is the forward NTT.  It can be computed
	// efficiently by computing
	//
	//  a ↦ ( a mod x¹²⁸ - z¹²⁸, a mod x¹²⁸ + z¹²⁸ )
	//    ↦ ( a mod x⁶⁴ - z⁶⁴,  a mod x⁶⁴ + z⁶⁴,
	//        a mod x⁶⁴ - z¹⁹², a mod x⁶⁴ + z¹⁹² )
	//       et cetera
	//
	// If N was 8 then this can be pictured in the following diagram:
	//
	//  https://cnx.org/resources/17ee4dfe517a6adda05377b25a00bf6e6c93c334/File0026.png
	//
	// Each cross is a Cooley--Tukey butterfly: it's the map
	//
	//      (a, b) ↦ (a + ζ, a - ζ)
	//
	// for the appropriate ζ for that column and row group.

	k := 0 // Index into Zetas

	// l runs effectively over the columns in the diagram above; it is
	// half the height of a row group, i.e. the number of butterflies in
	// each row group.  In the diagram above it would be 4, 2, 1.
	for l := uint(N / 2); l > 0; l >>= 1 {
		// On the n-th iteration of the l-loop, the coefficients start off
		// bounded by n*2*Q.
		//
		// offset effectively loops over the row groups in this column; it
		// is the first row in the row group.
		for offset := uint(0); offset < N-l; offset += 2 * l {
			k++
			zeta := uint64(Zetas[k])

			// j loops over each butterfly in the row group.
			for j := offset; j < offset+l; j++ {
				t := montReduceLe2Q(int64(zeta) * int64(p[j+l]))
				p[j+l] = p[j] - t // Cooley--Tukey butterfly
				p[j] = p[j] + t
			}
		}
	}
}

// Execute an in-place inverse NTT and multiply by Montgomery factor R
//
// Assumes the coefficients are in Montgomery representation and bounded
// by 2*Q.  The resulting coefficients are again in Montgomery representation
// and bounded by 2*Q.
func (p *Poly) invNttGeneric() {
	f := int64(41978) // mont^2/256
	k := 256          // Index into Zetas

	// We basically do the opposite of NTT, but postpone dividing by 2 in the
	// inverse of the Cooley--Tukey butterfly and accumulate that to a big
	// division by 2⁸ at the end.  See comments in the NTT() function.

	for l := 1; l < N; l <<= 1 {
		// On the n-th iteration of the l-loop, the coefficients start off
		// bounded by 2ⁿ⁻¹*2*Q, so by 256*Q on the last.
		for offset := 0; offset < N-l; offset += 2 * l {
			k--
			zeta := -zeta[k]
			for j := offset; j < offset+l; j++ {
				t := p[j] // Gentleman--Sande butterfly
				p[j] = t + p[j+l]
				p[j+l] = t - p[j+l]
				p[j+l] = montReduceLe2Q(int64(zeta) * p[j+l])
			}
		}
	}

	for j := 0; j < N; j++ {
		// ROver256 = 41978 = (256)⁻¹ R²
		p[j] = montReduceLe2Q(f * p[j])
	}
}
