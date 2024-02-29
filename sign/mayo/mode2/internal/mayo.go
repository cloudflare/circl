// Code generated from mode1/internal/mayo.go by gen.go

package internal

import (
	"crypto/aes"
	"crypto/cipher"
	cryptoRand "crypto/rand"
	"crypto/subtle"
	"io"
	"unsafe"

	"github.com/cloudflare/circl/internal/sha3"
)

type (
	PrivateKey [PrivateKeySize]byte
	PublicKey  [PublicKeySize]byte
)

func (pk *PublicKey) Equal(other *PublicKey) bool {
	return *pk == *other
}

func (sk *PrivateKey) Equal(other *PrivateKey) bool {
	return subtle.ConstantTimeCompare((*sk)[:], (*other)[:]) == 1
}

type ExpandedPublicKey struct {
	p1 [P1Size]byte
	p2 [P2Size]byte
	p3 [P3Size]byte
}

type ExpandedPrivateKey struct {
	seed [KeySeedSize]byte
	o    [V * O]byte
	p1   [M * V * V / 16]uint64
	l    [M * V * O / 16]uint64
}

func (pk *PublicKey) Expand() *ExpandedPublicKey {
	seedPk := pk[:PublicKeySeedSize]

	var nonce [16]byte // zero-initialized
	block, _ := aes.NewCipher(seedPk[:])
	ctr := cipher.NewCTR(block, nonce[:])

	epk := ExpandedPublicKey{}
	ctr.XORKeyStream(epk.p1[:], epk.p1[:])
	ctr.XORKeyStream(epk.p2[:], epk.p2[:])

	copy(epk.p3[:], pk[PublicKeySeedSize:])

	return &epk
}

func (sk *PrivateKey) Expand() *ExpandedPrivateKey {
	var epk ExpandedPrivateKey

	seed := (*sk)[:KeySeedSize]
	copy(epk.seed[:], seed)

	var seedPk [PublicKeySeedSize]byte
	var o [OSize]byte

	h := sha3.NewShake256()
	_, _ = h.Write(seed[:])
	_, _ = h.Read(seedPk[:])
	_, _ = h.Read(o[:])

	var nonce [16]byte // zero-initialized
	block, _ := aes.NewCipher(seedPk[:])
	ctr := cipher.NewCTR(block, nonce[:])

	var p12 [P1Size + P2Size]byte
	ctr.XORKeyStream(p12[:], p12[:])

	decode(o[:], epk.o[:])

	p1Tri := viewBytesAsUint64Slice(p12[:P1Size])
	p2 := viewBytesAsUint64Slice(p12[P1Size:])

	// TODO: this copy can be saved by reusing buffers but ugly
	copy(epk.p1[:], p1Tri)
	copy(epk.l[:], p2)

	// compute L_i = (P1 + P1^t)*O + P2
	mulAddMUpperTriangularWithTransposeMatXMat(epk.l[:], p1Tri, epk.o[:], V, O)

	return &epk
}

// decode unpacks N bytes from src to N*2 nibbles to dst.
// The length is determined by len(dst)
func decode(src []byte, dst []byte) {
	i := 0
	for ; i < len(dst)/2; i++ {
		dst[i*2] = src[i] & 0xf
		dst[i*2+1] = src[i] >> 4
	}

	// Account for odd length
	if len(dst)%2 == 1 {
		dst[i*2] = src[i] & 0xf
	}
}

// encode packs N=length low nibbles from src to (N+1)/2 bytes in dst.
func encode(src []byte, dst []byte, length int) {
	var i int
	for i = 0; i+1 < length; i += 2 {
		dst[i/2] = (src[i+0] << 0) | (src[i+1] << 4)
	}
	if length%2 == 1 {
		dst[i/2] = (src[i+0] << 0)
	}
}

func viewBytesAsUint64Slice(data []byte) []uint64 {
	numUint64 := len(data) / 8
	return unsafe.Slice((*uint64)(unsafe.Pointer(&data[0])), numUint64)
}

func viewUint64SliceAsBytes(data []uint64) []byte {
	numByte := len(data) * 8
	return unsafe.Slice((*uint8)(unsafe.Pointer(&data[0])), numByte)
}

// GenerateKey generates a public/private key pair using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func GenerateKey(rand io.Reader) (*PublicKey, *PrivateKey, error) {
	var seed [KeySeedSize]byte
	if rand == nil {
		rand = cryptoRand.Reader
	}
	_, err := io.ReadFull(rand, seed[:])
	if err != nil {
		return nil, nil, err
	}
	pk, sk := NewKeyFromSeed(seed)
	return pk, sk, nil
}

func NewKeyFromSeed(seed [KeySeedSize]byte) (*PublicKey, *PrivateKey) {
	var sk PrivateKey
	copy(sk[:], seed[:])

	return sk.Public(), &sk
}

func (sk *PrivateKey) Public() *PublicKey {
	var pk PublicKey
	seedPk := pk[:PublicKeySeedSize]
	var o [OSize]byte

	h := sha3.NewShake256()
	_, _ = h.Write(sk[:])
	_, _ = h.Read(seedPk[:])
	_, _ = h.Read(o[:])

	var nonce [16]byte // zero-initialized
	block, _ := aes.NewCipher(seedPk[:])
	ctr := cipher.NewCTR(block, nonce[:])

	var p12 [P1Size + P2Size]byte
	ctr.XORKeyStream(p12[:], p12[:])

	var oo [V * O]byte
	decode(o[:], oo[:])

	p1Tri := viewBytesAsUint64Slice(p12[:P1Size])
	p1OP2 := viewBytesAsUint64Slice(p12[P1Size:])

	var p3full [M * O * O / 16]uint64
	var p3 [P3Size / 8]uint64

	mulAddMUpperTriangularMatXMat(p1OP2, p1Tri, oo[:], V, O)
	mulAddMatTransXMMat(p3full[:], oo[:], p1OP2, V, O, O)

	upper(p3full[:], p3[:], O)

	xx := viewUint64SliceAsBytes(p3[:])
	copy(pk[PublicKeySeedSize:], xx[:])

	return &pk
}

func Sign(msg []byte, sk *ExpandedPrivateKey, rand io.Reader) ([]byte, error) {
	if rand == nil {
		rand = cryptoRand.Reader
	}

	var digest [DigestSize]byte

	h := sha3.NewShake256()
	_, _ = h.Write(msg[:])
	_, _ = h.Read(digest[:])

	var salt [SaltSize]byte

	// R <- $
	if _, err := io.ReadFull(rand, salt[:]); err != nil {
		return nil, err
	}

	h.Reset()
	_, _ = h.Write(digest[:])
	_, _ = h.Write(salt[:])
	_, _ = h.Write(sk.seed[:])
	_, _ = h.Read(salt[:])

	h.Reset()
	_, _ = h.Write(digest[:])
	_, _ = h.Write(salt[:])

	var tenc [M / 2]byte
	_, _ = h.Read(tenc[:])

	var t [M]byte
	decode(tenc[:], t[:])

	var v [K * V]byte
	var x [K*O + 1]byte // + 1 for buffer
	for ctr := 0; ctr <= 255; ctr++ {
		ctrByte := []byte{byte(ctr)}
		h.Reset()
		_, _ = h.Write(digest[:])
		_, _ = h.Write(salt[:])
		_, _ = h.Write(sk.seed[:])
		_, _ = h.Write(ctrByte[:])

		var venc [K * VSize]byte
		var renc [K * O / 2]byte
		_, _ = h.Read(venc[:])
		_, _ = h.Read(renc[:])

		var r [K * O]byte

		for i := 0; i < K; i++ {
			decode(venc[i*VSize:], v[i*V:(i+1)*V])
		}
		decode(renc[:], r[:])

		// M = vL
		var m [M * K * O / 16]uint64
		mulAddMatXMMat(m[:], v[:], sk.l[:], K, V, O)

		// pv = P1 * V^T
		var pv [M * V * K / 16]uint64
		mulAddMMatXMatTrans(pv[:], sk.p1[:], v[:], V, V, K, V, true)

		// V * pv
		var vpv [M * K * K / 16]uint64
		mulAddMatXMMat(vpv[:], v[:], pv[:], K, V, K)

		var y [M]byte
		copy(y[:], t[:])
		emulsifyInto(vpv[:], y[:])

		var A [M * (K*O + 1)]byte
		_ = A

		computeA(m[:], A[:])

		if sampleSolution(A[:], y[:], r[:], x[:]) {
			break
		}
	}

	var s [K * N]byte
	for i := 0; i <= K-1; i++ {
		copy(s[i*N:][:V], v[i*V:])
		mulAddMatVec(s[i*N:], sk.o[:], x[i*O:], V, O)
		copy(s[i*N+V:][:O], x[i*O:])
	}

	var sig [(K*N+1)/2 + SaltSize]byte
	encode(s[:], sig[:], K*N)
	copy(sig[(K*N+1)/2:], salt[:])

	return sig[:], nil
}

// assume last (KO+1-th) column of a is zero
func sampleSolution(a []byte, y []byte, r []byte, x []byte) bool {
	const aCols = K*O + 1

	copy(x[:], r[:])

	var ar [M]byte
	mulAddMatVec(ar[:], a[:], x[:], M, aCols)

	// move y - Ar to last column of matrix A
	for i := 0; i < M; i++ {
		a[K*O+i*(aCols)] = y[i] ^ ar[i]
	}

	ef(a[:], M, aCols)

	fullRank := byte(0)
	for i := 0; i < aCols-1; i++ {
		fullRank |= a[(M-1)*(aCols)+i]
	}

	if fullRank == 0 {
		return false
	}

	// back substitution in constant time
	// the index of the first nonzero entry in each row is secret, which makes
	// things less efficient

	for row := M - 1; row >= 0; row-- {
		finished := byte(0)
		colUpperBound := min(row+(32/(M-row)), K*O)
		// the first nonzero entry in row r is between r and col_upper_bound with probability at least ~1-q^{-32}

		for col := row; col <= colUpperBound; col++ {
			// Compare two chars in constant time.
			// Returns 0x00 if the byte arrays are equal, 0xff otherwise.
			correctColumn := ctCompare8((a[row*aCols+col]), 0) & ^finished

			u := correctColumn & a[row*aCols+aCols-1]
			x[col] ^= u

			for i := 0; i < row; i += 8 {
				tmp := (uint64(a[i*aCols+col]) << 0) ^ (uint64(a[(i+1)*aCols+col]) << 8) ^
					(uint64(a[(i+2)*aCols+col]) << 16) ^ (uint64(a[(i+3)*aCols+col]) << 24) ^
					(uint64(a[(i+4)*aCols+col]) << 32) ^ (uint64(a[(i+5)*aCols+col]) << 40) ^
					(uint64(a[(i+6)*aCols+col]) << 48) ^ (uint64(a[(i+7)*aCols+col]) << 56)

				tmp = mulx8(u, tmp)

				a[i*aCols+aCols-1] ^= byte((tmp) & 0xf)
				a[(i+1)*aCols+aCols-1] ^= byte((tmp >> 8) & 0xf)
				a[(i+2)*aCols+aCols-1] ^= byte((tmp >> 16) & 0xf)
				a[(i+3)*aCols+aCols-1] ^= byte((tmp >> 24) & 0xf)
				a[(i+4)*aCols+aCols-1] ^= byte((tmp >> 32) & 0xf)
				a[(i+5)*aCols+aCols-1] ^= byte((tmp >> 40) & 0xf)
				a[(i+6)*aCols+aCols-1] ^= byte((tmp >> 48) & 0xf)
				a[(i+7)*aCols+aCols-1] ^= byte((tmp >> 56) & 0xf)
			}

			finished = finished | correctColumn
		}
	}

	return true
}

// if a == b -> 0x0000000000000000, else 0xFFFFFFFFFFFFFFFF
func ctCompare64(a, b int) uint64 {
	return uint64((-(int64)(a ^ b)) >> 63)
}

// a > b -> b - a is negative
// returns 0xFFFFFFFF if true, 0x00000000 if false
func ct64IsGreaterThan(a, b int) uint64 {
	diff := int64(b) - int64(a)
	return uint64(diff >> 63)
}

// if a == b -> 0x00, else 0xFF
func ctCompare8(a, b byte) byte {
	return byte((-int32(a ^ b)) >> (31))
}

func extract(in []uint64, index int) byte {
	leg := index / 16
	offset := index % 16

	return byte((in[leg] >> (offset * 4)) & 0xF)
}

// put matrix in row echelon form with ones on first nonzero entries *in constant time*
func ef(A []byte, nrows, ncols int) {
	// ncols is actually always K*O + 1

	// we operate each row by packing nibbles to uint64s.
	rowLen := (ncols + 15) / 16

	var pivotRowData [(K*O + 1 + 15) / 16]uint64 // rounds up
	var pivotRowData2 [(K*O + 1 + 15) / 16]uint64

	// nibbleslice the matrix A
	var packedAbyte [((K*O + 1 + 15) / 16) * M * 8]byte
	for i := 0; i < nrows; i++ {
		encode(A[i*ncols:], packedAbyte[i*rowLen*8:], ncols)
	}

	packedA := viewBytesAsUint64Slice(packedAbyte[:])

	// pivot row is secret, pivot col is not
	pivotRow := 0
	for pivotCol := 0; pivotCol < ncols; pivotCol++ {
		pivotRowLowerBound := max(0, pivotCol+nrows-ncols)
		pivotRowUpperBound := min(nrows-1, pivotCol)
		// the pivot row is guaranteed to be between these lower and upper bounds if
		// A has full rank

		// zero out pivot row
		for i := 0; i < rowLen; i++ {
			pivotRowData[i] = 0
			pivotRowData2[i] = 0
		}

		// try to get a pivot row in constant time
		var pivot byte = 0
		var pivotIsZero uint64 = 0xffffffffffffffff
		for row := pivotRowLowerBound; row <= min(nrows-1, pivotRowUpperBound+32); row++ {
			isPivotRow := ^ctCompare64(row, pivotRow)
			belowPivotRow := ct64IsGreaterThan(row, pivotRow)

			for j := 0; j < rowLen; j++ {
				mask := isPivotRow | (belowPivotRow & pivotIsZero)
				pivotRowData[j] ^= mask & packedA[row*rowLen+j]
			}
			pivot = extract(pivotRowData[:], pivotCol)
			pivotIsZero = ^ctCompare64(int(pivot), 0)
		}

		// multiply pivot row by inverse of pivot
		inverse := inverse(pivot)
		vecMulAddPacked(rowLen, pivotRowData[:], inverse, pivotRowData2[:])

		// conditionally write pivot row to the correct row, if there is a nonzero
		// pivot
		for row := pivotRowLowerBound; row <= pivotRowUpperBound; row++ {
			doCopy := ^ctCompare64(row, pivotRow) & ^pivotIsZero
			doNotCopy := ^doCopy
			for col := 0; col < rowLen; col++ {
				packedA[row*rowLen+col] = (doNotCopy & packedA[row*rowLen+col]) +
					(doCopy & pivotRowData2[col])
			}
		}

		// eliminate entries below pivot
		for row := pivotRowLowerBound; row < nrows; row++ {
			belowPivot := byte(0)
			if row > pivotRow {
				belowPivot = 1
			}
			eltToElim := extract(packedA[row*rowLen:], pivotCol)

			vecMulAddPacked(rowLen, pivotRowData2[:], belowPivot*eltToElim,
				packedA[row*rowLen:])
		}

		pivotRow += -int(^pivotIsZero)
	}

	var temp [(O*K + 1 + 15)]byte

	// unnibbleslice the matrix A
	for i := 0; i < nrows; i++ {
		decode(packedAbyte[i*rowLen*8:], temp[:rowLen*16])
		for j := 0; j < ncols; j++ {
			A[i*ncols+j] = temp[j]
		}
	}
}

func computeA(m []uint64, _a []byte) {
	// M is of K * O * (M / 16)

	// intermediate state of A, which is just accumulation of Mj*x^_ without reduction mod f
	// M/8 * K*O
	//                   uint64
	//              some idx ko @ K*O         idx = ko + 1
	// [  ...     [m0  m1 ...    m15]    [m0  m1    ... m15]  ....  ]
	// [  ...     [m16 m17 ...   m31]    [m16 m17 ...   m31]  ....  ]
	//               ...
	// [  ...     [m48 m49 ...   m63]    [m48 m49 ...   m63]  ....  ]   <--- for M=64, this is where reduction is not needed
	//               ...
	// [  ...     [m112 m113 ... m127]   [m112 m113 ... m127]  ....  ]  <--- here are for reductions later
	//              = sum of M_k @ ko
	//
	// later we will somehow transform it to the actual matrix form of A
	// for this, we need to group 16 uint64 words together as a chunk, hence OKpadded
	// ? why M/8, not something like ~ m+k*(K+1)/2  ?

	const OKpadded = (O*K + 15) / 16 * 16
	var a [(M / 8) * OKpadded]uint64

	// Emulsify, without reduction, by accumulating M
	bitsToShift, wordsToShift := 0, 0
	for i := 0; i < K; i++ {
		for j := K - 1; j >= i; j-- {
			// always maintain such that l = (bitsToShift + wordsToShift*64) / 4

			mj := m[j*O*M/16:]
			for c := 0; c < O; c++ {
				for k := 0; k < M/16; k++ { // currently 4
					a[(O*i+c)+(k+wordsToShift)*OKpadded] ^= mj[k+c*M/16] << bitsToShift
					if bitsToShift > 0 {
						a[(O*i+c)+(k+wordsToShift+1)*OKpadded] ^= mj[k+c*M/16] >> (64 - bitsToShift)
					}
				}
			}

			if i != j {
				mi := m[i*O*M/16:]
				for c := 0; c < O; c++ {
					for k := 0; k < M/16; k++ {
						a[(O*j)+c+(k+wordsToShift)*OKpadded] ^= mi[k+c*M/16] << bitsToShift
						if bitsToShift > 0 {
							a[(O*j)+c+(k+wordsToShift+1)*OKpadded] ^= mi[k+c*M/16] >> (64 - bitsToShift)
						}
					}
				}
			}

			bitsToShift += 4
			if bitsToShift == 64 {
				bitsToShift = 0
				wordsToShift++
			}
		}
	}

	// transpose among groups of 16 uint64s in each row, so that above matrix becomes
	//                   uint64
	// [  ...     { [m0  m0   ...  m0 ]    [m1  m1  ... m1 ]  .... [m15 m15  ... m15] }   ]
	// [  ...     { [m16 m16  ...  m16]    [m17 m7  ... m17]  .... [m31 m31  ... m31] }   ]
	//
	// where {} indicates a group of 16 uint64s

	for c := 0; c < OKpadded*((M+(K+1)*K/2+15)/16); c += 16 {
		transpose16x16Nibbles(a[c:])
	}

	// reduction mod f by folding rows >= M back around, using 4-bit multiplication table
	var tab [len(Tail) * 4]byte
	for i := 0; i < len(Tail); i++ {
		tab[4*i] = mul(Tail[i], 1)
		tab[4*i+1] = mul(Tail[i], 2)
		tab[4*i+2] = mul(Tail[i], 4)
		tab[4*i+3] = mul(Tail[i], 8)
	}

	const lsb = 0x1111111111111111

	for c := 0; c < OKpadded; c += 16 {
		for r := M; r < M+(K+1)*K/2; r++ {
			pos := (r/16)*OKpadded + c + (r % 16)
			t0 := a[pos] & lsb
			t1 := (a[pos] >> 1) & lsb
			t2 := (a[pos] >> 2) & lsb
			t3 := (a[pos] >> 3) & lsb
			for t := 0; t < len(Tail); t++ {
				a[((r+t-M)/16)*OKpadded+c+((r+t)%16)] ^= t0*uint64(tab[4*t+0]) ^ t1*uint64(tab[4*t+1]) ^ t2*uint64(tab[4*t+2]) ^ t3*uint64(tab[4*t+3])
			}
		}
	}

	// transform the temporary matrix into the desired form of A matrix
	KO1 := K*O + 1
	for r := 0; r < M; r += 16 {
		for c := 0; c < KO1-1; c += 16 {
			for i := 0; i < 16; i++ {
				src := viewUint64SliceAsBytes(a[r/16*OKpadded+c+i:])
				offset := KO1*(r+i) + c
				decode(src, _a[offset:offset+min(16, KO1-1-c)])
			}
		}
	}
}

func transpose16x16Nibbles(m []uint64) {
	const evenNibbles = 0x0f0f0f0f0f0f0f0f
	const evenBytes = 0x00ff00ff00ff00ff
	const even2Bytes = 0x0000ffff0000ffff
	const evenHalf = 0x00000000ffffffff

	for i := 0; i < 16; i += 2 {
		t := ((m[i] >> 4) ^ m[i+1]) & evenNibbles
		m[i] ^= t << 4
		m[i+1] ^= t
	}

	for i := 0; i < 16; i += 4 {
		t0 := ((m[i] >> 8) ^ m[i+2]) & evenBytes
		t1 := ((m[i+1] >> 8) ^ m[i+3]) & evenBytes
		m[i] ^= (t0 << 8)
		m[i+1] ^= (t1 << 8)
		m[i+2] ^= t0
		m[i+3] ^= t1
	}

	for i := 0; i < 4; i++ {
		t0 := ((m[i] >> 16) ^ m[i+4]) & even2Bytes
		t1 := ((m[i+8] >> 16) ^ m[i+12]) & even2Bytes

		m[i] ^= t0 << 16
		m[i+8] ^= t1 << 16
		m[i+4] ^= t0
		m[i+12] ^= t1
	}

	for i := 0; i < 8; i++ {
		t := ((m[i] >> 32) ^ m[i+8]) & evenHalf
		m[i] ^= t << 32
		m[i+8] ^= t
	}
}

func Verify(msg []byte, sig []byte, epk *ExpandedPublicKey) bool {
	if len(sig) != SignatureSize {
		panic("sig must be of length SignatureSize")
	}

	var digest [DigestSize]byte

	h := sha3.NewShake256()
	_, _ = h.Write(msg[:])
	_, _ = h.Read(digest[:])

	h.Reset()
	_, _ = h.Write(digest[:])
	_, _ = h.Write(sig[SignatureSize-SaltSize : SignatureSize])

	var tenc [M / 2]byte
	_, _ = h.Read(tenc[:])

	var t [M]byte
	decode(tenc[:], t[:])

	var s [K * N]byte
	decode(sig[:(K*N+1)/2], s[:])

	P1 := viewBytesAsUint64Slice(epk.p1[:])
	P2 := viewBytesAsUint64Slice(epk.p2[:])
	P3 := viewBytesAsUint64Slice(epk.p3[:])

	// Note: the variable time approach is overall about 30% faster
	// compute P * S^t = [ P1  P2 ] * [S1] = [P1*S1 + P2*S2]
	//                   [  0  P3 ]   [S2]   [        P3*S2]
	var pst [M * N * K / 16]uint64
	// mulAddMMatXMatTrans(pst[:], P1, s[:], V, V, K, N, true)
	// mulAddMMatXMatTrans(pst[:], P2, s[V:], V, O, K, N, false)
	// mulAddMMatXMatTrans(pst[M*V*K/16:], P3, s[V:], O, O, K, N, true)
	variableTime(pst[:], P1, P2, P3, s[:])

	// compute S * PST
	var sps [M * K * K / 16]uint64
	// mulAddMatXMMat(sps[:], s[:], pst[:], K, N, K)
	variableTime2(sps[:], s[:], pst[:])

	emulsifyInto(sps[:], t[:])

	var zeros [M]byte
	return subtle.ConstantTimeCompare(t[:], zeros[:]) == 1
}

// GF(16) multiplication mod x^4 + x + 1
func mul(a, b uint8) uint8 {
	// carryless multiply
	p := (a & 1) * b
	p ^= (a & 2) * b
	p ^= (a & 4) * b
	p ^= (a & 8) * b

	// reduce mod x^4 + x + 1
	top := p & 0xf0
	return (p ^ (top >> 4) ^ (top >> 3)) & 0x0f
}

func mulx8(a byte, b uint64) uint64 {
	// carryless multiply
	p := uint64(a&1) * b
	p ^= uint64(a&2) * b
	p ^= uint64(a&4) * b
	p ^= uint64(a&8) * b

	// reduce mod x^4 + x + 1
	top := p & 0xf0f0f0f0f0f0f0f0
	return (p ^ (top >> 4) ^ (top >> 3)) & 0x0f0f0f0f0f0f0f0f
}

func inverse(a byte) byte {
	// static unsigned char table[16] = {0, 1, 9, 14, 13, 11, 7, 6, 15, 2, 12, 5,
	// 10, 4, 3, 8}; return table[a & 15];

	a2 := mul(a, a)
	a4 := mul(a2, a2)
	a8 := mul(a4, a4)
	a6 := mul(a2, a4)
	a14 := mul(a8, a6)

	return a14
}

func emulsifyInto(sps []uint64, y []uint8) {
	var acc [M / 16]uint64
	accBytes := viewUint64SliceAsBytes(acc[:])

	for i := K - 1; i >= 0; i-- {
		for j := i; j < K; j++ {
			top := uint8(acc[M/16-1] >> 60)

			acc[M/16-1] <<= 4
			for k := M/16 - 2; k >= 0; k-- {
				acc[k+1] ^= acc[k] >> 60
				acc[k] <<= 4
			}

			for k := 0; k < len(Tail); k++ {
				if k%2 == 0 {
					accBytes[k/2] ^= mul(top, Tail[k])
				} else {
					accBytes[k/2] ^= mul(top, Tail[k]) << 4
				}
			}

			for k := 0; k < M/16; k++ {
				acc[k] ^= sps[(i*K+j)*(M/16)+k]
				if i != j {
					acc[k] ^= sps[(j*K+i)*(M/16)+k]
				}
			}
		}
	}

	// add to y
	for i := 0; i < M; i += 2 {
		y[i] ^= accBytes[i/2] & 0xF
		y[i+1] ^= accBytes[i/2] >> 4
	}
}
