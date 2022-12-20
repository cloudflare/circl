package internal

/*
CPU division instruction typically takes time depending on x.
This software is designed to take time independent of x.
Time still varies depending on m; user must ensure that m is constant.
Time also varies on CPUs where multiplication is variable-time.
There could be more CPU issues.
There could also be compiler issues.
*/
// q, r = x/m
// Returns quotient and remainder
func Uint32DivmodUint14(q *uint32, r *uint16, x uint32, m uint16) {
	var v uint32 = 0x80000000

	v /= uint32(m)

	*q = 0

	qpart := uint32(uint64(x) * uint64(v) >> 31)

	x -= qpart * uint32(m)
	*q += qpart

	qpart = uint32(uint64(x) * uint64(v) >> 31)
	x -= qpart * uint32(m)
	*q += qpart

	x -= uint32(m)
	*q += 1
	mask := -(x >> 31)
	x += mask & uint32(m)
	*q += mask

	*r = uint16(x)
}

// Returns the quotient of x/m
func Uint32DivUint14(x uint32, m uint16) uint32 {
	var q uint32
	var r uint16
	Uint32DivmodUint14(&q, &r, x, m)
	return q
}

// Returns the remainder of x/m
func Uint32ModUint14(x uint32, m uint16) uint16 {
	var q uint32
	var r uint16
	Uint32DivmodUint14(&q, &r, x, m)
	return r
}

// Calculates quotient and remainder
func Int32DivmodUint14(q *int32, r *uint16, x int32, m uint16) {
	var uq, uq2 uint32
	var ur, ur2 uint16
	var mask uint32

	Uint32DivmodUint14(&uq, &ur, 0x80000000+uint32(x), m)
	Uint32DivmodUint14(&uq2, &ur2, 0x80000000, m)

	ur -= ur2
	uq -= uq2
	mask = -(uint32)(ur >> 15)
	ur += uint16(mask & uint32(m))
	uq += mask
	*r = ur
	*q = int32(uq)
}

// Returns quotient of x/m
func Int32DivUint14(x int32, m uint16) int32 {
	var q int32
	var r uint16
	Int32DivmodUint14(&q, &r, x, m)
	return q
}

// Returns remainder of x/m
func Int32ModUint14(x int32, m uint16) uint16 {
	var q int32
	var r uint16
	Int32DivmodUint14(&q, &r, x, m)
	return r
}

// Returns -1 if x!=0; else return 0
func Int16NonzeroMask(x int16) int {
	u := uint16(x) /* 0, else 1...65535 */
	v := uint32(u) /* 0, else 1...65535 */
	v = -v         /* 0, else 2^32-65535...2^32-1 */
	v >>= 31       /* 0, else 1 */
	return -int(v) /* 0, else -1 */
}

// Returns -1 if x<0; otherwise return 0
func Int16NegativeMask(x int16) int {
	u := uint16(x)
	u >>= 15
	return -(int)(u)
}
