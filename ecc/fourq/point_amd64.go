//go:build amd64 && !purego
// +build amd64,!purego

package fourq

import "unsafe"

const ( // constants used in assembly implementation
	_x       = unsafe.Offsetof(pointR1{}.X)
	_y       = unsafe.Offsetof(pointR1{}.Y)
	_z       = unsafe.Offsetof(pointR1{}.Z)
	_ta      = unsafe.Offsetof(pointR1{}.Ta)
	_tb      = unsafe.Offsetof(pointR1{}.Tb)
	_addYXR2 = unsafe.Offsetof(pointR2{}.addYX)
	_subYXR2 = unsafe.Offsetof(pointR2{}.subYX)
	_z2R2    = unsafe.Offsetof(pointR2{}.z2)
	_dt2R2   = unsafe.Offsetof(pointR2{}.dt2)
	_addYXR3 = unsafe.Offsetof(pointR3{}.addYX)
	_subYXR3 = unsafe.Offsetof(pointR3{}.subYX)
	_dt2R3   = unsafe.Offsetof(pointR3{}.dt2)
	_        = _x + _y + _z + _ta + _tb + _addYXR2 + _subYXR2 +
		_z2R2 + _dt2R2 + _addYXR3 + _subYXR3 + _dt2R3
)

func (P *pointR1) double()           { doubleAmd64(P) }
func (P *pointR1) add(Q *pointR2)    { addAmd64(P, Q) }
func (P *pointR1) mixAdd(Q *pointR3) { mixAddAmd64(P, Q) }

//go:noescape
func doubleAmd64(P *pointR1)

//go:noescape
func addAmd64(P *pointR1, Q *pointR2)

//go:noescape
func mixAddAmd64(P *pointR1, Q *pointR3)
