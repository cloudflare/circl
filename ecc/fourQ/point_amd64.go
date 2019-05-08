// +build amd64,go1.12

package fourQ

import "unsafe"

const ( // constants used in assembly implementation
	_x_        = unsafe.Offsetof(pointR1{}.X)
	_y_        = unsafe.Offsetof(pointR1{}.Y)
	_z_        = unsafe.Offsetof(pointR1{}.Z)
	_ta_       = unsafe.Offsetof(pointR1{}.Ta)
	_tb_       = unsafe.Offsetof(pointR1{}.Tb)
	_addYX_R2_ = unsafe.Offsetof(pointR2{}.addYX)
	_subYX_R2_ = unsafe.Offsetof(pointR2{}.subYX)
	_z2_R2_    = unsafe.Offsetof(pointR2{}.z2)
	_dt2_R2_   = unsafe.Offsetof(pointR2{}.dt2)
	_addYX_R3_ = unsafe.Offsetof(pointR3{}.addYX)
	_subYX_R3_ = unsafe.Offsetof(pointR3{}.subYX)
	_dt2_R3_   = unsafe.Offsetof(pointR3{}.dt2)
	_          = _x_ + _y_ + _z_ + _ta_ + _tb_ + _addYX_R2_ + _subYX_R2_ +
		_z2_R2_ + _dt2_R2_ + _addYX_R3_ + _subYX_R3_ + _dt2_R3_
)

func (P *pointR1) double()           { doubleAsm(P) }
func (P *pointR1) add(Q *pointR2)    { addAsm(P, Q) }
func (P *pointR1) mixAdd(Q *pointR3) { mixAddAsm(P, Q) }

//go:noescape
func doubleAsm(P *pointR1)

//go:noescape
func addAsm(P *pointR1, Q *pointR2)

//go:noescape
func mixAddAsm(P *pointR1, Q *pointR3)
