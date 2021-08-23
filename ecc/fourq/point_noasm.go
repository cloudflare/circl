//go:build !amd64 || purego
// +build !amd64 purego

package fourq

func (P *pointR1) double()           { doubleGeneric(P) }
func (P *pointR1) add(Q *pointR2)    { addGeneric(P, Q) }
func (P *pointR1) mixAdd(Q *pointR3) { mixAddGeneric(P, Q) }
