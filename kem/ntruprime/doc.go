//go:generate go run gen.go

// Package ntruprime implements the NTRU Prime IND-CCA2 secure
// key encapsulation mechanism (KEM) as submitted to round 3 of the NIST PQC
// competition and described in
//
//	https://ntruprime.cr.yp.to/nist/ntruprime-20201007.pdf
//
// The code is translated from the C reference implementation.
package ntruprime
