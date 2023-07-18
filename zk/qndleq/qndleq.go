// Package qndleq provides zero-knowledge proofs of Discrete-Logarithm Equivalence (DLEQ) on Qn.
//
// This package implements proofs on the group Qn (the subgroup of squares in (Z/nZ)*).
//
// # Notation
//
//	Z/nZ is the ring of integers modulo N.
//	(Z/nZ)* is the multiplicative group of Z/nZ, a.k.a. the units of Z/nZ, the elements with inverse mod N.
//	Qn is the subgroup of squares in (Z/nZ)*.
//
// A number x belongs to Qn if
//
//	gcd(x, N) = 1, and
//	exists y such that x = y^2 mod N.
//
// # References
//
// [DLEQ Proof] "Wallet databases with observers" by Chaum-Pedersen.
// https://doi.org/10.1007/3-540-48071-4_7
//
// [Qn] "Practical Threshold Signatures" by Shoup.
// https://www.iacr.org/archive/eurocrypt2000/1807/18070209-new.pdf
package qndleq

import (
	"crypto/rand"
	"io"
	"math/big"

	"github.com/cloudflare/circl/internal/sha3"
)

type Proof struct {
	Z, C     *big.Int
	SecParam uint
}

// SampleQn returns an element of Qn (the subgroup of squares in (Z/nZ)*).
// SampleQn will return error for any error returned by crypto/rand.Int.
func SampleQn(random io.Reader, N *big.Int) (*big.Int, error) {
	one := big.NewInt(1)
	gcd := new(big.Int)
	x := new(big.Int)

	for {
		y, err := rand.Int(random, N)
		if err != nil {
			return nil, err
		}
		// x is a square by construction.
		x.Mul(y, y).Mod(x, N)
		gcd.GCD(nil, nil, x, N)
		// now check whether h is coprime to N.
		if gcd.Cmp(one) == 0 {
			return x, nil
		}
	}
}

// Prove creates a DLEQ Proof that attests that the pairs (g,gx)
// and (h,hx) have the same discrete logarithm equal to x.
//
// Given g, h in Qn (the subgroup of squares in (Z/nZ)*), it holds
//
//	gx = g^x mod N
//	hx = h^x mod N
//	x  = Log_g(g^x) = Log_h(h^x)
func Prove(random io.Reader, x, g, gx, h, hx, N *big.Int, secParam uint) (*Proof, error) {
	rSizeBits := uint(N.BitLen()) + 2*secParam
	rSizeBytes := (rSizeBits + 7) / 8

	rBytes := make([]byte, rSizeBytes)
	_, err := io.ReadFull(random, rBytes)
	if err != nil {
		return nil, err
	}
	r := new(big.Int).SetBytes(rBytes)

	gP := new(big.Int).Exp(g, r, N)
	hP := new(big.Int).Exp(h, r, N)

	c := doChallenge(g, gx, h, hx, gP, hP, N, secParam)
	z := new(big.Int)
	z.Mul(c, x).Add(z, r)
	r.Xor(r, r)

	return &Proof{Z: z, C: c, SecParam: secParam}, nil
}

// Verify checks whether x = Log_g(g^x) = Log_h(h^x).
func (p Proof) Verify(g, gx, h, hx, N *big.Int) bool {
	gPNum := new(big.Int).Exp(g, p.Z, N)
	gPDen := new(big.Int).Exp(gx, p.C, N)
	ok := gPDen.ModInverse(gPDen, N)
	if ok == nil {
		return false
	}
	gP := gPNum.Mul(gPNum, gPDen)
	gP.Mod(gP, N)

	hPNum := new(big.Int).Exp(h, p.Z, N)
	hPDen := new(big.Int).Exp(hx, p.C, N)
	ok = hPDen.ModInverse(hPDen, N)
	if ok == nil {
		return false
	}
	hP := hPNum.Mul(hPNum, hPDen)
	hP.Mod(hP, N)

	c := doChallenge(g, gx, h, hx, gP, hP, N, p.SecParam)

	return p.C.Cmp(c) == 0
}

func mustWrite(w io.Writer, b []byte) {
	n, err := w.Write(b)
	if err != nil {
		panic(err)
	}
	if len(b) != n {
		panic("qndleq: failed to write on hash")
	}
}

func doChallenge(g, gx, h, hx, gP, hP, N *big.Int, secParam uint) *big.Int {
	modulusLenBytes := (N.BitLen() + 7) / 8
	nBytes := make([]byte, modulusLenBytes)
	cByteLen := (secParam + 7) / 8
	cBytes := make([]byte, cByteLen)

	H := sha3.NewShake256()
	mustWrite(&H, g.FillBytes(nBytes))
	mustWrite(&H, h.FillBytes(nBytes))
	mustWrite(&H, gx.FillBytes(nBytes))
	mustWrite(&H, hx.FillBytes(nBytes))
	mustWrite(&H, gP.FillBytes(nBytes))
	mustWrite(&H, hP.FillBytes(nBytes))
	_, err := H.Read(cBytes)
	if err != nil {
		panic(err)
	}

	return new(big.Int).SetBytes(cBytes)
}
