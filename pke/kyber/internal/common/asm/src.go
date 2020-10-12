//go:generate go run src.go -out ../amd64.s -stubs ../stubs_amd64.go -pkg common

// AVX2 optimized version of polynomial operations.  See the comments on the
// generic implementation for the details of the maths involved.
package main

import (
    . "github.com/mmcloughlin/avo/build" // nolint:golint,stylecheck
    . "github.com/mmcloughlin/avo/operand" // nolint:golint,stylecheck
    . "github.com/mmcloughlin/avo/reg" // nolint:golint,stylecheck
)

// XXX align Poly on 16 bytes such that we can use aligned moves
// XXX ensure Zetas and InvZetas are 16 byte aligned

func addAVX2() {
    TEXT("addAVX2", NOSPLIT, "func(p, a, b *[256]int16)")
    Pragma("noescape")

    pPtr := Load(Param("p"), GP64())
    aPtr := Load(Param("a"), GP64())
    bPtr := Load(Param("b"), GP64())

    var a [8]VecVirtual
    var b [8]VecVirtual
    for i := 0; i < 8; i++ {
        a[i] = YMM()
        b[i] = YMM()
    }

    for j := 0; j < 2; j++ {
        for i := 0; i < 8; i++ {
            VMOVDQU(Mem{Base: aPtr, Disp: 32*(8*j+i)}, a[i])
        }
        for i := 0; i < 8; i++ {
            VMOVDQU(Mem{Base: bPtr, Disp: 32*(8*j+i)}, b[i])
        }
        for i := 0; i < 8; i++ {
            VPADDW(a[i], b[i], b[i])
        }
        for i := 0; i < 8; i++ {
            VMOVDQU(b[i], Mem{Base: pPtr, Disp: 32*(8*j+i)})
        }
    }

    RET()
}

func subAVX2() {
    TEXT("subAVX2", NOSPLIT, "func(p, a, b *[256]int16)")
    Pragma("noescape")

    pPtr := Load(Param("p"), GP64())
    aPtr := Load(Param("a"), GP64())
    bPtr := Load(Param("b"), GP64())

    var a [8]VecVirtual
    var b [8]VecVirtual
    for i := 0; i < 8; i++ {
        a[i] = YMM()
        b[i] = YMM()
    }

    for j := 0; j < 2; j++ {
        for i := 0; i < 8; i++ {
            VMOVDQU(Mem{Base: aPtr, Disp: 32*(8*j+i)}, a[i])
        }
        for i := 0; i < 8; i++ {
            VMOVDQU(Mem{Base: bPtr, Disp: 32*(8*j+i)}, b[i])
        }
        for i := 0; i < 8; i++ {
            VPSUBW(b[i], a[i], b[i])
        }
        for i := 0; i < 8; i++ {
            VMOVDQU(b[i], Mem{Base: pPtr, Disp: 32*(8*j+i)})
        }
    }

    RET()
}


func main() {
    ConstraintExpr("amd64")

    addAVX2()
    subAVX2()

    Generate()
}
