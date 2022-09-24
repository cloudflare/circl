package internal

import (
	"reflect"
	"testing"

	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/kem/mceliece/testdata"
)

const testPath = "../testdata/testdata.txt"

func TestLayer1(t *testing.T) {
	N := 4
	S := 1
	p := []int16{0, 3, 7, 11}
	cb := []byte{63}
	test.CheckOk(len(p) == N, "length does not match", t)
	layer(p, cb, S, N)
	pRef := []int16{7, 11, 0, 3}
	if !reflect.DeepEqual(pRef, p) {
		test.ReportError(t, p, pRef)
	}
}

func TestLayer2(t *testing.T) {
	N := 8
	S := 2
	p := []int16{0, 3, 7, 11, 13, 17, 23, 0}
	cb := []byte{0xAA, 0xFF, 0x02}
	test.CheckOk(len(p) == N, "length does not match", t)
	layer(p, cb, S, N)
	pRef := []int16{0, 17, 7, 0, 13, 3, 23, 11}
	if !reflect.DeepEqual(pRef, p) {
		test.ReportError(t, p, pRef)
	}
}

func TestRecursion1(t *testing.T) {
	const (
		W    = 3
		N    = 1 << W
		STEP = 1
		POS  = 0
	)
	pi := []int16{0, 2, 4, 6, 1, 3, 5, 7}
	temp := [2 * N]int32{}
	out := [3]byte{}
	cbRecursion(out[:], POS, STEP, pi, W, N, temp[:])
	outRef := [3]byte{0xCA, 0x66, 0x0C}
	if !reflect.DeepEqual(outRef, out) {
		test.ReportError(t, out, outRef)
	}
}

func TestRecursion2(t *testing.T) {
	const (
		W    = 3
		N    = 1 << W
		STEP = 2
		POS  = 0
	)
	pi := []int16{0, 2, 4, 6, 1, 3, 5, 7}
	temp := [2 * N]int32{}
	out := [5]byte{}
	cbRecursion(out[:], POS, STEP, pi, W, N, temp[:])
	outRef := [5]byte{0x44, 0x50, 0x14, 0x14, 0x50}
	if !reflect.DeepEqual(outRef, out) {
		test.ReportError(t, out, outRef)
	}
}

func TestControlBitsFromPermutationKat3Mceliece348864(t *testing.T) {
	pi, err := testdata.FindTestDataI16("controlbits_kat3_mceliece348864_pi", testPath)
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	want, err := testdata.FindTestDataByte("controlbits_kat3_mceliece348864_out_ref", testPath)
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	out := make([]byte, 5888)
	ControlBitsFromPermutation(out, pi, 12, 4096)
	if !reflect.DeepEqual(out, want) {
		test.ReportError(t, out, want)
	}
}

func TestControlBitsFromPermutationKat8Mceliece348864(t *testing.T) {
	pi, err := testdata.FindTestDataI16("controlbits_kat8_mceliece348864_pi", testPath)
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	want, err := testdata.FindTestDataByte("controlbits_kat8_mceliece348864_out_ref", testPath)
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	out := make([]byte, 5888)
	ControlBitsFromPermutation(out, pi, 12, 4096)
	if !reflect.DeepEqual(out, want) {
		test.ReportError(t, out, want)
	}
}

func TestControlBitsFromPermutationKat9Mceliece348864(t *testing.T) {
	pi, err := testdata.FindTestDataI16("controlbits_kat9_mceliece348864_pi", testPath)
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	want, err := testdata.FindTestDataByte("controlbits_kat9_mceliece348864_out_ref", testPath)
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	out := make([]byte, 5888)
	ControlBitsFromPermutation(out, pi, 12, 4096)
	if !reflect.DeepEqual(out, want) {
		test.ReportError(t, out, want)
	}
}
