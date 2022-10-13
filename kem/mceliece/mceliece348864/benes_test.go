package mceliece348864

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/kem/mceliece/testdata"
)

const testPath = "../testdata/testdata.txt.bz2"

func TestLayer(t *testing.T) {
	data := [64]uint64{}
	bits := [32]uint64{}
	for i := 0; i < len(data); i++ {
		data[i] = 0xAAAA ^ (uint64(i) * 17)
	}
	for i := 0; i < len(bits); i++ {
		bits[i] = uint64(i) << 3
	}
	layer(data[:], bits[:], 4)
	want := [64]uint64{
		0xAAAA, 0xAABB, 0xAA98, 0xAA89, 0xAAEE, 0xAADF, 0xAADC, 0xAAED, 0xAA22, 0xAA33,
		0xAA10, 0xAA41, 0xAA66, 0xAA57, 0xAA54, 0xAA25, 0xABBA, 0xAB8B, 0xAB88, 0xABF9,
		0xABFE, 0xABEF, 0xABCC, 0xAB1D, 0xAB32, 0xAB03, 0xAB00, 0xAB31, 0xAB76, 0xAB67,
		0xAB44, 0xA8D5, 0xA88A, 0xA89B, 0xA8F8, 0xA8E9, 0xA8CE, 0xA87F, 0xA83C, 0xA80D,
		0xA802, 0xA853, 0xA870, 0xA861, 0xA846, 0xA8B7, 0xA9B4, 0xA985, 0xA99A, 0xA9EB,
		0xA9E8, 0xA9D9, 0xA9DE, 0xA98F, 0xA92C, 0xA93D, 0xA912, 0xA923, 0xA960, 0xA951,
		0xA956, 0xAE47, 0xAEA4, 0xAEB5,
	}
	if !reflect.DeepEqual(data, want) {
		test.ReportError(t, fmt.Sprintf("%X", data), fmt.Sprintf("%X", want))
	}
}

func TestLayer2(t *testing.T) {
	data, err := testdata.FindTestDataU64("mceliece348864_benes_layer_data_before", testPath)
	if err != nil {
		t.Fatal(err)
	}
	bits, err := testdata.FindTestDataU64("mceliece348864_benes_layer_bits", testPath)
	if err != nil {
		t.Fatal(err)
	}
	want, err := testdata.FindTestDataU64("mceliece348864_benes_layer_data_after", testPath)
	if err != nil {
		t.Fatal(err)
	}

	layer(data, bits, 0)
	if !reflect.DeepEqual(data, want) {
		test.ReportError(t, fmt.Sprintf("%X", data), fmt.Sprintf("%X", want))
	}
}

func TestApplyBenes(t *testing.T) {
	r, err := testdata.FindTestDataByte("mceliece348864_benes_apply_benes_r_before", testPath)
	if err != nil {
		t.Fatal(err)
	}
	bits, err := testdata.FindTestDataByte("mceliece348864_benes_apply_benes_bits", testPath)
	if err != nil {
		t.Fatal(err)
	}
	want, err := testdata.FindTestDataByte("mceliece348864_benes_apply_benes_r_after", testPath)
	if err != nil {
		t.Fatal(err)
	}

	applyBenes((*[512]byte)(r), (*[5888]byte)(bits))
	if !reflect.DeepEqual(r[:], want) {
		test.ReportError(t, fmt.Sprintf("%X", r), fmt.Sprintf("%X", want))
	}
}
