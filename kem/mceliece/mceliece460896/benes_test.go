package mceliece460896

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/kem/mceliece/testdata"
)

const testPath = "../testdata/testdata.txt"

func TestLayerIn(t *testing.T) {
	data0, err := testdata.FindTestDataU64("mceliece460896_benes_layer_in_data0_before", testPath)
	if err != nil {
		t.Fatal(err)
	}
	data1, err := testdata.FindTestDataU64("mceliece460896_benes_layer_in_data1_before", testPath)
	if err != nil {
		t.Fatal(err)
	}
	data := [2][64]uint64{}
	copy(data[0][:], data0)
	copy(data[1][:], data1)
	bitsArg, err := testdata.FindTestDataU64("mceliece460896_benes_layer_in_bits", testPath)
	if err != nil {
		t.Fatal(err)
	}
	layerIn(&data, (*[64]uint64)(bitsArg), 0)
	want0, err := testdata.FindTestDataU64("mceliece460896_benes_layer_in_data0_after", testPath)
	if err != nil {
		t.Fatal(err)
	}
	want1, err := testdata.FindTestDataU64("mceliece460896_benes_layer_in_data1_after", testPath)
	if err != nil {
		t.Fatal(err)
	}
	want := [2][64]uint64{}
	copy(want[0][:], want0)
	copy(want[1][:], want1)
	if !reflect.DeepEqual(want, data) {
		test.ReportError(t, data, want)
	}
}

func TestLayerEx(t *testing.T) {
	data := [2][64]uint64{}
	bits := [64]uint64{}
	for i := uint64(0); i < 64; i++ {
		data[0][i] = 0xFC81 ^ (i * 17)
		data[1][i] = 0x9837 ^ (i * 3)
		bits[i] = i << 3
	}
	layerEx(&data, &bits, 5)

	want := [2][64]uint64{
		{
			0xFC81, 0xFC90, 0xFCA3, 0xFCB2, 0xFCE5, 0xFCF4, 0xFCC7, 0xFCD6, 0xFC09, 0xFC18,
			0xFC6B, 0xFC7A, 0xFC6D, 0xFC7C, 0xFC0F, 0xFC1E, 0xFD91, 0xFDA0, 0xFDB3, 0xFDC2,
			0xFDF5, 0xFD44, 0xFD57, 0xFD26, 0xFD19, 0xFD68, 0xFD7B, 0xFD4A, 0xFD7D, 0xFD8C,
			0xFD9F, 0xFEAE, 0xFEA1, 0xFEB0, 0xFEC3, 0xFED2, 0xFEC5, 0xFED4, 0xFE27, 0xFE36,
			0xFE29, 0xFE38, 0xFE0B, 0xFE1A, 0xFE4D, 0xFE5C, 0xFFEF, 0xFFFE, 0xFFB1, 0xFFC0,
			0xFFD3, 0xFFE2, 0xFFD5, 0xFFA4, 0xFFB7, 0xFF06, 0xFF39, 0xFF08, 0xFF1B, 0xFF6A,
			0xFF5D, 0xF86C, 0xF87F, 0xF88E,
		}, {
			0x9837, 0x9834, 0x9831, 0x983E, 0x981B, 0x9818, 0x9805, 0x9802, 0x986F, 0x986C,
			0x9869, 0x9816, 0x9833, 0x9830, 0x983D, 0x983A, 0x9887, 0x9884, 0x9881, 0x988E,
			0x98AB, 0x98A8, 0x98D5, 0x98D2, 0x98BF, 0x98BC, 0x98B9, 0x98A6, 0x9883, 0x9880,
			0x988D, 0x988A, 0x9857, 0x9854, 0x9851, 0x985E, 0x987B, 0x9878, 0x9865, 0x9862,
			0x980F, 0x980C, 0x9809, 0x98B6, 0x9893, 0x9890, 0x989D, 0x989A, 0x9827, 0x9824,
			0x9821, 0x982E, 0x980B, 0x9808, 0x9835, 0x9832, 0x985F, 0x985C, 0x9859, 0x9846,
			0x9863, 0x9860, 0x986D, 0x986A,
		},
	}

	if !reflect.DeepEqual(want, data) {
		test.ReportError(t, data, want)
	}
}

func TestBenes(t *testing.T) {
	rArg, err := testdata.FindTestDataByte("mceliece460896orlarger_benes_apply_benes_r_before", testPath)
	if err != nil {
		t.Fatal(err)
	}
	bitsArg, err := testdata.FindTestDataByte("mceliece460896orlarger_benes_apply_benes_bits", testPath)
	if err != nil {
		t.Fatal(err)
	}
	applyBenes((*[1024]byte)(rArg), (*[condBytes]byte)(bitsArg))
	want, err := testdata.FindTestDataByte("mceliece460896orlarger_benes_apply_benes_r_after", testPath)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(want, rArg) {
		test.ReportError(t, fmt.Sprintf("%X", rArg), fmt.Sprintf("%X", want))
	}
}
