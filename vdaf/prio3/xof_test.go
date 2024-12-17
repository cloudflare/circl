package prio3

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/cloudflare/circl/internal/sha3"
	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/vdaf/prio3/arith"
	"github.com/cloudflare/circl/vdaf/prio3/arith/fp128"
	"github.com/cloudflare/circl/vdaf/prio3/internal/prio3"
)

type VecXof struct {
	Binder         Hex  `json:"binder"`
	DerivedSeed    Hex  `json:"derived_seed"`
	Dst            Hex  `json:"dst"`
	ExpVecField128 Hex  `json:"expanded_vec_field128"`
	Seed           Hex  `json:"seed"`
	Length         uint `json:"length"`
}

func prepXof(
	t *testing.T, seed *prio3.Seed, dst, binder []byte,
) (*sha3.State, error) {
	context := dst[8:]
	usage := binary.BigEndian.Uint16(dst[6:])

	x, err := prio3.NewXof[fp128.Vec](0, context)
	test.CheckNoErr(t, err, "NewXof failed")
	copy(x.Header[2:], dst)

	err = x.Init(usage, seed)
	if err != nil {
		return nil, err
	}

	err = x.SetBinderBytes(binder)
	if err != nil {
		return nil, err
	}

	return &x.State, nil
}

func TestXof(t *testing.T) {
	v := readFile[VecXof](t, "testdata/XofTurboShake128.json")

	t.Run("DeriveSeed", func(t *testing.T) {
		r, err := prepXof(t, (*prio3.Seed)(v.Seed), v.Dst, v.Binder)
		test.CheckNoErr(t, err, "create xof failed")

		var got prio3.Seed
		_, err = r.Read(got[:])
		test.CheckNoErr(t, err, "deriving seed failed")

		want := prio3.Seed(v.DerivedSeed)
		if got != want {
			test.ReportError(t, got, want)
		}
	})

	t.Run("VecFp128/RandomSHA3", func(t *testing.T) {
		r, err := prepXof(t, (*prio3.Seed)(v.Seed), v.Dst, v.Binder)
		test.CheckNoErr(t, err, "create xof failed")

		a := arith.NewVec[fp128.Vec](v.Length)
		err = a.RandomSHA3(r)
		test.CheckNoErr(t, err, "random vector failed")

		got, err := a.MarshalBinary()
		test.CheckNoErr(t, err, "MarshalBinary failed")

		want := v.ExpVecField128
		if !bytes.Equal(got, want) {
			test.ReportError(t, got, want)
		}
	})

	t.Run("VecFp128/RandomSHA3Bytes", func(t *testing.T) {
		r, err := prepXof(t, (*prio3.Seed)(v.Seed), v.Dst, v.Binder)
		test.CheckNoErr(t, err, "create xof failed")

		a := arith.NewVec[fp128.Vec](v.Length)
		got := make([]byte, a.Size())
		err = a.RandomSHA3Bytes(got[:0], r)
		test.CheckNoErr(t, err, "random vector failed")

		want := v.ExpVecField128
		if !bytes.Equal(got, want) {
			test.ReportError(t, got, want)
		}
	})
}
