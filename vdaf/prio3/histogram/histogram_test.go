package histogram

import (
	"errors"
	"testing"

	"github.com/cloudflare/circl/vdaf/prio3/internal/flp"
	"github.com/cloudflare/circl/vdaf/prio3/internal/flp_test"
)

func TestHistogram(t *testing.T) {
	t.Run("Query", func(t *testing.T) {
		h := newFlpHistogram(4, 3)
		flp_test.TestInvalidQuery(t, &h.FLP)
	})

	// A measurement must be a bucket index in [0, length). Encoding one equal
	// to length used to index one past the end of the output vector, panicking
	// instead of reporting an error.
	t.Run("EncodeOutOfRange", func(t *testing.T) {
		const length, chunkLen = 4, 3
		h := newFlpHistogram(length, chunkLen)

		for _, measurement := range []uint64{length, length + 1, ^uint64(0)} {
			out, err := h.Encode(measurement)
			if !errors.Is(err, flp.ErrMeasurementValue) {
				t.Errorf("Encode(%v): got err %v, want %v",
					measurement, err, flp.ErrMeasurementValue)
			}
			if out != nil {
				t.Errorf("Encode(%v): got non-nil output", measurement)
			}
		}

		for measurement := uint64(0); measurement < length; measurement++ {
			out, err := h.Encode(measurement)
			if err != nil {
				t.Fatalf("Encode(%v): unexpected error: %v", measurement, err)
			}
			if len(out) != length {
				t.Fatalf("Encode(%v): got length %v, want %v",
					measurement, len(out), length)
			}
			for i := range out {
				want := uint64(0)
				if uint64(i) == measurement {
					want = 1
				}
				got, err := out[i].GetUint64()
				if err != nil {
					t.Fatal(err)
				}
				if got != want {
					t.Errorf("Encode(%v)[%v] = %v, want %v",
						measurement, i, got, want)
				}
			}
		}
	})
}

func TestNewRejectsZeroParameters(t *testing.T) {
	tests := []struct {
		name     string
		length   uint
		chunkLen uint
		want     error
	}{
		{"length", 0, 1, ErrLength},
		{"chunk length", 1, 0, ErrChunkLength},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(2, tc.length, tc.chunkLen, []byte("test")); !errors.Is(err, tc.want) {
				t.Fatalf("got error %v, want %v", err, tc.want)
			}
		})
	}
}
