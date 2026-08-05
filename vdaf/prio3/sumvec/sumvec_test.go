package sumvec

import (
	"errors"
	"testing"

	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/vdaf/prio3/internal/flp_test"
)

func TestSumVec(t *testing.T) {
	t.Run("Query", func(t *testing.T) {
		s, err := newFlpSumVec(4, 4, 3)
		test.CheckNoErr(t, err, "new flp failed")
		flp_test.TestInvalidQuery(t, &s.FLP)
	})
}

func TestNewRejectsInvalidParameters(t *testing.T) {
	tests := []struct {
		name                string
		length, bits, chunk uint
		want                error
	}{
		{"length", 0, 1, 1, ErrLength},
		{"zero bits", 1, 0, 1, ErrBits},
		{"too many bits", 1, 65, 1, ErrBits},
		{"chunk length", 1, 1, 0, ErrChunkLength},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(2, tc.length, tc.bits, tc.chunk, []byte("test")); !errors.Is(err, tc.want) {
				t.Fatalf("got error %v, want %v", err, tc.want)
			}
		})
	}
}
