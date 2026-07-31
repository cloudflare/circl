package histogram

import (
	"errors"
	"testing"

	"github.com/cloudflare/circl/vdaf/prio3/internal/flp_test"
)

func TestHistogram(t *testing.T) {
	t.Run("Query", func(t *testing.T) {
		h := newFlpHistogram(4, 3)
		flp_test.TestInvalidQuery(t, &h.FLP)
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
