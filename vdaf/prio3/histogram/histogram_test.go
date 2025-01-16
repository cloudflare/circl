package histogram

import (
	"testing"

	"github.com/cloudflare/circl/vdaf/prio3/internal/flp_test"
)

func TestHistogram(t *testing.T) {
	t.Run("Query", func(t *testing.T) {
		h := newFlpHistogram(4, 3)
		flp_test.TestInvalidQuery(t, &h.FLP)
	})
}
