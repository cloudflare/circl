package sum

import (
	"errors"
	"math"
	"testing"

	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/vdaf/prio3/internal/flp"
	"github.com/cloudflare/circl/vdaf/prio3/internal/flp_test"
)

func TestSum(t *testing.T) {
	t.Run("Query", func(t *testing.T) {
		const MaxMeas = 4
		s, err := newFlpSum(MaxMeas)
		test.CheckNoErr(t, err, "new flp failed")
		flp_test.TestInvalidQuery(t, &s.FLP)
	})
}

func TestMaxMeasurement(t *testing.T) {
	if _, err := newFlpSum(1<<63 - 1); err != nil {
		t.Fatalf("safe maximum rejected: %v", err)
	}

	for _, maxMeasurement := range []uint64{1 << 63, math.MaxUint64} {
		if _, err := newFlpSum(maxMeasurement); !errors.Is(err, ErrMaxMeasurement) {
			t.Fatalf("newFlpSum(%d): got error %v, want %v",
				maxMeasurement, err, ErrMaxMeasurement)
		}
	}
}

func TestEncodeRejectsOutOfRangeMeasurement(t *testing.T) {
	const maxMeasurement = 4
	s, err := newFlpSum(maxMeasurement)
	test.CheckNoErr(t, err, "new flp failed")

	if _, err = s.Encode(maxMeasurement); err != nil {
		t.Fatalf("maximum measurement rejected: %v", err)
	}
	if _, err = s.Encode(maxMeasurement + 1); !errors.Is(err, flp.ErrMeasurementValue) {
		t.Fatalf("got error %v, want %v", err, flp.ErrMeasurementValue)
	}
}
