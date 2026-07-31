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

func TestDecodeRejectsAggregateWrap(t *testing.T) {
	tests := []struct {
		name           string
		maxMeasurement uint64
		numMeas        uint
	}{
		{"field order", 1<<63 - 1, 2},
		{"uint64 overflow", 1 << 62, math.MaxUint},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := newFlpSum(tc.maxMeasurement)
			test.CheckNoErr(t, err, "new flp failed")
			result, err := s.Decode(make(Vec, 1), tc.numMeas)
			if !errors.Is(err, ErrAggregateBound) {
				t.Fatalf("got error %v, want %v", err, ErrAggregateBound)
			}
			if result != nil {
				t.Fatal("got non-nil aggregate result")
			}
		})
	}

	s, err := newFlpSum(4)
	test.CheckNoErr(t, err, "new flp failed")
	result, err := s.Decode(make(Vec, 1), 2)
	test.CheckNoErr(t, err, "safe aggregate bound rejected")
	if result == nil || *result != 0 {
		t.Fatalf("got result %v, want 0", result)
	}
}
