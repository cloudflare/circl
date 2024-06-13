package internal

import (
	"math/rand"
	"sort"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

type (
	foo []int32
	bar []uint64
)

//nolint:gosec
func TestSortInt32(t *testing.T) {
	arr := make(foo, 314)
	for i := 0; i < len(arr); i++ {
		arr[i] = rand.Int31()
	}

	int32Sort(arr, int32(len(arr)))
	if !sort.IsSorted(arr) {
		want := make(foo, len(arr))
		copy(want, arr)
		sort.Sort(want)
		test.ReportError(t, arr, want)
	}
}

//nolint:gosec
func TestSortUInt64(t *testing.T) {
	arr := make(bar, 314)
	for i := 0; i < len(arr); i++ {
		arr[i] = rand.Uint64()
	}

	UInt64Sort(arr, len(arr))
	if !sort.IsSorted(arr) {
		want := make(bar, len(arr))
		copy(want, arr)
		sort.Sort(want)
		test.ReportError(t, arr, want)
	}
}

func (f foo) Len() int {
	return len(f)
}

func (f foo) Less(i, j int) bool {
	return f[i] < f[j]
}

func (f foo) Swap(i, j int) {
	f[i], f[j] = f[j], f[i]
}

func (f bar) Len() int {
	return len(f)
}

func (f bar) Less(i, j int) bool {
	return f[i] < f[j]
}

func (f bar) Swap(i, j int) {
	f[i], f[j] = f[j], f[i]
}
