package tkn

import (
	"crypto/rand"
	"testing"
)

func TestShare(t *testing.T) {
	f := Formula{
		Gates: []Gate{
			{Andgate, 2, 3, 4},
			{Andgate, 0, 1, 3},
		},
	}
	k, err := randomMatrixZp(rand.Reader, 1, 17)
	if err != nil {
		t.Fatalf("error generating vector: %s", err)
	}
	res, err := f.share(rand.Reader, k)
	if err != nil {
		t.Fatalf("error sharing: %s", err)
	}
	if len(res) != 3 {
		t.Errorf("res wrong size")
	}
	acc := newMatrixZp(1, 17)
	for i := 0; i < len(res); i++ {
		acc.add(acc, res[i])
	}
	if !acc.Equal(k) {
		t.Errorf("incorrect share")
	}
}

func TestFormulaMarshal(t *testing.T) {
	f := Formula{
		Gates: []Gate{
			{Andgate, 0, 1, 3},
			{Andgate, 2, 3, 4},
		},
	}
	data, err := f.MarshalBinary()
	if err != nil {
		t.Fatalf("error marshalling: %s", err)
	}
	g := &Formula{}
	err = g.UnmarshalBinary(data)
	if err != nil {
		t.Fatalf("error unmarshalling: %s", err)
	}
	if !f.Equal(*g) {
		t.Fatal("failure to recover formula")
	}
}
