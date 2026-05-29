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

// TestShareAndGateNoSingleLeafReconstructs is a regression test for the
// AND-share bug in (*Formula).share. For an AND gate the two child shares must
// sum to the parent share, but NEITHER child alone may equal the parent share,
// and neither child may be the all-zero share (a zero share would leave its
// sibling carrying the entire secret). Before the fix, In0 received the whole
// parent share and In1 received zero, which let a single AND leaf reconstruct
// the shared KEM secret.
func TestShareAndGateNoSingleLeafReconstructs(t *testing.T) {
	f := Formula{
		Gates: []Gate{
			{Andgate, 0, 1, 2},
		},
	}
	k, err := randomMatrixZp(rand.Reader, 2, 1)
	if err != nil {
		t.Fatalf("error generating vector: %s", err)
	}
	shares, err := f.share(rand.Reader, k)
	if err != nil {
		t.Fatalf("error sharing: %s", err)
	}
	if len(shares) != 2 {
		t.Fatalf("expected 2 input shares, got %d", len(shares))
	}

	// The shares must reconstruct the secret when combined.
	acc := newMatrixZp(2, 1)
	acc.add(shares[0], shares[1])
	if !acc.Equal(k) {
		t.Fatalf("AND shares do not reconstruct the secret")
	}

	zero := newMatrixZp(2, 1)
	for i, s := range shares {
		if s.Equal(k) {
			t.Fatalf("AND leaf %d alone reconstructs the secret (AND-share bug present)", i)
		}
		if s.Equal(zero) {
			t.Fatalf("AND leaf %d is the all-zero share (AND-share bug present)", i)
		}
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
