//go:generate go run gen.go

// Package arith provides arithmetic operations over prime fields, vectors,
// and polynomials.
package arith

import (
	"encoding"
	"io"

	"github.com/cloudflare/circl/internal/conv"
	"github.com/cloudflare/circl/internal/sha3"
	"golang.org/x/crypto/cryptobyte"
)

// Elt is any type that stores a prime field element.
type Elt any

// Fp lists the functionality that a prime field element must have denoting
// methods with a pointer receiver.
type Fp[E Elt] interface {
	*E
	// Size returns the number of bytes to encode a field element.
	Size() uint
	// Returns true if the element is the neutral additive element.
	IsZero() bool
	// Returns true if the element is the neutral multiplicative element.
	IsOne() bool
	// Returns true if the element is equivalent to x.
	IsEqual(x *E) bool
	// Set the element to the neutral additive element.
	SetOne()
	// Set the element to x if x < Order().
	SetUint64(uint64) error
	// Returns the integer representative of the element if x < 2^64.
	GetUint64() (x uint64, err error)
	// Set the element to the principal root of unity of order 2^n.
	SetRootOfUnityTwoN(n uint)
	// AddAssing calculates z = z + x.
	AddAssign(x *E)
	// SubAssign calculates z = z - x.
	SubAssign(x *E)
	// MulAssign calculates z = z * x.
	MulAssign(x *E)
	// Add calculates z = x + y.
	Add(x, y *E)
	// Sub calculates z = x - y.
	Sub(x, y *E)
	// Mul calculates z = x * y.
	Mul(x, y *E)
	// Sqr calculates z = x * x.
	Sqr(x *E)
	// Inv calculates z = 1 / x.
	Inv(x *E)
	// InvUint64 calculates z = 1 / x.
	InvUint64(x uint64)
	// InvTwoN calculates z = 1 / 2^n.
	InvTwoN(x uint)
	// Random samples an element from an io.Reader.
	Random(io.Reader) error
	// RandomSHA3 samples an element from a SHA3 state.
	RandomSHA3(*sha3.State) error
	// Encodes an element to bytes.
	encoding.BinaryMarshaler
	// Decodes an element from bytes.
	encoding.BinaryUnmarshaler
	// Encodes an element using a cryptobyte.Builder.
	cryptobyte.MarshalingValue
	// Decodes an element from a cryptobyte.String.
	conv.UnmarshalingValue
}

// NewVec returns a vector of length n.
func NewVec[V Vec[V, E], E Elt](n uint) V { return make(V, n) }

// Vec list the funtionality of a vector of field elements.
type Vec[Vec ~[]E, E Elt] interface {
	~[]E
	// Size returns the number of bytes to encode a vector.
	Size() uint
	// AddAssing calculates z = z + x.
	AddAssign(x Vec)
	// SubAssign calculates z = z - x.
	SubAssign(x Vec)
	// ScalarMul calculates z[i] = z[i] * x.
	ScalarMul(x *E)
	// DotProduct calculates z[i] = z[i] * x[i].
	DotProduct(x Vec) E
	// NTT calculates the number theoretic transform on values.
	NTT(Vec)
	// InvNTT calculates the inverse number theoretic transform on values.
	InvNTT(Vec)
	// SplitBits sets the vector of elements corresponding to the bits of n.
	SplitBits(n uint64) error
	// JoinBits calculates the element sum( 2^i * z[i] ).
	JoinBits() E
	// Random samples a vector from an io.Reader.
	Random(io.Reader) error
	// RandomSHA3 samples a vector from a SHA3 state.
	RandomSHA3(*sha3.State) error
	// RandomSHA3Bytes reads a vector from a SHA3 state copying the bytes read.
	RandomSHA3Bytes([]byte, *sha3.State) error
	// Encodes a vector to bytes.
	encoding.BinaryMarshaler
	// Decodes a vector from bytes.
	encoding.BinaryUnmarshaler
	// Encodes a vector using a cryptobyte.Builder.
	cryptobyte.MarshalingValue
	// Decodes a vector from a cryptobyte.String.
	conv.UnmarshalingValue
}

// NewPoly returns a polynomial of the given degree.
func NewPoly[P Poly[P, E], E Elt](degree uint) P { return make(P, degree+1) }

// Poly lists the funtionality of polynomials with coefficients in a field.
type Poly[Poly ~[]E, E Elt] interface {
	~[]E
	// AddAssing calculates z = z + x.
	AddAssign(Poly)
	// SubAssign calculates z = z - x.
	SubAssign(Poly)
	// Mul calculates z = x * y.
	Mul(x, y Poly)
	// Sqr calculates z = x * x.
	Sqr(Poly)
	// Evaluate calculates the polynomial evaluation p(x).
	Evaluate(x *E) E
	// Strip removes the higher-degree zero terms.
	Strip() Poly
	// Interpolate a polynomial on given the values.
	Interpolate([]E)
}
