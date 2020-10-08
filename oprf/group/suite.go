package group

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"hash"
	"io"
	"math/big"

	"github.com/armfazh/h2c-go-ref"
)

// Ciphersuite corresponds to the OPRF ciphersuite that is chosen. The
// Ciphersuite object determines the prime-order group (pog) that is used for
// performing the OPRF operations, along with the different hash function
// definitions.
// Should be created using NewSuite, using an string.
type Ciphersuite struct {
	// name of the ciphersuite.
	name string

	// dst string used for hashing to curve.
	dst string

	// hash defines the hash function to be used.
	Hash hash.Hash

	curve elliptic.Curve
}

// Suite is an interface that defines operations within additive
// groups of prime order. This is the setting in which the OPRF operations
// take place.
type Suite interface {
	// Returns the identifying name of the group
	Name() string

	// Returns the canonical (fixed) generator for defined group
	Generator() *Point

	// Returns the order of the canonical generator in the group.
	Order() *Scalar

	// Performs a transformation to encode bytes as a Element object in the
	// group.
	HashToGroup([]byte) (*Point, error)

	// Performs a transformation to encode bytes as a Scalar object in the
	// appropriate group.
	// TODO: should we keep it? Seems only be used on the Verified case..
	HashToScalar([]byte) (Scalar, error)

	// Samples a random scalar value from the field of scalars defined by the
	// group order.
	RandomScalar() (*Scalar, error)

	// Performs a scalar multiplication of the Generator with some scalar
	// input
	ScalarMultBase(*Scalar) *Point

	// Returns the ByteLength of objects associated with the Ciphersuite
	ByteLength() int
}

// Name returns the name associated with the chosen ciphersuite.
func (c *Ciphersuite) Name() string {
	return c.name
}

// Generator returns the canonical (fixed) generator for the defined group.
func (c *Ciphersuite) Generator() *Point {
	return &Point{c, c.curve.Params().Gx, c.curve.Params().Gy}
}

// Order returns the order of the canonical generator in the group.
func (c *Ciphersuite) Order() *Scalar {
	return &Scalar{c, c.curve.Params().N}
}

func getH2CSuite(c *Ciphersuite) (HashToPoint, error) {
	var suite h2c.SuiteID

	switch c.Name() {
	case "OPRFP256-SHA512-ELL2-RO":
		suite = h2c.P256_XMDSHA256_SSWU_RO_
	case "OPRFP384-SHA512-ELL2-RO":
		suite = h2c.P384_XMDSHA512_SSWU_RO_
	case "OPRFP521-SHA512-ELL2-RO":
		suite = h2c.P521_XMDSHA512_SSWU_RO_
	default:
		return nil, errors.New("invalid suite")
	}

	hasher, err := suite.Get([]byte(c.dst))
	if err != nil {
		return nil, err
	}

	return eccHasher{c, hasher}, nil
}

// HashToPoint produces a new point by hashing the input message.
type HashToPoint interface {
	Hash(msg []byte) (*Point, error)
}

type eccHasher struct {
	suite  *Ciphersuite
	hasher h2c.HashToPoint
}

func (h eccHasher) Hash(in []byte) (*Point, error) {
	q := h.hasher.Hash(in)
	x := q.X().Polynomial()
	y := q.Y().Polynomial()

	p := &Point{h.suite, new(big.Int), new(big.Int)}
	p.x.Set(x[0])
	p.y.Set(y[0])

	// TODO: failing here
	if !p.IsValid() {
		return nil, errors.New("invalid point")
	}

	return p, nil
}

// HashToGroup performs a transformation to encode bytes as a Element object in the
// group.
func (c *Ciphersuite) HashToGroup(in []byte) (*Point, error) {
	hasher, err := getH2CSuite(c)
	if err != nil {
		return nil, err
	}

	p, err := hasher.Hash(in)
	if err != nil {
		return nil, err
	}

	return p, nil
}

// HashToScalar performs a transformation to encode bytes as a Scalar object in the
// appropriate group.
func (c *Ciphersuite) HashToScalar([]byte) (*Scalar, error) {
	return &Scalar{}, nil
}

// RandomScalar samples a random scalar value from the field of scalars defined by the
// group order.
// TODO: not constant time
func (c *Ciphersuite) RandomScalar() (*Scalar, error) {
	N := c.Order()
	bitLen := N.x.BitLen()
	byteLen := (bitLen + 7) >> 3
	buf := make([]byte, byteLen)

	// rejection sampling
	for {
		_, err := io.ReadFull(rand.Reader, buf)
		if err != nil {
			return nil, errors.New("scalar generation failed")
		}
		// Mask to account for field sizes that are not a whole number of bytes.
		var mask = []byte{0xff, 0x1, 0x3, 0x7, 0xf, 0x1f, 0x3f, 0x7f}
		buf[0] = buf[0] & mask[bitLen%8]

		// Check if scalar is in the correct range.
		if new(big.Int).SetBytes(buf).Cmp(N.x) >= 0 {
			continue
		}
		break
	}

	x := new(big.Int).SetBytes(buf)
	return &Scalar{c, x}, nil
}

// ScalarMultBase performs a scalar multiplication of the Generator with some scalar
// input
func (c *Ciphersuite) ScalarMultBase(s *Scalar) *Point {
	gen := c.Generator()

	return gen.ScalarMult(s)
}

// ByteLength returns the ByteLength of objects associated with the Ciphersuite.
func (c *Ciphersuite) ByteLength() int {
	return (c.curve.Params().BitSize + 7) / 8
}

// NewSuite creates a new ciphersuite for the requested name.
func NewSuite(name string) (*Ciphersuite, error) {
	cSuite := &Ciphersuite{}

	switch name {
	case "P-256":
		cSuite.name = "OPRFP256-SHA512-ELL2-RO"
		cSuite.dst = "RFCXXXX-P256_XMD:SHA-512_SSWU_RO_"
		cSuite.Hash = sha512.New() // TODO: maybe it is too early to init it as the compiler might release it in a weird way..
		cSuite.curve = elliptic.P256()
	// TODO: might be good to use the circl one as well
	case "P-384":
		cSuite.name = "OPRFP384-SHA512-ELL2-RO"
		cSuite.dst = "RFCXXXX-P384_XMD:SHA-512_SSWU_RO_"
		cSuite.Hash = sha512.New()
		cSuite.curve = elliptic.P384()
	case "P-521":
		cSuite.name = "OPRFP521-SHA512-ELL2-RO"
		cSuite.dst = "RFCXXXX-P521_XMD:SHA-512_SSWU_RO_"
		cSuite.Hash = sha512.New()
		cSuite.curve = elliptic.P521()
	// TODO: what other libraries should be used?
	default:
		return nil, errors.New("the chosen group is not supported")
	}

	return cSuite, nil
}
