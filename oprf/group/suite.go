package group

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
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
// Should be created using NewSuite, using the appropriate string.
type Ciphersuite struct {
	// id of the ciphersuite.
	id uint16

	// name of the ciphersuite.
	name string

	// dst is a tag to be used for hashing to curve.
	dst []byte

	// hash defines the hash function to be used.
	hash hash.Hash

	// Curve defines the underlying used curve.
	Curve elliptic.Curve
}

// Identifier returns the id associated with the chosen ciphersuite.
func (c *Ciphersuite) Identifier() uint16 {
	return c.id
}

// Name returns the name associated with the chosen ciphersuite.
func (c *Ciphersuite) Name() string {
	return c.name
}

// Generator returns the canonical (fixed) generator for the defined group.
func (c *Ciphersuite) Generator() *Element {
	return &Element{c.Curve, c.Curve.Params().Gx, c.Curve.Params().Gy, true}
}

// Order returns the order of the canonical generator in the group.
func (c *Ciphersuite) Order() *Scalar {
	return &Scalar{c.Curve, c.Curve.Params().N}
}

func getH2CSuite(c *Ciphersuite) (HashToElement, error) {
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

	hasher, err := suite.Get(c.dst)
	if err != nil {
		return nil, err
	}

	return eccHasher{c, hasher}, nil
}

// HashToElement produces a new point by hashing the input message.
type HashToElement interface {
	Hash(msg []byte) (*Element, error)
}

type eccHasher struct {
	suite  *Ciphersuite
	hasher h2c.HashToPoint
}

// Hash hashes a byte array into an Element.
func (h eccHasher) Hash(in []byte) (*Element, error) {
	q := h.hasher.Hash(in)
	x := q.X().Polynomial()
	y := q.Y().Polynomial()

	p := &Element{h.suite.Curve, new(big.Int), new(big.Int), true}
	p.x.Set(x[0])
	p.y.Set(y[0])

	if !p.IsValid() {
		return nil, errors.New("invalid point")
	}

	return p, nil
}

// HashToGroup performs a transformation to encode bytes as a Element object in the
// group.
func (c *Ciphersuite) HashToGroup(in []byte) (*Element, error) {
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
func (c *Ciphersuite) RandomScalar() *Scalar {
	N := c.Order()
	bitLen := N.x.BitLen()
	byteLen := (bitLen + 7) >> 3
	buf := make([]byte, byteLen)

	// rejection sampling
	for {
		_, err := io.ReadFull(rand.Reader, buf)
		if err != nil {
			panic("scalar generation failed")
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
	return &Scalar{c.Curve, x}
}

// ScalarMultBase performs a scalar multiplication of the Generator with some scalar
// input
func (c *Ciphersuite) ScalarMultBase(s *Scalar) *Element {
	gen := c.Generator()

	return gen.ScalarMult(s)
}

// FinalizeHash computes the final hash for the suite
func FinalizeHash(c *Ciphersuite, data, iToken, info, ctx []byte) []byte {
	h := c.hash
	lenBuf := make([]byte, 2)

	binary.BigEndian.PutUint16(lenBuf, uint16(len(data)))
	_, _ = h.Write(lenBuf)
	_, _ = h.Write(data)

	binary.BigEndian.PutUint16(lenBuf, uint16(len(iToken)))
	_, _ = h.Write(lenBuf)
	_, _ = h.Write(iToken)

	binary.BigEndian.PutUint16(lenBuf, uint16(len(info)))
	_, _ = h.Write(lenBuf)
	_, _ = h.Write(info)

	dst := []byte("VOPRF05-Finalize-")
	dst = append(dst, ctx...)

	binary.BigEndian.PutUint16(lenBuf, uint16(len(dst)))
	_, _ = h.Write(lenBuf)
	_, _ = h.Write(dst)

	return h.Sum(nil)
}

// NewSuite creates a new ciphersuite for the requested name.
func NewSuite(id uint16, ctx []byte) (*Ciphersuite, error) {
	cSuite := &Ciphersuite{}
	dst := []byte("VOPRF05-")

	switch id {
	case 0x0003:
		cSuite.id = id
		cSuite.name = "OPRFP256-SHA512-ELL2-RO"
		cSuite.dst = append(dst, ctx...)
		cSuite.hash = sha256.New()
		cSuite.Curve = elliptic.P256()
	// TODO: might be good to use the circl one as well
	case 0x0004:
		cSuite.id = id
		cSuite.name = "OPRFP384-SHA512-ELL2-RO"
		cSuite.dst = append(dst, ctx...)
		cSuite.hash = sha512.New()
		cSuite.Curve = elliptic.P384()
	case 0x0005:
		cSuite.id = id
		cSuite.name = "OPRFP521-SHA512-ELL2-RO"
		cSuite.dst = append(dst, ctx...)
		cSuite.hash = sha512.New()
		cSuite.Curve = elliptic.P521()
	// TODO: support ristretto255 and decaf448
	default:
		return nil, errors.New("the chosen group is not supported")
	}

	return cSuite, nil
}
