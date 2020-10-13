package oprf

import (
	"crypto/subtle"
	"errors"
	"math/big"

	"github.com/cloudflare/circl/oprf/group"
)

const (
	// OPRFP256 is the constant to represent the OPRF P-256 with SHA-512 (SSWU-RO) group.
	OPRFP256 uint16 = 0x0003
	// OPRFP384 is the constant to represent the OPRF P-384 with SHA-512 (SSWU-RO) group.
	OPRFP384 uint16 = 0x0004
	// OPRFP521 is the constant to represent the OPRF P-521 with SHA-512 (SSWU-RO) group.
	OPRFP521 uint16 = 0x0005
)

var (
	// OPRFMode is the context string to define a OPRF.
	OPRFMode *big.Int = big.NewInt(0)
)

var (
	// ErrUnsupportedGroup is an error stating that the ciphersuite chosen is not supported
	ErrUnsupportedGroup = errors.New("the chosen group is not supported")
)

// BlindToken corresponds to a token that has been blinded.
// Internally, it is a serialized Element.
type BlindToken []byte

// IssuedToken corresponds to a token that has been issued.
// Internally, it is a serialized Element.
type IssuedToken []byte

// Token is the object issuance of the protocol.
type Token struct {
	data  []byte
	blind *group.Scalar
}

// Evaluation corresponds to the evaluation over a token.
type Evaluation struct {
	element []byte
}

// KeyPair is an struct containing a public and private key.
type KeyPair struct {
	PubK  *group.Element
	PrivK *group.Scalar
}

// Client is a representation of a Client during protocol execution.
type Client struct {
	suite *group.Ciphersuite
	ctx   []byte
}

// ClientContext implements the functionality of a Client.
type ClientContext interface {
	// Request generates a token and blinded data.
	Request(in []byte) (*Token, *BlindToken, error)

	// Finalize unblinds the server response and outputs a byte array that corresponds to its input.
	Finalize(t *Token, e *Evaluation, info []byte) (IssuedToken, []byte, error)
}

// Server is a representation of a Server during protocol execution.
type Server struct {
	suite *group.Ciphersuite
	ctx   []byte
	Keys  *KeyPair
}

// ServerContext implements the functionality of a Server.
type ServerContext interface {
	// Evaluate evaluates the token.
	Evaluate(b BlindToken) (*Evaluation, error)
}

// i2OSP converts a nonnegative integer to an octet string of a
// specified length.
func i2OSP(b *big.Int, n int) []byte {
	var (
		octetString     = b.Bytes()
		octetStringSize = len(octetString)
		result          = make([]byte, n)
	)
	if !(b.Sign() == 0 || b.Sign() == 1) {
		panic("I2OSP error: integer must be zero or positive")
	}
	if n == 0 || octetStringSize > n {
		panic("I2OSP error: integer too large")
	}

	subtle.ConstantTimeCopy(1, result[:n-octetStringSize], result[:n-octetStringSize])
	subtle.ConstantTimeCopy(1, result[n-octetStringSize:], octetString)
	return result
}

func generateCtx(suiteID uint16) []byte {
	mode := i2OSP(OPRFMode, 1)
	tmp := big.NewInt(int64(byte(suiteID)))
	id := i2OSP(tmp, 2)

	var ctx []byte
	ctx = append(ctx, mode...)
	ctx = append(ctx, id...)
	return ctx
}

func generateKeyPair(suite *group.Ciphersuite) *KeyPair {
	privK := suite.RandomScalar()
	pubK := suite.ScalarMultBase(privK)

	return &KeyPair{pubK, privK}
}

func suiteFromID(suiteID uint16) (*group.Ciphersuite, error) {
	var err error
	var suite *group.Ciphersuite

	switch suiteID {
	case OPRFP256:
		suite, err = group.NewSuite("P-256")
	case OPRFP384:
		suite, err = group.NewSuite("P-384")
	case OPRFP521:
		suite, err = group.NewSuite("P-521")
	default:
		return suite, ErrUnsupportedGroup
	}
	if err != nil {
		return nil, err
	}

	return suite, nil
}

// NewServer creates a new instantiation of a Server.
func NewServer(suiteID uint16) (*Server, error) {
	suite, err := suiteFromID(suiteID)
	if err != nil {
		return nil, err
	}

	ctx := generateCtx(suiteID)

	keyPair := generateKeyPair(suite)

	server := &Server{}
	server.suite = suite
	server.ctx = ctx
	server.Keys = keyPair

	return server, nil
}

// Evaluate creates an evaluation of the blided token.
func (s *Server) Evaluate(b BlindToken) (*Evaluation, error) {
	p := group.NewElement(s.suite)
	err := p.Deserialize(b)
	if err != nil {
		return nil, err
	}

	z := p.ScalarMult(s.Keys.PrivK)

	ser := z.Serialize()

	return &Evaluation{ser}, nil
}

// NewClient creates a new instantiation of a Client.
func NewClient(suiteID uint16) (*Client, error) {
	suite, err := suiteFromID(suiteID)
	if err != nil {
		return nil, err
	}

	ctx := generateCtx(suiteID)

	client := &Client{}
	client.suite = suite
	client.ctx = ctx

	return &Client{
		suite: suite,
		ctx:   ctx,
	}, nil
}

// Blind generates a token and blinded data.
func (c *Client) Blind(in []byte) (*Token, BlindToken, error) {
	r := c.suite.RandomScalar()

	p, err := c.suite.HashToGroup(in)
	if err != nil {
		return nil, nil, err
	}

	t := p.ScalarMult(r)

	bToken := t.Serialize()

	token := &Token{in, r}
	return token, bToken, nil
}

// Finalize unblinds the server response and outputs a byte array that corresponds to the client input.
func (c *Client) Finalize(t *Token, e *Evaluation, info []byte) (IssuedToken, []byte, error) {
	p := group.NewElement(c.suite)
	err := p.Deserialize(e.element)
	if err != nil {
		return nil, []byte{}, err
	}

	r := t.blind
	rInv := r.Inv()

	tt := p.ScalarMult(rInv)
	iToken := tt.Serialize()

	h := group.FinalizeHash(c.suite, t.data, iToken, info, c.ctx)

	return iToken, h, nil
}
