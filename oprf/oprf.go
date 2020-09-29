package oprf

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/oprf/group"
)

const (
	// OPRFCurve25519 is the constant to represent the OPRF curve25519 with SHA-512 (ELL2-RO) group.
	OPRFCurve25519 uint16 = 0x0001
	// OPRFCurve448 is the constant to represent the OPRF curve448 with SHA-512 (ELL2-RO) group.
	OPRFCurve448 uint16 = 0x0002
	// OPRFP256 is the constant to represent the OPRF P-256 with SHA-512 (SSWU-RO) group.
	OPRFP256 uint16 = 0x0003
	// OPRFP384 is the constant to represent the OPRF P-384 with SHA-512 (SSWU-RO) group.
	OPRFP384 uint16 = 0x0004
	// OPRFP521 is the constant to represent the OPRF P-521 with SHA-512 (SSWU-RO) group.
	OPRFP521 uint16 = 0x0005
)

const (
	// OPRFMode is the context string to define a OPRF.
	OPRFMode string = "000"
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

// PublicKey is a struct representing a public key.
type PublicKey *group.Point

// PrivateKey is a struct representing a private key.
type PrivateKey *group.Scalar

// KeyPair is an struct containing a public and private key.
type KeyPair struct {
	PubK  PublicKey
	PrivK PrivateKey
}

// Client is a representation of a Client during protocol execution.
type Client struct {
	suite *group.Ciphersuite
	ctx   string
}

// ClientContext implements the functionality of a Client.
type ClientContext interface {
	// Blind generates a token and blinded data.
	Blind(in []byte) (*Token, *BlindToken, error)

	// Unblind unblinds the server response.
	Unblind(t *Token, e *Evaluation) (IssuedToken, error)

	// Finalize outputs a byte array that corresponds to its input.
	Finalize(t *Token, issuedT IssuedToken, info []byte) []byte
}

// Server is a representation of a Server during protocol execution.
type Server struct {
	suite *group.Ciphersuite
	ctx   string
	K     *KeyPair
}

// ServerContext implements the functionality of a Server.
// TODO: add FullEvaluate
type ServerContext interface {
	// Evaluate evaluates the token.
	Evaluate(b BlindToken) (*Evaluation, error)
}

func generateCtx(suiteID uint16) string {
	ctx := OPRFMode + fmt.Sprintf("%x", suiteID)

	return ctx
}

func generateKeys(suite *group.Ciphersuite) (*KeyPair, error) {
	privK, err := suite.RandomScalar()
	if err != nil {
		return nil, err
	}

	pubK, err := suite.ScalarMultBase(privK)
	if err != nil {
		return nil, err
	}

	return &KeyPair{pubK, privK}, nil
}

func suiteFromID(suiteID uint16) (*group.Ciphersuite, error) {
	var err error
	var suite *group.Ciphersuite

	// TODO: add other suites
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

	keyPair, err := generateKeys(suite)
	if err != nil {
		return nil, err
	}

	server := &Server{}
	server.suite = suite
	server.ctx = ctx
	server.K = keyPair

	return server, nil
}

// Evaluate creates an evaluation of the blided token.
func (s *Server) Evaluate(b BlindToken) (*Evaluation, error) {
	p := group.NewPoint(s.suite)
	err := p.Deserialize(b)
	if err != nil {
		return nil, err
	}

	z, err := p.ScalarMult(s.K.PrivK)
	if err != nil {
		return nil, err
	}

	ser, err := z.Serialize()
	if err != nil {
		return nil, err
	}

	eval := &Evaluation{ser}
	return eval, nil
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

	return client, nil
}

// Blind generates a token and blinded data.
func (c *Client) Blind(in []byte) (*Token, BlindToken, error) {
	r, err := c.suite.RandomScalar()
	if err != nil {
		return nil, nil, errors.New("failed at blinding")
	}

	p, err := c.suite.HashToGroup(in)
	if err != nil {
		return nil, nil, errors.New("failed at blinding")
	}

	t, err := p.ScalarMult(r)
	if err != nil {
		return nil, nil, err
	}

	bToken, err := t.Serialize()
	if err != nil {
		return nil, nil, err
	}

	token := &Token{in, r}
	return token, bToken, nil
}

// Unblind unblinds the server response.
func (c *Client) Unblind(t *Token, e *Evaluation) (IssuedToken, error) {
	p := group.NewPoint(c.suite)
	err := p.Deserialize(e.element)
	if err != nil {
		return nil, err
	}

	r := t.blind
	rInv := r.Inv()

	tt, err := p.ScalarMult(rInv)
	if err != nil {
		return nil, err
	}

	iToken, err := tt.Serialize()
	if err != nil {
		return nil, err
	}

	return IssuedToken(iToken), nil
}

// Finalize outputs a byte array that corresponds to the client input.
func (c *Client) Finalize(t *Token, issuedT IssuedToken, info []byte) []byte {
	h := c.suite.Hash

	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(t.data)))
	h.Write(lenBuf) //nolint:errcheck
	h.Write(t.data) //nolint:errcheck

	binary.BigEndian.PutUint16(lenBuf, uint16(len(issuedT)))
	h.Write(lenBuf)  //nolint:errcheck
	h.Write(issuedT) //nolint:errcheck

	binary.BigEndian.PutUint16(lenBuf, uint16(len(info)))
	h.Write(lenBuf) //nolint:errcheck
	h.Write(info)   //nolint:errcheck

	dst := []byte("RFCXXXX-Finalize")
	dst = append(dst, c.ctx...)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(dst)))
	h.Write(lenBuf) //nolint:errcheck
	h.Write(dst)    //nolint:errcheck

	return h.Sum(nil)
}
