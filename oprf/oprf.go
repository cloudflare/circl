// Package oprf provides an Oblivious Pseudo-Random Function protocol.
//
// An Oblivious Pseudorandom Function (OPRFs) is a two-party protocol for
// computing the output of a PRF. One party (the server) holds the PRF secret
// key, and the other (the client) holds the PRF input.
//
// The 'obliviousness' property ensures that the server does not learn anything
// about the client's input during the evaluation.
//
// OPRF is defined on draft-irtf-cfrg-voprf: https://datatracker.ietf.org/doc/draft-irtf-cfrg-voprf
//
// Client implements:
//   - Blind
//   - Unblind
//   - Finalize
//
// Server implements:
//   - Setup
//   - Evaluate
//   - VerifyFinalize
package oprf

import (
	"crypto"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"

	"github.com/cloudflare/circl/group"
)

const version = "VOPRF05-"

// SuiteID is a type that represents the ID of a Suite.
type SuiteID uint16

const (
	// OPRFP256 is the constant to represent the OPRF P-256 with SHA-256 (SSWU-RO) group.
	OPRFP256 SuiteID = 0x0003
	// OPRFP384 is the constant to represent the OPRF P-384 with SHA-512 (SSWU-RO) group.
	OPRFP384 SuiteID = 0x0004
	// OPRFP521 is the constant to represent the OPRF P-521 with SHA-512 (SSWU-RO) group.
	OPRFP521 SuiteID = 0x0005
)

// OPRFMode is the context string to define a OPRF.
const OPRFMode byte = 0x00

// ErrUnsupportedSuite is an error stating that the suite chosen is not supported
var ErrUnsupportedSuite = errors.New("unsupported suite")

// BlindToken corresponds to a token that has been blinded.
// Internally, it is a serialized Element.
type BlindToken []byte

// IssuedToken corresponds to a token that has been issued.
// Internally, it is a serialized Element.
type IssuedToken []byte

// Token is the object issuance of the protocol.
type Token struct {
	data  []byte
	blind group.Scalar
}

// Evaluation corresponds to the evaluation over a token.
type Evaluation struct {
	Element []byte
}

// KeyPair is an struct containing a public and private key.
type KeyPair struct {
	publicKey  group.Element
	privateKey group.Scalar
}

// Client is a representation of a Client during protocol execution.
type Client struct {
	suite   *suite
	context []byte
}

// Server is a representation of a Server during protocol execution.
type Server struct {
	suite   *suite
	context []byte
	Kp      KeyPair
}

type suite struct {
	group.Group
	crypto.Hash
}

func (id SuiteID) String() string {
	switch id {
	case OPRFP256:
		return "OPRFP256"
	case OPRFP384:
		return "OPRFP384"
	case OPRFP521:
		return "OPRFP521"
	default:
		panic(ErrUnsupportedSuite)
	}
}

// Serialize serializes a KeyPair elements into byte arrays.
func (kp *KeyPair) Serialize() []byte {
	data, err := kp.privateKey.MarshalBinary()
	if err != nil {
		panic("error on serializing")
	}
	return data
}

// Deserialize deserializes a KeyPair into an element and field element of the group.
func (kp *KeyPair) Deserialize(s *suite, encoded []byte) error {
	privateKey := s.NewScl()
	err := privateKey.UnmarshalBinary(encoded)
	if err != nil {
		return err
	}
	publicKey := s.NewElt()
	publicKey.MulGen(privateKey)

	kp.publicKey = publicKey
	kp.privateKey = privateKey

	return nil
}

func generateContext(id SuiteID) (ctx [3]byte) {
	ctx[0] = OPRFMode
	ctx[1] = 0
	ctx[2] = byte(id)
	return
}

// GenerateKeyPair generates a KeyPair in accordance with the group.
func GenerateKeyPair(s *suite) KeyPair {
	r := s.Random()
	privateKey := r.RndScl(rand.Reader)
	publicKey := s.NewElt()
	publicKey.MulGen(privateKey)

	return KeyPair{publicKey, privateKey}
}

func suiteFromID(id SuiteID) (*suite, error) {
	switch id {
	case OPRFP256:
		return &suite{group.P256, crypto.SHA256}, nil
	case OPRFP384:
		return &suite{group.P384, crypto.SHA512}, nil
	case OPRFP521:
		return &suite{group.P521, crypto.SHA512}, nil
	default:
		return nil, ErrUnsupportedSuite
	}
}

// NewServer creates a new instantiation of a Server.
func NewServer(id SuiteID) (*Server, error) {
	suite, err := suiteFromID(id)
	if err != nil {
		return nil, err
	}
	context := generateContext(id)
	keyPair := GenerateKeyPair(suite)

	return &Server{
		suite:   suite,
		context: context[:],
		Kp:      keyPair,
	}, nil
}

// NewServerWithKeyPair creates a new instantiation of a Server. It can create
// a server with existing keys or use pre-generated keys.
func NewServerWithKeyPair(id SuiteID, kp KeyPair) (*Server, error) {
	suite, err := suiteFromID(id)
	if err != nil {
		return nil, err
	}
	context := generateContext(id)

	return &Server{
		suite:   suite,
		context: context[:],
		Kp:      kp,
	}, nil
}

// Evaluate blindly signs a client token.
func (s *Server) Evaluate(b BlindToken) (*Evaluation, error) {
	p := s.suite.NewElt()
	err := p.UnmarshalBinary(b)
	if err != nil {
		return nil, err
	}

	z := s.suite.NewElt()
	z.Mul(p, s.Kp.privateKey)
	ser, err := z.MarshalBinaryCompress()
	if err != nil {
		return nil, err
	}

	return &Evaluation{ser}, nil
}

func mustWrite(h io.Writer, data []byte) {
	dataLen, err := h.Write(data)
	if err != nil {
		panic(err)
	}
	if len(data) != dataLen {
		panic("failed to write")
	}
}

// FinalizeHash computes the final hash for the suite.
func finalizeHash(s *suite, data, iToken, info, context []byte) []byte {
	h := s.New()

	lenBuf := make([]byte, 2)

	binary.BigEndian.PutUint16(lenBuf, uint16(len(data)))
	mustWrite(h, lenBuf)
	mustWrite(h, data)

	binary.BigEndian.PutUint16(lenBuf, uint16(len(iToken)))
	mustWrite(h, lenBuf)
	mustWrite(h, iToken)

	binary.BigEndian.PutUint16(lenBuf, uint16(len(info)))
	mustWrite(h, lenBuf)
	mustWrite(h, info)

	dst := append(append([]byte{}, []byte(version)...), []byte("Finalize-")...)
	dst = append(dst, context...)

	binary.BigEndian.PutUint16(lenBuf, uint16(len(dst)))
	mustWrite(h, lenBuf)
	mustWrite(h, dst)

	return h.Sum(nil)
}

// FullEvaluate performs a full evaluation at the server side.
func (s *Server) FullEvaluate(in, info []byte) ([]byte, error) {
	dst := append(append([]byte{}, []byte(version)...), s.context...)
	h2c := s.suite.Group.Hashes(dst)
	p := h2c.Hash(in)

	t := s.suite.Group.NewElt()
	t.Mul(p, s.Kp.privateKey)
	iToken, err := t.MarshalBinaryCompress()
	if err != nil {
		return nil, err
	}

	h := finalizeHash(s.suite, in, iToken, info, s.context)

	return h, nil
}

// VerifyFinalize verifies the evaluation.
func (s *Server) VerifyFinalize(in, info, out []byte) bool {
	dst := append(append([]byte{}, []byte(version)...), s.context...)
	h2c := s.suite.Group.Hashes(dst)
	p := h2c.Hash(in)

	el, err := p.MarshalBinaryCompress()
	if err != nil {
		return false
	}

	e, err := s.Evaluate(el)
	if err != nil {
		return false
	}

	h := finalizeHash(s.suite, in, e.Element, info, s.context)
	return subtle.ConstantTimeCompare(h, out) == 1
}

// NewClient creates a new instantiation of a Client.
func NewClient(id SuiteID) (*Client, error) {
	suite, err := suiteFromID(id)
	if err != nil {
		return nil, err
	}
	context := generateContext(id)

	return &Client{
		suite:   suite,
		context: context[:],
	}, nil
}

// ClientRequest is a structure to encapsulate the output of a Request call.
type ClientRequest struct {
	suite        *suite
	context      []byte
	token        *Token
	BlindedToken BlindToken
}

// Request generates a token and its blinded version.
func (c *Client) Request(in []byte) (*ClientRequest, error) {
	rnd := c.suite.Group.Random()
	r := rnd.RndScl(rand.Reader)

	dst := append(append([]byte{}, []byte(version)...), c.context...)
	h2c := c.suite.Group.Hashes(dst)
	p := h2c.Hash(in)

	t := c.suite.Group.NewElt()
	t.Mul(p, r)
	BlindedToken, err := t.MarshalBinaryCompress()
	if err != nil {
		return nil, err
	}

	tk := &Token{in, r}
	return &ClientRequest{c.suite, c.context, tk, BlindedToken}, nil
}

// Finalize computes the signed token from the server Evaluation and returns
// the output of the OPRF protocol.
func (cr *ClientRequest) Finalize(e *Evaluation, info []byte) ([]byte, error) {
	p := cr.suite.Group.NewElt()
	err := p.UnmarshalBinary(e.Element)
	if err != nil {
		return nil, err
	}

	r := cr.token.blind
	rInv := cr.suite.Group.NewScl()
	rInv.Inv(r)

	tt := cr.suite.Group.NewElt()
	tt.Mul(p, rInv)
	iToken, err := tt.MarshalBinaryCompress()
	if err != nil {
		return nil, err
	}

	h := finalizeHash(cr.suite, cr.token.data, iToken, info, cr.context)
	return h, nil
}
