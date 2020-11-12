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

const version = "VOPRF06-"

// SuiteID identifies supported suites.
type SuiteID = uint16

const (
	// OPRFP256 represents the OPRF with P-256 and SHA-256.
	OPRFP256 SuiteID = 0x0003
	// OPRFP384 represents the OPRF with P-384 and SHA-512.
	OPRFP384 SuiteID = 0x0004
	// OPRFP521 represents the OPRF with P-521 and SHA-512.
	OPRFP521 SuiteID = 0x0005
)

// Mode specifies a variant of the OPRF protocol.
type Mode = uint8

const (
	BaseMode       Mode = 0x00
	VerifiableMode Mode = 0x01
)

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
	id         SuiteID
	publicKey  group.Element
	privateKey group.Scalar
}

// Client is a representation of a Client during protocol execution.
type Client struct {
	suite
}

// Server is a representation of a Server during protocol execution.
type Server struct {
	suite
	Kp KeyPair
}

type suite struct {
	SuiteID
	Mode
	group.Group
	crypto.Hash
}

func (s *suite) GetGroup() group.Group { return s.Group }

func (s *suite) getHashToGroup() group.Hasher {
	dst := append(append(append([]byte{},
		[]byte(version)...),
		[]byte("HashToGroup-")...),
		[]byte{s.Mode, 0, byte(s.SuiteID)}...)
	return s.Group.Hashes(dst)
}

func (s *suite) dstHash() []byte {
	return append(append(append([]byte{},
		[]byte(version)...),
		[]byte("Finalize-")...),
		[]byte{s.Mode, 0, byte(s.SuiteID)}...)
}

func (s *suite) generateKeyPair() *KeyPair {
	r := s.Random()
	privateKey := r.RndScl(rand.Reader)
	publicKey := s.NewElt()
	publicKey.MulGen(privateKey)

	return &KeyPair{s.SuiteID, publicKey, privateKey}
}

// Serialize serializes a KeyPair elements into byte arrays.
func (kp *KeyPair) Serialize() ([]byte, error) { return kp.privateKey.MarshalBinary() }

// Deserialize deserializes a KeyPair into an element and field element of the group.
func (kp *KeyPair) Deserialize(id SuiteID, encoded []byte) error {
	s, err := suiteFromID(id)
	if err != nil {
		return err
	}
	privateKey := s.NewScl()
	err = privateKey.UnmarshalBinary(encoded)
	if err != nil {
		return err
	}
	publicKey := s.NewElt()
	publicKey.MulGen(privateKey)

	kp.id = id
	kp.publicKey = publicKey
	kp.privateKey = privateKey

	return nil
}

// GenerateKeyPair generates a KeyPair in accordance with the group.
func GenerateKeyPair(id SuiteID) (*KeyPair, error) {
	suite, err := suiteFromID(id)
	if err != nil {
		return nil, err
	}
	return suite.generateKeyPair(), nil
}

func suiteFromID(id SuiteID) (*suite, error) {
	switch id {
	case OPRFP256:
		return &suite{id, BaseMode, group.P256, crypto.SHA256}, nil
	case OPRFP384:
		return &suite{id, BaseMode, group.P384, crypto.SHA512}, nil
	case OPRFP521:
		return &suite{id, BaseMode, group.P521, crypto.SHA512}, nil
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
	keyPair := suite.generateKeyPair()

	return &Server{*suite, *keyPair}, nil
}

// NewServerWithKeyPair creates a new instantiation of a Server. It can create
// a server with existing keys or use pre-generated keys.
func NewServerWithKeyPair(id SuiteID, kp KeyPair) (*Server, error) {
	// Verifies keypair corresponds to SuiteID.
	if id != kp.id {
		return nil, ErrUnsupportedSuite
	}

	suite, err := suiteFromID(id)
	if err != nil {
		return nil, err
	}

	return &Server{*suite, kp}, nil
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
func (s *suite) finalizeHash(data, iToken, info []byte) []byte {
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

	dst := s.dstHash()
	binary.BigEndian.PutUint16(lenBuf, uint16(len(dst)))
	mustWrite(h, lenBuf)
	mustWrite(h, dst)

	return h.Sum(nil)
}

// FullEvaluate performs a full evaluation at the server side.
func (s *Server) FullEvaluate(in, info []byte) ([]byte, error) {
	H := s.getHashToGroup()
	p := H.Hash(in)

	t := s.suite.Group.NewElt()
	t.Mul(p, s.Kp.privateKey)
	iToken, err := t.MarshalBinaryCompress()
	if err != nil {
		return nil, err
	}

	h := s.finalizeHash(in, iToken, info)

	return h, nil
}

// VerifyFinalize verifies the evaluation.
func (s *Server) VerifyFinalize(in, info, out []byte) bool {
	H := s.getHashToGroup()
	p := H.Hash(in)

	el, err := p.MarshalBinaryCompress()
	if err != nil {
		return false
	}

	e, err := s.Evaluate(el)
	if err != nil {
		return false
	}

	h := s.finalizeHash(in, e.Element, info)
	return subtle.ConstantTimeCompare(h, out) == 1
}

// NewClient creates a new instantiation of a Client.
func NewClient(id SuiteID) (*Client, error) {
	suite, err := suiteFromID(id)
	if err != nil {
		return nil, err
	}

	return &Client{*suite}, nil
}

// ClientRequest is a structure to encapsulate the output of a Request call.
type ClientRequest struct {
	suite        *suite
	token        *Token
	BlindedToken BlindToken
}

// Request generates a token and its blinded version.
func (c *Client) Request(in []byte) (*ClientRequest, error) {
	rnd := c.suite.Group.Random()
	r := rnd.RndScl(rand.Reader)
	return c.blind(in, r)
}

func (c *Client) blind(in []byte, blind group.Scalar) (*ClientRequest, error) {
	H := c.getHashToGroup()
	p := H.Hash(in)

	t := c.suite.Group.NewElt()
	t.Mul(p, blind)
	BlindedToken, err := t.MarshalBinaryCompress()
	if err != nil {
		return nil, err
	}
	return &ClientRequest{&c.suite, &Token{in, blind}, BlindedToken}, nil
}

func (cr *ClientRequest) unblind(e *Evaluation) ([]byte, error) {
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
	return tt.MarshalBinaryCompress()
}

// Finalize computes the signed token from the server Evaluation and returns
// the output of the OPRF protocol.
func (cr *ClientRequest) Finalize(e *Evaluation, info []byte) ([]byte, error) {
	iToken, err := cr.unblind(e)
	if err != nil {
		return nil, err
	}
	h := cr.suite.finalizeHash(cr.token.data, iToken, info)
	return h, nil
}
