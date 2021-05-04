// Package oprf provides an Oblivious Pseudo-Random Function protocol.
//
// An Oblivious Pseudorandom Function (OPRFs) is a two-party protocol for
// computing the output of a PRF. One party (the server) holds the PRF secret
// key, and the other (the client) holds the PRF input.
//
// Obliviousness: Ensures that the server does not learn anything
// about the client's input during the Evaluation step.
//
// Verifiability: Allows the client to verify that the server used
// a committed secret key during Evaluation step.
//
// OPRF is defined on draft-irtf-cfrg-voprf: https://datatracker.ietf.org/doc/draft-irtf-cfrg-voprf
//
package oprf

import (
	"crypto"
	"encoding/binary"
	"errors"
	"io"

	"github.com/cloudflare/circl/group"
)

const (
	version         = "VOPRF06-"
	seedDST         = "Seed-"
	challengeDST    = "Challenge-"
	finalizeDST     = "Finalize-"
	compositeDST    = "Composite-"
	hashToGroupDST  = "HashToGroup-"
	hashToScalarDST = "HashToScalar-"
)

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

// Mode specifies properties of the OPRF protocol.
type Mode = uint8

const (
	// BaseMode provides obliviousness.
	BaseMode Mode = 0x00
	// VerifiableMode provides obliviousness and verifiability.
	VerifiableMode Mode = 0x01
)

// ErrUnsupportedSuite is thrown when requesting a non-supported suite.
var ErrUnsupportedSuite = errors.New("non-supported suite")

type Blind group.Scalar
type SerializedElement = []byte
type SerializedScalar = []byte
type Blinded = SerializedElement

type Proof struct {
	C, S SerializedScalar
}

type Evaluation struct {
	Elements []SerializedElement
	Proof    *Proof
}

type suite struct {
	SuiteID
	Mode
	group.Group
	crypto.Hash
}

func suiteFromID(id SuiteID, m Mode) (*suite, error) {
	if !(m == BaseMode || m == VerifiableMode) {
		return nil, ErrUnsupportedSuite
	}
	switch id {
	case OPRFP256:
		return &suite{id, m, group.P256, crypto.SHA256}, nil
	case OPRFP384:
		return &suite{id, m, group.P384, crypto.SHA512}, nil
	case OPRFP521:
		return &suite{id, m, group.P521, crypto.SHA512}, nil
	default:
		return nil, ErrUnsupportedSuite
	}
}

// GetSizes returns the size in bytes of a SerializedElement, SerializedScalar,
// and the length of the OPRF's output protocol.
func GetSizes(id SuiteID) (
	s struct {
		SerializedElementLength uint // Size in bytes of a serialized element.
		SerializedScalarLength  uint // Size in bytes of a serialized scalar.
		OutputLength            uint // Size in bytes of OPRF's output.
	},
	err error,
) {
	if suite, err := suiteFromID(id, BaseMode); err == nil {
		p := suite.Group.Params()
		s.SerializedElementLength = p.CompressedElementLength
		s.SerializedScalarLength = p.ScalarLength
		s.OutputLength = uint(suite.Size())
	}
	return
}

func (s *suite) GetMode() Mode { return s.Mode }
func (s *suite) getDST(name string) []byte {
	return append(append(append([]byte{},
		[]byte(name)...),
		[]byte(version)...),
		[]byte{s.Mode, 0, byte(s.SuiteID)}...)
}

func (s *suite) scalarMult(e group.Element, k group.Scalar) ([]byte, error) {
	t := s.Group.NewElement()
	t.Mul(e, k)
	return t.MarshalBinaryCompress()
}

func (s *suite) finalizeHash(input, element []byte) []byte {
	h := s.New()

	lenBuf := []byte{0, 0}

	binary.BigEndian.PutUint16(lenBuf, uint16(len(input)))
	mustWrite(h, lenBuf)
	mustWrite(h, input)

	binary.BigEndian.PutUint16(lenBuf, uint16(len(element)))
	mustWrite(h, lenBuf)
	mustWrite(h, element)

	dst := s.getDST(finalizeDST)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(dst)))
	mustWrite(h, lenBuf)
	mustWrite(h, dst)

	return h.Sum(nil)
}

func mustWrite(h io.Writer, bytes []byte) {
	bytesLen, err := h.Write(bytes)
	if err != nil {
		panic(err)
	}
	if len(bytes) != bytesLen {
		panic("failed to write")
	}
}

func (s *suite) computeComposites(
	k group.Scalar,
	B group.Element,
	Cs []group.Element,
	Ds []group.Element,
) (group.Element, group.Element, error) {
	Bm, err := B.MarshalBinaryCompress()
	if err != nil {
		return nil, nil, err
	}

	lenBuf := []byte{0, 0}
	H := s.New()

	binary.BigEndian.PutUint16(lenBuf, uint16(len(Bm)))
	mustWrite(H, lenBuf)
	mustWrite(H, Bm)

	dst := s.getDST(seedDST)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(dst)))
	mustWrite(H, lenBuf)
	mustWrite(H, dst)

	seed := H.Sum(nil)

	M := s.Group.Identity()
	Z := s.Group.Identity()
	h2sDST := s.getDST(hashToScalarDST)
	for i := range Cs {
		h2Input := []byte{}

		Ci, err := Cs[i].MarshalBinaryCompress()
		if err != nil {
			return nil, nil, err
		}

		Di, err := Ds[i].MarshalBinaryCompress()
		if err != nil {
			return nil, nil, err
		}

		binary.BigEndian.PutUint16(lenBuf, uint16(len(seed)))
		h2Input = append(append(h2Input, lenBuf...), seed...)

		binary.BigEndian.PutUint16(lenBuf, uint16(i))
		h2Input = append(h2Input, lenBuf...)

		binary.BigEndian.PutUint16(lenBuf, uint16(len(Ci)))
		h2Input = append(append(h2Input, lenBuf...), Ci...)

		binary.BigEndian.PutUint16(lenBuf, uint16(len(Di)))
		h2Input = append(append(h2Input, lenBuf...), Di...)

		dst := s.getDST(compositeDST)
		binary.BigEndian.PutUint16(lenBuf, uint16(len(dst)))
		h2Input = append(append(h2Input, lenBuf...), dst...)

		di := s.Group.HashToScalar(h2Input, h2sDST)
		Mi := s.Group.NewElement()
		Mi.Mul(Cs[i], di)
		M.Add(M, Mi)

		if k == nil {
			Zi := s.Group.NewElement()
			Zi.Mul(Ds[i], di)
			Z.Add(Z, Zi)
		}
	}

	if k != nil {
		Z.Mul(M, k)
	}

	return M, Z, nil
}

func (s *suite) doChallenge(a [5][]byte) group.Scalar {
	h2Input := []byte{}
	lenBuf := []byte{0, 0}

	for i := range a {
		binary.BigEndian.PutUint16(lenBuf, uint16(len(a[i])))
		h2Input = append(append(h2Input, lenBuf...), a[i]...)
	}

	dst := s.getDST(challengeDST)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(dst)))
	h2Input = append(append(h2Input, lenBuf...), dst...)

	return s.Group.HashToScalar(h2Input, s.getDST(hashToScalarDST))
}
