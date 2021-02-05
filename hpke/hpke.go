// Package hpke implements the Hybrid Public Key Encryption (HPKE) standard
// specified by draft-irtf-cfrg-hpke-06.
//
// HPKE works for any combination of a public-key encapsulation mechanism
// (KEM), a key derivation function (KDF), and an authenticated encryption
// scheme with additional data (AEAD).
//
// Specification in
// https://datatracker.ietf.org/doc/draft-irtf-cfrg-hpke
package hpke

import (
	"crypto/rand"
	"encoding"
	"errors"
	"io"

	"github.com/cloudflare/circl/kem"
)

const versionLabel = "HPKE-06"

// Context defines the capabilities of an HPKE context.
type Context interface {
	encoding.BinaryMarshaler
	// Export takes a context string exporterContext and a desired length (in
	// bytes), and produces a secret derived from the internal exporter secret
	// using the corresponding KDF Expand function. It panics if length is greater
	// than 255*N bytes, where N is the size (in bytes) of the KDF's output.
	Export(exporterContext []byte, length uint) []byte
	// Suite returns the cipher suite corresponding to this context.
	Suite() Suite
}

// Sealer encrypts a plaintext using an AEAD encryption.
type Sealer interface {
	Context
	// Seal takes a plaintext and associated data to produce a ciphertext.
	// The nonce is handled by the Sealer and incremented after each call.
	Seal(pt, aad []byte) (ct []byte, err error)
}

// Opener decrypts a ciphertext using an AEAD encryption.
type Opener interface {
	Context
	// Open takes a ciphertext and associated data to recover, if successful,
	// the plaintext. The nonce is handled by the Opener and incremented after
	// each call.
	Open(ct, aad []byte) (pt []byte, err error)
}

// modeID represents an HPKE variant.
type modeID = uint8

const (
	// modeBase to enable encryption to the holder of a given KEM private key.
	modeBase modeID = 0x00
	// modePSK extends the base mode by allowing the Receiver to authenticate
	// that the sender possessed a given pre-shared key (PSK).
	modePSK modeID = 0x01
	// modeAuth extends the base mode by allowing the Receiver to authenticate
	// that the sender possessed a given KEM private key.
	modeAuth modeID = 0x02
	// modeAuthPSK provides a combination of the PSK and Auth modes.
	modeAuthPSK modeID = 0x03
)

// Suite is an HPKE cipher suite consisting of a KEM, KDF, and AEAD algorithm.
type Suite struct {
	KemID  KemID
	KdfID  KdfID
	AeadID AeadID
	_      struct{}
}

// NewSuite builds a Suite from a specified set of algorithms. Panics if an
// algorithm identifier is not valid.
func NewSuite(kemID KemID, kdfID KdfID, aeadID AeadID) Suite {
	s := Suite{KemID: kemID, KdfID: kdfID, AeadID: aeadID}
	if !s.isValid() {
		panic(errHpkeInvalidSuite)
	}
	return s
}

type state struct {
	Suite
	modeID modeID
	skS    kem.PrivateKey
	pkS    kem.PublicKey
	psk    []byte
	pskID  []byte
	info   []byte
}

// Sender performs hybrid public-key encryption.
type Sender struct {
	state
	pkR kem.PublicKey
}

// NewSender creates a Sender with knowledge of the receiver's public-key.
func (suite Suite) NewSender(pkR kem.PublicKey, info []byte) (*Sender, error) {
	if !suite.KemID.validatePublicKey(pkR) {
		return nil, errKemInvalidPublicKey
	}

	return &Sender{
		state: state{Suite: suite, info: info},
		pkR:   pkR,
	}, nil
}

// Setup generates a new HPKE context used for Base Mode encryption.
// Returns the Sealer and corresponding encapsulated key.
func (s *Sender) Setup(rnd io.Reader) (enc []byte, seal Sealer, err error) {
	s.modeID = modeBase
	return s.allSetup(rnd)
}

// SetupAuth generates a new HPKE context used for Auth Mode encryption.
// Returns the Sealer and corresponding encapsulated key.
func (s *Sender) SetupAuth(rnd io.Reader, skS kem.PrivateKey) (
	enc []byte, seal Sealer, err error,
) {
	if !s.KemID.validatePrivateKey(skS) {
		return nil, nil, errKemInvalidPrivateKey
	}

	s.modeID = modeAuth
	s.state.skS = skS
	return s.allSetup(rnd)
}

// SetupPSK generates a new HPKE context used for PSK Mode encryption.
// Returns the Sealer and corresponding encapsulated key.
func (s *Sender) SetupPSK(rnd io.Reader, psk, pskID []byte) (
	enc []byte, seal Sealer, err error,
) {
	s.modeID = modePSK
	s.state.psk = psk
	s.state.pskID = pskID
	return s.allSetup(rnd)
}

// SetupAuthPSK generates a new HPKE context used for Auth-PSK Mode encryption.
// Returns the Sealer and corresponding encapsulated key.
func (s *Sender) SetupAuthPSK(rnd io.Reader, skS kem.PrivateKey, psk, pskID []byte) (
	enc []byte, seal Sealer, err error,
) {
	if !s.KemID.validatePrivateKey(skS) {
		return nil, nil, errKemInvalidPrivateKey
	}

	s.modeID = modeAuthPSK
	s.state.skS = skS
	s.state.psk = psk
	s.state.pskID = pskID
	return s.allSetup(rnd)
}

// Receiver performs hybrid public-key decryption.
type Receiver struct {
	state
	skR kem.PrivateKey
	enc []byte
}

// NewReceiver creates a Receiver with knwoledge of a private key.
func (suite Suite) NewReceiver(skR kem.PrivateKey, info []byte) (
	*Receiver, error,
) {
	if !suite.KemID.validatePrivateKey(skR) {
		return nil, errKemInvalidPrivateKey
	}

	return &Receiver{state: state{Suite: suite, info: info}, skR: skR}, nil
}

// Setup generates a new HPKE context used for Base Mode encryption.
// Setup takes an encapsulated key and returns an Opener.
func (r *Receiver) Setup(enc []byte) (Opener, error) {
	r.modeID = modeBase
	r.enc = enc
	return r.allSetup()
}

// SetupAuth generates a new HPKE context used for Auth Mode encryption.
// SetupAuth takes an encapsulated key and a public key, and returns an Opener.
func (r *Receiver) SetupAuth(enc []byte, pkS kem.PublicKey) (Opener, error) {
	if !r.KemID.validatePublicKey(pkS) {
		return nil, errKemInvalidPublicKey
	}

	r.modeID = modeAuth
	r.enc = enc
	r.state.pkS = pkS
	return r.allSetup()
}

// SetupPSK generates a new HPKE context used for PSK Mode encryption.
// SetupPSK takes an encapsulated key, and a pre-shared key; and returns an
// Opener.
func (r *Receiver) SetupPSK(enc, psk, pskID []byte) (Opener, error) {
	r.modeID = modePSK
	r.enc = enc
	r.state.psk = psk
	r.state.pskID = pskID
	return r.allSetup()
}

// SetupAuthPSK generates a new HPKE context used for Auth-PSK Mode encryption.
// SetupAuthPSK takes an encapsulated key, a public key, and a pre-shared key;
// and returns an Opener.
func (r *Receiver) SetupAuthPSK(enc, psk, pskID []byte, pkS kem.PublicKey) (
	Opener, error) {
	if !r.KemID.validatePublicKey(pkS) {
		return nil, errKemInvalidPublicKey
	}

	r.modeID = modeAuthPSK
	r.enc = enc
	r.state.psk = psk
	r.state.pskID = pskID
	r.state.pkS = pkS
	return r.allSetup()
}

func (s *Sender) allSetup(rnd io.Reader) ([]byte, Sealer, error) {
	k := s.KemID.Scheme()

	if rnd == nil {
		rnd = rand.Reader
	}
	seed := make([]byte, k.SeedSize())
	_, err := io.ReadFull(rnd, seed)
	if err != nil {
		return nil, nil, err
	}

	var enc, ss []byte
	switch s.modeID {
	case modeBase, modePSK:
		enc, ss, err = k.EncapsulateDeterministically(s.pkR, seed)
	case modeAuth, modeAuthPSK:
		enc, ss, err = k.AuthEncapsulateDeterministically(s.pkR, s.skS, seed)
	}
	if err != nil {
		return nil, nil, err
	}

	ctx, err := s.keySchedule(ss, s.info, s.psk, s.pskID)
	if err != nil {
		return nil, nil, err
	}

	return enc, &sealContext{ctx}, nil
}

func (r *Receiver) allSetup() (Opener, error) {
	var err error
	var ss []byte
	k := r.KemID.Scheme()
	switch r.modeID {
	case modeBase, modePSK:
		ss, err = k.Decapsulate(r.skR, r.enc)
	case modeAuth, modeAuthPSK:
		ss, err = k.AuthDecapsulate(r.skR, r.enc, r.pkS)
	}
	if err != nil {
		return nil, err
	}

	ctx, err := r.keySchedule(ss, r.info, r.psk, r.pskID)
	if err != nil {
		return nil, err
	}
	return &openContext{ctx}, nil
}

var (
	errHpkeInvalidSuite       = errors.New("invalid hpke suite")
	errKemInvalidPublicKey    = errors.New("invalid kem public key")
	errKemInvalidPrivateKey   = errors.New("invalid kem private key")
	errKemInvalidSharedSecret = errors.New("invalid shared secret")
	errAeadSeqOverflows       = errors.New("aead sequence number overflows")
)
