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
	"errors"

	"github.com/cloudflare/circl/kem"
)

const versionLabel = "HPKE-06"

// Exporter allows exporting secrets from an HPKE context using a
// variable-length PRF.
type Exporter interface {
	// Export takes a context string expCtx and a desired length (in bytes),
	// and produces a secret derived from the internal exporter secret using
	// the corresponding KDF Expand function. It panics if length is greater
	// than 255*N bytes, where N is the size (in bytes) of the KDF's output.
	Export(expCtx []byte, length uint) []byte
}

// Sealer encrypts a plaintext using an AEAD encryption.
type Sealer interface {
	Exporter
	// Seal takes a plaintext and associated data to produce a ciphertext.
	// The nonce is handled by the Sealer and incremented after each call.
	Seal(pt, aad []byte) (ct []byte, err error)
}

// Opener decrypts a ciphertext using an AEAD encryption.
type Opener interface {
	Exporter
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
	if !suite.isValid() {
		return nil, errors.New("invalid suite")
	}

	if !suite.KemID.validatePublicKey(pkR) {
		return nil, kem.ErrTypeMismatch
	}

	return &Sender{
		state: state{Suite: suite, info: info},
		pkR:   pkR,
	}, nil
}

// Setup generates a new HPKE context used for Base Mode encryption.
// Returns the Sealer and corresponding encapsulated key.
func (s *Sender) Setup() (enc []byte, seal Sealer, err error) {
	return s.buildBase().allSetup(s.KemID.Scheme())
}

func (s *Sender) buildBase() *Sender {
	s.modeID = modeBase
	return s
}

// SetupAuth generates a new HPKE context used for Auth Mode encryption.
// Returns the Sealer and corresponding encapsulated key.
func (s *Sender) SetupAuth(skS kem.PrivateKey) (
	enc []byte, seal Sealer, err error,
) {
	_, err = s.buildAuth(skS)
	if err != nil {
		return nil, nil, err
	}
	return s.allSetup(s.KemID.Scheme())
}

func (s *Sender) buildAuth(skS kem.PrivateKey) (*Sender, error) {
	if !s.KemID.validatePrivateKey(skS) {
		return nil, kem.ErrTypeMismatch
	}

	s.modeID = modeAuth
	s.state.skS = skS
	return s, nil
}

// SetupPSK generates a new HPKE context used for PSK Mode encryption.
// Returns the Sealer and corresponding encapsulated key.
func (s *Sender) SetupPSK(psk, pskID []byte) (
	enc []byte, seal Sealer, err error,
) {
	return s.buildPSK(psk, pskID).allSetup(s.KemID.Scheme())
}

func (s *Sender) buildPSK(psk, pskID []byte) *Sender {
	s.modeID = modePSK
	s.state.psk = psk
	s.state.pskID = pskID
	return s
}

// SetupAuthPSK generates a new HPKE context used for Auth-PSK Mode encryption.
// Returns the Sealer and corresponding encapsulated key.
func (s *Sender) SetupAuthPSK(skS kem.PrivateKey, psk, pskID []byte) (
	enc []byte, seal Sealer, err error,
) {
	_, err = s.buildAuthPSK(skS, psk, pskID)
	if err != nil {
		return nil, nil, err
	}
	return s.allSetup(s.KemID.Scheme())
}

func (s *Sender) buildAuthPSK(skS kem.PrivateKey, psk, pskID []byte) (
	*Sender, error) {
	if !s.KemID.validatePrivateKey(skS) {
		return nil, kem.ErrTypeMismatch
	}

	s.modeID = modeAuthPSK
	s.state.skS = skS
	s.state.psk = psk
	s.state.pskID = pskID
	return s, nil
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
	if !suite.isValid() {
		return nil, errors.New("invalid suite")
	}
	if !suite.KemID.validatePrivateKey(skR) {
		return nil, kem.ErrTypeMismatch
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
		return nil, kem.ErrTypeMismatch
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
		return nil, kem.ErrTypeMismatch
	}

	r.modeID = modeAuthPSK
	r.enc = enc
	r.state.psk = psk
	r.state.pskID = pskID
	r.state.pkS = pkS
	return r.allSetup()
}

func (s *Sender) allSetup(k kem.AuthScheme) ([]byte, Sealer, error) {
	var err error
	var enc, ss []byte

	switch s.modeID {
	case modeBase, modePSK:
		enc, ss, err = k.Encapsulate(s.pkR)
	case modeAuth, modeAuthPSK:
		enc, ss, err = k.AuthEncapsulate(s.pkR, s.skS)
	}
	if err != nil {
		return nil, nil, err
	}

	ctx, err := s.keySchedule(ss, s.info, s.psk, s.pskID)
	if err != nil {
		return nil, nil, err
	}

	return enc, &sealCtx{ctx}, nil
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
	return &openCtx{ctx}, nil
}
