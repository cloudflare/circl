package bbs

import (
	"errors"
	"slices"
)

const (
	PublicKeySize      = 96 // Size in bytes of public keys.
	PrivateKeySize     = 32 // Size in bytes of private keys.
	SignatureSize      = 80 // Size in bytes of signatures.
	KeyMaterialMinSize = 32 // Minimum size in bytes of private key material.
)

// [Msg] is a byte slice marked either as [Disclosed] or [Concealed].
type Msg interface{ get() []byte }

// Disclosed marks a message as disclosed. Implements the [Msg] interface.
type Disclosed []byte

func (b Disclosed) get() []byte { return b }

// Concealed marks a message as concealed. Implements the [Msg] interface.
type Concealed []byte

func (b Concealed) get() []byte { return b }

// Disclose returns a list of messages specifying the messages to be disclosed,
// and the others are concealed.
// Indexes must be unique and lesser than len(messages),
// otherwise returns an error.
func Disclose(messages [][]byte, disclosed []uint) ([]Msg, error) {
	return choose[Disclosed, Concealed](messages, disclosed)
}

// Conceal returns a list of messages specifying the messages to be concealed,
// and the others are disclosed.
// Indexes must be unique and lesser than len(messages),
// otherwise returns an error.
func Conceal(messages [][]byte, concealed []uint) ([]Msg, error) {
	return choose[Concealed, Disclosed](messages, concealed)
}

func choose[
	This, Other interface {
		~[]byte
		Msg
	},
](msgs [][]byte, indexes []uint) ([]Msg, error) {
	indexesNoDup := slices.Clone(indexes)
	slices.Sort(indexesNoDup)
	indexesNoDup = slices.Compact(indexesNoDup)
	l := len(indexesNoDup)
	// check for duplicates.
	if l != len(indexes) {
		return nil, ErrIndexes
	}

	// check for out-of-range indexes.
	if l > 0 && indexesNoDup[l-1] >= uint(len(msgs)) {
		return nil, ErrIndexes
	}

	choices := make([]Msg, len(msgs))
	for i := range msgs {
		choices[i] = Other(msgs[i])
	}

	for _, idx := range indexesNoDup {
		choices[idx] = This(msgs[idx])
	}

	return choices, nil
}

var (
	ErrInvalidSuiteID = errors.New("bbs: invalid suite identifier")
	ErrKeyMaterial    = errors.New("bbs: invalid keyMaterial size")
	ErrKeyInfo        = errors.New("bbs: invalid keyGen keyInfo")
	ErrInvalidOpts    = errors.New("bbs: invalid options")
	ErrIndexes        = errors.New("bbs: invalid indexes")
	ErrSignature      = errors.New("bbs: invalid signature")
	ErrGenerators     = errors.New("bbs: invalid generators")
)
