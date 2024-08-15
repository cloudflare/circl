// Package slhdsa provides Stateless Hash-based Digital Signature Algorithm.
//
// This package is compliant with [FIPS 205] and the [ParamID] represents
// the following parameter sets:
//
// Category 1
//   - Based on SHA2: [ParamIDSHA2Small128] and [ParamIDSHA2Fast128].
//   - Based on SHAKE: [ParamIDSHAKESmall128] and [ParamIDSHAKEFast128].
//
// Category 3
//   - Based on SHA2: [ParamIDSHA2Small192] and [ParamIDSHA2Fast192]
//   - Based on SHAKE: [ParamIDSHAKESmall192] and [ParamIDSHAKEFast192]
//
// Category 5
//   - Based on SHA2: [ParamIDSHA2Small256] and [ParamIDSHA2Fast256].
//   - Based on SHAKE: [ParamIDSHAKESmall256] and [ParamIDSHAKEFast256].
//
// [FIPS 205]: https://doi.org/10.6028/NIST.FIPS.205
package slhdsa

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/internal/sha3"
	"github.com/cloudflare/circl/sign"
)

// [MaxContextSize] is the maximum byte length of a context for signing.
const MaxContextSize = 255

// GenerateKey returns a pair of keys using the parameter set specified.
// It returns an error if it fails reading from the random source.
func GenerateKey(
	random io.Reader, id ParamID,
) (pub PublicKey, priv PrivateKey, err error) {
	// See FIPS 205 -- Section 10.1 -- Algorithm 21.
	params := id.params()

	var skPrf, skSeed, pkSeed []byte
	skSeed, err = readRandom(random, params.n)
	if err != nil {
		return
	}

	skPrf, err = readRandom(random, params.n)
	if err != nil {
		return
	}

	pkSeed, err = readRandom(random, params.n)
	if err != nil {
		return
	}

	pub, priv = slhKeyGenInternal(params, skSeed, skPrf, pkSeed)

	return
}

// GenerateKey is similar to [GenerateKey] function, except it always reads
// random bytes from [rand.Reader].
func (id ParamID) GenerateKey() (sign.PublicKey, sign.PrivateKey, error) {
	pub, priv, err := GenerateKey(rand.Reader, id)
	if err != nil {
		return nil, nil, err
	}

	return &pub, &priv, nil
}

// Deterministically derives a pair of keys from a seed. If you're unsure,
// you're better off using [GenerateKey] function.
//
// Panics if seed is not of length [ParamID.SeedSize].
func (id ParamID) DeriveKey(seed []byte) (sign.PublicKey, sign.PrivateKey) {
	params := id.params()
	if len(seed) != id.SeedSize() {
		panic(sign.ErrSeedSize)
	}

	m := make([]byte, 3*params.n)
	if params.isSHA2 {
		params.mgf1(m, seed, 3*params.n)
	} else {
		sha3.ShakeSum256(m, seed)
	}

	pub, priv, err := GenerateKey(bytes.NewReader(m), id)
	if err != nil {
		return nil, nil
	}

	return &pub, &priv
}

// SignRandomized returns a random signature of the message with the
// specified context.
// It returns an error if it fails reading from the random source.
func (k *PrivateKey) SignRandomized(
	random io.Reader, message *Message, context []byte,
) (signature []byte, err error) {
	params := k.ParamID.params()
	addRand, err := readRandom(random, params.n)
	if err != nil {
		return nil, err
	}

	return k.doSign(message, context, addRand)
}

// SignDeterministic returns the signature of the message with the
// specified context.
// It returns an error if it fails reading from the random source.
func (k *PrivateKey) SignDeterministic(
	message *Message, context []byte,
) (signature []byte, err error) {
	return k.doSign(message, context, k.publicKey.seed)
}

func (k *PrivateKey) doSign(msg *Message, ctx, addRnd []byte) ([]byte, error) {
	// See FIPS 205 -- Section 10.2 -- Algorithm 22.
	params := k.ParamID.params()
	msgPrime, err := msg.getMsgPrime(ctx)
	if err != nil {
		return nil, err
	}

	return slhSignInternal(params, k, msgPrime, addRnd)
}

// [PrivateKey.Sign] returns a signature of the message with the specified
// options.
//
// When options is a [SignatureOpts] struct, the signature is generated as
// specified by the options. Otherwise, options.HashFunc is used as the
// pre-hash function (allowing only SHA256 or SHA512).
// If options is nil, the message is not prehased, and a randomized
// signature with an empty context is generated.
// It returns an error if it fails reading from the random source.
func (k *PrivateKey) Sign(
	random io.Reader, message []byte, options crypto.SignerOpts,
) (signature []byte, err error) {
	var signOptions SignatureOpts
	if options != nil {
		switch options.HashFunc() {
		case crypto.SHA256:
			signOptions.PreHashID = PreHashSHA256
		case crypto.SHA512:
			signOptions.PreHashID = PreHashSHA512
		}

		otherOptions, ok := options.(SignatureOpts)
		if ok {
			signOptions = otherOptions
		}
	}

	msg := new(Message)
	err = msg.init(signOptions.PreHashID, message)
	if err != nil {
		return nil, err
	}

	if signOptions.IsDeterministic {
		return k.SignDeterministic(msg, signOptions.Context)
	} else {
		return k.SignRandomized(random, msg, signOptions.Context)
	}
}

// [ParamID.Sign] returns a randomized signature of the message with the
// specified options.
// This function never pre-hashes the message and uses the context provided
// in options. If options is nil, an empty context is used.
// It returns an empty slice if it fails reading from the random source.
//
// Panics if the key is not a [*PrivateKey] or mismatches with the ParamID.
func (id ParamID) Sign(
	key sign.PrivateKey, message []byte, options *sign.SignatureOpts,
) (signature []byte) {
	k, ok := key.(*PrivateKey)
	if !ok || id != k.ParamID {
		panic(sign.ErrTypeMismatch)
	}

	var context []byte
	if options != nil {
		context = []byte(options.Context)
	}

	msg := NewMessage(message)
	signature, err := k.SignRandomized(rand.Reader, &msg, context)
	if err != nil {
		return nil
	}

	return
}

// [Verify] returns true if the signature of the message with the specified
// context is valid.
func Verify(key *PublicKey, message *Message, context, signature []byte) bool {
	// See FIPS 205 -- Section 10.3 -- Algorithm 24.
	params := key.ParamID.params()
	msgPrime, err := message.getMsgPrime(context)
	if err != nil {
		return false
	}

	return slhVerifyInternal(params, key, msgPrime, signature)
}

// [Verify] returns true if the signature of the message with the specified
// context is valid.
// This function never pre-hashes the message and uses the context provided
// in options. If options is nil, an empty context is used.
//
// Panics if the key is not a [*PublicKey] or mismatches with the ParamID.
func (id ParamID) Verify(
	key sign.PublicKey, message, signature []byte, options *sign.SignatureOpts,
) bool {
	k, ok := key.(*PublicKey)
	if !ok || id != k.ParamID {
		panic(sign.ErrTypeMismatch)
	}

	var context []byte
	if options != nil {
		context = []byte(options.Context)
	}

	msg := NewMessage(message)
	return Verify(k, &msg, context, signature)
}

// [SignatureOpts] is used to specify the generation and verification
// procedure of signatures.
type SignatureOpts struct {
	// When set to [NoPreHash] (the zero value), the signature is generated
	// over the original message.
	// Otherwise, it specifies the function used to pre-hash the message
	// before signing.
	PreHashID PreHashID
	// A context of at most MaxContextSize bytes.
	Context []byte
	// True for deterministic signatures, false for randomized signatures.
	IsDeterministic bool
}

// HashFunc returns a [crypto.Hash] function only when the PreHashID field
// in the options corresponds to either SHA256 or SHA512.
// Otherwise, it returns the zero value.
func (s SignatureOpts) HashFunc() (h crypto.Hash) {
	switch s.PreHashID {
	case PreHashSHA256, PreHashSHA512:
		h = crypto.Hash(s.PreHashID)
	}
	return
}

func readRandom(random io.Reader, size uint32) (out []byte, err error) {
	out = make([]byte, size)
	if random == nil {
		random = rand.Reader
	}
	_, err = io.ReadFull(random, out)
	return
}

var (
	ErrContext  = fmt.Errorf("sign/slhdsa: context is larger than MaxContextSize=%v bytes", MaxContextSize)
	ErrParam    = errors.New("sign/slhdsa: invalid SLH-DSA parameter")
	ErrPreHash  = errors.New("sign/slhdsa: invalid prehash function")
	ErrSigParse = errors.New("sign/slhdsa: failed to decode the signature")
	ErrTree     = errors.New("sign/slhdsa: invalid tree height or tree index")
	ErrWriting  = errors.New("sign/slhdsa: failed to write to a hash function")
)
