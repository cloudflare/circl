package sidh

import (
	"crypto/subtle"
	"errors"
	"io"

	"github.com/cloudflare/circl/dh/sidh/internal/common"
	"github.com/cloudflare/circl/internal/sha3"
)

// SIKE KEM interface.
//
// Deprecated: not cryptographically secure.
type KEM struct {
	allocated   bool
	rng         io.Reader
	msg         []byte
	secretBytes []byte
	params      *common.SidhParams
	shake       sha3.State
}

// NewSike434 instantiates SIKE/p434 KEM.
//
// Deprecated: not cryptographically secure.
func NewSike434(rng io.Reader) *KEM {
	var c KEM
	c.Allocate(Fp434, rng)
	return &c
}

// NewSike503 instantiates SIKE/p503 KEM.
//
// Deprecated: not cryptographically secure.
func NewSike503(rng io.Reader) *KEM {
	var c KEM
	c.Allocate(Fp503, rng)
	return &c
}

// NewSike751 instantiates SIKE/p751 KEM.
//
// Deprecated: not cryptographically secure.
func NewSike751(rng io.Reader) *KEM {
	var c KEM
	c.Allocate(Fp751, rng)
	return &c
}

// Allocate allocates KEM object for multiple SIKE operations. The rng
// must be cryptographically secure PRNG.
func (c *KEM) Allocate(id uint8, rng io.Reader) {
	c.rng = rng
	c.params = common.Params(id)
	c.msg = make([]byte, c.params.MsgLen)
	c.secretBytes = make([]byte, c.params.A.SecretByteLen)
	c.shake = sha3.NewShake256()
	c.allocated = true
}

// Encapsulate receives the public key and generates SIKE ciphertext and shared secret.
// The generated ciphertext is used for authentication.
// Error is returned in case PRNG fails. Function panics in case wrongly formatted
// input was provided.
func (c *KEM) Encapsulate(ciphertext, secret []byte, pub *PublicKey) error {
	if !c.allocated {
		panic("KEM unallocated")
	}

	if KeyVariantSike != pub.keyVariant {
		panic("Wrong type of public key")
	}

	if len(secret) < c.SharedSecretSize() {
		panic("shared secret buffer to small")
	}

	if len(ciphertext) < c.CiphertextSize() {
		panic("ciphertext buffer to small")
	}

	// Generate ephemeral value
	_, err := io.ReadFull(c.rng, c.msg[:])
	if err != nil {
		return err
	}

	var buf [3 * common.MaxSharedSecretBsz]byte
	skA := PrivateKey{
		key: key{
			params:     c.params,
			keyVariant: KeyVariantSidhA,
		},
		Scalar: c.secretBytes,
	}
	pkA := NewPublicKey(c.params.ID, KeyVariantSidhA)

	pub.Export(buf[:])
	c.shake.Reset()
	_, _ = c.shake.Write(c.msg)
	_, _ = c.shake.Write(buf[:3*c.params.SharedSecretSize])
	_, _ = c.shake.Read(skA.Scalar)

	// Ensure bitlength is not bigger then to 2^e2-1
	skA.Scalar[len(skA.Scalar)-1] &= (1 << (c.params.A.SecretBitLen % 8)) - 1
	skA.GeneratePublicKey(pkA)
	c.generateCiphertext(ciphertext, &skA, pkA, pub, c.msg[:])

	// K = H(msg||(c0||c1))
	c.shake.Reset()
	_, _ = c.shake.Write(c.msg)
	_, _ = c.shake.Write(ciphertext)
	_, _ = c.shake.Read(secret[:c.SharedSecretSize()])
	return nil
}

// Decapsulate given the keypair and ciphertext as inputs, Decapsulate outputs a shared
// secret if plaintext verifies correctly, otherwise function outputs random value.
// Decapsulation may panic in case input is wrongly formatted, in particular, size of
// the 'ciphertext' must be exactly equal to c.CiphertextSize().
func (c *KEM) Decapsulate(secret []byte, prv *PrivateKey, pub *PublicKey, ciphertext []byte) error {
	if !c.allocated {
		panic("KEM unallocated")
	}

	if KeyVariantSike != pub.keyVariant {
		panic("Wrong type of public key")
	}

	if pub.keyVariant != prv.keyVariant {
		panic("Public and private key are of different type")
	}

	if len(secret) < c.SharedSecretSize() {
		panic("shared secret buffer to small")
	}

	if len(ciphertext) != c.CiphertextSize() {
		panic("ciphertext buffer to small")
	}

	var m [common.MaxMsgBsz]byte
	var r [common.MaxSidhPrivateKeyBsz]byte
	var pkBytes [3 * common.MaxSharedSecretBsz]byte
	skA := PrivateKey{
		key: key{
			params:     c.params,
			keyVariant: KeyVariantSidhA,
		},
		Scalar: c.secretBytes,
	}
	pkA := NewPublicKey(c.params.ID, KeyVariantSidhA)
	c1Len, err := c.decrypt(m[:], prv, ciphertext)
	if err != nil {
		return err
	}

	// r' = G(m'||pub)
	pub.Export(pkBytes[:])
	c.shake.Reset()
	_, _ = c.shake.Write(m[:c1Len])
	_, _ = c.shake.Write(pkBytes[:3*c.params.SharedSecretSize])
	_, _ = c.shake.Read(r[:c.params.A.SecretByteLen])
	// Ensure bitlength is not bigger than 2^e2-1
	r[c.params.A.SecretByteLen-1] &= (1 << (c.params.A.SecretBitLen % 8)) - 1

	err = skA.Import(r[:c.params.A.SecretByteLen])
	if err != nil {
		return err
	}
	skA.GeneratePublicKey(pkA)
	pkA.Export(pkBytes[:])

	// S is chosen at random when generating a key and unknown to other party. It is
	// important that S is unpredictable to the other party.  Without this check, would
	// be possible to recover a secret, by providing series of invalid ciphertexts.
	//
	// See more details in "On the security of supersingular isogeny cryptosystems"
	// (S. Galbraith, et al., 2016, ePrint #859).
	mask := subtle.ConstantTimeCompare(pkBytes[:c.params.PublicKeySize], ciphertext[:pub.params.PublicKeySize])
	common.Cpick(mask, m[:c1Len], m[:c1Len], prv.S)
	c.shake.Reset()
	_, _ = c.shake.Write(m[:c1Len])
	_, _ = c.shake.Write(ciphertext)
	_, _ = c.shake.Read(secret[:c.SharedSecretSize()])
	return nil
}

// Resets internal state of KEM. Function should be used
// after Allocate and between subsequent calls to Encapsulate
// and/or Decapsulate.
func (c *KEM) Reset() {
	for i := range c.msg {
		c.msg[i] = 0
	}

	for i := range c.secretBytes {
		c.secretBytes[i] = 0
	}
}

// Returns size of resulting ciphertext.
func (c *KEM) CiphertextSize() int {
	return c.params.CiphertextSize
}

// Returns size of resulting shared secret.
func (c *KEM) SharedSecretSize() int {
	return c.params.KemSize
}

// PublicKeySize returns size of the public key in bytes.
func (c *KEM) PublicKeySize() int {
	return c.params.PublicKeySize
}

// Size returns size of the private key in bytes.
func (c *KEM) PrivateKeySize() int {
	return int(c.params.B.SecretByteLen) + c.params.MsgLen
}

func (c *KEM) generateCiphertext(ctext []byte, skA *PrivateKey, pkA, pkB *PublicKey, ptext []byte) {
	var n [common.MaxMsgBsz]byte
	var j [common.MaxSharedSecretBsz]byte
	ptextLen := skA.params.MsgLen

	skA.DeriveSecret(j[:], pkB)
	c.shake.Reset()
	_, _ = c.shake.Write(j[:skA.params.SharedSecretSize])
	_, _ = c.shake.Read(n[:ptextLen])
	for i := range ptext {
		n[i] ^= ptext[i]
	}

	pkA.Export(ctext)
	copy(ctext[pkA.Size():], n[:ptextLen])
}

// encrypt uses SIKE public key to encrypt plaintext. Requires cryptographically secure
// PRNG. Returns ciphertext in case encryption succeeds. Returns error in case PRNG fails
// or wrongly formated input was provided.
func (c *KEM) encrypt(ctext []byte, rng io.Reader, pub *PublicKey, ptext []byte) error {
	ptextLen := len(ptext)
	// c1 must be security level + 64 bits (see [SIKE] 1.4 and 4.3.3)
	if ptextLen != pub.params.KemSize {
		return errors.New("unsupported message length")
	}

	skA := NewPrivateKey(pub.params.ID, KeyVariantSidhA)
	pkA := NewPublicKey(pub.params.ID, KeyVariantSidhA)
	err := skA.Generate(rng)
	if err != nil {
		return err
	}

	skA.GeneratePublicKey(pkA)
	c.generateCiphertext(ctext, skA, pkA, pub, ptext)
	return nil
}

// decrypt uses SIKE private key to decrypt ciphertext. Returns plaintext in case
// decryption succeeds or error in case unexpected input was provided.
// Constant time.
func (c *KEM) decrypt(n []byte, prv *PrivateKey, ctext []byte) (int, error) {
	var c1Len int
	var j [common.MaxSharedSecretBsz]byte
	pkLen := prv.params.PublicKeySize

	// ctext is a concatenation of (ciphertext = pubkey_A || c1)
	// it must be security level + 64 bits (see [SIKE] 1.4 and 4.3.3)
	// Lengths has been already checked by Decapsulate()
	c1Len = len(ctext) - pkLen
	c0 := NewPublicKey(prv.params.ID, KeyVariantSidhA)
	err := c0.Import(ctext[:pkLen])
	prv.DeriveSecret(j[:], c0)
	c.shake.Reset()
	_, _ = c.shake.Write(j[:prv.params.SharedSecretSize])
	_, _ = c.shake.Read(n[:c1Len])
	for i := range n[:c1Len] {
		n[i] ^= ctext[pkLen+i]
	}
	return c1Len, err
}
