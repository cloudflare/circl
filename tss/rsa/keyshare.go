package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"

	"github.com/cloudflare/circl/internal/conv"
	"github.com/cloudflare/circl/zk/qndleq"
	"golang.org/x/crypto/cryptobyte"
)

// VerifyKeys contains keys used to verify whether a signature share
// was computed using the signer's key share.
type VerifyKeys struct {
	// This key is common to the group of signers.
	GroupKey *big.Int
	// This key is the (public) key associated with the (private) key share.
	VerifyKey *big.Int
}

func (v VerifyKeys) String() string {
	return fmt.Sprintf("groupKey: 0x%v verifyKey: 0x%v",
		v.GroupKey.Text(16), v.VerifyKey.Text(16))
}

// KeyShare represents a portion of the key. It can only be used to generate SignShare's. During the dealing phase (when Deal is called), one KeyShare is generated per player.
type KeyShare struct {
	share

	si         *big.Int
	twoDeltaSi *big.Int // this value is used to marginally speed up SignShare generation in Sign.

	// It stores keys to produce verifiable signature shares.
	// If it's nil, signature shares are still produced but
	// they are not verifiable.
	// This field is present only if the RSA private key is
	// composed of two safe primes.
	vk *VerifyKeys
}

func (kshare KeyShare) String() string {
	return fmt.Sprintf("%v si: 0x%v twoDeltaSi: 0x%v vk: {%v}",
		kshare.share, kshare.si.Text(16), kshare.twoDeltaSi.Text(16), kshare.vk,
	)
}

func (kshare *KeyShare) MarshalBinary() ([]byte, error) { return conv.MarshalBinary(kshare) }
func (kshare *KeyShare) UnmarshalBinary(b []byte) error { return conv.UnmarshalBinary(kshare, b) }

func (kshare *KeyShare) Marshal(b *cryptobyte.Builder) error {
	buf := make([]byte, (kshare.ModulusLength+7)/8)
	b.AddValue(&kshare.share)
	b.AddBytes(kshare.si.FillBytes(buf))
	b.AddBytes(kshare.twoDeltaSi.FillBytes(buf))

	isVerifiable := kshare.IsVerifiable()
	var flag uint8
	if isVerifiable {
		flag = 0x01
	}
	b.AddUint8(flag)
	if isVerifiable {
		b.AddBytes(kshare.vk.GroupKey.FillBytes(buf))
		b.AddBytes(kshare.vk.VerifyKey.FillBytes(buf))
	}

	return nil
}

func (kshare *KeyShare) ReadValue(r *cryptobyte.String) bool {
	var sh share
	ok := sh.ReadValue(r)
	if !ok {
		return false
	}

	mlen := int((sh.ModulusLength + 7) / 8)
	var siBytes, twoDeltaSiBytes []byte
	ok = r.ReadBytes(&siBytes, mlen) &&
		r.ReadBytes(&twoDeltaSiBytes, mlen)
	if !ok {
		return false
	}

	var isVerifiable uint8
	ok = r.ReadUint8(&isVerifiable)
	if !ok {
		return false
	}

	var vk *VerifyKeys
	switch isVerifiable {
	case 0:
		vk = nil
	case 1:
		var groupKeyBytes, verifyKeyBytes []byte
		ok = r.ReadBytes(&groupKeyBytes, mlen) &&
			r.ReadBytes(&verifyKeyBytes, mlen)
		if !ok {
			return false
		}

		vk = &VerifyKeys{
			GroupKey:  new(big.Int).SetBytes(groupKeyBytes),
			VerifyKey: new(big.Int).SetBytes(verifyKeyBytes),
		}
	default:
		return false
	}

	kshare.share = sh
	kshare.si = new(big.Int).SetBytes(siBytes)
	kshare.twoDeltaSi = new(big.Int).SetBytes(twoDeltaSiBytes)
	kshare.vk = vk

	return true
}

// Returns calculates and returns twoDeltaSi = 2∆s_i mod m.
func (kshare *KeyShare) get2DeltaSi(players int64, m *big.Int) *big.Int {
	delta := calculateDelta(players)
	// 2∆s_i
	// delta << 1 == delta * 2
	delta.Lsh(delta, 1).Mul(delta, kshare.si).Mod(delta, m)
	kshare.twoDeltaSi = delta
	return delta
}

// IsVerifiable returns true if the key share can produce
// verifiable signature shares.
func (kshare *KeyShare) IsVerifiable() bool { return kshare.vk != nil }

// VerifyKeys returns a copy of the verification keys used to verify
// signature shares. Panics if the key share cannot produce
// verifiable signature shares. Use the [IsVerifiable] method to
// determine whether there are associated verification keys.
func (kshare *KeyShare) VerifyKeys() (vk *VerifyKeys) {
	if !kshare.IsVerifiable() {
		panic(ErrKeyShareNonVerifiable)
	}

	return &VerifyKeys{
		GroupKey:  new(big.Int).Set(kshare.vk.GroupKey),
		VerifyKey: new(big.Int).Set(kshare.vk.VerifyKey),
	}
}

// Sign msg using a KeyShare. msg MUST be padded and hashed. Call PadHash before this method.
//
// If rand is not nil then blinding will be used to avoid timing
// side-channel attacks.
//
// parallel indicates whether the blinding operations should use go routines to operate in parallel.
// If parallel is false, blinding will take about 2x longer than nonbinding, otherwise it will take about the same time
// (see benchmarks). If randSource is nil, parallel has no effect. parallel should almost always be set to true.
func (kshare *KeyShare) Sign(randSource io.Reader, pub *rsa.PublicKey, digest []byte, parallel bool) (*SignShare, error) {
	x := &big.Int{}
	x.SetBytes(digest)

	exp := kshare.twoDeltaSi

	signShare := new(SignShare)
	signShare.share = kshare.share
	signShare.xi = &big.Int{}

	if randSource != nil {
		// Let's blind.
		// We can't use traditional RSA blinding (as used in rsa.go) because we are exponentiating by exp and not d.
		// As such, Euler's theorem doesn't apply ( exp * d != 0 (mod ϕ(n)) ).
		// Instead, we will choose a random r and compute x^{exp+r} * x^{-r} = x^{exp}.
		// This should (hopefully) prevent revealing information of the true value of exp, since with exp you can derive
		// s_i, the secret key share.

		r, err := rand.Int(randSource, pub.N)
		if err != nil {
			return nil, errors.New("rsa_threshold: unable to get random value for blinding")
		}
		expPlusr := big.Int{}
		// exp + r
		expPlusr.Add(exp, r)

		var wg *sync.WaitGroup

		// x^{|2∆s_i+r|}
		if parallel {
			wg = &sync.WaitGroup{}
			wg.Add(1)
			go func() {
				signShare.xi.Exp(x, &expPlusr, pub.N)
				wg.Done()
			}()
		} else {
			signShare.xi.Exp(x, &expPlusr, pub.N)
		}

		xExpr := big.Int{}
		// x^r
		xExpr.Exp(x, r, pub.N)
		// x^{-r}
		res := xExpr.ModInverse(&xExpr, pub.N)

		if res == nil {
			// extremely unlikely, somehow x^r is p or q
			return nil, errors.New("rsa_threshold: no mod inverse")
		}

		if wg != nil {
			wg.Wait()
		}

		// x^{|2∆s_i+r|} * x^{-r} = x^{2∆s_i}
		signShare.xi.Mul(signShare.xi, &xExpr)
		signShare.xi.Mod(signShare.xi, pub.N)
	} else {
		// x^{2∆s_i}
		signShare.xi = &big.Int{}
		signShare.xi.Exp(x, exp, pub.N)
	}

	// When verification keys are available, a DLEQ Proof is included.
	if kshare.vk != nil {
		const SecParam = 128
		fourDelta := calculateDelta(int64(kshare.Players))
		fourDelta.Lsh(fourDelta, 2)
		x4Delta := new(big.Int).Exp(x, fourDelta, pub.N)
		xiSqr := new(big.Int).Mul(signShare.xi, signShare.xi)
		xiSqr.Mod(xiSqr, pub.N)

		proof, err := qndleq.Prove(randSource,
			kshare.si,
			kshare.vk.GroupKey, kshare.vk.VerifyKey,
			x4Delta, xiSqr,
			pub.N, SecParam)
		if err != nil {
			return nil, err
		}
		signShare.proof = proof
	}

	return signShare, nil
}
