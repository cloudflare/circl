package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"sync"
)

// KeyShare represents a portion of the key. It can only be used to generate SignShare's. During the dealing phase (when Deal is called), one KeyShare is generated per player.
type KeyShare struct {
	si *big.Int

	twoDeltaSi *big.Int // optional cached value, this value is used to marginally speed up SignShare generation in Sign. If nil, it will be generated when needed and then cached.
	Index      uint     // When KeyShare's are generated they are each assigned an index sequentially
}

// MarshalBinary encodes a KeyShare into a byte array in a format readable by UnmarshalBinary.
// Note: Only Index's up to math.MaxUint16 are supported
func (kshare *KeyShare) MarshalBinary() ([]byte, error) {
	// The encoding format is
	// | Index: uint16 | siLen: uint16 | si: []byte | twoDeltaSi: []byte |
	// with all values in big-endian.

	if kshare.Index > math.MaxUint16 {
		return nil, fmt.Errorf("rsa_threshold: keyshare marshall: Index is too big to fit in a uint16")
	}

	index := uint16(kshare.Index)

	var twoDeltaSiBytes []byte
	if kshare.twoDeltaSi != nil {
		twoDeltaSiBytes = kshare.twoDeltaSi.Bytes()
		if len(twoDeltaSiBytes) == 0 { // if twoDeltaSiBytes has a value of 0, then len(.Bytes) returns 0
			// but we actually want to store this so lets use a byte
			twoDeltaSiBytes = []byte{0}
		}
	}

	siBytes := kshare.si.Bytes()
	if len(siBytes) > math.MaxInt16 {
		return nil, fmt.Errorf("rsa_threshold: keyshare marshall: siBytes is too big to fit it's length in a uint16")
	}
	siLength := len(siBytes)
	if siLength == 0 { // same as above
		siLength = 1
	}

	blen := 2 + 2 + siLength + len(twoDeltaSiBytes)
	out := make([]byte, blen)

	binary.BigEndian.PutUint16(out[0:2], index) // ok because of condition checked above

	binary.BigEndian.PutUint16(out[2:4], uint16(siLength))

	copy(out[4:4+siLength], siBytes)

	copy(out[4+siLength:], twoDeltaSiBytes)

	return out, nil
}

// UnmarshalBinary recovers a KeyShare from a slice of bytes, or returns an error if the encoding is invalid.
func (kshare *KeyShare) UnmarshalBinary(data []byte) error {
	// The encoding format is
	// | Index: uint16 | siLen: uint16 | si: []byte | twoDeltaSi: []byte |
	// with all values in big-endian.
	if len(data) < 2 {
		return fmt.Errorf("rsa_threshold: keyshare unmarshal failed: data length was too short for reading Index")
	}

	i := binary.BigEndian.Uint16(data[0:2])

	if len(data[2:]) < 2 {
		return fmt.Errorf("rsa_threshold: keyshare unmarshal failed: data length was too short for reading siLen length")
	}

	siLen := binary.BigEndian.Uint16(data[2:4])

	if siLen == 0 {
		return fmt.Errorf("rsa_threshold: keyshare unmarshal failed: si is a required field but siLen was 0")
	}

	if uint16(len(data[4:])) < siLen {
		return fmt.Errorf("rsa_threshold: keyshare unmarshal failed: data length was too short for reading si, needed: %d found: %d", siLen, len(data[3:]))
	}

	si := new(big.Int).SetBytes(data[4 : 4+siLen])

	var twoDeltaSi *big.Int
	if len(data[4+siLen:]) > 0 {
		tmp := make([]byte, len(data[4+siLen:]))
		copy(tmp, data[4+siLen:])
		twoDeltaSi = &big.Int{}
		twoDeltaSi.SetBytes(tmp)
	}

	kshare.Index = uint(i)
	kshare.si = si
	kshare.twoDeltaSi = twoDeltaSi

	return nil
}

// Returns the cached value in twoDeltaSi or if nil, generates 2∆s_i, stores it in twoDeltaSi, and returns it
func (kshare *KeyShare) get2DeltaSi(players int64) *big.Int {
	// use the cached value if it exists
	if kshare.twoDeltaSi != nil {
		return kshare.twoDeltaSi
	}
	delta := calculateDelta(players)
	// 2∆s_i
	// delta << 1 == delta * 2
	delta.Lsh(delta, 1).Mul(delta, kshare.si)
	kshare.twoDeltaSi = delta
	return delta
}

// Sign msg using a KeyShare. msg MUST be padded and hashed. Call PadHash before this method.
//
// If rand is not nil then blinding will be used to avoid timing
// side-channel attacks.
//
// parallel indicates whether the blinding operations should use go routines to operate in parallel.
// If parallel is false, blinding will take about 2x longer than nonbinding, otherwise it will take about the same time
// (see benchmarks). If randSource is nil, parallel has no effect. parallel should almost always be set to true.
func (kshare *KeyShare) Sign(randSource io.Reader, players int64, pub *rsa.PublicKey, msg []byte, parallel bool) (SignShare, error) {
	x := &big.Int{}
	x.SetBytes(msg)

	exp := kshare.get2DeltaSi(players)

	var signShare SignShare
	signShare.Index = kshare.Index

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
			return SignShare{}, errors.New("rsa_threshold: unable to get random value for blinding")
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
			return SignShare{}, errors.New("rsa_threshold: no mod inverse")
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

	return signShare, nil
}
