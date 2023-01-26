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

	Players   uint
	Threshold uint
}

func (kshare KeyShare) String() string {
	return fmt.Sprintf("(t,n): (%v,%v) index: %v si: 0x%v",
		kshare.Threshold, kshare.Players, kshare.Index, kshare.si.Text(16))
}

// MarshalBinary encodes a KeyShare into a byte array in a format readable by UnmarshalBinary.
// Note: Only Index's up to math.MaxUint16 are supported
func (kshare *KeyShare) MarshalBinary() ([]byte, error) {
	// The encoding format is
	// | Players: uint16 | Threshold: uint16 | Index: uint16 | siLen: uint16 | si: []byte | twoDeltaSiNil: bool | twoDeltaSiLen: uint16 | twoDeltaSi: []byte |
	// with all values in big-endian.

	if kshare.Players > math.MaxUint16 {
		return nil, fmt.Errorf("rsa_threshold: keyshare marshall: Players is too big to fit in a uint16")
	}

	if kshare.Threshold > math.MaxUint16 {
		return nil, fmt.Errorf("rsa_threshold: keyshare marshall: Threhsold is too big to fit in a uint16")
	}

	if kshare.Index > math.MaxUint16 {
		return nil, fmt.Errorf("rsa_threshold: keyshare marshall: Index is too big to fit in a uint16")
	}

	players := uint16(kshare.Players)
	threshold := uint16(kshare.Threshold)
	index := uint16(kshare.Index)

	twoDeltaSiBytes := []byte(nil)
	if kshare.twoDeltaSi != nil {
		twoDeltaSiBytes = kshare.twoDeltaSi.Bytes()
	}

	twoDeltaSiLen := len(twoDeltaSiBytes)

	if twoDeltaSiLen > math.MaxInt16 {
		return nil, fmt.Errorf("rsa_threshold: keyshare marshall: twoDeltaSiBytes is too big to fit it's length in a uint16")
	}

	siBytes := kshare.si.Bytes()

	siLength := len(siBytes)

	if siLength == 0 {
		siLength = 1
		siBytes = []byte{0}
	}

	if siLength > math.MaxInt16 {
		return nil, fmt.Errorf("rsa_threshold: keyshare marshall: siBytes is too big to fit it's length in a uint16")
	}

	blen := 2 + 2 + 2 + 2 + 2 + 1 + siLength + twoDeltaSiLen
	out := make([]byte, blen)

	binary.BigEndian.PutUint16(out[0:2], players)
	binary.BigEndian.PutUint16(out[2:4], threshold)
	binary.BigEndian.PutUint16(out[4:6], index)

	binary.BigEndian.PutUint16(out[6:8], uint16(siLength)) // okay because of conditions checked above

	copy(out[8:8+siLength], siBytes)

	if twoDeltaSiBytes != nil {
		out[8+siLength] = 1 // twoDeltaSiNil
	}

	binary.BigEndian.PutUint16(out[8+siLength+1:8+siLength+3], uint16(twoDeltaSiLen))

	if twoDeltaSiBytes != nil {
		copy(out[8+siLength+3:8+siLength+3+twoDeltaSiLen], twoDeltaSiBytes)
	}

	return out, nil
}

// UnmarshalBinary recovers a KeyShare from a slice of bytes, or returns an error if the encoding is invalid.
func (kshare *KeyShare) UnmarshalBinary(data []byte) error {
	// The encoding format is
	// | Players: uint16 | Threshold: uint16 | Index: uint16 | siLen: uint16 | si: []byte | twoDeltaSiNil: bool | twoDeltaSiLen: uint16 | twoDeltaSi: []byte |
	// with all values in big-endian.
	if len(data) < 6 {
		return fmt.Errorf("rsa_threshold: keyshare unmarshalKeyShareTest failed: data length was too short for reading Players, Threashold, Index")
	}

	players := binary.BigEndian.Uint16(data[0:2])
	threshold := binary.BigEndian.Uint16(data[2:4])
	index := binary.BigEndian.Uint16(data[4:6])

	if len(data[6:]) < 2 {
		return fmt.Errorf("rsa_threshold: keyshare unmarshalKeyShareTest failed: data length was too short for reading siLen length")
	}

	siLen := binary.BigEndian.Uint16(data[6:8])

	if siLen == 0 {
		return fmt.Errorf("rsa_threshold: keyshare unmarshalKeyShareTest failed: si is a required field but siLen was 0")
	}

	if uint16(len(data[8:])) < siLen {
		return fmt.Errorf("rsa_threshold: keyshare unmarshalKeyShareTest failed: data length was too short for reading si, needed: %d found: %d", siLen, len(data[8:]))
	}

	si := new(big.Int).SetBytes(data[8 : 8+siLen])

	if len(data[8+siLen:]) < 1 {
		return fmt.Errorf("rsa_threshold: keyshare unmarshalKeyShareTest failed: data length was too short for reading twoDeltaSiNil")
	}

	isNil := data[8+siLen]

	var twoDeltaSi *big.Int

	if isNil != 0 {
		if len(data[8+siLen+1:]) < 2 {
			return fmt.Errorf("rsa_threshold: keyshare unmarshalKeyShareTest failed: data length was too short for reading twoDeltaSiLen length")
		}

		twoDeltaSiLen := binary.BigEndian.Uint16(data[8+siLen+1 : 8+siLen+3])

		if uint16(len(data[8+siLen+3:])) < twoDeltaSiLen {
			return fmt.Errorf("rsa_threshold: keyshare unmarshalKeyShareTest failed: data length was too short for reading twoDeltaSi, needed: %d found: %d", twoDeltaSiLen, len(data[8+siLen+2:]))
		}

		twoDeltaSi = new(big.Int).SetBytes(data[8+siLen+3 : 8+siLen+3+twoDeltaSiLen])
	}

	kshare.Players = uint(players)
	kshare.Threshold = uint(threshold)
	kshare.Index = uint(index)
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
func (kshare *KeyShare) Sign(randSource io.Reader, pub *rsa.PublicKey, digest []byte, parallel bool) (SignShare, error) {
	x := &big.Int{}
	x.SetBytes(digest)

	exp := kshare.get2DeltaSi(int64(kshare.Players))

	var signShare SignShare
	signShare.Players = kshare.Players
	signShare.Threshold = kshare.Threshold
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
