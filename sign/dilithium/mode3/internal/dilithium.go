package internal

import (
	cryptoRand "crypto/rand"
	"io"

	"github.com/cloudflare/circl/internal/shake"
	common "github.com/cloudflare/circl/sign/dilithium/internal"
)

const (
	// Size of a packed polynomial of norm ≤η.
	// (Note that the  formula is not valid in general.)
	PolyLeqEtaSize = (common.N * DoubleEtaBits) / 8
)

// PublicKey is the type of Dilithium public keys.
type PublicKey struct {
	rho [32]byte
	t1  VecK

	// Cached values
	t1p [common.PolyT1Size * K]byte
	A   *Mat
	tr  *[48]byte
}

// PrivateKey is the type of Dilithium private keys.
type PrivateKey struct {
	rho [32]byte
	key [32]byte
	s1  VecL
	s2  VecK
	t0  VecK
	tr  [48]byte

	// Cached values
	A   Mat  // ExpandA(ρ)
	s1h VecL // NTT(s₁)
	s2h VecK // NTT(s₂)
	t0h VecK // NTT(t₀)
}

type unpackedSignature struct {
	z    VecL
	hint VecK
	c    common.Poly
}

// Packs the signature into buf.
func (sig *unpackedSignature) Pack(buf []byte) {
	sig.z.PackLeGamma1(buf[:])
	sig.hint.PackHint(buf[L*common.PolyLeGamma1Size:])
	sig.c.PackB60(buf[L*common.PolyLeGamma1Size+Omega+K:])
}

// Sets sig to the signature encoded in the buffer.
//
// Returns whether buf contains a properly packed signature.
func (sig *unpackedSignature) Unpack(buf []byte) bool {
	if len(buf) < SignatureSize {
		return false
	}
	sig.z.UnpackLeGamma1(buf[:])
	if sig.z.Exceeds(common.Gamma1 - Beta) {
		return false
	}
	if !sig.hint.UnpackHint(buf[L*common.PolyLeGamma1Size:]) {
		return false
	}
	sig.c.UnpackB60(buf[L*common.PolyLeGamma1Size+Omega+K:])
	return true
}

// Packs the public key into buf.
func (pk *PublicKey) Pack(buf *[PublicKeySize]byte) {
	copy(buf[:32], pk.rho[:])
	copy(buf[32:], pk.t1p[:])
}

// Sets pk to the public key encoded in buf.
func (pk *PublicKey) Unpack(buf *[PublicKeySize]byte) {
	copy(pk.rho[:], buf[:32])
	copy(pk.t1p[:], buf[32:])

	pk.t1.UnpackT1(pk.t1p[:])
	pk.A = new(Mat)
	pk.A.Derive(&pk.rho)

	// tr = CRH(ρ ‖ t1) = CRH(pk)
	pk.tr = new([48]byte)
	h := shake.NewShake256()
	_, _ = h.Write(buf[:])
	_, _ = h.Read(pk.tr[:])
}

// Packs the private key into buf.
func (sk *PrivateKey) Pack(buf *[PrivateKeySize]byte) {
	copy(buf[:32], sk.rho[:])
	copy(buf[32:64], sk.key[:])
	copy(buf[64:112], sk.tr[:])
	offset := 112
	sk.s1.PackLeqEta(buf[offset:])
	offset += PolyLeqEtaSize * L
	sk.s2.PackLeqEta(buf[offset:])
	offset += PolyLeqEtaSize * K
	sk.t0.PackT0(buf[offset:])
}

// Sets sk to the private key encoded in buf.
func (sk *PrivateKey) Unpack(buf *[PrivateKeySize]byte) {
	copy(sk.rho[:], buf[:32])
	copy(sk.key[:], buf[32:64])
	copy(sk.tr[:], buf[64:112])
	offset := 112
	sk.s1.UnpackLeqEta(buf[offset:])
	offset += PolyLeqEtaSize * L
	sk.s2.UnpackLeqEta(buf[offset:])
	offset += PolyLeqEtaSize * K
	sk.t0.UnpackT0(buf[offset:])

	// Cached values
	sk.A.Derive(&sk.rho)
	sk.t0h = sk.t0
	sk.t0h.NTT()
	sk.s1h = sk.s1
	sk.s1h.NTT()
	sk.s2h = sk.s2
	sk.s2h.NTT()
}

// GenerateKey generates a public/private key pair using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func GenerateKey(rand io.Reader) (*PublicKey, *PrivateKey, error) {
	var seed [32]byte
	if rand == nil {
		rand = cryptoRand.Reader
	}
	_, err := io.ReadFull(rand, seed[:])
	if err != nil {
		return nil, nil, err
	}
	pk, sk := NewKeyFromSeed(&seed)
	return pk, sk, nil
}

// NewKeyFromExpandedSeed derives a public/private key pair using the
// given expanded seed.
//
// Use NewKeyFromSeed instead of this function.  This function is only exposed
// to generate the NIST KAT test vectors.
func NewKeyFromExpandedSeed(seed *[96]byte) (*PublicKey, *PrivateKey) {
	var pk PublicKey
	var sk PrivateKey
	var sSeed [32]byte

	copy(pk.rho[:], seed[:32])
	copy(sSeed[:], seed[32:64])
	copy(sk.key[:], seed[64:])
	copy(sk.rho[:], pk.rho[:])

	sk.A.Derive(&pk.rho)

	for i := uint16(0); i < L; i++ {
		PolyDeriveUniformLeqEta(&sk.s1[i], &sSeed, i)
	}

	for i := uint16(0); i < K; i++ {
		PolyDeriveUniformLeqEta(&sk.s2[i], &sSeed, i+L)
	}

	sk.s1h = sk.s1
	sk.s1h.NTT()
	sk.s2h = sk.s2
	sk.s2h.NTT()

	sk.computeT0andT1(&sk.t0, &pk.t1)

	sk.t0h = sk.t0
	sk.t0h.NTT()

	// Complete public key far enough to be packed
	pk.t1.PackT1(pk.t1p[:])
	pk.A = &sk.A

	// Finish private key
	var packedPk [PublicKeySize]byte
	pk.Pack(&packedPk)

	// tr = CRH(ρ ‖ t1) = CRH(pk)
	h := shake.NewShake256()
	_, _ = h.Write(packedPk[:])
	_, _ = h.Read(sk.tr[:])

	// Finish cache of public key
	pk.tr = &sk.tr

	return &pk, &sk
}

// Computes t0 and t1 from sk.s1h, sk.s2 and sk.A.
func (sk *PrivateKey) computeT0andT1(t0, t1 *VecK) {
	var t VecK

	// Set t to A s₁ + s₂
	for i := 0; i < K; i++ {
		PolyDotHat(&t[i], &sk.A[i], &sk.s1h)
		t[i].ReduceLe2Q()
		t[i].InvNTT()
	}
	t.Add(&t, &sk.s2)
	t.Normalize()

	// Compute t₀, t₁ = Power2Round(t)
	t.Power2Round(t0, t1)
}

// NewKeyFromSeed derives a public/private key pair using the given seed.
func NewKeyFromSeed(seed *[common.SeedSize]byte) (*PublicKey, *PrivateKey) {
	var buf [96]byte
	h := shake.NewShake128()
	_, _ = h.Write(seed[:])
	_, _ = h.Read(buf[:])
	return NewKeyFromExpandedSeed(&buf)
}

// Verify checks whether the given signature by pk on msg is valid.
func Verify(pk *PublicKey, msg []byte, signature []byte) bool {
	var sig unpackedSignature
	var mu [48]byte
	var zh VecL
	var Az, Az2dct1, w1 VecK
	var ch, cp common.Poly

	// Note that Unpack() checked whether ‖z‖_∞ < γ₁ - β
	// and ensured that there at most ω ones in pk.hint.
	if !sig.Unpack(signature) {
		return false
	}

	// μ = CRH(tr ‖ msg)
	h := shake.NewShake256()
	_, _ = h.Write(pk.tr[:])
	_, _ = h.Write(msg)
	_, _ = h.Read(mu[:])

	// Compute Az
	zh = sig.z
	zh.NTT()

	for i := 0; i < K; i++ {
		PolyDotHat(&Az[i], &pk.A[i], &zh)
	}

	// Next, we compute Az - 2ᵈ·c·t₁.
	// Note that the coefficients of t₁ are bounded by 256 = 2⁹,
	// so the coefficients of Az2dct1 will bounded by 2⁹⁺ᵈ = 2²³ < 2q,
	// which is small enough for NTT().
	Az2dct1.MulBy2toD(&pk.t1)
	Az2dct1.NTT()
	ch = sig.c
	ch.NTT()
	for i := 0; i < K; i++ {
		Az2dct1[i].MulHat(&Az2dct1[i], &ch)
	}
	Az2dct1.Sub(&Az, &Az2dct1)
	Az2dct1.ReduceLe2Q()
	Az2dct1.InvNTT()
	Az2dct1.NormalizeAssumingLe2Q()

	// UseHint(pk.hint, Az - 2ᵈ·c·t₁)
	//    = UseHint(pk.hint, w - c·s₂ + c·t₀)
	//    = UseHint(pk.hint, r + c·t₀)
	//    = r₁ = w₁.
	w1.UseHint(&Az2dct1, &sig.hint)

	// c' = H(μ, w₁)
	PolyDeriveUniformB60(&cp, &mu, &w1)
	return sig.c == cp
}

// SignTo signs the given message and writes the signature into signature.
func SignTo(sk *PrivateKey, msg []byte, signature []byte) {
	var mu, rhop [48]byte
	var y, yh VecL
	var w, w0, w1, w0mcs2, ct0, w0mcs2pct0 VecK
	var ch common.Poly
	var yNonce uint16
	var sig unpackedSignature

	if len(signature) < SignatureSize {
		panic("Signature does not fit in that byteslice")
	}

	//  μ = CRH(tr ‖ msg)
	h := shake.NewShake256()
	_, _ = h.Write(sk.tr[:])
	_, _ = h.Write(msg)
	_, _ = h.Read(mu[:])

	// ρ' = CRH(μ ‖ key)
	h.Reset()
	_, _ = h.Write(sk.key[:])
	_, _ = h.Write(mu[:])
	_, _ = h.Read(rhop[:])

	// Main rejection loop
	attempt := 0
	for {
		attempt++
		if attempt >= 576 {
			// Depending on the mode, one try has a chance between 1/7 and 1/4
			// of succeeding.  Thus it is safe to say that 576 iterations
			// are enough as (6/7)⁵⁷⁶ < 2⁻¹²⁸.
			panic("This should only happen 1 in  2^{128}: something is wrong.")
		}

		// y = ExpandMask(ρ', key)
		VecLDeriveUniformLeGamma1(&y, &rhop, yNonce)
		yNonce += uint16(L)

		// Set w to A y
		yh = y
		yh.NTT()
		for i := 0; i < K; i++ {
			PolyDotHat(&w[i], &sk.A[i], &yh)
			w[i].ReduceLe2Q()
			w[i].InvNTT()
		}

		// Decompose w into w₀ and w₁
		w.NormalizeAssumingLe2Q()
		w.Decompose(&w0, &w1)

		// c = H(μ, w₁)
		PolyDeriveUniformB60(&sig.c, &mu, &w1)
		ch = sig.c
		ch.NTT()

		// Ensure ‖ w₀ - c·s2 ‖_∞ < γ₂ - β.
		//
		// By Lemma 3 of the specification this is equivalent to checking that
		// both ‖ r₀ ‖_∞ < γ₂ - β and r₁ = w₁, for the decomposition
		// w - c·s₂	 = r₁ α + r₀ as computed by decompose().
		// See also §4.1 of the specification.
		for i := 0; i < K; i++ {
			w0mcs2[i].MulHat(&ch, &sk.s2h[i])
			w0mcs2[i].InvNTT()
		}
		w0mcs2.Sub(&w0, &w0mcs2)
		w0mcs2.Normalize()

		if w0mcs2.Exceeds(common.Gamma2 - Beta) {
			continue
		}

		// z = y + c·s₁
		for i := 0; i < L; i++ {
			sig.z[i].MulHat(&ch, &sk.s1h[i])
			sig.z[i].InvNTT()
		}
		sig.z.Add(&sig.z, &y)
		sig.z.Normalize()

		// Ensure  ‖z‖_∞ < γ₁ - β
		if sig.z.Exceeds(common.Gamma1 - Beta) {
			continue
		}

		// Compute c·t₀
		for i := 0; i < K; i++ {
			ct0[i].MulHat(&ch, &sk.t0h[i])
			ct0[i].InvNTT()
		}
		ct0.NormalizeAssumingLe2Q()

		// Ensure ‖c·t₀‖_∞ < γ₂.
		if ct0.Exceeds(common.Gamma2) {
			continue
		}

		// Create the hint to be able to reconstruct w₁ from w - c·s₂ + c·t0.
		// Note that we're not using makeHint() in the obvious way as we
		// do not know whether ‖ sc·s₂ - c·t₀ ‖_∞ < γ₂.  Instead we note
		// that our makeHint() is actually the same as a makeHint for a
		// different decomposition:
		//
		// Earlier we ensured indirectly with a check that r₁ = w₁ where
		// r = w - c·s₂.  Hence r₀ = r - r₁ α = w - c·s₂ - w₁ α = w₀ - c·s₂.
		// Thus  MakeHint(w₀ - c·s₂ + c·t₀, w₁) = MakeHint(r0 + c·t₀, r₁)
		// and UseHint(w - c·s₂ + c·t₀, w₁) = UseHint(r + c·t₀, r₁).
		// As we just ensured that ‖ c·t₀ ‖_∞ < γ₂ our usage is correct.
		w0mcs2pct0.Add(&w0mcs2, &ct0)
		w0mcs2pct0.NormalizeAssumingLe2Q()
		hintPop := sig.hint.MakeHint(&w0mcs2pct0, &w1)
		if hintPop > Omega {
			continue
		}

		break
	}

	sig.Pack(signature[:])
}

// Computes the public key corresponding to this private key.
func (sk *PrivateKey) Public() *PublicKey {
	var t0 VecK
	pk := &PublicKey{
		rho: sk.rho,
		A:   &sk.A,
		tr:  &sk.tr,
	}
	sk.computeT0andT1(&t0, &pk.t1)
	pk.t1.PackT1(pk.t1p[:])
	return pk
}
