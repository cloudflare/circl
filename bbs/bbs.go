package bbs

import (
	"crypto"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/cloudflare/circl/ecc/bls12381"
	pairing "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/cloudflare/circl/expander"
)

var (
	// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-03#name-bls12-381-sha-256
	ciphersuiteID  = []byte("BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_")
	octetScalarLen = 32
	octetPointLen  = 48
	h2cSuite       = []byte("BLS12381G1_XMD:SHA-256_SSWU_RO_")
	expandLength   = uint(48)
)

func ciphersuiteString(suffix string) []byte {
	// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-03#name-ciphersuite-id
	return append(ciphersuiteID, []byte(suffix)...)
}

func computeP1() *pairing.G1 {
	generatorSeed := ciphersuiteString("BP_MESSAGE_GENERATOR_SEED")
	p1 := hashToGenerators(1, generatorSeed)
	return p1[0]
}

type Signature struct {
	A *pairing.G1
	e *pairing.Scalar
}

func (s Signature) Encode() []byte {
	AEnc := s.A.BytesCompressed()
	eEnc, err := s.e.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return append(AEnc, eEnc...)
}

func UnmarshalSignature(data []byte) (Signature, error) {
	// 1.  expected_len = octet_point_length + octet_scalar_length
	expectedLen := octetPointLen + octetScalarLen
	// 2.  if length(signature_octets) != expected_len, return INVALID
	if len(data) != expectedLen {
		return Signature{}, fmt.Errorf("bbs: malformed signature")
	}

	// 3.  A_octets = signature_octets[0..(octet_point_length - 1)]
	// 4.  A = octets_to_point_g1(A_octets)
	AOctets := data[0:octetPointLen]
	A := &pairing.G1{}
	A.SetBytes(AOctets)

	// 5.  if A is INVALID, return INVALID
	if !A.IsOnG1() {
		return Signature{}, fmt.Errorf("bbs: invalid A signature component (not in G1)")
	}
	// 6.  if A == Identity_G1, return INVALID
	if A.IsIdentity() {
		return Signature{}, fmt.Errorf("bbs: invalid A signature component (identity element)")
	}

	// 7.  index = octet_point_length
	// 8.  end_index = index + octet_scalar_length - 1
	// 9.  e = OS2IP(signature_octets[index..end_index])
	e := &pairing.Scalar{}
	e.SetBytes(data[octetPointLen:])

	// 10. if e = 0 OR e >= r, return INVALID
	// 11. return (A, e)

	return Signature{
		A: A,
		e: e,
	}, nil
}

type Proof struct {
	Abar        *pairing.G1
	Bbar        *pairing.G1
	r2h         *pairing.Scalar
	r3h         *pairing.Scalar
	commitments []*pairing.Scalar
	c           *pairing.Scalar
}

func (p Proof) Encode() []byte {
	ABarEnc := p.Abar.BytesCompressed()
	BBarEnc := p.Bbar.BytesCompressed()
	r2hEnc, err := p.r2h.MarshalBinary()
	if err != nil {
		panic(err)
	}
	r3hEnc, err := p.r3h.MarshalBinary()
	if err != nil {
		panic(err)
	}
	cEnc, err := p.c.MarshalBinary()
	if err != nil {
		panic(err)
	}

	result := append(ABarEnc, BBarEnc...)
	result = append(result, r2hEnc...)
	result = append(result, r3hEnc...)
	for i := 0; i < len(p.commitments); i++ {
		commitmentEnc, err := p.commitments[i].MarshalBinary()
		if err != nil {
			panic(err)
		}
		result = append(result, commitmentEnc...)
	}
	result = append(result, cEnc...)
	return result
}

func unmarshalProof(data []byte) (Proof, error) {
	proofLenFloor := 2*octetPointLen + 3*octetScalarLen
	if len(data) < proofLenFloor {
		return Proof{}, fmt.Errorf("bbs: malformed proof")
	}

	// // Points (i.e., (Abar, Bbar) in ProofGen) de-serialization.
	// 3.  index = 0
	// 4.  for i in range(0, 1):
	// 5.      end_index = index + octet_point_length - 1
	// 6.      A_i = octets_to_point_g1(proof_octets[index..end_index])
	// 7.      if A_i is INVALID or Identity_G1, return INVALID
	// 8.      index += octet_point_length
	// index := 0

	index := 0

	// Abar
	octets := data[index : index+octetPointLen]
	Abar := &pairing.G1{}
	Abar.SetBytes(octets)
	index += octetPointLen

	// Bbar
	octets = data[index : index+octetPointLen]
	Bbar := &pairing.G1{}
	Bbar.SetBytes(octets)
	index += octetPointLen

	// Scalars (i.e., (r2^, r3^, m^_j1, ..., m^_jU, c) in
	// r2h and r3h
	r2h := &pairing.Scalar{}
	r2h.SetBytes(data[index : index+octetScalarLen])
	index += octetScalarLen
	r3h := &pairing.Scalar{}
	r3h.SetBytes(data[index : index+octetScalarLen])
	index += octetScalarLen

	i := 0
	scalars := make([]*pairing.Scalar, 0)
	for {
		if index < len(data) {
			// XXX(caw): need to check if there is enough data
			scalars = append(scalars, &pairing.Scalar{})
			scalars[i].SetBytes(data[index : index+octetScalarLen])
			index += octetScalarLen
			i += 1
		} else {
			if index != len(data) {
				return Proof{}, fmt.Errorf("bbs: malformed proof")
			}
			if len(scalars) < 3 {
				return Proof{}, fmt.Errorf("bbs: malformed proof")
			}
			return Proof{
				Abar:        Abar,
				Bbar:        Bbar,
				r2h:         r2h,
				r3h:         r3h,
				commitments: scalars[0 : len(scalars)-1],
				c:           scalars[len(scalars)-1],
			}, nil
		}
	}

	// // ProofGen) de-serialization.
	// 9.  j = 0
	// 10. while index < length(proof_octets):
	// 11.     end_index = index + octet_scalar_length - 1
	// 12.     s_j = OS2IP(proof_octets[index..end_index])
	// 13.     if s_j = 0 or if s_j >= r, return INVALID
	// 14.     index += octet_scalar_length
	// 15.     j += 1

	// 16. if index != length(proof_octets), return INVALID
	// 17. msg_commitments = ()
	// 18. If j > 3, set msg_commitments = (s_2, ..., s_(j-2))
	// 19. return (A_0, A_1, s_0, s_1, msg_commitments, s_(j-1))

	// return Proof{}, nil
}

type SecretKey struct {
	sk *pairing.Scalar
}

type PublicKey []byte

func (s SecretKey) Public() PublicKey {
	W := pairing.G2Generator()
	W.ScalarMult(s.sk, W)

	// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-03#section-6.2.2-3
	return W.BytesCompressed()
}

func (s SecretKey) Encode() []byte {
	enc, err := s.sk.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return enc
}

// Key generation
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-03#name-key-generation-operations
func KeyGen(ikm []byte, keyInfo, keyDst []byte) (SecretKey, error) {
	if len(ikm) < 32 {
		return SecretKey{}, fmt.Errorf("bbs: invalid keyGen ikm")
	}
	if len(keyInfo) > 65535 {
		return SecretKey{}, fmt.Errorf("bbs: invalid keyGen keyInfo")
	}
	if keyDst == nil {
		// keyDst = ciphersuite_id || "KEYGEN_DST_"
		keyDst = ciphersuiteString("KEYGEN_DST_")
	}

	// derive_input = key_material || I2OSP(length(key_info), 2) || key_info
	lenBuffer := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuffer, uint16(len(keyInfo)))
	deriveInput := append(append(ikm, lenBuffer...), keyInfo...)

	// SK = hash_to_scalar(derive_input, key_dst)
	sk := hashToScalar(deriveInput, keyDst)

	// if SK is INVALID, return INVALID
	// XXX(caw): what does it mean for SK to be invalid if hash_to_scalar never returns an invalid scalar?

	return SecretKey{
		sk: sk,
	}, nil
}

// Domain calculation
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-03#name-domain-calculation
// XXX(caw): this function needs test vectors for the draft
func calculateDomain(pk []byte, Q1 *pairing.G1, hPoints []*pairing.G1, header []byte) *pairing.Scalar {
	// XXX(caw): check for length of header

	// L = length(H_Points)
	L := len(hPoints)
	lenBuffer := make([]byte, 8)
	binary.BigEndian.PutUint64(lenBuffer, uint64(L))

	// 1. dom_array = (L, Q_1, H_1, ..., H_L)
	// 2. dom_octs = serialize(dom_array) || ciphersuite_id
	octets := append(lenBuffer, Q1.BytesCompressed()...)
	for _, hi := range hPoints {
		octets = append(octets, hi.BytesCompressed()...)
	}
	octets = append(octets, ciphersuiteID...)

	// 3. dom_input = PK || dom_octs || I2OSP(length(header), 8) || header
	domInput := append(pk, octets...)
	binary.BigEndian.PutUint64(lenBuffer, uint64(len(header)))
	domInput = append(domInput, lenBuffer...)
	domInput = append(domInput, header...)

	// 4. return hash_to_scalar(dom_input)
	// XXX(caw): this should have an explicit DST and not default to nil
	return hashToScalar(domInput, nil)
}

func encodeInt(x int) []byte {
	xBuffer := make([]byte, 8)
	binary.BigEndian.PutUint64(xBuffer, uint64(x))
	return xBuffer
}

func concat(x, y []byte) []byte {
	return append(x, y...)
}

// Challenge calculation
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-03#name-challenge-calculation
func calculateChallenge(Abar, Bbar, C *pairing.G1, indexArray []int, msgArray []*pairing.Scalar, domain *pairing.Scalar, ph []byte) (*pairing.Scalar, error) {
	// Deserialization:

	// 1. R = length(i_array)
	// 2. (i1, ..., iR) = i_array
	// 3. (msg_i1, ..., msg_iR) = msg_array

	// ABORT if:

	// 1. R > 2^64 - 1 or R != length(msg_array)
	// 2. length(ph) > 2^64 - 1

	// Procedure:

	// 1. c_arr = (Abar, Bbar, C, R, i1, ..., iR, msg_i1, ..., msg_iR, domain)
	// 2. c_octs = serialize(c_array)
	challengeInput := []byte{}
	challengeInput = concat(challengeInput, Abar.Bytes())
	challengeInput = concat(challengeInput, Bbar.Bytes())
	challengeInput = concat(challengeInput, C.Bytes())
	for i := 0; i < len(indexArray); i++ {
		challengeInput = concat(challengeInput, encodeInt(indexArray[i]))
	}
	for i := 0; i < len(msgArray); i++ {
		msgEnc, err := msgArray[i].MarshalBinary()
		if err != nil {
			return nil, err
		}
		challengeInput = concat(challengeInput, msgEnc)
	}
	domainEnc, err := domain.MarshalBinary()
	if err != nil {
		return nil, err
	}
	challengeInput = concat(challengeInput, domainEnc)

	// 3. return hash_to_scalar(c_octs || I2OSP(length(ph), 8) || ph)
	challengeInput = concat(challengeInput, encodeInt(len(ph)))
	challengeInput = concat(challengeInput, ph)

	// XXX(caw): this should have an explicit DST
	return hashToScalar(challengeInput, nil), nil
}

// Generators calculation
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-03#name-generators-calculation
func createGenerators(count int, pk []byte) []*pairing.G1 {
	// create_generators(count, PK) := hash_to_generator(count)
	generatorSeed := ciphersuiteString("MESSAGE_GENERATOR_SEED")
	return hashToGenerators(count, generatorSeed)
}

func hashToGenerators(count int, generatorSeed []byte) []*pairing.G1 {
	// ABORT if:

	// 1. count > 2^64 - 1
	if uint64(count) > ^uint64(0) {
		panic("invalid invocation")
	}

	// Procedure:

	seedDst := ciphersuiteString("SIG_GENERATOR_SEED_")
	generatorDst := ciphersuiteString("SIG_GENERATOR_DST_")

	// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#section-8.8.1
	exp := expander.NewExpanderMD(crypto.SHA256, seedDst)

	// 1. v = expand_message(generator_seed, seed_dst, expand_len)
	v := exp.Expand(generatorSeed, expandLength)

	lenBuffer := make([]byte, 8)

	// 2. for i in range(1, count):
	generators := make([]*pairing.G1, count)
	for i := 0; i < count; i++ {
		binary.BigEndian.PutUint64(lenBuffer, uint64(i+1))
		expandInput := append(v, lenBuffer...)
		// 3.    v = expand_message(v || I2OSP(i, 8), seed_dst, expand_len)
		// 4.    generator_i = hash_to_curve_g1(v, generator_dst)
		v = exp.Expand(expandInput, expandLength)
		generators[i] = hashToCurveG1(v, generatorDst)
	}

	// 5. return (generator_1, ..., generator_count)
	return generators
}

func hashToCurveG1(seed []byte, dst []byte) *pairing.G1 {
	p := &pairing.G1{}
	p.Hash(seed, dst)
	return p
}

// Signature generation
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-03#name-signature-generation-sign
func rawSign(sk SecretKey, pk []byte, header []byte, messages [][]byte) (Signature, error) {
	// Deserialization:

	// 1. L = length(messages)
	L := len(messages)

	// 2. (msg_1, ..., msg_L) = messages_to_scalars(messages)
	msgs := messagesToScalars(messages)

	// Procedure:

	// 1. (Q_1, H_1, ..., H_L) = create_generators(L+1, PK)
	generators := createGenerators(L+1, pk)

	// 2. domain = calculate_domain(PK, Q_1, (H_1, ..., H_L), header)
	domain := calculateDomain(pk, generators[0], generators[1:], header)

	// e_input = serialize((SK, domain, msg_1, ..., msg_L))
	skEnc, err := sk.sk.MarshalBinary()
	if err != nil {
		return Signature{}, err
	}
	domainEnc, err := domain.MarshalBinary()
	if err != nil {
		return Signature{}, err
	}
	hashInput := append(skEnc, domainEnc...)
	for i := 0; i < L; i++ {
		msgEnc, err := msgs[i].MarshalBinary()
		if err != nil {
			return Signature{}, err
		}
		hashInput = append(hashInput, msgEnc...)
	}

	// 3. e = hash_to_scalar(serialize((SK, domain, msg_1, ..., msg_L)))
	e := hashToScalar(hashInput, nil)

	// 4. B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L
	P1 := computeP1()
	B := &pairing.G1{}
	B.ScalarMult(domain, generators[0]) // Q_1 * domain
	B.Add(P1, B)                        // P1 + Q_1 * domain
	for i := 1; i <= L; i++ {
		hi := generators[i]
		v := &pairing.G1{}
		v.ScalarMult(msgs[i-1], hi)
		B.Add(B, v)
	}

	// 5. A = B * (1 / (SK + e))
	skE := &pairing.Scalar{}
	skE.Add(sk.sk, e)
	skEInv := &pairing.Scalar{}
	skEInv.Inv(skE)
	A := &pairing.G1{}
	A.ScalarMult(skEInv, B)

	// 6. return signature_to_octets(A, e)
	return Signature{
		A: A,
		e: e,
	}, nil
}

func Sign(sk SecretKey, pk []byte, header []byte, messages [][]byte) ([]byte, error) {
	sig, err := rawSign(sk, pk, header, messages)
	if err != nil {
		return nil, err
	}
	return sig.Encode(), nil
}

// Signature verification
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-03#name-signature-verification-veri
func rawVerify(pk []byte, signature Signature, header []byte, messages [][]byte) error {
	// 1. L = length(messages)
	L := len(messages)

	// 2. (msg_1, ..., msg_L) = messages_to_scalars(messages)
	msgs := messagesToScalars(messages)

	// Procedure:

	// 1. (Q_1, H_1, ..., H_L) = create_generators(L+1, PK)
	generators := createGenerators(L+1, pk)

	// 2. domain = calculate_domain(PK, Q_1, (H_1, ..., H_L), header)
	domain := calculateDomain(pk, generators[0], generators[1:], header)

	// 3. B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L
	// XXX(caw): this is shared between sign and verify, so pull it out into a function
	P1 := computeP1()
	B := &pairing.G1{}
	B.ScalarMult(domain, generators[0]) // Q_1 * domain
	B.Add(P1, B)                        // P1 + Q_1 * domain
	for i := 1; i <= L; i++ {
		hi := generators[i]
		v := &pairing.G1{}
		v.ScalarMult(msgs[i-1], hi)
		B.Add(B, v)
	}

	// 4. if e(A, W + BP2 * e) * e(B, -BP2) != Identity_GT, return INVALID
	W := &pairing.G2{}
	W.SetBytes(pk)
	lg2 := pairing.G2Generator()
	lg2.ScalarMult(signature.e, lg2)
	lg2.Add(lg2, W)

	rg2 := pairing.G2Generator()
	rg2.Neg()

	l := pairing.Pair(signature.A, lg2)
	r := pairing.Pair(B, rg2)
	target := &pairing.Gt{}
	target.Mul(l, r)
	if !target.IsIdentity() {
		return fmt.Errorf("bbs: invalid signature")
	}

	return nil
}

func Verify(pk PublicKey, signature, header []byte, messages [][]byte) error {
	// 1. signature_result = octets_to_signature(signature)
	sig, err := UnmarshalSignature(signature)
	if err != nil {
		return err
	}

	return rawVerify(pk, sig, header, messages)
}

// Random scalars
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-03#name-random-scalars
func calculateRandomScalars(count int) ([]*pairing.Scalar, error) {
	scalars := make([]*pairing.Scalar, count)
	for i := 0; i < count; i++ {
		scalars[i] = &pairing.Scalar{}
		err := scalars[i].Random(rand.Reader)
		if err != nil {
			return nil, err
		}
	}
	return scalars, nil
}

// Mocked random scalars
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-03#name-mocked-random-scalars
func calculateFixedScalars(count int) ([]*pairing.Scalar, error) {
	// 1. out_len = expand_len * count
	expandLength := uint(256)
	outLen := uint(int(expandLength) * count)
	seed := []byte{0x00}

	// 2. v = expand_message(SEED, dst, out_len)
	dst := ciphersuiteString("MOCK_RANDOM_SCALARS_DST_")
	exp := expander.NewExpanderMD(crypto.SHA256, dst)

	uniformBytes := exp.Expand(seed, outLen)
	scalars := make([]*pairing.Scalar, count)
	for i := 0; i < count; i++ {
		start := i * int(expandLength)
		end := (i + 1) * int(expandLength)
		scalars[i] = &pairing.Scalar{}
		scalars[i].SetBytes(uniformBytes[start:end])
	}

	return scalars, nil
}

// XXX(caw): refactor this implementation
func difference(x []int, count int) []int {
	if len(x) > count {
		panic("invalid difference invocation")
	}
	indices := make([]int, count-len(x))
	index := 0
	for i := 0; i < count; i++ {
		match := false
		for _, xi := range x {
			if xi == i {
				match = true
			}
		}
		if !match {
			indices[index] = i
			index++
		}
	}

	return indices
}

// Proof generation
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-03#name-proof-generation-proofgen
func rawProofGen(pk []byte, signature Signature, header []byte, ph []byte, messages [][]byte, disclosedIndexes []int) (Proof, error) {
	// XXX(caw): need to validate the input disclosedIndexes value to make sure it doesn't have repeated indexes or whatever

	L := len(messages)
	msgs := messagesToScalars(messages)

	// ABORT if for i in (i1, ..., iR), i < 1 or i > L

	R := len(disclosedIndexes)
	U := L - R
	disclosedMsgs := make([]*pairing.Scalar, R)
	for i := 0; i < R; i++ {
		disclosedMsgs[i] = msgs[disclosedIndexes[i]]
	}

	undisclosedIndexes := difference(disclosedIndexes, L)
	if len(undisclosedIndexes) != U {
		panic("internal error")
	}
	undisclosedMsgs := make([]*pairing.Scalar, U)
	for i := 0; i < U; i++ {
		undisclosedMsgs[i] = msgs[undisclosedIndexes[i]]
	}

	// Procedure:

	// 1. (Q_1, MsgGenerators) = create_generators(L+1, PK) // XXX(Caw): inconsistent notation (Q1, MsgGEnerators) vs (Q1, H1, .... HL)
	// 2.  (H_1, ..., H_L) = MsgGenerators
	generators := createGenerators(L+1, pk)
	msgGenerators := generators[1:]

	// 3.  (H_j1, ..., H_jU) = (MsgGenerators[j1], ..., MsgGenerators[jU])

	undisclosedGenerators := make([]*pairing.G1, U)
	for i, index := range undisclosedIndexes {
		undisclosedGenerators[i] = msgGenerators[index]
	}

	// 4.  domain = calculate_domain(PK, Q_1, (H_1, ..., H_L), header)
	domain := calculateDomain(pk, generators[0], msgGenerators, header)

	// 5.  random_scalars = calculate_random_scalars(3+U)
	// 6.  (r1, r2, r3, m~_j1, ..., m~_jU) = random_scalars
	randomScalars, err := calculateRandomScalars(3 + U)
	r1 := randomScalars[0]
	r2 := randomScalars[1]
	r3 := randomScalars[2]
	blinds := randomScalars[3:]
	if err != nil {
		return Proof{}, err
	}

	// 7.  B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L
	P1 := computeP1()
	Q1 := generators[0]
	B := &pairing.G1{}
	B.ScalarMult(domain, Q1)
	B.Add(B, P1)
	for i := 1; i <= L; i++ {
		hi := generators[i]
		v := &pairing.G1{}
		v.ScalarMult(msgs[i-1], hi)
		B.Add(B, v)
	}

	// 8.  Abar = A * r1
	Abar := &pairing.G1{}
	Abar.ScalarMult(r1, signature.A)

	// 9.  Bbar = B * r1 - Abar * e
	v := &pairing.G1{}
	v.ScalarMult(signature.e, Abar)
	v.Neg() // -1 * (Abar * e)
	Bbar := &pairing.G1{}
	Bbar.ScalarMult(r1, B)
	Bbar.Add(Bbar, v) // B * r1 - Abar * e

	// 10. T =  Abar * r2 + Bbar * r3 + H_j1 * m~_j1 + ... + H_jU * m~_jU
	T1 := &pairing.G1{}
	T1.ScalarMult(r2, Abar) // Abar * r2
	T2 := &pairing.G1{}
	T2.ScalarMult(r3, Bbar) // Bbar * r3
	T := &pairing.G1{}
	T.Add(T1, T2) // (Abar * r2) + (Bbar * r3)
	for i := 0; i < U; i++ {
		msg := undisclosedGenerators[i]
		v := &pairing.G1{}
		v.ScalarMult(blinds[i], msg)
		T.Add(T, v)
	}

	// 11. c = calculate_challenge(Abar, Bbar, T, (i1, ..., iR),
	// 							(msg_i1, ..., msg_iR), domain, ph)
	c, err := calculateChallenge(Abar, Bbar, T, disclosedIndexes, disclosedMsgs, domain, ph)
	if err != nil {
		return Proof{}, fmt.Errorf("bbs: challenge calculate error: %s", err.Error())
	}

	// 12. r4 = - r1^-1 (mod r)
	r4 := &pairing.Scalar{}
	r4.Inv(r1) //   r1^-1 (mod r)
	r4.Neg()   // - r1^-1 (mod r)

	// 13. r2^ = r2 + e * r4 * c (mod r)
	r2h := &pairing.Scalar{}
	r2h.Mul(r4, c)            //          r4 * c (mod r)
	r2h.Mul(r2h, signature.e) //      e * r4 * c (mod r)
	r2h.Add(r2, r2h)          // r2 + e * r4 * c (mod r)

	// 14. r3^ = r3 + r4 * c (mod r)
	r3h := &pairing.Scalar{}
	r3h.Mul(r4, c)   //      r4 * c (mod r)
	r3h.Add(r3, r3h) // r3 + r4 * c (mod r)

	// 15. for j in (j1, ..., jU): m^_j = m~_j + msg_j * c (mod r)
	commitments := make([]*pairing.Scalar, U)
	for i := 0; i < U; i++ {
		t := &pairing.Scalar{}
		t.Mul(undisclosedMsgs[i], c)
		t.Add(t, blinds[i])
		commitments[i] = t
	}

	// 16. proof = (Abar, Bbar, r2^, r3^, (m^_j1, ..., m^_jU), c)
	proof := Proof{
		Abar:        Abar,
		Bbar:        Bbar,
		r2h:         r2h,
		r3h:         r3h,
		commitments: commitments,
		c:           c,
	}

	// 17. return proof_to_octets(proof)
	return proof, nil
}

func ProofGen(pk PublicKey, signature []byte, header []byte, ph []byte, messages [][]byte, disclosedIndexes []int) ([]byte, error) {
	// func rawProofGen(pk []byte, signature Signature, header []byte, ph []byte, messages [][]byte, disclosedIndexes []int) (Proof, error) {
	sig, err := UnmarshalSignature(signature)
	if err != nil {
		return nil, err
	}
	proof, err := rawProofGen(pk, sig, header, ph, messages, disclosedIndexes)
	if err != nil {
		return nil, err
	}

	return proof.Encode(), nil
}

// Proof verification
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-03#name-proof-verification-proofver
func rawProofVerify(pk []byte, proof Proof, header []byte, ph []byte, disclosedMessages [][]byte, disclosedIndexes []int) error {
	// Procedure:

	R := len(disclosedIndexes)
	U := len(proof.commitments)
	L := U + R

	disclosedMsgs := messagesToScalars(disclosedMessages)

	// 1.  (Q_1, MsgGenerators) = create_generators(L+1, PK)
	generators := createGenerators(L+1, pk)
	Q1 := generators[0]

	// 2.  (H_1, ..., H_L) = MsgGenerators
	msgGenerators := generators[1:]

	// 3.  (H_i1, ..., H_iR) = (MsgGenerators[i1], ..., MsgGenerators[iR])
	// XXX(caw): rename this garbage
	disclosedGenerators := make([]*pairing.G1, U)
	for i, index := range disclosedIndexes {
		disclosedGenerators[i] = msgGenerators[index]
	}

	// 4.  (H_j1, ..., H_jU) = (MsgGenerators[j1], ..., MsgGenerators[jU])
	undisclosedIndexes := difference(disclosedIndexes, L)
	// XXX(caw): rename this garbage
	undisclosedGenerators := make([]*pairing.G1, U)
	for i, index := range undisclosedIndexes {
		undisclosedGenerators[i] = msgGenerators[index]
	}

	// 5.  domain = calculate_domain(PK, Q_1, (H_1, ..., H_L), header)
	domain := calculateDomain(pk, generators[0], msgGenerators, header)

	// 6.  D = P1 + Q_1 * domain + H_i1 * msg_i1 + ... + H_iR * msg_iR
	D1 := &pairing.G1{}
	D1.ScalarMult(domain, Q1) // Q_1 * domain
	D := &pairing.G1{}
	P1 := computeP1()
	D.Add(D1, P1) // P1 + Q_1 * domain
	for i := 0; i < R; i++ {
		msg := disclosedMsgs[i] // H_i1 * msg_i1
		v := &pairing.G1{}
		v.ScalarMult(msg, disclosedGenerators[i])
		D.Add(D, v) // D += H_i1 * msg_i1
	}

	// 7.  T =  Abar * r2^ + Bbar * r3^ + H_j1 * m^_j1 + ... +  H_jU * m^_jU
	T1 := &pairing.G1{}
	T1.ScalarMult(proof.r2h, proof.Abar) // Abar * r2^
	T2 := &pairing.G1{}
	T2.ScalarMult(proof.r3h, proof.Bbar) // Bbar * r3^
	T := &pairing.G1{}
	T.Add(T1, T2) // (Abar * r2^) + (Bbar * r3^)
	for i := 0; i < U; i++ {
		msg := undisclosedGenerators[i]
		v := &pairing.G1{}
		v.ScalarMult(proof.commitments[i], msg)
		T.Add(T, v) // T += H_j1 * m^_j1
	}

	// 8.  T = T + D * c
	T1 = &pairing.G1{}
	T1.ScalarMult(proof.c, D)
	T.Add(T, T1)

	// 9.  cv = calculate_challenge(Abar, Bbar, T, (i1, ..., iR),
	// 							 (msg_i1, ..., msg_iR), domain, ph)
	cv, err := calculateChallenge(proof.Abar, proof.Bbar, T, disclosedIndexes, disclosedMsgs, domain, ph)
	if err != nil {
		return fmt.Errorf("bbs: challenge calculate error: %s", err.Error())
	}

	// 10. if c != cv, return INVALID
	if proof.c.IsEqual(cv) != 1 {
		return fmt.Errorf("bbs: invalid proof (challenge mismatch)")
	}

	// 11. if e(Abar, W) * e(Bbar, -BP2) != Identity_GT, return INVALID
	W := &pairing.G2{}
	W.SetBytes(pk)
	l := pairing.Pair(proof.Abar, W) // e(Abar, W)

	rg2 := pairing.G2Generator()
	rg2.Neg()
	r := pairing.Pair(proof.Bbar, rg2) // e(Bbar, -BP2)

	target := &pairing.Gt{}
	target.Mul(l, r) // e(Abar, W) * e(Bbar, -BP2)
	if !target.IsIdentity() {
		return fmt.Errorf("bbs: invalid proof (pairing failure): %s", target.String())
	}

	// 12. return VALID
	return nil
}

func ProofVerify(pk, proof, header, ph []byte, disclosedMessages [][]byte, disclosedIndexes []int) error {
	// func rawProofVerify(pk []byte, proof Proof, header []byte, ph []byte, disclosedMessages [][]byte, disclosedIndexes []int) error {
	p, err := unmarshalProof(proof)
	if err != nil {
		return err
	}
	return rawProofVerify(pk, p, header, ph, disclosedMessages, disclosedIndexes)
}

// Hash-to-scalar
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-03#name-hash-to-scalar

func messagesToScalars(messages [][]byte) []*pairing.Scalar {
	scalars := make([]*pairing.Scalar, len(messages))
	for i, msg := range messages {
		scalars[i] = mapToScalar(msg, i)
	}
	return scalars
}

func mapToScalar(msg []byte, index int) *pairing.Scalar {
	// dst = ciphersuite_id || "MAP_MSG_TO_SCALAR_AS_HASH_", where ciphersuite_id is defined by the ciphersuite.
	// XXX(caw): should MAP_MSG_TO_SCALAR_AS_HASH_ be MAP_TO_SCALAR_ID?, e.g., dst = ciphersuite_id || MAP_TO_SCALAR_ID
	dst := ciphersuiteString("MAP_MSG_TO_SCALAR_AS_HASH_")
	return hashToScalar(msg, dst)
}

// XXX(caw): dst SHOULD NOT be optional with the same domain separation tag used everywhere in the spec
func hashToScalar(msg, dst []byte) *pairing.Scalar {
	// XXX(caw): this should just call hash_to_field(msg, 1) directly

	// uniform_bytes = expand_message(msg_octets, dst, expand_len)
	// return OS2IP(uniform_bytes) mod r

	if dst == nil {
		dst = ciphersuiteString("H2S_")
	}

	exp := expander.NewExpanderMD(crypto.SHA256, dst)
	uniformBytes := exp.Expand(msg, expandLength)
	scalar := new(big.Int).SetBytes(uniformBytes)
	order := new(big.Int).SetBytes(bls12381.Order())
	scalar.Mod(scalar, order)

	result := &bls12381.Scalar{}
	result.SetBytes(scalar.Bytes())
	return result
}
