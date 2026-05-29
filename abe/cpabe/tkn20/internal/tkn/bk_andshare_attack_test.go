package tkn

// Regression test that simulates the AND-share / Boneh-Katz wildcard attack.
//
// The CCA (Boneh-Katz) transform wraps a user's policy in a new outer AND gate
// whose left child is an internal wildcard leaf (bkAttribute). Every CCA
// attribute key carries that attribute as a wildcard, so any key can pair
// against the wildcard leaf. With the AND-share bug, that single leaf received
// the entire KEM secret, so a key that does NOT satisfy the public policy could
// still recover the message by running the decapsulation pairing equations on
// the wildcard wire alone -- even though the stock API's Satisfaction() check
// (local, non-cryptographic) refuses such a key.
//
// This test runs that exact attacker computation and asserts it no longer
// recovers the plaintext once the AND-share sharing is fixed.

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"testing"

	pairing "github.com/cloudflare/circl/ecc/bls12381"
	"golang.org/x/crypto/blake2b"
)

// attackerDecapsulateBKOnly reconstructs the encapsulated GT key using ONLY the
// internal Boneh-Katz wildcard wire. It mirrors the relevant portion of
// decapsulate (see tk.go) but (a) never calls Satisfaction and (b) uses a
// "satisfying set" of exactly {BK wire}, which is unsatisfiable in the honest
// scheme but succeeded under the AND-share bug.
func attackerDecapsulateBKOnly(header *ciphertextHeader, key *AttributesKey) (*pairing.Gt, error) {
	bkWire := -1
	for i := range header.p.Inputs {
		if header.p.Inputs[i].Label == bkAttribute {
			bkWire = i
		}
	}
	if bkWire < 0 {
		return nil, fmt.Errorf("attack precondition failed: no BK wire in transformed policy")
	}
	if key.k3[bkAttribute] == nil || key.k3wild[bkAttribute] == nil {
		return nil, fmt.Errorf("attack precondition failed: key lacks BK wildcard material")
	}

	pi := header.p.pi()
	d := max(pi) + 1
	p1 := make([]*matrixG1, d)
	p2 := make([]*matrixG1, d)

	// The attacker selects ONLY the BK wire, ignoring the real policy.
	matches := []match{{wire: bkWire, label: bkAttribute}}
	for _, m := range matches {
		j := pi[m.wire]
		if p1[j] == nil {
			p1[j] = newMatrixG1(header.c3[m.wire].rows, header.c3[m.wire].cols)
		}
		if p2[j] == nil {
			p2[j] = newMatrixG1(key.k3[m.label].rows, key.k3[m.label].cols)
		}
		// The BK wire is Positive and the key's BK attribute is a wildcard,
		// so this mirrors the positive+wild branch of decapsulate.
		p1[j].add(p1[j], header.c3[m.wire])
		y := header.p.Inputs[m.wire].Value
		tmp1 := newMatrixG1(0, 0)
		tmp1.scalarMult(y, key.k3[m.label])
		tmp1.add(tmp1, key.k3wild[m.label])
		p2[j].add(p2[j], tmp1)
	}

	pairs := &pairAccum{}
	var pTot *matrixG1
	for i := 0; i < d; i++ {
		if p1[i] != nil {
			if pTot == nil {
				pTot = newMatrixG1(p1[i].rows, p1[i].cols)
			}
			pTot.add(pTot, p1[i])
			pairs.addDuals(p2[i], header.c2[i], 1)
		}
	}
	pairs.addDuals(pTot, key.k1, -1)
	pairs.addDuals(key.k2.copy(), header.c1, 1)
	return pairs.eval(), nil
}

// attackerDecryptCCA parses a public CCA ciphertext like DecryptCCA but swaps
// the honest decapsulate for attackerDecapsulateBKOnly. It needs only public
// ciphertext bytes plus the attacker's own attribute key.
func attackerDecryptCCA(ciphertext []byte, key *AttributesKey) ([]byte, error) {
	rest, removeLenPrefixedVar := checkCiphertextFormat(ciphertext)
	id, rest, err := removeLenPrefixed(rest)
	if err != nil {
		return nil, err
	}
	macData, rest, err := removeLenPrefixedVar(rest)
	if err != nil {
		return nil, err
	}
	tag, _, err := removeLenPrefixed(rest)
	if err != nil {
		return nil, err
	}
	C1, envRaw, err := removeLenPrefixedVar(macData)
	if err != nil {
		return nil, err
	}
	env, _, err := removeLenPrefixedVar(envRaw)
	if err != nil {
		return nil, err
	}

	header := &ciphertextHeader{}
	if err = header.unmarshalBinary(C1); err != nil {
		return nil, err
	}

	// Recompute the CCA/BK scalar from the public ciphertext id and apply the
	// same BK transform the library would.
	numid := &pairing.Scalar{}
	numid.SetBytes(id)
	header.p = header.p.transformBK(numid)

	encPoint, err := attackerDecapsulateBKOnly(header, key)
	if err != nil {
		return nil, err
	}
	encKey, err := encPoint.MarshalBinary()
	if err != nil {
		return nil, err
	}
	hashedEncKey := blake2b.Sum256(encKey)

	decEnv, err := blakeDecrypt(hashedEncKey[:], env)
	if err != nil {
		return nil, err
	}
	if len(decEnv) < macKeySeedSize {
		return nil, fmt.Errorf("envelope too short")
	}
	seed := decEnv[0:macKeySeedSize]
	ptx := make([]byte, len(decEnv)-macKeySeedSize)
	copy(ptx, decEnv[macKeySeedSize:])

	// Validate the recovered key via the MAC/id, exactly as a receiver would.
	// If the GT key is wrong (as it is once the AND-share bug is fixed) this
	// check fails.
	compID, macKey, err := expandSeed(seed)
	if err != nil {
		return nil, err
	}
	compTag, err := blakeMac(macKey, macData)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(compTag, tag)&subtle.ConstantTimeCompare(compID, id) != 1 {
		return nil, fmt.Errorf("recovered key did not validate")
	}
	return ptx, nil
}

// TestBKWildcardAttackFails encrypts under a policy the attacker does not
// satisfy, then checks that (1) the stock API refuses the attacker's key and
// (2) the single-wildcard-wire attack no longer recovers the plaintext.
func TestBKWildcardAttackFails(t *testing.T) {
	public, secret, err := GenerateParams(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateParams: %s", err)
	}

	// Target policy: (role:admin AND dept:engineering). At least one gate.
	const (
		roleAdmin = 101
		deptEng   = 202
		roleGuest = 999
	)
	policy := &Policy{
		Inputs: []Wire{
			{Label: "role", RawValue: "admin", Value: ToScalar(roleAdmin), Positive: true},
			{Label: "dept", RawValue: "engineering", Value: ToScalar(deptEng), Positive: true},
		},
		F: Formula{Gates: []Gate{{Andgate, 0, 1, 2}}},
	}

	secretMsg := []byte("TOP SECRET: launch codes for the engineering admins only")
	ciphertext, err := EncryptCCA(rand.Reader, public, policy, secretMsg)
	if err != nil {
		t.Fatalf("EncryptCCA: %s", err)
	}

	// Attacker key: an unrelated, non-satisfying attribute set.
	attackerAttrs := &Attributes{
		"role": {wild: false, Value: ToScalar(roleGuest)},
	}
	attackerKey, err := DeriveAttributeKeysCCA(rand.Reader, secret, attackerAttrs)
	if err != nil {
		t.Fatalf("DeriveAttributeKeysCCA: %s", err)
	}

	// Treat the serialized key as adversary-controlled material.
	keyBytes, err := attackerKey.MarshalBinary()
	if err != nil {
		t.Fatalf("attackerKey.MarshalBinary: %s", err)
	}
	advKey := &AttributesKey{}
	if err = advKey.UnmarshalBinary(keyBytes); err != nil {
		t.Fatalf("advKey.UnmarshalBinary: %s", err)
	}

	// (1) The honest API must refuse the non-satisfying key.
	if _, err = DecryptCCA(ciphertext, advKey); err == nil {
		t.Fatalf("stock DecryptCCA accepted a non-satisfying key")
	}

	// (2) The BK-wildcard-wire attack must not recover the plaintext.
	recovered, err := attackerDecryptCCA(ciphertext, advKey)
	if err == nil && bytes.Equal(recovered, secretMsg) {
		t.Fatalf("AND-share bug present: BK-only attack recovered the plaintext %q", recovered)
	}
}
