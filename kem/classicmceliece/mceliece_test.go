package classicmceliece

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/cloudflare/circl/internal/nist"
	"github.com/cloudflare/circl/kem"
	i348864 "github.com/cloudflare/circl/kem/classicmceliece/internal/mceliece348864"
	i348864f "github.com/cloudflare/circl/kem/classicmceliece/internal/mceliece348864f"
	i460896 "github.com/cloudflare/circl/kem/classicmceliece/internal/mceliece460896"
	i460896f "github.com/cloudflare/circl/kem/classicmceliece/internal/mceliece460896f"
	i6688128 "github.com/cloudflare/circl/kem/classicmceliece/internal/mceliece6688128"
	i6688128f "github.com/cloudflare/circl/kem/classicmceliece/internal/mceliece6688128f"
	i6960119 "github.com/cloudflare/circl/kem/classicmceliece/internal/mceliece6960119"
	i6960119f "github.com/cloudflare/circl/kem/classicmceliece/internal/mceliece6960119f"
	i8192128 "github.com/cloudflare/circl/kem/classicmceliece/internal/mceliece8192128"
	i8192128f "github.com/cloudflare/circl/kem/classicmceliece/internal/mceliece8192128f"
	p348864 "github.com/cloudflare/circl/kem/classicmceliece/mceliece348864"
	p348864f "github.com/cloudflare/circl/kem/classicmceliece/mceliece348864f"
	p460896 "github.com/cloudflare/circl/kem/classicmceliece/mceliece460896"
	p460896f "github.com/cloudflare/circl/kem/classicmceliece/mceliece460896f"
	p6688128 "github.com/cloudflare/circl/kem/classicmceliece/mceliece6688128"
	p6688128f "github.com/cloudflare/circl/kem/classicmceliece/mceliece6688128f"
	p6960119 "github.com/cloudflare/circl/kem/classicmceliece/mceliece6960119"
	p6960119f "github.com/cloudflare/circl/kem/classicmceliece/mceliece6960119f"
	p8192128 "github.com/cloudflare/circl/kem/classicmceliece/mceliece8192128"
	p8192128f "github.com/cloudflare/circl/kem/classicmceliece/mceliece8192128f"
)

type publicVariant struct {
	katName        string
	scheme         kem.Scheme
	publicKeySize  int
	privateKeySize int
	ciphertextSize int
}

var publicVariants = []publicVariant{
	{"mceliece348864", p348864.Scheme(), p348864.PublicKeySize, p348864.PrivateKeySize, p348864.CiphertextSize},
	{"mceliece348864f", p348864f.Scheme(), p348864f.PublicKeySize, p348864f.PrivateKeySize, p348864f.CiphertextSize},
	{"mceliece460896", p460896.Scheme(), p460896.PublicKeySize, p460896.PrivateKeySize, p460896.CiphertextSize},
	{"mceliece460896f", p460896f.Scheme(), p460896f.PublicKeySize, p460896f.PrivateKeySize, p460896f.CiphertextSize},
	{"mceliece6688128", p6688128.Scheme(), p6688128.PublicKeySize, p6688128.PrivateKeySize, p6688128.CiphertextSize},
	{"mceliece6688128f", p6688128f.Scheme(), p6688128f.PublicKeySize, p6688128f.PrivateKeySize, p6688128f.CiphertextSize},
	{"mceliece6960119", p6960119.Scheme(), p6960119.PublicKeySize, p6960119.PrivateKeySize, p6960119.CiphertextSize},
	{"mceliece6960119f", p6960119f.Scheme(), p6960119f.PublicKeySize, p6960119f.PrivateKeySize, p6960119f.CiphertextSize},
	{"mceliece8192128", p8192128.Scheme(), p8192128.PublicKeySize, p8192128.PrivateKeySize, p8192128.CiphertextSize},
	{"mceliece8192128f", p8192128f.Scheme(), p8192128f.PublicKeySize, p8192128f.PrivateKeySize, p8192128f.CiphertextSize},
}

func TestRound4Sizes(t *testing.T) {
	for _, v := range publicVariants {
		t.Run(v.katName, func(t *testing.T) {
			if got := v.scheme.PublicKeySize(); got != v.publicKeySize {
				t.Fatalf("public key size: got %d, want %d", got, v.publicKeySize)
			}
			if got := v.scheme.PrivateKeySize(); got != v.privateKeySize {
				t.Fatalf("private key size: got %d, want %d", got, v.privateKeySize)
			}
			if got := v.scheme.CiphertextSize(); got != v.ciphertextSize {
				t.Fatalf("ciphertext size: got %d, want %d", got, v.ciphertextSize)
			}
			if got := v.scheme.SharedKeySize(); got != 32 {
				t.Fatalf("shared key size: got %d, want 32", got)
			}
		})
	}
}

func TestSchemeAPI(t *testing.T) {
	// The KAT test below exercises the core of every parameter set. Keep the
	// public API round-trip focused on one representative wrapper so the default
	// package test remains practical even with the large KAT archive in testdata.
	v := publicVariants[1] // mceliece348864f
	vec := readFirstKATVector(t, v.katName)
	pk, sk := v.scheme.DeriveKeyPair(vec.sk[:v.scheme.SeedSize()])
	pkb, err := pk.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	skb, err := sk.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	checkEqual(t, "public key", pkb, vec.pk)
	checkEqual(t, "private key", skb, vec.sk)

	pk2, err := v.scheme.UnmarshalBinaryPublicKey(pkb)
	if err != nil {
		t.Fatal(err)
	}
	sk2, err := v.scheme.UnmarshalBinaryPrivateKey(skb)
	if err != nil {
		t.Fatal(err)
	}
	if !pk.Equal(pk2) || !sk.Equal(sk2) {
		t.Fatalf("key equality failed after marshal/unmarshal")
	}
	if !pk.Equal(sk2.Public()) {
		t.Fatalf("recovered public key mismatch")
	}

	ct, ss, err := v.scheme.EncapsulateDeterministically(pk, bytes.Repeat([]byte{0x22}, v.scheme.EncapsulationSeedSize()))
	if err != nil {
		t.Fatal(err)
	}
	ss2, err := v.scheme.Decapsulate(sk, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ss, ss2) {
		t.Fatalf("shared secret mismatch")
	}
}

type internalVariant struct {
	katName          string
	generate         func(io.Reader) ([]byte, []byte, error)
	generateFromSeed func([]byte) ([]byte, []byte, error)
	encapsulate      func([]byte, io.Reader) ([]byte, []byte, error)
	decapsulate      func([]byte, []byte) ([]byte, error)
}

var internalVariants = map[string]internalVariant{
	"mceliece348864":   {"mceliece348864", i348864.GenerateKeyPairWithRandom, i348864.GenerateKeyPairFromSeed, i348864.EncapsulateWithRandom, i348864.Decapsulate},
	"mceliece348864f":  {"mceliece348864f", i348864f.GenerateKeyPairWithRandom, i348864f.GenerateKeyPairFromSeed, i348864f.EncapsulateWithRandom, i348864f.Decapsulate},
	"mceliece460896":   {"mceliece460896", i460896.GenerateKeyPairWithRandom, i460896.GenerateKeyPairFromSeed, i460896.EncapsulateWithRandom, i460896.Decapsulate},
	"mceliece460896f":  {"mceliece460896f", i460896f.GenerateKeyPairWithRandom, i460896f.GenerateKeyPairFromSeed, i460896f.EncapsulateWithRandom, i460896f.Decapsulate},
	"mceliece6688128":  {"mceliece6688128", i6688128.GenerateKeyPairWithRandom, i6688128.GenerateKeyPairFromSeed, i6688128.EncapsulateWithRandom, i6688128.Decapsulate},
	"mceliece6688128f": {"mceliece6688128f", i6688128f.GenerateKeyPairWithRandom, i6688128f.GenerateKeyPairFromSeed, i6688128f.EncapsulateWithRandom, i6688128f.Decapsulate},
	"mceliece6960119":  {"mceliece6960119", i6960119.GenerateKeyPairWithRandom, i6960119.GenerateKeyPairFromSeed, i6960119.EncapsulateWithRandom, i6960119.Decapsulate},
	"mceliece6960119f": {"mceliece6960119f", i6960119f.GenerateKeyPairWithRandom, i6960119f.GenerateKeyPairFromSeed, i6960119f.EncapsulateWithRandom, i6960119f.Decapsulate},
	"mceliece8192128":  {"mceliece8192128", i8192128.GenerateKeyPairWithRandom, i8192128.GenerateKeyPairFromSeed, i8192128.EncapsulateWithRandom, i8192128.Decapsulate},
	"mceliece8192128f": {"mceliece8192128f", i8192128f.GenerateKeyPairWithRandom, i8192128f.GenerateKeyPairFromSeed, i8192128f.EncapsulateWithRandom, i8192128f.Decapsulate},
}

func TestOfficialKAT(t *testing.T) {
	limit := 1
	if os.Getenv("CIRCL_MCELIECE_FULL_KAT") != "" {
		limit = 0 // all vectors present in the KAT archive
	}
	filter := os.Getenv("CIRCL_MCELIECE_KAT_VARIANT")
	if filter != "" {
		if _, ok := internalVariants[filter]; !ok {
			t.Fatalf("unknown KAT variant %q", filter)
		}
	}

	for _, v := range publicVariants {
		impl := internalVariants[v.katName]
		if filter != "" && filter != impl.katName {
			continue
		}
		t.Run(impl.katName, func(t *testing.T) {
			t.Parallel()
			count, err := testKATArchive(t, impl, limit)
			if err != nil {
				t.Fatal(err)
			}
			if limit > 0 && count != limit {
				t.Fatalf("tested %d KAT vectors, want %d", count, limit)
			}
			if limit == 0 && count == 0 {
				t.Fatalf("tested no KAT vectors")
			}
		})
	}
}

func openKATStream(t *testing.T, katName string) io.Reader {
	t.Helper()
	// The committed archive holds only the first vector per variant to keep the
	// package hermetic and small. Point CIRCL_MCELIECE_KAT_ARCHIVE at the full
	// official gzip archive to run the complete KAT set (with CIRCL_MCELIECE_FULL_KAT).
	katPath := os.Getenv("CIRCL_MCELIECE_KAT_ARCHIVE")
	if katPath == "" {
		katPath = filepath.Join("testdata", "mceliece-kat-20221023.tar.gz")
	}
	f, err := os.Open(katPath) //nolint:gosec // fixed testdata path or explicit opt-in override
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gz.Close() })

	want := "mceliece-kat-20221023/KAT/kem/" + katName + "/kat_kem.rsp"
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			t.Fatalf("%s not found in KAT archive", want)
		}
		if err != nil {
			t.Fatal(err)
		}
		if hdr.Name == want {
			return tr
		}
	}
}

func testKATArchive(t *testing.T, impl internalVariant, limit int) (int, error) {
	t.Helper()
	return testKATVectors(t, impl, openKATStream(t, impl.katName), limit)
}

func readFirstKATVector(t *testing.T, name string) katVector {
	t.Helper()
	impl, ok := internalVariants[name]
	if !ok {
		t.Fatalf("unknown KAT variant %q", name)
	}
	var out katVector
	err := scanKATVectors(openKATStream(t, impl.katName), 1, func(vec katVector) error {
		out = vec
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

type katVector struct {
	count int
	seed  []byte
	pk    []byte
	sk    []byte
	ct    []byte
	ss    []byte
}

type nistReader struct{ drbg *nist.DRBG }

func (r nistReader) Read(p []byte) (int, error) {
	r.drbg.Fill(p)
	return len(p), nil
}

func testKATVectors(t *testing.T, impl internalVariant, r io.Reader, limit int) (int, error) {
	t.Helper()
	var tested int
	err := scanKATVectors(r, limit, func(vec katVector) error {
		t.Run(fmt.Sprintf("%s/count=%d", impl.katName, vec.count), func(t *testing.T) {
			tested++
			if len(vec.seed) != 48 {
				t.Fatalf("seed length: got %d, want 48", len(vec.seed))
			}
			var seed [48]byte
			copy(seed[:], vec.seed)
			drbg := nist.NewDRBG(&seed)
			rng := nistReader{drbg: &drbg}

			pk, sk := vec.pk, vec.sk
			var err error
			if os.Getenv("CIRCL_MCELIECE_KAT_STRICT_DRBG") != "" {
				pk, sk, err = impl.generate(rng)
				if err != nil {
					t.Fatalf("keypair: %v", err)
				}
			} else {
				var consumed [32]byte
				drbg.Fill(consumed[:])
				// Keep default KAT coverage for deterministic key generation without
				// making the full KAT path spend most of its time regenerating public keys.
				if vec.count == 0 {
					pk0, sk0, genErr := impl.generateFromSeed(vec.sk[:32])
					if genErr != nil {
						t.Fatalf("keypair: %v", genErr)
					}
					checkEqual(t, "pk", pk0, vec.pk)
					checkEqual(t, "sk", sk0, vec.sk)
				}
			}
			ct, ss, err := impl.encapsulate(pk, rng)
			if err != nil {
				t.Fatalf("encapsulate: %v", err)
			}
			ss2, err := impl.decapsulate(sk, ct)
			if err != nil {
				t.Fatalf("decapsulate: %v", err)
			}
			if !bytes.Equal(ss, ss2) {
				t.Fatalf("decapsulated shared secret mismatch")
			}
			checkEqual(t, "pk", pk, vec.pk)
			checkEqual(t, "sk", sk, vec.sk)
			checkEqual(t, "ct", ct, vec.ct)
			checkEqual(t, "ss", ss, vec.ss)
		})
		return nil
	})
	return tested, err
}

func scanKATVectors(r io.Reader, limit int, f func(katVector) error) error {
	br := bufio.NewReaderSize(r, 4*1024*1024)
	var vec katVector
	have := false
	processed := 0
	for {
		line, readErr := br.ReadString('\n')
		if readErr != nil && readErr != io.EOF {
			return readErr
		}
		line = strings.TrimSpace(line)
		if line == "" {
			if have {
				if err := f(vec); err != nil {
					return err
				}
				processed++
				if limit > 0 && processed == limit {
					return nil
				}
				vec = katVector{}
				have = false
			}
		} else if !strings.HasPrefix(line, "#") {
			key, value, ok := strings.Cut(line, " = ")
			if !ok {
				return fmt.Errorf("malformed KAT line: %q", line)
			}
			if err := applyKATField(&vec, key, value); err != nil {
				return err
			}
			if key == "count" {
				have = true
			}
		}
		if readErr == io.EOF {
			break
		}
	}
	if have && (limit == 0 || processed < limit) {
		if err := f(vec); err != nil {
			return err
		}
		processed++
	}
	if limit > 0 && processed != limit {
		return fmt.Errorf("processed %d vectors, want %d", processed, limit)
	}
	if limit == 0 && processed == 0 {
		return fmt.Errorf("processed no vectors")
	}
	return nil
}

func applyKATField(vec *katVector, key, value string) error {
	switch key {
	case "count":
		n, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		vec.count = n
	case "seed":
		b, err := hex.DecodeString(value)
		if err != nil {
			return fmt.Errorf("seed: %w", err)
		}
		vec.seed = b
	case "pk":
		b, err := hex.DecodeString(value)
		if err != nil {
			return fmt.Errorf("pk: %w", err)
		}
		vec.pk = b
	case "sk":
		b, err := hex.DecodeString(value)
		if err != nil {
			return fmt.Errorf("sk: %w", err)
		}
		vec.sk = b
	case "ct":
		b, err := hex.DecodeString(value)
		if err != nil {
			return fmt.Errorf("ct: %w", err)
		}
		vec.ct = b
	case "ss":
		b, err := hex.DecodeString(value)
		if err != nil {
			return fmt.Errorf("ss: %w", err)
		}
		vec.ss = b
	}
	return nil
}

func checkEqual(t *testing.T, what string, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Fatalf("%s mismatch: got %d bytes, want %d bytes", what, len(got), len(want))
	}
}
