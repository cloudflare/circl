package main

import (
	"bytes"
	"embed"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

//go:embed templates/*.tmpl
var templateFS embed.FS

type scheme struct {
	Name            string
	Suffix          string
	GFBits          int
	SysN            int
	SysT            int
	PublicKeySize   int
	PrivateKeySize  int
	CiphertextSize  int
	BitrevShift     int
	GFPolyTerms     []int
	UseF            bool
	PKNRowsMod8     int
	PKNRowsAligned  bool
	CheckPadding    bool
	FullSupport     bool
	StoreFullPivots bool
	KATHashes       []string
}

// katHashes maps each scheme to the SHA-256 digests of its official Round 4
// KAT vectors (SHA-256(pk || sk || ct || ss), one per count). They are consumed
// by kat_test.go.tmpl, which regenerates the deterministic NIST KAT test from
// the AES-CTR-DRBG seed. Currently the count=0 vector is pinned per scheme.
var katHashes = map[string][]string{
	"mceliece348864":   {"5aa6b623698e811e729c269f293ae51f8f8fdaa35fa68e5d1cea9d2337857353"},
	"mceliece348864f":  {"3def5860ce030e18dbb1a0acb3a272a9dfdd472c6826284f8687d2f30b1a3280"},
	"mceliece460896":   {"08db58887b402273f96358a3eaf3cb357e092b19e52abb33dd30f038694e6899"},
	"mceliece460896f":  {"20eacc59f02488649818291610fc476397d6a47abfe523bbc345e0e29df1f40d"},
	"mceliece6688128":  {"6cec5636f30bf71554e3dee7ec2c957c723f8bd92bf41b892bccadeaaf1021af"},
	"mceliece6688128f": {"3ba6541ed7fd900d7adb5ecfa7524b3848b4c7fc90cc7f61a76d7fd9081d5e75"},
	"mceliece6960119":  {"fc0a611f070752f01a458abff804ae96ec7b35011fe964ca6ee50894ac115c9a"},
	"mceliece6960119f": {"88d3fad79b199017c0de198ce63e9d08e0469fed5ffdafe5509b4c29b410edf3"},
	"mceliece8192128":  {"5a135b5c38a64aff7aae642f0ea7888ebd4239913f00a030a0bf9efc6ed2ed31"},
	"mceliece8192128f": {"644ab68f9adf604e646af81cffce9ed7c1acfb85be6b67ed2393bc28a6d6ebcc"},
}

var schemes = []scheme{
	newScheme("mceliece348864", 12, 3488, 64, 261120, 6492, 96, 4, []int{3, 1, 0}, false),
	newScheme("mceliece348864f", 12, 3488, 64, 261120, 6492, 96, 4, []int{3, 1, 0}, true),
	newScheme("mceliece460896", 13, 4608, 96, 524160, 13608, 156, 3, []int{10, 9, 6, 0}, false),
	newScheme("mceliece460896f", 13, 4608, 96, 524160, 13608, 156, 3, []int{10, 9, 6, 0}, true),
	newScheme("mceliece6688128", 13, 6688, 128, 1044992, 13932, 208, 3, []int{7, 2, 1, 0}, false),
	newScheme("mceliece6688128f", 13, 6688, 128, 1044992, 13932, 208, 3, []int{7, 2, 1, 0}, true),
	newScheme("mceliece6960119", 13, 6960, 119, 1047319, 13948, 194, 3, []int{8, 0}, false),
	newScheme("mceliece6960119f", 13, 6960, 119, 1047319, 13948, 194, 3, []int{8, 0}, true),
	newScheme("mceliece8192128", 13, 8192, 128, 1357824, 14120, 208, 3, []int{7, 2, 1, 0}, false),
	newScheme("mceliece8192128f", 13, 8192, 128, 1357824, 14120, 208, 3, []int{7, 2, 1, 0}, true),
}

func newScheme(name string, gfBits, sysN, sysT, pkSize, skSize, ctSize, bitrevShift int, gfPolyTerms []int, useF bool) scheme {
	pkNRowsMod8 := (sysT * gfBits) % 8
	s := scheme{
		Name:            name,
		Suffix:          strings.TrimPrefix(name, "mceliece"),
		GFBits:          gfBits,
		SysN:            sysN,
		SysT:            sysT,
		PublicKeySize:   pkSize,
		PrivateKeySize:  skSize,
		CiphertextSize:  ctSize,
		BitrevShift:     bitrevShift,
		GFPolyTerms:     gfPolyTerms,
		UseF:            useF,
		PKNRowsMod8:     pkNRowsMod8,
		PKNRowsAligned:  pkNRowsMod8 == 0,
		CheckPadding:    pkNRowsMod8 != 0,
		FullSupport:     sysN == (1 << gfBits),
		StoreFullPivots: !useF,
		KATHashes:       katHashes[name],
	}
	return s
}

var commonInternalTemplates = []string{
	"bm.go.tmpl",
	"controlbits.go.tmpl",
	"decrypt.go.tmpl",
	"encrypt.go.tmpl",
	"kat_test.go.tmpl",
	"kem.go.tmpl",
	"kem_test.go.tmpl",
	"masks.go.tmpl",
	"pk_gen.go.tmpl",
	"root.go.tmpl",
	"sk_gen.go.tmpl",
	"sort.go.tmpl",
	"synd.go.tmpl",
	"transpose.go.tmpl",
	"util.go.tmpl",
	"params.go.tmpl",
}

func main() {
	t, err := template.New("mceliece").ParseFS(templateFS, "templates/*.tmpl")
	if err != nil {
		fatal(err)
	}

	for _, s := range schemes {
		if err := generateScheme(t, s); err != nil {
			fatal(fmt.Errorf("%s: %w", s.Name, err))
		}
	}
}

func generateScheme(t *template.Template, s scheme) error {
	internalDir := filepath.Join("internal", s.Name)
	publicDir := s.Name
	if err := os.MkdirAll(internalDir, 0o750); err != nil {
		return err
	}
	if err := os.MkdirAll(publicDir, 0o750); err != nil {
		return err
	}

	for _, tmplName := range commonInternalTemplates {
		out := strings.TrimSuffix(tmplName, ".tmpl")
		if err := render(t, tmplName, filepath.Join(internalDir, out), s); err != nil {
			return err
		}
	}

	gfTemplate := "gf12.go.tmpl"
	benesTemplate := "benes12.go.tmpl"
	if s.GFBits == 13 {
		gfTemplate = "gf13.go.tmpl"
		benesTemplate = "benes13.go.tmpl"
	}
	if err := render(t, gfTemplate, filepath.Join(internalDir, "gf.go"), s); err != nil {
		return err
	}
	if err := render(t, benesTemplate, filepath.Join(internalDir, "benes.go"), s); err != nil {
		return err
	}
	if err := render(t, "public_mceliece.go.tmpl", filepath.Join(publicDir, "mceliece.go"), s); err != nil {
		return err
	}
	if err := render(t, "public_mceliece_test.go.tmpl", filepath.Join(publicDir, "mceliece_test.go"), s); err != nil {
		return err
	}
	return nil
}

func render(t *template.Template, tmplName, out string, data scheme) error {
	var b bytes.Buffer
	b.WriteString("// Code generated by go generate; DO NOT EDIT.\n\n")
	if err := t.ExecuteTemplate(&b, tmplName, data); err != nil {
		return fmt.Errorf("execute %s: %w", tmplName, err)
	}

	formatted, err := format.Source(b.Bytes())
	if err != nil {
		return fmt.Errorf("format %s: %w", out, err)
	}
	return os.WriteFile(out, formatted, 0o600)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
