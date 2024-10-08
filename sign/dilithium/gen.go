//go:build ignore
// +build ignore

// Autogenerates wrappers from templates to prevent too much duplicated code
// between the code for different modes.
package main

import (
	"bytes"
	"fmt"
	"go/format"
	"os"
	"path"
	"strings"
	"text/template"

	"github.com/cloudflare/circl/sign/internal/dilithium/params"
)

type Mode struct {
	Name          string
	K             int
	L             int
	Eta           int
	DoubleEtaBits int
	Omega         int
	Tau           int
	Gamma1Bits    int
	Gamma2        int
	TRSize        int
	CTildeSize    int
}

func (m Mode) Pkg() string {
	return strings.ToLower(m.Mode())
}

func (m Mode) PkgPath() string {
	if m.NIST() {
		return path.Join("..", "mldsa", m.Pkg())
	}

	return m.Pkg()
}

func (m Mode) Impl() string {
	return "impl" + m.Mode()
}

func (m Mode) Mode() string {
	if m.NIST() {
		return strings.ReplaceAll(m.Name, "-", "")
	}

	return strings.ReplaceAll(strings.ReplaceAll(m.Name,
		"Dilithium", "Mode"), "-AES", "AES")
}

func (m Mode) UseAES() bool {
	return strings.HasSuffix(m.Name, "-AES")
}

func (m Mode) NIST() bool {
	return strings.HasPrefix(m.Name, "ML-DSA-")
}

var (
	Modes = []Mode{
		{
			Name:          "Dilithium2",
			K:             4,
			L:             4,
			Eta:           2,
			DoubleEtaBits: 3,
			Omega:         80,
			Tau:           39,
			Gamma1Bits:    17,
			Gamma2:        (params.Q - 1) / 88,
			TRSize:        32,
			CTildeSize:    32,
		},
		{
			Name:          "Dilithium2-AES",
			K:             4,
			L:             4,
			Eta:           2,
			DoubleEtaBits: 3,
			Omega:         80,
			Tau:           39,
			Gamma1Bits:    17,
			Gamma2:        (params.Q - 1) / 88,
			TRSize:        32,
			CTildeSize:    32,
		},
		{
			Name:          "Dilithium3",
			K:             6,
			L:             5,
			Eta:           4,
			DoubleEtaBits: 4,
			Omega:         55,
			Tau:           49,
			Gamma1Bits:    19,
			Gamma2:        (params.Q - 1) / 32,
			TRSize:        32,
			CTildeSize:    32,
		},
		{
			Name:          "Dilithium3-AES",
			K:             6,
			L:             5,
			Eta:           4,
			DoubleEtaBits: 4,
			Omega:         55,
			Tau:           49,
			Gamma1Bits:    19,
			Gamma2:        (params.Q - 1) / 32,
			TRSize:        32,
			CTildeSize:    32,
		},
		{
			Name:          "Dilithium5",
			K:             8,
			L:             7,
			Eta:           2,
			DoubleEtaBits: 3,
			Omega:         75,
			Tau:           60,
			Gamma1Bits:    19,
			Gamma2:        (params.Q - 1) / 32,
			TRSize:        32,
			CTildeSize:    32,
		},
		{
			Name:          "Dilithium5-AES",
			K:             8,
			L:             7,
			Eta:           2,
			DoubleEtaBits: 3,
			Omega:         75,
			Tau:           60,
			Gamma1Bits:    19,
			Gamma2:        (params.Q - 1) / 32,
			TRSize:        32,
			CTildeSize:    32,
		},
		{
			Name:          "ML-DSA-44",
			K:             4,
			L:             4,
			Eta:           2,
			DoubleEtaBits: 3,
			Omega:         80,
			Tau:           39,
			Gamma1Bits:    17,
			Gamma2:        (params.Q - 1) / 88,
			TRSize:        64,
			CTildeSize:    32,
		},
		{
			Name:          "ML-DSA-65",
			K:             6,
			L:             5,
			Eta:           4,
			DoubleEtaBits: 4,
			Omega:         55,
			Tau:           49,
			Gamma1Bits:    19,
			Gamma2:        (params.Q - 1) / 32,
			TRSize:        64,
			CTildeSize:    48,
		},
		{
			Name:          "ML-DSA-87",
			K:             8,
			L:             7,
			Eta:           2,
			DoubleEtaBits: 3,
			Omega:         75,
			Tau:           60,
			Gamma1Bits:    19,
			Gamma2:        (params.Q - 1) / 32,
			TRSize:        64,
			CTildeSize:    64,
		},
	}
	TemplateWarning = "// Code generated from"
)

func main() {
	generateModePackageFiles()
	generateModeToplevelFiles()
	generateParamsFiles()
	generateSourceFiles()
}

// Generates modeX/internal/params.go from templates/params.templ.go
func generateParamsFiles() {
	tl, err := template.ParseFiles("templates/params.templ.go")
	if err != nil {
		panic(err)
	}

	for _, mode := range Modes {
		buf := new(bytes.Buffer)
		err := tl.Execute(buf, mode)
		if err != nil {
			panic(err)
		}

		// Formating output code
		code, err := format.Source(buf.Bytes())
		if err != nil {
			panic("error formating code")
		}

		res := string(code)
		offset := strings.Index(res, TemplateWarning)
		if offset == -1 {
			panic("Missing template warning in params.templ.go")
		}
		err = os.WriteFile(mode.PkgPath()+"/internal/params.go",
			[]byte(res[offset:]), 0o644)
		if err != nil {
			panic(err)
		}
	}
}

// Generates modeX.go from templates/mode.templ.go
func generateModeToplevelFiles() {
	tl, err := template.ParseFiles("templates/mode.templ.go")
	if err != nil {
		panic(err)
	}

	for _, mode := range Modes {
		buf := new(bytes.Buffer)
		err := tl.Execute(buf, mode)
		if err != nil {
			panic(err)
		}

		res := string(buf.Bytes())
		offset := strings.Index(res, TemplateWarning)
		if offset == -1 {
			panic("Missing template warning in mode.templ.go")
		}
		err = os.WriteFile(mode.Pkg()+".go", []byte(res[offset:]), 0o644)
		if err != nil {
			panic(err)
		}
	}
}

// Generates modeX/dilithium.go from templates/modePkg.templ.go
func generateModePackageFiles() {
	tl, err := template.ParseFiles("templates/modePkg.templ.go")
	if err != nil {
		panic(err)
	}

	for _, mode := range Modes {
		buf := new(bytes.Buffer)
		err := tl.Execute(buf, mode)
		if err != nil {
			panic(err)
		}

		res := string(buf.Bytes())
		offset := strings.Index(res, TemplateWarning)
		if offset == -1 {
			panic("Missing template warning in modePkg.templ.go")
		}
		err = os.WriteFile(mode.PkgPath()+"/dilithium.go", []byte(res[offset:]), 0o644)
		if err != nil {
			panic(err)
		}
	}
}

// Copies mode3 source files to other modes
func generateSourceFiles() {
	files := make(map[string][]byte)

	// Ignore mode specific files.
	ignored := func(x string) bool {
		return x == "params.go" || x == "params_test.go" ||
			strings.HasSuffix(x, ".swp")
	}

	fs, err := os.ReadDir("mode3/internal")
	if err != nil {
		panic(err)
	}

	// Read files
	for _, f := range fs {
		name := f.Name()
		if ignored(name) {
			continue
		}
		files[name], err = os.ReadFile(path.Join("mode3/internal", name))
		if err != nil {
			panic(err)
		}
	}

	// Go over modes
	for _, mode := range Modes {
		if mode.Name == "Dilithium3" {
			continue
		}

		fs, err = os.ReadDir(path.Join(mode.PkgPath(), "internal"))
		for _, f := range fs {
			name := f.Name()
			fn := path.Join(mode.PkgPath(), "internal", name)
			if ignored(name) {
				continue
			}
			_, ok := files[name]
			if !ok {
				fmt.Printf("Removing superfluous file: %s\n", fn)
				err = os.Remove(fn)
				if err != nil {
					panic(err)
				}
			}
			if f.IsDir() {
				panic(fmt.Sprintf("%s: is a directory", fn))
			}
			if f.Type()&os.ModeSymlink != 0 {
				fmt.Printf("Removing symlink: %s\n", fn)
				err = os.Remove(fn)
				if err != nil {
					panic(err)
				}
			}
		}
		for name, expected := range files {
			fn := path.Join(mode.PkgPath(), "internal", name)
			expected = []byte(fmt.Sprintf(
				"%s mode3/internal/%s by gen.go\n\n%s",
				TemplateWarning,
				name,
				string(expected),
			))
			got, err := os.ReadFile(fn)
			if err == nil {
				if bytes.Equal(got, expected) {
					continue
				}
			}
			fmt.Printf("Updating %s\n", fn)
			err = os.WriteFile(fn, expected, 0o644)
			if err != nil {
				panic(err)
			}
		}
	}
}
