// +build ignore

// Autogenerates wrappers from templates to prevent too much duplicated code
// between the code for different modes.
package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"text/template"

	"github.com/cloudflare/circl/sign/dilithium/internal/common/params"
)

type Mode struct {
	Name           string
	UseAES         bool
	PublicKeySize  int
	PrivateKeySize int
	SignatureSize  int
	K              int
	L              int
	Eta            int
	DoubleEtaBits  int
	Beta           int
	Omega          int
	Tau            int
	Gamma1         int
	Gamma2         int
}

func (m Mode) Pkg() string {
	return strings.ToLower(m.Mode())
}
func (m Mode) Impl() string {
	return "impl" + m.Mode()
}
func (m Mode) Mode() string {
	return strings.ReplaceAll(strings.ReplaceAll(m.Name,
		"Dilithium", "Mode"), "-AES", "AES")
}

var (
	Modes = []Mode{
		{
			Name:           "Dilithium2",
			UseAES:         false,
			PublicKeySize:  1312,
			PrivateKeySize: 2544,
			SignatureSize:  2420,
			K:              4,
			L:              4,
			Eta:            2,
			DoubleEtaBits:  3,
			Beta:           78,
			Omega:          80,
			Tau:            39,
			Gamma1:         1 << 17,
			Gamma2:         (params.Q - 1) / 88,
		},
		{
			Name:           "Dilithium2-AES",
			UseAES:         true,
			PublicKeySize:  1312,
			PrivateKeySize: 2544,
			SignatureSize:  2420,
			K:              4,
			L:              4,
			Eta:            2,
			DoubleEtaBits:  3,
			Beta:           78,
			Omega:          80,
			Tau:            39,
			Gamma1:         1 << 17,
			Gamma2:         (params.Q - 1) / 88,
		},
		{
			Name:           "Dilithium3",
			UseAES:         false,
			PublicKeySize:  1952,
			PrivateKeySize: 4016,
			SignatureSize:  3293,
			K:              6,
			L:              5,
			Eta:            4,
			DoubleEtaBits:  4,
			Beta:           196,
			Omega:          55,
			Tau:            49,
			Gamma1:         1 << 19,
			Gamma2:         (params.Q - 1) / 32,
		},
		{
			Name:           "Dilithium3-AES",
			UseAES:         true,
			PublicKeySize:  1952,
			PrivateKeySize: 4016,
			SignatureSize:  3293,
			K:              6,
			L:              5,
			Eta:            4,
			DoubleEtaBits:  4,
			Beta:           196,
			Omega:          55,
			Tau:            49,
			Gamma1:         1 << 19,
			Gamma2:         (params.Q - 1) / 32,
		}, {
			Name:           "Dilithium5",
			UseAES:         false,
			PublicKeySize:  2592,
			PrivateKeySize: 4880,
			SignatureSize:  4595,
			K:              8,
			L:              7,
			Eta:            2,
			DoubleEtaBits:  3,
			Beta:           120,
			Omega:          75,
			Tau:            60,
			Gamma1:         1 << 19,
			Gamma2:         (params.Q - 1) / 32,
		}, {
			Name:           "Dilithium5-AES",
			UseAES:         true,
			PublicKeySize:  2592,
			PrivateKeySize: 4880,
			SignatureSize:  4595,
			K:              8,
			L:              7,
			Eta:            2,
			DoubleEtaBits:  3,
			Beta:           120,
			Omega:          75,
			Tau:            60,
			Gamma1:         1 << 19,
			Gamma2:         (params.Q - 1) / 32,
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

		res := string(buf.Bytes())
		offset := strings.Index(res, TemplateWarning)
		if offset == -1 {
			panic("Missing template warning in params.templ.go")
		}
		err = ioutil.WriteFile(mode.Pkg()+"/internal/params.go",
			[]byte(res[offset:]), 0644)
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
		err = ioutil.WriteFile(mode.Pkg()+".go", []byte(res[offset:]), 0644)
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
		err = ioutil.WriteFile(mode.Pkg()+"/dilithium.go", []byte(res[offset:]), 0644)
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
		return x == "params.go" || x == "params_test.go"
	}

	fs, err := ioutil.ReadDir("mode3/internal")
	if err != nil {
		panic(err)
	}

	// Read files
	for _, f := range fs {
		name := f.Name()
		if ignored(name) {
			continue
		}
		files[name], err = ioutil.ReadFile(path.Join("mode3/internal", name))
		if err != nil {
			panic(err)
		}
	}

	// Go over modes
	for _, mode := range Modes {
		if mode.Name == "Dilithium3" {
			continue
		}

		fs, err = ioutil.ReadDir(path.Join(mode.Pkg(), "internal"))
		for _, f := range fs {
			name := f.Name()
			fn := path.Join(mode.Pkg(), "internal", name)
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
			if f.Mode().IsDir() {
				panic(fmt.Sprintf("%s: is a directory", fn))
			}
			if f.Mode()&os.ModeSymlink != 0 {
				fmt.Printf("Removing symlink: %s\n", fn)
				err = os.Remove(fn)
				if err != nil {
					panic(err)
				}
			}
		}
		for name, expected := range files {
			fn := path.Join(mode.Pkg(), "internal", name)
			expected = []byte(fmt.Sprintf(
				"%s mode3/internal/%s by gen.go\n\n%s",
				TemplateWarning,
				name,
				string(expected),
			))
			got, err := ioutil.ReadFile(fn)
			if err == nil {
				if bytes.Equal(got, expected) {
					continue
				}
			}
			fmt.Printf("Updating %s\n", fn)
			err = ioutil.WriteFile(fn, expected, 0644)
			if err != nil {
				panic(err)
			}
		}
	}

}
