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
			Name:           "Dilithium1",
			UseAES:         false,
			PublicKeySize:  896,
			PrivateKeySize: 2096,
			SignatureSize:  1387,
			K:              3,
			L:              2,
			Eta:            7,
			DoubleEtaBits:  4,
			Beta:           375,
			Omega:          64,
		},
		{
			Name:           "Dilithium1-AES",
			UseAES:         true,
			PublicKeySize:  896,
			PrivateKeySize: 2096,
			SignatureSize:  1387,
			K:              3,
			L:              2,
			Eta:            7,
			DoubleEtaBits:  4,
			Beta:           375,
			Omega:          64,
		},
		{
			Name:           "Dilithium2",
			UseAES:         false,
			PublicKeySize:  1184,
			PrivateKeySize: 2800,
			SignatureSize:  2044,
			K:              4,
			L:              3,
			Eta:            6,
			DoubleEtaBits:  4,
			Beta:           325,
			Omega:          80,
		},
		{
			Name:           "Dilithium2-AES",
			UseAES:         true,
			PublicKeySize:  1184,
			PrivateKeySize: 2800,
			SignatureSize:  2044,
			K:              4,
			L:              3,
			Eta:            6,
			DoubleEtaBits:  4,
			Beta:           325,
			Omega:          80,
		},
		{
			Name:           "Dilithium3",
			UseAES:         false,
			PublicKeySize:  1472,
			PrivateKeySize: 3504,
			SignatureSize:  2701,
			K:              5,
			L:              4,
			Eta:            5,
			DoubleEtaBits:  4,
			Beta:           275,
			Omega:          96,
		},
		{
			Name:           "Dilithium3-AES",
			UseAES:         true,
			PublicKeySize:  1472,
			PrivateKeySize: 3504,
			SignatureSize:  2701,
			K:              5,
			L:              4,
			Eta:            5,
			DoubleEtaBits:  4,
			Beta:           275,
			Omega:          96,
		}, {
			Name:           "Dilithium4",
			UseAES:         false,
			PublicKeySize:  1760,
			PrivateKeySize: 3856,
			SignatureSize:  3366,
			K:              6,
			L:              5,
			Eta:            3,
			DoubleEtaBits:  3,
			Beta:           175,
			Omega:          120,
		}, {
			Name:           "Dilithium4-AES",
			UseAES:         true,
			PublicKeySize:  1760,
			PrivateKeySize: 3856,
			SignatureSize:  3366,
			K:              6,
			L:              5,
			Eta:            3,
			DoubleEtaBits:  3,
			Beta:           175,
			Omega:          120,
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
				fmt.Printf("Removing superfluous file: %s", fn)
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
