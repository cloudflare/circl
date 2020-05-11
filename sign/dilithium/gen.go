// +build ignore

// Autogenerates wrappers from templates to prevent too much duplicated code
// between the code for different modes.
package main

import (
	"bytes"
	"io/ioutil"
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
