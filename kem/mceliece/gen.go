//go:build ignore
// +build ignore

// Autogenerates wrappers from templates to prevent too much duplicated code
// between the code for different modes.
package main

import (
	"bytes"
	"go/format"
	"io/ioutil"
	"strings"
	"text/template"
)

type Param struct {
	Gf             string
	PublicKeySize  uint
	PrivateKeySize uint
	CiphertextSize uint
	SysN           uint
	SysT           uint
}

type Instance struct {
	Name  string
	Param Param
}

func (m Instance) Pkg() string {
	return strings.ToLower(m.Name)
}

func (m Instance) IsSemiSystematic() bool {
	return strings.HasSuffix(m.Name, "f")
}

func (m Instance) Is348864() bool {
	return strings.Contains(m.Name, "348864")
}

func (m Instance) Is460896() bool {
	return strings.Contains(m.Name, "460896")
}

func (m Instance) Is6688128() bool {
	return strings.Contains(m.Name, "6688128")
}

func (m Instance) Is6960119() bool {
	return strings.Contains(m.Name, "6960119")
}

func (m Instance) Is8192128() bool {
	return strings.Contains(m.Name, "8192128")
}

var (
	McElieceParam348864 = Param{
		Gf:             "gf2e12",
		PublicKeySize:  261120,
		PrivateKeySize: 6492,
		CiphertextSize: 96,
		SysN:           3488,
		SysT:           64,
	}
	McElieceParam460896 = Param{
		Gf:             "gf2e13",
		PublicKeySize:  524160,
		PrivateKeySize: 13608,
		CiphertextSize: 156,
		SysN:           4608,
		SysT:           96,
	}
	McElieceParam6688128 = Param{
		Gf:             "gf2e13",
		PublicKeySize:  1044992,
		PrivateKeySize: 13932,
		CiphertextSize: 208,
		SysN:           6688,
		SysT:           128,
	}
	McElieceParam6960119 = Param{
		Gf:             "gf2e13",
		PublicKeySize:  1047319,
		PrivateKeySize: 13948,
		CiphertextSize: 194,
		SysN:           6960,
		SysT:           119,
	}
	McElieceParam8192128 = Param{
		Gf:             "gf2e13",
		PublicKeySize:  1357824,
		PrivateKeySize: 14120,
		CiphertextSize: 208,
		SysN:           8192,
		SysT:           128,
	}
	Instances = []Instance{
		{Name: "mceliece348864", Param: McElieceParam348864},
		{Name: "mceliece348864f", Param: McElieceParam348864},
		{Name: "mceliece460896", Param: McElieceParam460896},
		{Name: "mceliece460896f", Param: McElieceParam460896},
		{Name: "mceliece6688128", Param: McElieceParam6688128},
		{Name: "mceliece6688128f", Param: McElieceParam6688128},
		{Name: "mceliece6960119", Param: McElieceParam6960119},
		{Name: "mceliece6960119f", Param: McElieceParam6960119},
		{Name: "mceliece8192128", Param: McElieceParam8192128},
		{Name: "mceliece8192128f", Param: McElieceParam8192128},
	}

	TemplateWarning = "// Code generated from"
)

func main() {
	generateTemplateFilesIf("templates/benes_348864.templ.go", "benes", func(m Instance) bool { return m.Is348864() })
	generateTemplateFilesIf("templates/benes_other.templ.go", "benes", func(m Instance) bool { return !m.Is348864() })
	generateTemplateFilesIf("templates/operations_6960119.templ.go", "operations", func(m Instance) bool { return m.Is6960119() })
	generateTemplateFiles("templates/mceliece.templ.go", "mceliece")
	generateTemplateFiles("templates/pk_gen_vec.templ.go", "pk_gen")
	generateTemplateFiles("templates/vec.templ.go", "vec")
	generateTemplateFilesIf("templates/fft_348864.templ.go", "fft", func(m Instance) bool { return m.Is348864() })
	generateTemplateFilesIf("templates/fft_other.templ.go", "fft", func(m Instance) bool { return !m.Is348864() })
}

func generateTemplateFiles(templatePath, outputName string) {
	generateTemplateFilesIf(templatePath, outputName, func(instance Instance) bool { return true })
}

func generateTemplateFilesIf(templatePath, outputName string, predicate func(Instance) bool) {
	tl, err := template.ParseFiles(templatePath)
	if err != nil {
		panic(err)
	}

	for _, mode := range Instances {
		if !predicate(mode) {
			continue
		}
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
			panic("Missing template warning in pkg.templ.go")
		}
		err = ioutil.WriteFile(mode.Pkg()+"/"+outputName+".go", []byte(res[offset:]), 0o644)
		if err != nil {
			panic(err)
		}
	}
}
