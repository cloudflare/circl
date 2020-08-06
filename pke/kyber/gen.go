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

type Instance struct {
	Name           string
	K              int
	CiphertextSize int
	DU             int
	DV             int
}

func (m Instance) Pkg() string {
	return strings.ToLower(m.Name)
}
func (m Instance) Impl() string {
	return "impl" + m.Name
}

var (
	Instances = []Instance{
		{
			Name:           "Kyber512",
			K:              2,
			CiphertextSize: 736,
			DU:             10,
			DV:             3,
		},
		{
			Name:           "Kyber768",
			K:              3,
			CiphertextSize: 1088,
			DU:             10,
			DV:             4,
		},
		{
			Name:           "Kyber1024",
			K:              4,
			CiphertextSize: 1568,
			DU:             11,
			DV:             5,
		},
	}
	TemplateWarning = "// Code generated from"
)

func main() {
	generatePackageFiles()
	generateParamsFiles()
}

// Generates instance/internal/params.go from templates/params.templ.go
func generateParamsFiles() {
	tl, err := template.ParseFiles("templates/params.templ.go")
	if err != nil {
		panic(err)
	}

	for _, mode := range Instances {
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

// Generates instance/kyber.go from templates/pkg.templ.go
func generatePackageFiles() {
	tl, err := template.ParseFiles("templates/pkg.templ.go")
	if err != nil {
		panic(err)
	}

	for _, mode := range Instances {
		buf := new(bytes.Buffer)
		err := tl.Execute(buf, mode)
		if err != nil {
			panic(err)
		}

		res := string(buf.Bytes())
		offset := strings.Index(res, TemplateWarning)
		if offset == -1 {
			panic("Missing template warning in pkg.templ.go")
		}
		err = ioutil.WriteFile(mode.Pkg()+"/kyber.go", []byte(res[offset:]), 0644)
		if err != nil {
			panic(err)
		}
	}
}
