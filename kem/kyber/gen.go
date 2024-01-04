//go:build ignore
// +build ignore

// Autogenerates wrappers from templates to prevent too much duplicated code
// between the code for different modes.
package main

import (
	"bytes"
	"fmt"
	"go/format"
	"io/ioutil"
	"path"
	"strings"
	"text/template"
)

type Instance struct {
	Name string
}

func (m Instance) KemName() string {
	if m.NIST() {
		return m.Name
	}
	return m.Name + ".CCAKEM"
}

func (m Instance) NIST() bool {
	return strings.HasPrefix(m.Name, "ML-KEM")
}

func (m Instance) PkePkg() string {
	if !m.NIST() {
		return m.Pkg()
	}
	return strings.ReplaceAll(m.Pkg(), "mlkem", "kyber")
}

func (m Instance) Pkg() string {
	return strings.ToLower(strings.ReplaceAll(m.Name, "-", ""))
}

func (m Instance) PkgPath() string {
	if m.NIST() {
		return path.Join("..", "mlkem", m.Pkg())
	}
	return m.Pkg()
}

var (
	Instances = []Instance{
		{Name: "Kyber512"},
		{Name: "Kyber768"},
		{Name: "Kyber1024"},
		{Name: "ML-KEM-512"},
		{Name: "ML-KEM-768"},
		{Name: "ML-KEM-1024"},
	}
	TemplateWarning = "// Code generated from"
)

func main() {
	generatePackageFiles()
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

		// Formating output code
		code, err := format.Source(buf.Bytes())
		if err != nil {
			panic(fmt.Sprintf("error formating code: %v", err))
		}

		res := string(code)
		offset := strings.Index(res, TemplateWarning)
		if offset == -1 {
			panic("Missing template warning in pkg.templ.go")
		}
		err = ioutil.WriteFile(mode.PkgPath()+"/kyber.go", []byte(res[offset:]), 0o644)
		if err != nil {
			panic(err)
		}
	}
}
