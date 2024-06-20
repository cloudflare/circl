//go:build ignore
// +build ignore

package main

import (
	"bytes"
	"go/format"
	"io/ioutil"
	"strings"
	"text/template"
)

type Instance struct {
	Name string
	Hash string
}

func (m Instance) Pkg() string {
	return strings.ToLower(m.Name)
}

var (
	SInstances = []Instance{
		{Name: "SNTRUP761"},
		{Name: "SNTRUP653"},
		{Name: "SNTRUP857"},
		{Name: "SNTRUP953"},
		{Name: "SNTRUP1013"},
		{Name: "SNTRUP1277"},
	}
	LPRInstances = []Instance{
		{Name: "NTRULPR761"},
		{Name: "NTRULPR653"},
		{Name: "NTRULPR857"},
		{Name: "NTRULPR953"},
		{Name: "NTRULPR1013"},
		{Name: "NTRULPR1277"},
	}
	TemplateWarning = "// Code generated from"
)

func main() {
	generateStreamlinedPackageFiles()
	generateLPRPackageFiles()
}

func generateStreamlinedPackageFiles() {
	template, err := template.ParseFiles("templates/sntrup.templ.go")
	if err != nil {
		panic(err)
	}

	for _, mode := range SInstances {
		buf := new(bytes.Buffer)
		err := template.Execute(buf, mode)
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
		err = ioutil.WriteFile(mode.Pkg()+"/ntruprime.go", []byte(res[offset:]), 0o644)
		if err != nil {
			panic(err)
		}
	}
}

func generateLPRPackageFiles() {
	template, err := template.ParseFiles("templates/ntrulpr.templ.go")
	if err != nil {
		panic(err)
	}

	for _, mode := range LPRInstances {
		buf := new(bytes.Buffer)
		err := template.Execute(buf, mode)
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
		err = ioutil.WriteFile(mode.Pkg()+"/ntruprime.go", []byte(res[offset:]), 0o644)
		if err != nil {
			panic(err)
		}
	}
}

func generateKAT() {
	template, err := template.ParseFiles("templates/kat.templ.go")
	if err != nil {
		panic(err)
	}

	for _, mode := range SInstances {
		buf := new(bytes.Buffer)
		err := template.Execute(buf, mode)
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
		err = ioutil.WriteFile(mode.Pkg()+"/kat_test.go", []byte(res[offset:]), 0o600)
		if err != nil {
			panic(err)
		}
	}
}
