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
)

type Instance struct {
	Name           string
	K              int
	Eta1           int
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
			Eta1:           3,
			K:              2,
			CiphertextSize: 768,
			DU:             10,
			DV:             4,
		},
		{
			Name:           "Kyber768",
			Eta1:           2,
			K:              3,
			CiphertextSize: 1088,
			DU:             10,
			DV:             4,
		},
		{
			Name:           "Kyber1024",
			Eta1:           2,
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
	generateSourceFiles()
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
		err = os.WriteFile(mode.Pkg()+"/internal/params.go",
			[]byte(res[offset:]), 0o644)
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
		err = os.WriteFile(mode.Pkg()+"/kyber.go", []byte(res[offset:]), 0o644)
		if err != nil {
			panic(err)
		}
	}
}

// Copies kyber512 source files to other modes
func generateSourceFiles() {
	files := make(map[string][]byte)

	// Ignore mode specific files.
	ignored := func(x string) bool {
		return x == "params.go" || x == "params_test.go"
	}

	fs, err := os.ReadDir("kyber512/internal")
	if err != nil {
		panic(err)
	}

	// Read files
	for _, f := range fs {
		name := f.Name()
		if ignored(name) {
			continue
		}
		files[name], err = os.ReadFile(path.Join("kyber512/internal", name))
		if err != nil {
			panic(err)
		}
	}

	// Go over modes
	for _, mode := range Instances {
		if mode.Name == "Kyber512" {
			continue
		}

		fs, err = os.ReadDir(path.Join(mode.Pkg(), "internal"))
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
			fn := path.Join(mode.Pkg(), "internal", name)
			expected = []byte(fmt.Sprintf(
				"%s kyber512/internal/%s by gen.go\n\n%s",
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
