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

type Mode struct {
	Name        string
	N           int
	M           int
	O           int
	K           int
	KeySeedSize int
	DigestSize  int
	Tail        [5]uint8
}

func (m Mode) Pkg() string {
	return strings.ToLower(m.Mode())
}

func (m Mode) Impl() string {
	return "impl" + m.Mode()
}

func (m Mode) Mode() string {
	return strings.ReplaceAll(m.Name, "MAYO_", "Mode")
}

var (
	Modes = []Mode{
		{
			Name:        "MAYO_1",
			N:           66,
			M:           64,
			O:           8,
			K:           9,
			KeySeedSize: 24,
			DigestSize:  32,
			Tail:        [5]uint8{8, 0, 2, 8, 0},
		},
		{
			Name:        "MAYO_2",
			N:           78,
			M:           64,
			O:           18,
			K:           4,
			KeySeedSize: 24,
			DigestSize:  32,
			Tail:        [5]uint8{8, 0, 2, 8, 0},
		},
		{
			Name:        "MAYO_3",
			N:           99,
			M:           96,
			O:           10,
			K:           11,
			KeySeedSize: 32,
			DigestSize:  48,
			Tail:        [5]uint8{2, 2, 0, 2, 0},
		},
		{
			Name:        "MAYO_5",
			N:           133,
			M:           128,
			O:           12,
			K:           12,
			KeySeedSize: 40,
			DigestSize:  64,
			Tail:        [5]uint8{4, 8, 0, 4, 2},
		},
	}
	TemplateWarning = "// Code generated from"
)

func main() {
	generateModePackageFiles()
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
			fmt.Println(buf.String())
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

// Generates modeX/mayo.go from templates/modePkg.templ.go
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

		res := buf.String()
		offset := strings.Index(res, TemplateWarning)
		if offset == -1 {
			panic("Missing template warning in modePkg.templ.go")
		}
		err = os.WriteFile(mode.Pkg()+"/mayo.go", []byte(res[offset:]), 0o644)
		if err != nil {
			panic(err)
		}
	}
}

// Copies mode1 source files to other modes
func generateSourceFiles() {
	files := make(map[string][]byte)

	// Ignore mode specific files.
	ignored := func(x string) bool {
		return x == "params.go" || x == "params_test.go" ||
			strings.HasSuffix(x, ".swp")
	}

	fs, err := os.ReadDir("mode1/internal")
	if err != nil {
		panic(err)
	}

	// Read files
	for _, f := range fs {
		name := f.Name()
		if ignored(name) {
			continue
		}
		files[name], err = os.ReadFile(path.Join("mode1/internal", name))
		if err != nil {
			panic(err)
		}
	}

	// Go over modes
	for _, mode := range Modes {
		if mode.Name == "MAYO_1" {
			continue
		}

		fs, _ = os.ReadDir(path.Join(mode.Pkg(), "internal"))
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
				"%s mode1/internal/%s by gen.go\n\n%s",
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
