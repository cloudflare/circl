// The following directive is necessary to make the package coherent:

//go:build ignore
// +build ignore

// This program generates contributors.go. It can be invoked by running
// go generate
package main

import (
	"bytes"
	"fmt"
	"go/format"
	"os"
	"strings"
	"text/template"
)

var p34 = map[string]struct {
	pow_strategy string
	mul_strategy string
	mul_initial  int
}{
	"P434": {
		pow_strategy: "[]uint8{3, 10, 7, 5, 6, 5, 3, 8, 4, 7, 5, 6, 4, 5, 9, 6, 3, 11, 5, 5, 2, 8, 4, 7, 7, 8, 5, 6, 4, 8, 5, 2, 10, 6, 5, 4, 8, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 1}",
		mul_strategy: "[]uint8{2, 15, 9, 8, 14, 12, 2, 8, 5, 15, 8, 15, 6, 6, 3, 2, 0, 10, 9, 13, 1, 12, 3, 7, 1, 10, 8, 11, 2, 15, 14, 1, 11, 12, 14, 3, 11, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 0}",
		mul_initial:  8,
	},
	"P503": {
		pow_strategy: "[]uint8{12, 5, 5, 2, 7, 11, 3, 8, 4, 11, 4, 7, 5, 6, 3, 7, 5, 7, 2, 12, 5, 6, 4, 6, 8, 6, 4, 7, 5, 5, 8, 5, 8, 5, 5, 8, 9, 3, 6, 2, 10, 6, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 3}",
		mul_strategy: "[]uint8{12, 11, 10, 0, 1, 8, 3, 7, 1, 8, 3, 6, 7, 14, 2, 14, 14, 9, 0, 13, 9, 15, 5, 12, 7, 13, 7, 15, 6, 7, 9, 0, 5, 7, 6, 8, 8, 3, 7, 0, 10, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 3}",
		mul_initial:  0,
	},
	"P751": {
		pow_strategy: "[]uint8{5, 7, 6, 2, 10, 4, 6, 9, 8, 5, 9, 4, 7, 5, 5, 4, 8, 3, 9, 5, 5, 4, 10, 4, 6, 6, 6, 5, 8, 9, 3, 4, 9, 4, 5, 6, 6, 2, 9, 4, 5, 5, 5, 7, 7, 9, 4, 6, 4, 8, 5, 8, 6, 6, 2, 9, 7, 4, 8, 8, 8, 4, 6, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 2}",
		mul_strategy: "[]uint8{15, 11, 10, 0, 15, 3, 3, 3, 4, 4, 9, 7, 11, 11, 5, 3, 12, 2, 10, 8, 5, 2, 8, 3, 5, 4, 11, 4, 0, 9, 2, 1, 12, 7, 5, 14, 15, 0, 14, 5, 6, 4, 5, 13, 6, 9, 7, 15, 1, 14, 11, 15, 12, 5, 0, 10, 9, 7, 7, 10, 14, 6, 11, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 1}",
		mul_initial:  13,
	},
}

// P434 optimized implementation for
// ARM64 is not ported yet
var opt_arm = map[string]bool{
	"P434": false,
	"P503": true,
	"P751": true,
}

// Generates an 'fileNameBase.go' from 'fileNameBase.gotemp' file
// for a given finite 'field'. Maps placeholders to 'values'.
func gen(field, fileNameBase string, values interface{}) {
	// Template files are located in ../templates and have
	// extension .gotemp
	templateFile := "../templates/" + fileNameBase + ".gotemp"
	t, err := template.ParseFiles(templateFile)
	if err != nil {
		panic(fmt.Sprintf("Cannot open template file %s", templateFile))
	}
	var buf bytes.Buffer
	err = t.Execute(&buf, values)
	if err != nil {
		panic("bad template execution")
	}

	// Formating output code
	code, err := format.Source(buf.Bytes())
	if err != nil {
		panic("error formating code")
	}

	// name of the output .go file
	outFileName := fileNameBase + ".go"
	out, err := os.Create(outFileName)
	if err != nil {
		panic("Cannot open file")
	}
	_, err = out.Write(code)
	if err != nil {
		panic("error writing code")
	}

	err = out.Close()
	if err != nil {
		panic("Cant close generated file")
	}
}

func main() {
	field := os.Args[1]

	s := struct {
		FIELD            string
		PACKAGE          string
		P34_POW_STRATEGY string
		P34_MUL_STRATEGY string
		P34_INITIAL_MUL  int
		OPT_ARM          bool
	}{
		FIELD:            field,
		PACKAGE:          strings.ToLower(field),
		P34_POW_STRATEGY: p34[field].pow_strategy,
		P34_MUL_STRATEGY: p34[field].mul_strategy,
		P34_INITIAL_MUL:  p34[field].mul_initial,
		OPT_ARM:          opt_arm[field],
	}

	targets := map[string]interface{}{
		"arith_decl":    s,
		"arith_generic": s,
		"curve":         s,
		"fp2":           s,
		"core":          s,

		// tests
		"arith_test": s,
		"fp2_test":   s,
		"curve_test": s,
	}

	for v, s := range targets {
		gen(field, v, s)
	}
}
