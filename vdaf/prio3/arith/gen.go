//go:build ignore

package main

import (
	"bytes"
	"fmt"
	"go/format"
	"math/big"
	"os"
	"path"
	"strings"
	"text/template"
)

type Fp struct {
	Name          string
	Bits          uint
	NumRootsUnity uint
	NumInverseInt uint
	Modulus       string
	Generator     string
}

func (f Fp) NumUint64() int { return int(f.Bits) / 64 }

func (f Fp) NumUint8() int { return int(f.Bits) / 8 }

func (f Fp) OrderConst() (s string) {
	d := baseTwo64(f.Prime())
	for i := f.NumUint64() - 1; i >= 0; i-- {
		s += fmt.Sprintf("orderP%v = uint64(0x%v)\n", i, d[i].Text(16))
	}
	return
}

func (f Fp) OrderVar() string {
	var s []string
	for i := f.NumUint64() - 1; i >= 0; i-- {
		s = append(s, fmt.Sprintf("orderP%v", i))
	}
	return strings.Join(s, ",")
}

func (f Fp) Prime() *big.Int {
	p, _ := new(big.Int).SetString(f.Modulus, 16)
	return p
}

func (f Fp) Half() string {
	p := f.Prime()
	half := big.NewInt(2)
	half.ModInverse(half, p)
	f.toMont(half, p)
	return printDigits(half)
}

func (f Fp) RSquare() string {
	p := f.Prime()
	R2 := big.NewInt(1)
	R2.Lsh(R2, f.Bits)
	R2.Mul(R2, R2).Mod(R2, p)
	return printDigits(R2)
}

func (f Fp) RootsOfUnity() (s string) {
	p := f.Prime()
	g, _ := new(big.Int).SetString(f.Generator, 16)
	for i := range f.NumRootsUnity + 1 {
		twoI := big.NewInt(1)
		twoI.Lsh(twoI, f.NumRootsUnity-i)
		gi := new(big.Int).Exp(g, twoI, p)
		f.toMont(gi, p)
		s += "{" + printDigits(gi) + "},\n"
	}
	return
}

func (f Fp) InverseInt() (s string) {
	p := f.Prime()
	for i := range f.NumInverseInt {
		invI := new(big.Int).ModInverse(big.NewInt(int64(i+1)), p)
		f.toMont(invI, p)
		s += "{" + printDigits(invI) + "},\n"
	}
	return
}

func (f Fp) toMont(x, p *big.Int) {
	R := big.NewInt(1)
	R.Lsh(R, f.Bits)
	x.Mul(x, R).Mod(x, p)
}

func baseTwo64(v *big.Int) (d []*big.Int) {
	n := new(big.Int).Set(v)
	two64 := new(big.Int).Lsh(big.NewInt(1), 64)
	for n.Sign() > 0 {
		x := new(big.Int).Mod(n, two64)
		n.Rsh(n, 64)
		d = append(d, x)
	}
	return
}

func printDigits(n *big.Int) (s string) {
	for _, d := range baseTwo64(n) {
		s += fmt.Sprintf("0x%016x,", d)
	}
	return
}

func main() {
	const TemplateWarning = "// Code generated from"

	fields := []Fp{
		{
			Name:          "Fp64",
			Bits:          64,
			NumRootsUnity: 32,
			NumInverseInt: 8,
			// Modulus: 2^32 * 4294967295 + 1
			Modulus: "ffffffff00000001",
			// Generator: 7^4294967295
			Generator: "185629dcda58878c",
		},
		{
			Name:          "Fp128",
			Bits:          128,
			NumRootsUnity: 66,
			NumInverseInt: 8,
			// Modulus: 2^66 * 4611686018427387897 + 1
			Modulus: "ffffffffffffffe40000000000000001",
			// Generator: 7^4611686018427387897
			Generator: "6d278fbf4f60228b1f9b2759c5109f06",
		},
	}

	for _, file := range []string{"fp_test", "fp", "vector", "poly"} {
		tName := "templates/" + file + ".go.tmpl"
		tl, err := template.
			New(path.Base(tName)).
			Funcs(template.FuncMap{"ToLower": strings.ToLower}).
			ParseFiles(tName)
		if err != nil {
			panic(err)
		}

		for _, f := range fields {
			buf := new(bytes.Buffer)
			err := tl.Execute(buf, f)
			if err != nil {
				panic(err)
			}

			code := buf.Bytes()
			code, err = format.Source(code)
			if err != nil {
				panic("error formating code")
			}

			res := string(code)
			offset := strings.Index(res, TemplateWarning)
			if offset == -1 {
				panic("Missing template warning")
			}

			folder := strings.ToLower(f.Name)
			fileName := file
			if file == "fp_test" {
				folder = "."
				fileName = strings.ToLower(f.Name) + "_test"
			}

			path := fmt.Sprintf("%v/%v.go", folder, fileName)
			err = os.WriteFile(path, []byte(res[offset:]), 0o600)
			if err != nil {
				panic(err)
			}
		}
	}
}
