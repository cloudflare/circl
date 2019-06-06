package main

import (
	"fmt"
	"math/big"
	"os"
	"text/template"
)

type data struct {
	Field    int
	Prime    *big.Int
	A24      int
	SizeKey  int
	Size     int
	Num      int
	NumBytes int
	xCoord   int
	Table    []string
}

// Montgomery point doubling in projective (X:Z) coordintates.
func doubling(x, z *big.Int, d *data) {
	var A24, A, B, C big.Int
	A24.SetInt64(int64(d.A24))
	A.Add(x, z)
	A.Mod(&A, d.Prime)
	B.Sub(x, z)
	B.Mod(&B, d.Prime)
	A.Mul(&A, &A)
	B.Mul(&B, &B)
	x.Mul(&A, &B)
	x.Mod(x, d.Prime)
	C.Sub(&A, &B)
	z.Mul(&C, &A24)
	z.Add(z, &B)
	z.Mul(z, &C)
	z.Mod(z, d.Prime)
}

// Encoding (X+Z)/(X-Z) coordinate.
func encode(x, z *big.Int, d *data) *big.Int {
	var num, den, r big.Int
	num.Add(x, z)
	den.Sub(x, z)
	r.ModInverse(&den, d.Prime)
	r.Mul(&r, &num)
	r.Mod(&r, d.Prime)
	return &r
}

func toString(x *big.Int, d *data, i int) string {
	num := fmt.Sprintf(fmt.Sprintf("%%0%dx", d.SizeKey*2), x.Bytes())
	s := fmt.Sprintf("\t/* (2^%3d)P */", i)
	for j := 2*d.SizeKey - 2; j >= 0; j -= 2 {
		s += fmt.Sprintf(" 0x%v,", num[j:j+2])
	}
	s += "\n"
	return s
}

// Generates the set of coordinates
//    t[i] = (xi+1)/(xi-1),
// where (xi,yi) = 2^iG and G is the generator point
func genPoints(d *data) {
	var x, z big.Int
	x.SetInt64(int64(d.xCoord))
	z.SetInt64(int64(1))
	d.Table = make([]string, d.Num)
	for i := 0; i < d.Num; i++ {
		d.Table[i] = toString(encode(&x, &z, d), d, i)
		doubling(&x, &z, d)
	}
}

func genTable(d *data, nameTemplate, outFileName string) {
	t, err := template.ParseFiles(nameTemplate)
	if err != nil {
		panic("Cannot open file")
	}
	nameFile := fmt.Sprintf(outFileName, d.Field)
	file, err := os.Create(nameFile)
	if err != nil {
		panic("Cannot open file")
	}
	genPoints(d)

	err = t.Execute(file, d)
	if err != nil {
		panic("Error while generating file")
	}
	err = file.Close()
	if err != nil {
		panic("Error closing file")
	}
}

func genMontArith(d *data, nameTemplate, outFileName string) {
	t, err := template.ParseFiles(nameTemplate)
	if err != nil {
		panic("Cannot open file")
	}

	nameFile := fmt.Sprintf(outFileName, d.Field)
	file, err := os.Create(nameFile)
	if err != nil {
		panic("Cannot open file")
	}
	err = t.Execute(file, d)
	if err != nil {
		panic("Error while generating file")
	}
	err = file.Close()
	if err != nil {
		panic("Error closing file")
	}
}

func main() {
	var p255, p448 big.Int
	p255.SetInt64(1)
	p255.Lsh(&p255, 255)
	p255.Sub(&p255, new(big.Int).SetInt64(19))

	p448.SetInt64(1)
	p448.Lsh(&p448, 224)
	p448.Sub(&p448, new(big.Int).SetInt64(1))
	p448.Lsh(&p448, 224)
	p448.Sub(&p448, new(big.Int).SetInt64(1))

	fields := []data{
		{
			Field:    255,
			Num:      252,
			Size:     256,
			SizeKey:  32,
			NumBytes: (256 / 8) * 252,
			Prime:    &p255,
			xCoord:   9,
			A24:      121666,
		},
		{
			Field:    448,
			Num:      446,
			Size:     448,
			SizeKey:  56,
			NumBytes: (448 / 8) * 446,
			Prime:    &p448,
			xCoord:   5,
			A24:      39082,
		},
	}
	for _, f := range fields {
		genMontArith(&f, "templates/mont_amd64.txt", "mont%d_amd64.s")
		genTable(&f, "templates/tables.txt", "table%d.go")
	}
}
