package main

import (
	"fmt"
	"os"
	"text/template"
)

var p255 = `	io.prime.SetUint64(1)
	io.prime.Lsh(&io.prime, 255)
	io.prime.Sub(&io.prime, new(big.Int).SetInt64(19))
`

var p448 = `	io.prime.SetUint64(1)
	io.prime.Lsh(&io.prime, 224)
	io.prime.Sub(&io.prime, new(big.Int).SetInt64(1))
	io.prime.Lsh(&io.prime, 224)
	io.prime.Sub(&io.prime, new(big.Int).SetInt64(1))
`

type data struct {
	A24   int
	Field int
	Prime string
}

func genTests(fields []data) {
	t, err := template.ParseFiles("templates/field_test.txt")
	if err != nil {
		panic("Cannot open file")
	}
	for _, field := range fields {
		nameFile := fmt.Sprintf("fp%d_test.go", field.Field)
		file, err := os.Create(nameFile)
		if err != nil {
			panic("Cannot open file")
		}
		err = t.Execute(file, field)
		if err != nil {
			panic("Error while generating file")
		}
		err = file.Close()
		if err != nil {
			panic("Error closing file")
		}
	}
}

func genAPI(fields []data) {
	t, err := template.ParseFiles("templates/api_amd64.txt")
	if err != nil {
		panic("Cannot open file")
	}
	for _, field := range fields {
		nameFile := fmt.Sprintf("api%d_amd64.s", field.Field)
		file, err := os.Create(nameFile)
		if err != nil {
			panic("Cannot open file")
		}
		err = t.Execute(file, field)
		if err != nil {
			panic("Error while generating file")
		}
		err = file.Close()
		if err != nil {
			panic("Error closing file")
		}
	}
}
func main() {
	fields := []data{
		data{
			A24:   121666,
			Field: 255,
			Prime: p255,
		},
		data{
			A24:   39082,
			Field: 448,
			Prime: p448,
		},
	}
	genAPI(fields)
	genTests(fields)
}
