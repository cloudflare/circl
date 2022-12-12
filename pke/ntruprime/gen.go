package main

import (
	"bytes"
	"go/format"
	"io/ioutil"
	"strings"
	"text/template"
)

type StreamlinedInstance struct {
	Name                                                                                           string
	P, Q, Rounded_bytes, Rq_bytes, W, SharedKeySize, CiphertextSize, PublicKeySize, PrivateKeySize int
}

func (m StreamlinedInstance) Pkg() string {
	return strings.ToLower(m.Name)
}

type LPRInstance struct {
	Name                                                                                           string
	P, Q, Rounded_bytes, Rq_bytes, W, SharedKeySize, CiphertextSize, PublicKeySize, PrivateKeySize int
	Tau0, Tau1, Tau2, Tau3                                                                         int
}

func (m LPRInstance) Pkg() string {
	return strings.ToLower(m.Name)
}

var (
	StreamlinedInstances = []StreamlinedInstance{
		{Name: "SNTRUP761", P: 761, Q: 4591, Rounded_bytes: 1007, Rq_bytes: 1158, W: 286, SharedKeySize: 32, CiphertextSize: 1039, PublicKeySize: 1158, PrivateKeySize: 1763},
		{Name: "SNTRUP653", P: 653, Q: 4621, Rounded_bytes: 865, Rq_bytes: 994, W: 288, SharedKeySize: 32, CiphertextSize: 897, PublicKeySize: 994, PrivateKeySize: 1518},
		{Name: "SNTRUP857", P: 857, Q: 5167, Rounded_bytes: 1152, Rq_bytes: 1322, W: 322, SharedKeySize: 32, CiphertextSize: 1184, PublicKeySize: 1322, PrivateKeySize: 1999},
		{Name: "SNTRUP953", P: 953, Q: 6343, Rounded_bytes: 1317, Rq_bytes: 1505, W: 396, SharedKeySize: 32, CiphertextSize: 1349, PublicKeySize: 1505, PrivateKeySize: 2254},
		{Name: "SNTRUP1013", P: 1013, Q: 7177, Rounded_bytes: 1423, Rq_bytes: 1623, W: 448, SharedKeySize: 32, CiphertextSize: 1455, PublicKeySize: 1623, PrivateKeySize: 2417},
		{Name: "SNTRUP1277", P: 1277, Q: 7879, Rounded_bytes: 1815, Rq_bytes: 2067, W: 492, SharedKeySize: 32, CiphertextSize: 1847, PublicKeySize: 2067, PrivateKeySize: 3059},
	}
	LPRInstances = []LPRInstance{
		{Name: "NTRULPR653", P: 653, Q: 4621, Rounded_bytes: 865, W: 252, Tau0: 2175, Tau1: 113, Tau2: 2031, Tau3: 290, SharedKeySize: 32, CiphertextSize: 1025, PublicKeySize: 897, PrivateKeySize: 1125},
		{Name: "NTRULPR761", P: 761, Q: 4591, Rounded_bytes: 1007, W: 250, Tau0: 2156, Tau1: 114, Tau2: 2007, Tau3: 287, SharedKeySize: 32, CiphertextSize: 1167, PublicKeySize: 1039, PrivateKeySize: 1294},
		{Name: "NTRULPR857", P: 857, Q: 5167, Rounded_bytes: 1152, W: 281, Tau0: 2433, Tau1: 101, Tau2: 2265, Tau3: 324, SharedKeySize: 32, CiphertextSize: 1312, PublicKeySize: 1184, PrivateKeySize: 1463},
		{Name: "NTRULPR953", P: 953, Q: 6343, Rounded_bytes: 1317, W: 345, Tau0: 2997, Tau1: 82, Tau2: 2798, Tau3: 400, SharedKeySize: 32, CiphertextSize: 1477, PublicKeySize: 1349, PrivateKeySize: 1652},
		{Name: "NTRULPR1013", P: 1013, Q: 7177, Rounded_bytes: 1423, W: 392, Tau0: 3367, Tau1: 73, Tau2: 3143, Tau3: 449, SharedKeySize: 32, CiphertextSize: 1583, PublicKeySize: 1455, PrivateKeySize: 1773},
		{Name: "NTRULPR1277", P: 1277, Q: 7879, Rounded_bytes: 1815, W: 429, Tau0: 3724, Tau1: 66, Tau2: 3469, Tau3: 496, SharedKeySize: 32, CiphertextSize: 1975, PublicKeySize: 1847, PrivateKeySize: 2231},
	}
	TemplateWarning = "// Code generated from"
)

func main() {
	generatePackageFiles()
	generateLPRFiles()
}

func generatePackageFiles() {
	template, err := template.ParseFiles("templates/sntrup.params.templ.go")
	if err != nil {
		panic(err)
	}

	for _, mode := range StreamlinedInstances {
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
		err = ioutil.WriteFile(mode.Pkg()+"/params.go", []byte(res[offset:]), 0o644)
		if err != nil {
			panic(err)
		}
	}
}

func generateLPRFiles() {
	template, err := template.ParseFiles("templates/ntrulpr.params.templ.go")
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
		err = ioutil.WriteFile(mode.Pkg()+"/params.go", []byte(res[offset:]), 0o644)
		if err != nil {
			panic(err)
		}
	}
}
