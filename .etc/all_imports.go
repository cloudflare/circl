//go:build ignore
// +build ignore

// Generates a Go program with all the public imports of CIRCL. It is used to
// test compilation using static (buildmode=default) and dynamic linking
// (buildmode=plugin).
package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

func main() {
	outputFileName := flag.String("out", "circl.go", "name of the output file.")
	flag.Parse()

	f, err := os.Create(*outputFileName)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	skipDirs := []string{".", "testdata", "internal", "templates"}
	circl := "github.com/cloudflare/circl/"

	fmt.Fprintln(f, "package main")
	err = fs.WalkDir(os.DirFS("."), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			panic(err)
		}
		if d.IsDir() {
			for _, sd := range skipDirs {
				if strings.Contains(path, sd) {
					return nil
				}
			}
			fmt.Fprintf(f, "import _ \"%v%v\"\n", circl, path)
		}
		return nil
	})
	if err != nil {
		panic(err)
	}
	fmt.Fprintln(f, "func main() {}")
}
