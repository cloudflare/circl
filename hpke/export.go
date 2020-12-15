package hpke

import (
	"fmt"
)

type expContext struct {
	suite          Suite
	exporterSecret []byte
}

// Export takes a context string exporterContext and a desired length (in
// bytes), and produces a secret derived from the internal exporter secret
// using the corresponding KDF Expand function. It panics if length is greater
// than 255*N bytes, where N is the size (in bytes) of the KDF's output.
func (c *expContext) Export(exporterContext []byte, length uint) []byte {
	maxLength := uint(255 * c.suite.kdfID.ExtractSize())
	if length > maxLength {
		panic(fmt.Errorf("size greater than %v", maxLength))
	}
	return c.suite.labeledExpand(c.exporterSecret, []byte("sec"),
		exporterContext, uint16(length))
}

func (c *expContext) Suite() Suite {
	return c.suite
}
