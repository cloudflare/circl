package hpke

import (
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func TestExport(t *testing.T) {
	suite := Suite{kdfID: KDF_HKDF_SHA256, aeadID: AEAD_AES128GCM}
	exporter := &expContext{suite: suite}
	maxLength := uint(255 * suite.kdfID.ExtractSize())

	err := test.CheckPanic(func() {
		exporter.Export([]byte("exporter"), maxLength+1)
	})
	test.CheckNoErr(t, err, "exporter max size")
}
