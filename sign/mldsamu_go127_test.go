//go:build go1.27

package sign

import "crypto"

// Assert MLDSAMu matches the standard library.
const (
	_ = uint(MLDSAMu - crypto.MLDSAMu)
	_ = uint(crypto.MLDSAMu - MLDSAMu)
)
