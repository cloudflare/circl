// Package arc provides Anonymous Rate-Limited Credentials.
//
// This package implements ARC, an anonymous credential system for rate limiting.
// Implementation is compliant with the privacy pass draft [1].
//
// [1] https://datatracker.ietf.org/doc/html/draft-yun-privacypass-crypto-arc-00
//
// # Key Generation
//
// Server generates a pair of keys.
//
//	priv := KeyGen(rand.Reader, SuiteP256)
//	pub := priv.PublicKey()
//
// # Credential Issuance
//
// Client reaches Server to generate a credential.
//
//	Client(pub)               Server(priv,pub)
//	------------------------------------------
//	 fin,req := Request()
//	              --- req -->
//	                    res := Response(priv)
//	             <--- res ---
//	 cred := Finalize(fin,req,res,pub)
//	------------------------------------------
//
// # Presentation
//
// Client uses a credential to generate a fixed number of presentations.
//
//	Client(N)               Server(priv,pub,N)
//	------------------------------------------
//	 s := NewState(cred, N)
//	 for i := range N {
//	    pres_i := s.Present()
//	           --- pres_i -->
//	             b := Verify(priv, pres_i, N)
//	                = Ok/Invalid
//	 }
//	------------------------------------------
package arc

import "errors"

var (
	ErrSuite          = errors.New("invalid suite identifier")
	ErrVerifyReqProof = errors.New("invalid credential request proof")
	ErrVerifyResProof = errors.New("invalid credential response proof")
	ErrLimitValid     = errors.New("limit must be larger than zero")
	ErrLimitExceeded  = errors.New("presentation count exceeds limit")
	ErrContextLength  = errors.New("context length exceeded")
	ErrInvalidNonce   = errors.New("invalid nonce associated to presentation")
	ErrInvalidIndex   = errors.New("invalid index in proof")
)
