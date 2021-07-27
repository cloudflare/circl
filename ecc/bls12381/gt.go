package bls12381

import "github.com/cloudflare/circl/ecc/bls12381/ff"

// GtSize is the length in bytes of an element in Gt.
const GtSize = ff.URootSize

// Gt represents an element of the output (multiplicative) group of a pairing.
type Gt = ff.URoot
