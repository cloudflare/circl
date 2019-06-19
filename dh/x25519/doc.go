// Package x25519 provides Diffie-Hellman functions as specified in RFC-7748.
//
// References:
//  - RFC7748 https://rfc-editor.org/rfc/rfc7748.txt
//  - Curve25519 https://cr.yp.to/ecdh.html
//
// Validation of public keys.
//
// The Diffie-Hellman function, as described in RFC-7748, works for any public
// key. However, if a different protocol requires contributory behaviour, then
// the public keys must be validated against low-order points. To do that, the
// Shared function performs this validation internally and returns false when
// the public key is invalid (i.e., it is a low-order point).
// See https://cr.yp.to/ecdh.html#validate.
package x25519
