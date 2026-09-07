// Package ecmr implements the McCallum-Relyea key exchange protocol for P-521.
//
// This protocol is used by Tang/Clevis for network-bound disk encryption (NBDE).
// It allows a client to derive a shared secret with a server's help, without
// the server ever learning the secret.
//
// # Timing Properties
//
// The scalar operations in this package (multiplication, addition) use CIRCL's
// group.P521, which delegates to Go's crypto/ecdh for constant-time scalar
// multiplication.
//
// IMPORTANT: Point serialization and validation are NOT constant-time due to
// limitations in the underlying group package:
//   - MarshalBinary: calls big.Int.Mod and ecdsa.PublicKey.ECDH()
//   - UnmarshalBinary: uses big.Int for coordinate parsing and curve checks
//
// Both operations may leak timing information about point coordinates. For
// Tang/Clevis deployments where the threat model is network-based key escrow,
// this is typically acceptable. Evaluate whether this meets your requirements.
//
// # Subgroup Membership
//
// P-521 is a prime-order curve (cofactor = 1). Every point validated as on-curve
// is automatically in the prime-order subgroup. No additional cofactor clearing
// or subgroup checks are needed.
//
// # Tang/Clevis Interoperability
//
// For Tang compatibility:
//  1. Call Provision or RecoverKey to get SharedPoint (133 bytes, uncompressed)
//  2. Extract x-coordinate: x, err := ecmr.ExtractX(sharedPoint)
//  3. Apply Concat KDF (RFC 7518 §4.6) with x as the shared secret
//
// ExtractX validates the point is on-curve before extracting, preventing
// corrupted stored state from producing invalid keys. Note that this validation
// uses variable-time operations (see Timing Properties above).
//
// # Supported Curves
//
// Only P-521 is supported. The API uses concrete types with no curve parameters.
// All key construction goes through GenerateKey or UnmarshalBinary, which
// exclusively use group.P521. Zero-value structs (e.g., &PublicKey{}) will fail
// at runtime with ErrNilKey.
package ecmr
