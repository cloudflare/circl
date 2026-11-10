// Copyright (c) 2026 OmniTrust Security LLC. All rights reserved.
// OmniTrust Security LLC's additions and modifications are licensed under the
// Apache License, Version 2.0 (see LICENSE-APACHE).
// Existing third-party code remains under its original terms (see LICENSE).

// Package ecc provides curve interfaces, object identifiers, and binary-curve arithmetic.
//
// # Security
//
// BinaryCurveParams operations are not constant time and must not be used with
// secret scalars, private keys, or signing nonces. The custom prime curves in
// subpackages, including Brainpool and P-192, also use variable-time arithmetic.
// Registration of a curve does not imply modern security strength or suitability
// for secret data. Some curves delegate to existing constant-time implementations;
// consult the implementation used by the specific curve.
package ecc
