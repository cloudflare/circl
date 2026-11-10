// Copyright (c) 2026 OmniTrust Security LLC. All rights reserved.
// OmniTrust Security LLC's additions and modifications are licensed under the
// Apache License, Version 2.0 (see LICENSE-APACHE).
// Existing third-party code remains under its original terms (see LICENSE).

package ecc

import (
	"math/big"
	"strings"
)

func HexStringValidator(s string) string {
	var sb strings.Builder
	sb.Grow(len(s))
	s = strings.TrimPrefix(s, "0x")
	for _, c := range s {
		if '0' <= c && c <= '9' {
			sb.WriteRune(c)
		} else if 'a' <= c && c <= 'f' {
			sb.WriteRune(c)
		} else if 'A' <= c && c <= 'F' {
			sb.WriteRune(c)
		}
	}

	return sb.String()
}

func HexToBigInt(s string) *big.Int {
	s = HexStringValidator(s)
	if s == "" {
		return new(big.Int)
	}
	result, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic(s)
	}
	return result
}

// F function in terms of x to big int
func F(f ...int) *big.Int {
	ret := new(big.Int)
	for _, v := range f {
		tmp := big.NewInt(1)
		tmp.Lsh(tmp, uint(v))

		ret.Add(ret, tmp)
	}

	return ret
}
