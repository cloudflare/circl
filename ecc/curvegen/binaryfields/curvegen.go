// Copyright (c) 2026 OmniTrust Security LLC. All rights reserved.
// OmniTrust Security LLC's additions and modifications are licensed under the
// Apache License, Version 2.0 (see LICENSE-APACHE).
// Existing third-party code remains under its original terms (see LICENSE).

package main

import (
	"bufio"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/cloudflare/circl/ecc"
)

// The curve equation over a binary field F_2^m is y^2 + xy = x^3 + ax^2 + b.
// The arithmetic is polynomial-based.

// polyAdd performs polynomial addition over GF(2), which is simply an XOR operation.
func polyAdd(x, y *big.Int) *big.Int {
	return new(big.Int).Xor(x, y)
}

// polyMul performs polynomial multiplication over GF(2).
func polyMul(x, y *big.Int) *big.Int {
	result := new(big.Int).SetInt64(0)
	tempY := new(big.Int).Set(y)
	tempX := new(big.Int).Set(x)

	for tempY.Cmp(big.NewInt(0)) > 0 {
		if tempY.Bit(0) == 1 {
			result.Xor(result, tempX)
		}
		tempX.Lsh(tempX, 1)
		tempY.Rsh(tempY, 1)
	}
	return result
}

// polyDivMod performs polynomial division and returns quotient and remainder.
func polyDivMod(dividend, divisor *big.Int) (quotient, remainder *big.Int) {
	quotient = new(big.Int).SetInt64(0)
	remainder = new(big.Int).Set(dividend)
	tempDivisor := new(big.Int).Set(divisor)

	degDivisor := tempDivisor.BitLen() - 1

	for remainder.BitLen() >= degDivisor+1 {
		degRemainder := remainder.BitLen() - 1
		shiftAmount := degRemainder - degDivisor

		quotient.SetBit(quotient, shiftAmount, 1)

		tempDivisor.Lsh(divisor, uint(shiftAmount))
		remainder.Xor(remainder, tempDivisor)
	}
	return quotient, remainder
}

// polyMod performs polynomial division and returns the remainder.
func polyMod(x, irreduciblePoly *big.Int) *big.Int {
	_, rem := polyDivMod(x, irreduciblePoly)
	return rem
}

// polyInv calculates the modular multiplicative inverse of a polynomial modulo the irreducible polynomial.
// This is done using the Extended Euclidean Algorithm for polynomials over GF(2).
func polyInv(poly, irreduciblePoly *big.Int) *big.Int {
	a := new(big.Int).Set(irreduciblePoly)
	b := new(big.Int).Set(poly)
	u := new(big.Int).SetInt64(0)
	v := new(big.Int).SetInt64(1)

	for b.Cmp(big.NewInt(0)) != 0 {
		q, r := polyDivMod(a, b)
		a.Set(b)
		b.Set(r)

		v_temp := new(big.Int).Set(v)
		v = polyAdd(u, polyMul(q, v))
		u.Set(v_temp)
	}

	if a.Cmp(big.NewInt(1)) != 0 {
		return nil
	}

	return u
}

// pointDoublingGF2m performs point doubling on an elliptic curve over a binary field.
func pointDoublingGF2m(x1, y1, a, irreduciblePoly *big.Int) (*big.Int, *big.Int) {
	if x1 == nil || y1 == nil {
		return nil, nil // Point at infinity
	}
	if x1.Cmp(big.NewInt(0)) == 0 {
		return nil, nil // Vertical tangent
	}

	x1_inv := polyInv(x1, irreduciblePoly)
	if x1_inv == nil {
		return nil, nil
	}

	// lambda = x1 + y1/x1 = x1 + y1 * x1_inv
	lambda := polyAdd(x1, polyMul(y1, x1_inv))
	lambda = polyMod(lambda, irreduciblePoly)

	// x2 = lambda^2 + lambda + a
	lambda_sq := polyMul(lambda, lambda)
	x2 := polyAdd(lambda_sq, lambda)
	x2 = polyAdd(x2, a)
	x2 = polyMod(x2, irreduciblePoly)

	// y2 = x1^2 + (lambda + 1) * x2
	x1_sq := polyMul(x1, x1)
	y2 := polyAdd(x1_sq, polyMul(polyAdd(lambda, big.NewInt(1)), x2))
	y2 = polyMod(y2, irreduciblePoly)

	return x2, y2
}

// pointAdditionGF2m performs point addition on an elliptic curve over a binary field.
func pointAdditionGF2m(x1, y1, x2, y2, a, irreduciblePoly *big.Int) (*big.Int, *big.Int) {
	if x1 == nil || y1 == nil {
		return x2, y2
	}
	if x2 == nil || y2 == nil {
		return x1, y1
	}

	if x1.Cmp(x2) == 0 && y1.Cmp(y2) == 0 {
		return pointDoublingGF2m(x1, y1, a, irreduciblePoly)
	}

	if x1.Cmp(x2) == 0 && polyAdd(y1, y2).Cmp(x1) == 0 {
		return nil, nil // P1 and P2 are negations of each other
	}

	// lambda = (y1 + y2) / (x1 + x2)
	num := polyAdd(y1, y2)
	den := polyAdd(x1, x2)
	denInv := polyInv(den, irreduciblePoly)
	if denInv == nil {
		return nil, nil // Point is at infinity
	}

	lambda := polyMul(num, denInv)
	lambda = polyMod(lambda, irreduciblePoly)

	// x3 = lambda^2 + lambda + x1 + x2 + a
	lambda_sq := polyMul(lambda, lambda)
	x3 := polyAdd(lambda_sq, lambda)
	x3 = polyAdd(x3, x1)
	x3 = polyAdd(x3, x2)
	x3 = polyAdd(x3, a)
	x3 = polyMod(x3, irreduciblePoly)

	// y3 = lambda(x1 + x3) + x3 + y1
	y3 := polyMul(lambda, polyAdd(x1, x3))
	y3 = polyAdd(y3, x3)
	y3 = polyAdd(y3, y1)
	y3 = polyMod(y3, irreduciblePoly)

	return x3, y3
}

// scalarMultiplication performs scalar multiplication using the double-and-add algorithm.
func scalarMultiplication(k *big.Int, Px, Py, a, irreduciblePoly, n *big.Int) (*big.Int, *big.Int) {
	k.Mod(k, n)

	if k.Cmp(big.NewInt(0)) == 0 || Px == nil || Py == nil {
		return nil, nil
	}

	var resultX, resultY *big.Int

	binaryK := k.Text(2)

	for _, bit := range binaryK {
		resultX, resultY = pointDoublingGF2m(resultX, resultY, a, irreduciblePoly)
		if bit == '1' {
			resultX, resultY = pointAdditionGF2m(resultX, resultY, Px, Py, a, irreduciblePoly)
		}
	}
	return resultX, resultY
}

// parseCoeffs reads a comma-separated string of polynomial coefficients and converts it to a big.Int.
func parseCoeffs(prompt string, reader *bufio.Reader) *big.Int {
	fmt.Print(prompt)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	coeffs := strings.Split(input, ",")
	polyValue := new(big.Int).SetInt64(0)

	for _, coeffStr := range coeffs {
		coeffStr = strings.TrimSpace(coeffStr)
		coeff, err := strconv.Atoi(coeffStr)
		if err != nil {
			fmt.Printf("Error: Invalid coefficient value: %s\n", coeffStr)
			os.Exit(1)
		}

		// Set the bit at the specified coefficient position
		polyValue.SetBit(polyValue, coeff, 1)
	}
	return polyValue
}

// readBigInt reads a hexadecimal big.Int from the console.
func readBigInt(prompt string, reader *bufio.Reader) *big.Int {
	fmt.Print(prompt)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	return ecc.HexToBigInt(input)
}

// readPoint reads a point as an ordered pair (x, y) from the console.
func readPoint(prompt string, reader *bufio.Reader) (*big.Int, *big.Int) {
	fmt.Print(prompt)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	// Remove parentheses
	input = strings.TrimPrefix(input, "(")
	input = strings.TrimSuffix(input, ")")

	coords := strings.Split(input, ",")
	if len(coords) != 2 {
		fmt.Println("Error: Invalid point format. Please use (x, y).")
		os.Exit(1)
	}

	xStr := strings.TrimSpace(coords[0])
	yStr := strings.TrimSpace(coords[1])

	x := ecc.HexToBigInt(xStr)
	y := ecc.HexToBigInt(yStr)

	return x, y
}

func main() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("This program performs scalar multiplication on an elliptic curve over a binary field.")
	fmt.Println("The curve form is y^2 + xy = x^3 + ax^2 + b.")
	fmt.Println("Please enter the curve parameters and the scalar value below.")
	fmt.Println()

	// Read all elliptic curve parameters from the console
	// The irreducible polynomial is read as a list of coefficients.
	irreduciblePoly := parseCoeffs("Enter irreducible polynomial coefficients (e.g., 163, 7, 6, 3, 0): ", reader)
	a := readBigInt("Enter parameter a (hexadecimal): ", reader)
	Gx, Gy := readPoint("Enter base point G (x, y) in hexadecimal (e.g., 0x..., 0x...): ", reader)
	n := readBigInt("Enter group order n (hexadecimal): ", reader)

	// Read the scalar value to be multiplied
	fmt.Print("Enter scalar k (decimal): ")
	kStr, _ := reader.ReadString('\n')
	kStr = strings.TrimSpace(kStr)
	k, ok := new(big.Int).SetString(kStr, 10)
	if !ok {
		fmt.Printf("Error: Invalid scalar value: %s\n", kStr)
		os.Exit(1)
	}

	fmt.Printf("\nElliptic Curve Scalar Multiplication (%s * G)\n", k.String())
	fmt.Println("--------------------------------------------------")

	// Calculate k * G
	resultX, resultY := scalarMultiplication(k, Gx, Gy, a, irreduciblePoly, n)
	if resultX != nil && resultY != nil {
		fmt.Printf("Result of %s * G:\n x: \"0x%x\",\n y: \"0x%x\",\n\n", k.String(), resultX, resultY)
	} else {
		fmt.Printf("Result of %s * G is the point at infinity.\n", k.String())
	}
}
