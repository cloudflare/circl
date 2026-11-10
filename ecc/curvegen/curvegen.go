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
	"strings"

	"github.com/cloudflare/circl/ecc"
)

// inv calculates the modular multiplicative inverse of n modulo modulus.
func inv(n, modulus *big.Int) *big.Int {
	return new(big.Int).ModInverse(n, modulus)
}

// pointDoubling performs point doubling on the elliptic curve.
func pointDoubling(x1, y1, a, p *big.Int) (*big.Int, *big.Int) {
	if x1 == nil || y1 == nil {
		return nil, nil
	}

	// Calculate the slope lambda
	// lambda = (3*x1^2 + a) * (2*y1)^-1 mod p
	num := new(big.Int).Mul(new(big.Int).SetInt64(3), new(big.Int).Mul(x1, x1))
	num.Add(num, a)
	num.Mod(num, p)

	den := new(big.Int).Mul(new(big.Int).SetInt64(2), y1)
	den.Mod(den, p)

	denInv := inv(den, p)
	if denInv == nil {
		return nil, nil // Tangent is vertical, result is point at infinity
	}

	lambda := new(big.Int).Mul(num, denInv)
	lambda.Mod(lambda, p)

	// Calculate the new point (x2, y2)
	// x2 = lambda^2 - 2*x1 mod p
	x2 := new(big.Int).Mul(lambda, lambda)
	x2.Sub(x2, new(big.Int).Mul(new(big.Int).SetInt64(2), x1))
	x2.Mod(x2, p)

	// y2 = lambda * (x1 - x2) - y1 mod p
	y2 := new(big.Int).Sub(x1, x2)
	y2.Mul(y2, lambda)
	y2.Sub(y2, y1)
	y2.Mod(y2, p)

	return x2, y2
}

// pointAddition performs point addition on the elliptic curve.
func pointAddition(x1, y1, x2, y2, a, p *big.Int) (*big.Int, *big.Int) {
	if x1 == nil || y1 == nil {
		return x2, y2
	}
	if x2 == nil || y2 == nil {
		return x1, y1
	}

	if x1.Cmp(x2) == 0 && y1.Cmp(y2) != 0 {
		return nil, nil // P1 and P2 are negations of each other
	}

	if x1.Cmp(x2) == 0 && y1.Cmp(y2) == 0 {
		return pointDoubling(x1, y1, a, p)
	}

	// Calculate the slope lambda for distinct points
	// lambda = (y2 - y1) * (x2 - x1)^-1 mod p
	num := new(big.Int).Sub(y2, y1)
	num.Mod(num, p)

	den := new(big.Int).Sub(x2, x1)
	den.Mod(den, p)

	denInv := inv(den, p)

	lambda := new(big.Int).Mul(num, denInv)
	lambda.Mod(lambda, p)

	// Calculate the new point (x3, y3)
	// x3 = lambda^2 - x1 - x2 mod p
	x3 := new(big.Int).Mul(lambda, lambda)
	x3.Sub(x3, x1)
	x3.Sub(x3, x2)
	x3.Mod(x3, p)

	// y3 = lambda * (x1 - x3) - y1 mod p
	y3 := new(big.Int).Sub(x1, x3)
	y3.Mul(y3, lambda)
	y3.Sub(y3, y1)
	y3.Mod(y3, p)

	return x3, y3
}

// scalarMultiplication performs scalar multiplication using the double-and-add algorithm.
func scalarMultiplication(k *big.Int, Px, Py, a, p, n *big.Int) (*big.Int, *big.Int) {
	// First, take the scalar modulo n. This is a crucial step for correctness and security.
	k.Mod(k, n)

	if k.Cmp(big.NewInt(0)) == 0 || Px == nil || Py == nil {
		return nil, nil
	}

	var resultX, resultY *big.Int

	// Use binary representation of k
	binaryK := k.Text(2)

	for _, bit := range binaryK {
		resultX, resultY = pointDoubling(resultX, resultY, a, p)
		if bit == '1' {
			resultX, resultY = pointAddition(resultX, resultY, Px, Py, a, p)
		}
	}
	return resultX, resultY
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

func readBigInt(prompt string) *big.Int {
	fmt.Print(prompt)
	input, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	input = strings.TrimSpace(input)
	return ecc.HexToBigInt(input)
}

func main() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("This program performs scalar multiplication on an elliptic curve over a standard Weierstrass curve (non binary field).")
	fmt.Println("The curve form is y^2 = x^3 + ax + b.")
	fmt.Println("Please enter the curve parameters and the scalar value below.")
	fmt.Println()

	// Read all elliptic curve parameters from the console
	p := readBigInt("Enter prime p (hexadecimal): ")
	a := readBigInt("Enter parameter a (hexadecimal): ")
	Gx, Gy := readPoint("Enter base point G (x, y) in hexadecimal (e.g., 0x..., 0x...): ", reader)
	n := readBigInt("Enter group order n (hexadecimal): ")

	// Read the scalar value to be multiplied
	kStr := readBigInt("Enter scalar k (decimal): ").Text(10)
	k, _ := new(big.Int).SetString(kStr, 10)

	fmt.Printf("\nElliptic Curve Scalar Multiplication (%s * G)\n", k.String())
	fmt.Println("--------------------------------------------------")

	// Calculate k * G
	resultX, resultY := scalarMultiplication(k, Gx, Gy, a, p, n)
	if resultX != nil && resultY != nil {
		fmt.Printf("Result of %s * G:\n x: \"0x%x\",\n y: \"0x%x\",\n\n", k.String(), resultX, resultY)
	} else {
		fmt.Printf("Result of %s * G is the point at infinity.\n", k.String())
	}
}
