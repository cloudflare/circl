package ecmr

import (
	"github.com/cloudflare/circl/group"
)

// ExtractX extracts the x-coordinate from an uncompressed P-521 point.
// It validates the point is on-curve and not the identity before extracting.
func ExtractX(uncompressedPoint []byte) ([]byte, error) {
	element := group.P521.NewElement()
	if err := element.UnmarshalBinary(uncompressedPoint); err != nil {
		return nil, ErrMalformedPoint
	}
	if element.IsIdentity() {
		return nil, ErrIdentityPoint
	}

	canonical, err := element.MarshalBinary()
	if err != nil {
		return nil, ErrMalformedPoint
	}

	x := make([]byte, XCoordinateSize)
	copy(x, canonical[1:1+XCoordinateSize])
	return x, nil
}
