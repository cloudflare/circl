package ecmr

import (
	"errors"

	"github.com/cloudflare/circl/group"
)

const (
	PublicKeySize         = 133
	PrivateKeySize        = 66
	SharedPointSize       = 133
	UncompressedPointSize = 133
	XCoordinateSize       = 66
)

var (
	ErrMalformedPoint  = errors.New("ecmr: malformed point encoding")
	ErrIdentityPoint   = errors.New("ecmr: identity point not allowed")
	ErrMalformedScalar = errors.New("ecmr: malformed scalar encoding")
	ErrZeroScalar      = errors.New("ecmr: zero scalar not allowed")
	ErrNilReader       = errors.New("ecmr: nil random reader")
	ErrNilKey          = errors.New("ecmr: nil or uninitialized key")
)

type ProvisionResult struct {
	ClientPublic []byte
	SharedPoint  []byte
}

type RecoveryRequest struct {
	BlindedPoint []byte
}

type RecoveryResponse struct {
	ProcessedPoint []byte
}

type RecoveryState struct {
	ephemeral group.Scalar
	serverPub group.Element
}
