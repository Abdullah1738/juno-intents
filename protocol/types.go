package protocol

import (
	"errors"
)

type DeploymentID [32]byte

func (id DeploymentID) Hex() string { return hex32([32]byte(id)) }

func ParseDeploymentIDHex(s string) (DeploymentID, error) {
	b, err := parseHex32(s)
	return DeploymentID(b), err
}

type JunoBlockHash [32]byte

func (h JunoBlockHash) Hex() string { return hex32([32]byte(h)) }

type OrchardRoot [32]byte

func (r OrchardRoot) Hex() string { return hex32([32]byte(r)) }

type Cmx [32]byte

func (c Cmx) Hex() string { return hex32([32]byte(c)) }

type ReceiverTag [32]byte

func (t ReceiverTag) Hex() string { return hex32([32]byte(t)) }

type CandidateHash [32]byte

func (h CandidateHash) Hex() string { return hex32([32]byte(h)) }

type SpentReceiptID [32]byte

func (id SpentReceiptID) Hex() string { return hex32([32]byte(id)) }

type SolanaPubkey [32]byte

func (k SolanaPubkey) Hex() string { return hex32([32]byte(k)) }

type Zatoshi uint64

const OrchardReceiverBytesLen = 43

var errInvalidOrchardReceiverBytesLen = errors.New("invalid Orchard receiver bytes length")
