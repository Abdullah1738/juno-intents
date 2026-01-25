package iep

import (
	"encoding/binary"
	"errors"

	"github.com/Abdullah1738/juno-intents/offchain/solana"
)

const (
	ConfigV3Version = 3
	ConfigV3Len     = 291

	IntentV3Version = 3
	IntentV3Len     = 293
)

var (
	ErrInvalidConfig = errors.New("invalid iep config")
	ErrInvalidIntent = errors.New("invalid iep intent")
)

type ConfigV3 struct {
	DeploymentID [32]byte
	Mint         solana.Pubkey

	FeeBps        uint16
	FeeCollector  solana.Pubkey
	CheckpointCRP solana.Pubkey

	ReceiptVerifierProgram solana.Pubkey
	VerifierRouterProgram  solana.Pubkey
	Router                 solana.Pubkey
	VerifierEntry          solana.Pubkey
	VerifierProgram        solana.Pubkey
}

func ParseConfigV3(data []byte) (ConfigV3, error) {
	var out ConfigV3
	if len(data) < ConfigV3Len {
		return out, ErrInvalidConfig
	}
	if data[0] != ConfigV3Version {
		return out, ErrInvalidConfig
	}

	copy(out.DeploymentID[:], data[1:33])
	copy(out.Mint[:], data[33:65])
	out.FeeBps = binary.LittleEndian.Uint16(data[65:67])
	copy(out.FeeCollector[:], data[67:99])
	copy(out.CheckpointCRP[:], data[99:131])
	copy(out.ReceiptVerifierProgram[:], data[131:163])
	copy(out.VerifierRouterProgram[:], data[163:195])
	copy(out.Router[:], data[195:227])
	copy(out.VerifierEntry[:], data[227:259])
	copy(out.VerifierProgram[:], data[259:291])
	return out, nil
}

type IntentV3 struct {
	Status    uint8
	Direction uint8

	DeploymentID [32]byte
	Mint         solana.Pubkey

	SolanaRecipient solana.Pubkey
	NetAmount       uint64
	ExpirySlot      uint64
	IntentNonce     [32]byte
	Vault           solana.Pubkey

	Solver                solana.Pubkey
	ReceiverTag           [32]byte
	JunocashAmountRequired uint64
}

func ParseIntentV3(data []byte) (IntentV3, error) {
	var out IntentV3
	if len(data) < IntentV3Len {
		return out, ErrInvalidIntent
	}
	if data[0] != IntentV3Version {
		return out, ErrInvalidIntent
	}

	out.Status = data[1]
	out.Direction = data[2]

	copy(out.DeploymentID[:], data[3:35])
	copy(out.Mint[:], data[67:99])
	copy(out.SolanaRecipient[:], data[99:131])
	out.NetAmount = binary.LittleEndian.Uint64(data[131:139])
	out.ExpirySlot = binary.LittleEndian.Uint64(data[149:157])
	copy(out.IntentNonce[:], data[157:189])
	copy(out.Vault[:], data[189:221])

	copy(out.Solver[:], data[221:253])
	copy(out.ReceiverTag[:], data[253:285])
	out.JunocashAmountRequired = binary.LittleEndian.Uint64(data[285:293])
	return out, nil
}

func EncodeFillIntent(receiverTag [32]byte, junocashAmountRequired uint64) []byte {
	// Borsh enum variant index (u8) for FillIntent is 4.
	out := make([]byte, 0, 1+32+8)
	out = append(out, 4)
	out = append(out, receiverTag[:]...)
	var tmp8 [8]byte
	binary.LittleEndian.PutUint64(tmp8[:], junocashAmountRequired)
	out = append(out, tmp8[:]...)
	return out
}

