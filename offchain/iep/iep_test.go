package iep

import (
	"encoding/binary"
	"testing"

	"github.com/Abdullah1738/juno-intents/offchain/solana"
)

func TestParseConfigV3(t *testing.T) {
	mint := mustParsePubkey("2uWcLTNRtJKef2VXXruRsQ8MGfKqVtX8n9dWqRUQnw8Q")
	feeCollector := mustParsePubkey("7Qx1LJUMeCXr8ygfwdnEmGbYSsQPrgHrFU7VPuGXJeEH")

	var depID [32]byte
	depID[0] = 0xAA

	b := make([]byte, ConfigV3Len)
	b[0] = ConfigV3Version
	copy(b[1:33], depID[:])
	copy(b[33:65], mint[:])
	binary.LittleEndian.PutUint16(b[65:67], 25)
	copy(b[67:99], feeCollector[:])

	got, err := ParseConfigV3(b)
	if err != nil {
		t.Fatalf("ParseConfigV3: %v", err)
	}
	if got.DeploymentID != depID {
		t.Fatalf("deployment id mismatch")
	}
	if got.Mint != mint {
		t.Fatalf("mint mismatch")
	}
	if got.FeeBps != 25 {
		t.Fatalf("fee_bps=%d, want 25", got.FeeBps)
	}
	if got.FeeCollector != feeCollector {
		t.Fatalf("fee_collector mismatch")
	}
}

func TestParseIntentV3(t *testing.T) {
	solver := mustParsePubkey("H3DVXUXK3F8Z6Qcx8r1d9q7g6ZQhKZkqvHnU3QmCw7jD")
	mint := mustParsePubkey("2uWcLTNRtJKef2VXXruRsQ8MGfKqVtX8n9dWqRUQnw8Q")
	recipient := mustParsePubkey("C9oCkY4m5cE7B9dEo7mPSdQjH7fW8p7zH1yqV1wQq2pM")
	vault := mustParsePubkey("4oJYkqf6QZ3o5U2HfS3b6QzZVvFQhDqk2dX4dZf5w9bP")

	var depID [32]byte
	depID[0] = 0x11
	var intentNonce [32]byte
	intentNonce[0] = 0x22
	var receiverTag [32]byte
	receiverTag[0] = 0x33

	b := make([]byte, IntentV3Len)
	b[0] = IntentV3Version
	b[1] = 0 // open
	b[2] = 2 // direction B
	copy(b[3:35], depID[:])
	copy(b[67:99], mint[:])
	copy(b[99:131], recipient[:])
	binary.LittleEndian.PutUint64(b[131:139], 100_000)
	binary.LittleEndian.PutUint64(b[149:157], 12345)
	copy(b[157:189], intentNonce[:])
	copy(b[189:221], vault[:])
	copy(b[221:253], solver[:])
	copy(b[253:285], receiverTag[:])
	binary.LittleEndian.PutUint64(b[285:293], 999)

	got, err := ParseIntentV3(b)
	if err != nil {
		t.Fatalf("ParseIntentV3: %v", err)
	}
	if got.Status != 0 || got.Direction != 2 {
		t.Fatalf("status=%d dir=%d", got.Status, got.Direction)
	}
	if got.DeploymentID != depID {
		t.Fatalf("deployment id mismatch")
	}
	if got.Mint != mint || got.SolanaRecipient != recipient || got.Vault != vault {
		t.Fatalf("pubkey fields mismatch")
	}
	if got.NetAmount != 100_000 || got.ExpirySlot != 12345 || got.JunocashAmountRequired != 999 {
		t.Fatalf("amount fields mismatch")
	}
	if got.IntentNonce != intentNonce || got.ReceiverTag != receiverTag {
		t.Fatalf("nonce/tag mismatch")
	}
	if got.Solver != solver {
		t.Fatalf("solver mismatch")
	}
}

func TestEncodeFillIntent(t *testing.T) {
	var receiverTag [32]byte
	receiverTag[0] = 0xAB
	got := EncodeFillIntent(receiverTag, 123)
	if len(got) != 1+32+8 {
		t.Fatalf("len=%d", len(got))
	}
	if got[0] != 4 {
		t.Fatalf("variant=%d", got[0])
	}
	if got[1] != 0xAB {
		t.Fatalf("receiver tag mismatch")
	}
	if binary.LittleEndian.Uint64(got[33:41]) != 123 {
		t.Fatalf("amount mismatch")
	}
}

func mustParsePubkey(s string) solana.Pubkey {
	pk, err := solana.ParsePubkey(s)
	if err != nil {
		panic(err)
	}
	return pk
}

