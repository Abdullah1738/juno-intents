package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Abdullah1738/juno-intents/protocol"
	"github.com/Abdullah1738/juno-intents/zk/receipt"
)

func cmdReceiptInputs(argv []string) error {
	fs := flag.NewFlagSet("receipt-inputs", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		witnessHex string
		jsonOut    bool
	)

	fs.StringVar(&witnessHex, "witness-hex", "", "ReceiptWitnessV1 hex (defaults to JUNO_RECEIPT_WITNESS_HEX env)")
	fs.BoolVar(&jsonOut, "json", true, "If set, prints JSON (default: true)")

	if err := fs.Parse(argv); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return fmt.Errorf("unexpected args: %v", fs.Args())
	}
	if strings.TrimSpace(witnessHex) == "" {
		witnessHex = os.Getenv("JUNO_RECEIPT_WITNESS_HEX")
	}
	if strings.TrimSpace(witnessHex) == "" {
		return errors.New("--witness-hex or JUNO_RECEIPT_WITNESS_HEX is required")
	}

	raw, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(witnessHex), "0x"))
	if err != nil {
		return fmt.Errorf("decode witness hex: %w", err)
	}

	var w receipt.ReceiptWitnessV1
	if err := w.UnmarshalBinary(raw); err != nil {
		return fmt.Errorf("decode witness: %w", err)
	}
	pi, err := w.PublicInputs()
	if err != nil {
		return fmt.Errorf("public inputs: %w", err)
	}

	type out struct {
		DeploymentID string `json:"deployment_id"`
		FillID       string `json:"fill_id"`
		OrchardRoot  string `json:"orchard_root"`
		Cmx          string `json:"cmx"`
		Amount       uint64 `json:"amount"`
		ReceiverTag  string `json:"receiver_tag"`
	}

	o := out{
		DeploymentID: pi.DeploymentID.Hex(),
		FillID:       protocol.FillID(pi.FillID).Hex(),
		OrchardRoot:  pi.OrchardRoot.Hex(),
		Cmx:          pi.Cmx.Hex(),
		Amount:       uint64(pi.Amount),
		ReceiverTag:  pi.ReceiverTag.Hex(),
	}

	if !jsonOut {
		fmt.Fprintf(os.Stdout, "deployment_id=%s\n", o.DeploymentID)
		fmt.Fprintf(os.Stdout, "fill_id=%s\n", o.FillID)
		fmt.Fprintf(os.Stdout, "orchard_root=%s\n", o.OrchardRoot)
		fmt.Fprintf(os.Stdout, "cmx=%s\n", o.Cmx)
		fmt.Fprintf(os.Stdout, "amount=%d\n", o.Amount)
		fmt.Fprintf(os.Stdout, "receiver_tag=%s\n", o.ReceiverTag)
		return nil
	}

	js, err := json.Marshal(o)
	if err != nil {
		return err
	}
	os.Stdout.Write(js)
	os.Stdout.Write([]byte("\n"))
	return nil
}
