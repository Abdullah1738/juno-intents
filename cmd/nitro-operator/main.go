package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/mr-tron/base58"

	"github.com/Abdullah1738/juno-intents/offchain/nitro"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(argv []string) error {
	if len(argv) == 0 || argv[0] == "-h" || argv[0] == "--help" || argv[0] == "help" {
		usage(os.Stdout)
		return nil
	}

	switch argv[0] {
	case "init-key":
		return cmdInitKey(argv[1:])
	case "pubkey":
		return cmdPubkey(argv[1:])
	default:
		return fmt.Errorf("unknown command: %s", argv[0])
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "nitro-operator: host tooling for the Nitro enclave operator")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  nitro-operator init-key --enclave-cid <u32> --kms-key-id <id> [--region <aws-region>] [--enclave-port <u32>] [--kms-vsock-port <u32>] [--sealed-key-file <path>]")
	fmt.Fprintln(w, "  nitro-operator pubkey   --enclave-cid <u32> [--enclave-port <u32>]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Notes:")
	fmt.Fprintln(w, "  - init-key requires a host-side vsock proxy to KMS listening on --kms-vsock-port.")
}

func cmdPubkey(argv []string) error {
	fs := flag.NewFlagSet("pubkey", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var enclaveCID uint
	var enclavePort uint
	fs.UintVar(&enclaveCID, "enclave-cid", 0, "Enclave CID (u32)")
	fs.UintVar(&enclavePort, "enclave-port", 5000, "Enclave AF_VSOCK port")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if enclaveCID == 0 {
		return errors.New("--enclave-cid is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var pubHex string
	if err := nitro.Call(ctx, uint32(enclaveCID), uint32(enclavePort), "pubkey", nil, &pubHex); err != nil {
		return err
	}
	pubHex = strings.TrimSpace(strings.TrimPrefix(pubHex, "0x"))

	pub, err := hex.DecodeString(pubHex)
	if err != nil {
		return fmt.Errorf("invalid pubkey hex: %w", err)
	}
	fmt.Printf("operator_pubkey_hex=%s\n", pubHex)
	fmt.Printf("operator_pubkey_base58=%s\n", base58.Encode(pub))
	return nil
}

func cmdInitKey(argv []string) error {
	fs := flag.NewFlagSet("init-key", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var enclaveCID uint
	var enclavePort uint
	var region string
	var kmsKeyID string
	var kmsVsockPort uint
	var sealedKeyFile string

	fs.UintVar(&enclaveCID, "enclave-cid", 0, "Enclave CID (u32)")
	fs.UintVar(&enclavePort, "enclave-port", 5000, "Enclave AF_VSOCK port")
	fs.StringVar(&region, "region", getenvAny("JUNO_AWS_REGION", "AWS_REGION"), "AWS region")
	fs.StringVar(&kmsKeyID, "kms-key-id", getenvAny("JUNO_NITRO_KMS_KEY_ID", "JUNO_KMS_KEY_ID"), "KMS key id/ARN/alias")
	fs.UintVar(&kmsVsockPort, "kms-vsock-port", 8000, "Host vsock proxy port to KMS")
	fs.StringVar(&sealedKeyFile, "sealed-key-file", getenvAny("JUNO_NITRO_SEALED_KEY_FILE", "JUNO_SEALED_KEY_FILE"), "Path to persist sealed key JSON (0600); if empty, will not persist")

	if err := fs.Parse(argv); err != nil {
		return err
	}
	if enclaveCID == 0 {
		return errors.New("--enclave-cid is required")
	}
	if strings.TrimSpace(region) == "" {
		return errors.New("--region is required (or set JUNO_AWS_REGION/AWS_REGION)")
	}
	if strings.TrimSpace(kmsKeyID) == "" {
		return errors.New("--kms-key-id is required (or set JUNO_NITRO_KMS_KEY_ID/JUNO_KMS_KEY_ID)")
	}
	if kmsVsockPort == 0 || kmsVsockPort > 0xffff_ffff {
		return errors.New("--kms-vsock-port must fit in u32")
	}

	var sealed *nitro.SealedSigningKeyV1
	if sealedKeyFile != "" {
		if b, err := os.ReadFile(sealedKeyFile); err == nil {
			var sk nitro.SealedSigningKeyV1
			if err := jsonUnmarshalStrict(b, &sk); err != nil {
				return fmt.Errorf("read sealed key: %w", err)
			}
			sealed = &sk
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("read sealed key: %w", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return fmt.Errorf("aws config: %w", err)
	}
	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("aws credentials: %w", err)
	}

	params := nitro.InitSigningKeyParams{
		AwsRegion:     region,
		KmsKeyID:      kmsKeyID,
		KmsVsockPort:  uint32(kmsVsockPort),
		AwsAccessKey:  creds.AccessKeyID,
		AwsSecretKey:  creds.SecretAccessKey,
		AwsSessionTok: creds.SessionToken,
		SealedKey:     sealed,
	}
	var out nitro.InitSigningKeyResult
	if err := nitro.Call(ctx, uint32(enclaveCID), uint32(enclavePort), "init_signing_key", params, &out); err != nil {
		return err
	}

	pubHex := strings.TrimSpace(strings.TrimPrefix(out.SignerPubkeyHex, "0x"))
	pub, err := hex.DecodeString(pubHex)
	if err != nil {
		return fmt.Errorf("invalid signer_pubkey_hex: %w", err)
	}
	fmt.Printf("operator_pubkey_hex=%s\n", pubHex)
	fmt.Printf("operator_pubkey_base58=%s\n", base58.Encode(pub))

	if sealedKeyFile != "" {
		if err := os.MkdirAll(filepath.Dir(sealedKeyFile), 0o755); err != nil {
			return fmt.Errorf("mkdir sealed key dir: %w", err)
		}
		if err := writeJSON0600(sealedKeyFile, out.SealedKey); err != nil {
			return fmt.Errorf("write sealed key: %w", err)
		}
		fmt.Printf("sealed_key_file=%s\n", sealedKeyFile)
	}

	return nil
}

func getenvAny(keys ...string) string {
	for _, k := range keys {
		if v, ok := os.LookupEnv(k); ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
