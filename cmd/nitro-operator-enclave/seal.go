package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	enclave "github.com/edgebitio/nitro-enclaves-sdk-go"

	"github.com/Abdullah1738/juno-intents/internal/vsock"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"golang.org/x/sys/unix"
)

const (
	defaultKmsVsockPort = 8000

	sealedSigningKeyVersionV1 = 1
	ed25519SeedLen            = 32
	aes256Len                 = 32
	aesGcmNonceLen            = 12
)

type sealedSigningKeyV1 struct {
	Version              int    `json:"version"`
	KmsCiphertextBlobB64 string `json:"kms_ciphertext_blob_b64"`
	NonceB64             string `json:"nonce_b64"`
	SeedCiphertextB64    string `json:"seed_ciphertext_b64"`
}

type decodedSealedKeyV1 struct {
	kmsCiphertextBlob []byte
	nonce             []byte
	seedCiphertext    []byte
}

func (k sealedSigningKeyV1) decode() (decodedSealedKeyV1, error) {
	if k.Version != sealedSigningKeyVersionV1 {
		return decodedSealedKeyV1{}, fmt.Errorf("unsupported sealed_key version: %d", k.Version)
	}
	blob, err := base64.StdEncoding.DecodeString(k.KmsCiphertextBlobB64)
	if err != nil || len(blob) == 0 {
		return decodedSealedKeyV1{}, errors.New("invalid sealed_key kms_ciphertext_blob_b64")
	}
	nonce, err := base64.StdEncoding.DecodeString(k.NonceB64)
	if err != nil || len(nonce) != aesGcmNonceLen {
		return decodedSealedKeyV1{}, errors.New("invalid sealed_key nonce_b64")
	}
	ct, err := base64.StdEncoding.DecodeString(k.SeedCiphertextB64)
	if err != nil || len(ct) == 0 {
		return decodedSealedKeyV1{}, errors.New("invalid sealed_key seed_ciphertext_b64")
	}
	return decodedSealedKeyV1{
		kmsCiphertextBlob: blob,
		nonce:             nonce,
		seedCiphertext:    ct,
	}, nil
}

func initSigningKey(ctx context.Context, state *enclaveState, p initSigningKeyParams) (initSigningKeyResult, error) {
	if stringsTrim(p.AwsRegion) == "" {
		return initSigningKeyResult{}, errors.New("missing_aws_region")
	}
	if stringsTrim(p.KmsKeyID) == "" {
		return initSigningKeyResult{}, errors.New("missing_kms_key_id")
	}
	if p.KmsVsockPort == 0 {
		p.KmsVsockPort = defaultKmsVsockPort
	}
	if p.AwsAccessKey == "" || p.AwsSecretKey == "" {
		return initSigningKeyResult{}, errors.New("missing_aws_credentials")
	}

	handle, err := enclave.GetOrInitializeHandle()
	if err != nil {
		return initSigningKeyResult{}, errors.New("nsm_unavailable")
	}
	attDoc, err := handle.Attest(enclave.AttestationOptions{})
	if err != nil {
		return initSigningKeyResult{}, errors.New("attestation_failed")
	}

	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	cfg, err := config.LoadDefaultConfig(
		ctx,
		config.WithRegion(stringsTrim(p.AwsRegion)),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(p.AwsAccessKey, p.AwsSecretKey, p.AwsSessionTok)),
		config.WithHTTPClient(newVsockHTTPClient(p.KmsVsockPort)),
	)
	if err != nil {
		return initSigningKeyResult{}, errors.New("aws_config_failed")
	}
	kc := kms.NewFromConfig(cfg)

	recipient := &types.RecipientInfoType{
		AttestationDocument:    attDoc,
		KeyEncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha256,
	}

	if p.SealedKey == nil {
		seed := make([]byte, ed25519SeedLen)
		if _, err := rand.Read(seed); err != nil {
			return initSigningKeyResult{}, err
		}

		dk, err := kc.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
			KeyId:     aws.String(stringsTrim(p.KmsKeyID)),
			KeySpec:   types.DataKeySpecAes256,
			Recipient: recipient,
		})
		if err != nil {
			return initSigningKeyResult{}, fmt.Errorf("kms_generate_data_key_failed: %w", err)
		}
		if len(dk.CiphertextBlob) == 0 || len(dk.CiphertextForRecipient) == 0 {
			return initSigningKeyResult{}, errors.New("kms_generate_data_key_missing_fields")
		}

		dataKey, err := handle.DecryptKMSEnvelopedKey(dk.CiphertextForRecipient)
		if err != nil {
			return initSigningKeyResult{}, errors.New("kms_recipient_decrypt_failed")
		}
		if len(dataKey) != aes256Len {
			return initSigningKeyResult{}, errors.New("kms_data_key_invalid_len")
		}

		nonce := make([]byte, aesGcmNonceLen)
		if _, err := rand.Read(nonce); err != nil {
			return initSigningKeyResult{}, err
		}

		seedCiphertext, err := aesGcmSeal(dataKey, nonce, seed)
		if err != nil {
			return initSigningKeyResult{}, err
		}

		priv := ed25519.NewKeyFromSeed(seed)
		zero(seed)
		zero(dataKey)
		pub := priv.Public().(ed25519.PublicKey)
		state.SetKey(priv, pub)
		zero(priv)

		sealed := sealedSigningKeyV1{
			Version:              sealedSigningKeyVersionV1,
			KmsCiphertextBlobB64: base64.StdEncoding.EncodeToString(dk.CiphertextBlob),
			NonceB64:             base64.StdEncoding.EncodeToString(nonce),
			SeedCiphertextB64:    base64.StdEncoding.EncodeToString(seedCiphertext),
		}
		return initSigningKeyResult{
			SignerPubkeyHex: hex.EncodeToString(pub),
			SealedKey:       sealed,
		}, nil
	}

	decoded, err := p.SealedKey.decode()
	if err != nil {
		return initSigningKeyResult{}, err
	}

	dec, err := kc.Decrypt(ctx, &kms.DecryptInput{
		KeyId:          aws.String(stringsTrim(p.KmsKeyID)),
		CiphertextBlob: decoded.kmsCiphertextBlob,
		Recipient:      recipient,
	})
	if err != nil {
		return initSigningKeyResult{}, fmt.Errorf("kms_decrypt_failed: %w", err)
	}
	if len(dec.CiphertextForRecipient) == 0 {
		return initSigningKeyResult{}, errors.New("kms_decrypt_missing_recipient_ciphertext")
	}
	dataKey, err := handle.DecryptKMSEnvelopedKey(dec.CiphertextForRecipient)
	if err != nil {
		return initSigningKeyResult{}, errors.New("kms_recipient_decrypt_failed")
	}
	if len(dataKey) != aes256Len {
		return initSigningKeyResult{}, errors.New("kms_data_key_invalid_len")
	}

	seed, err := aesGcmOpen(dataKey, decoded.nonce, decoded.seedCiphertext)
	zero(dataKey)
	if err != nil {
		return initSigningKeyResult{}, errors.New("sealed_key_decrypt_failed")
	}
	if len(seed) != ed25519SeedLen {
		return initSigningKeyResult{}, errors.New("sealed_key_invalid_seed_len")
	}

	priv := ed25519.NewKeyFromSeed(seed)
	zero(seed)
	pub := priv.Public().(ed25519.PublicKey)
	state.SetKey(priv, pub)
	zero(priv)

	return initSigningKeyResult{
		SignerPubkeyHex: hex.EncodeToString(pub),
		SealedKey:       *p.SealedKey,
	}, nil
}

func stringsTrim(s string) string {
	return strings.TrimSpace(strings.Trim(s, "\""))
}

func aesGcmSeal(key []byte, nonce []byte, plaintext []byte) ([]byte, error) {
	if len(key) != aes256Len {
		return nil, errors.New("invalid aes256 key length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, errors.New("invalid nonce length")
	}
	return aead.Seal(nil, nonce, plaintext, nil), nil
}

func aesGcmOpen(key []byte, nonce []byte, ciphertext []byte) ([]byte, error) {
	if len(key) != aes256Len {
		return nil, errors.New("invalid aes256 key length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, errors.New("invalid nonce length")
	}
	return aead.Open(nil, nonce, ciphertext, nil)
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

type vsockDialer struct {
	port uint32
}

func (d vsockDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	conn, err := vsock.Dial(unix.VMADDR_CID_HOST, d.port)
	if err != nil {
		return nil, err
	}

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	return conn, nil
}

func newVsockHTTPClient(vsockPort uint32) *http.Client {
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           vsockDialer{port: vsockPort}.DialContext,
		ForceAttemptHTTP2:     false,
		DisableCompression:    false,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		MaxIdleConns:          2,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   60 * time.Second,
	}
}
