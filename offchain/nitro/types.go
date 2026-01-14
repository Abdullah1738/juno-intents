package nitro

type SealedSigningKeyV1 struct {
	Version              int    `json:"version"`
	KmsCiphertextBlobB64 string `json:"kms_ciphertext_blob_b64"`
	NonceB64             string `json:"nonce_b64"`
	SeedCiphertextB64    string `json:"seed_ciphertext_b64"`
}

type InitSigningKeyParams struct {
	AwsRegion     string `json:"aws_region"`
	KmsKeyID      string `json:"kms_key_id"`
	KmsVsockPort  uint32 `json:"kms_vsock_port"`
	AwsAccessKey  string `json:"aws_access_key_id"`
	AwsSecretKey  string `json:"aws_secret_access_key"`
	AwsSessionTok string `json:"aws_session_token,omitempty"`

	SealedKey *SealedSigningKeyV1 `json:"sealed_key,omitempty"`
}

type InitSigningKeyResult struct {
	SignerPubkeyHex string             `json:"signer_pubkey_hex"`
	SealedKey       SealedSigningKeyV1 `json:"sealed_key"`
}
