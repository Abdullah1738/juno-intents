use coset::{CborSerializable, CoseSign1};
use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use spki::SubjectPublicKeyInfoRef;
use std::collections::BTreeMap;
use thiserror::Error;
use x509_parser::certificate::X509Certificate;
use x509_parser::oid_registry::OID_SIG_ECDSA_WITH_SHA384;
use x509_parser::prelude::FromDer;

const DOMAIN_SEPARATOR: &str = "JUNO_INTENTS";
const PROTOCOL_VERSION: u16 = 1;

const PURPOSE_OPERATOR_MEASUREMENT: &str = "nitro_pcr_digest";

pub const ATTESTATION_WITNESS_VERSION_V1: u16 = 1;
pub const ATTESTATION_JOURNAL_VERSION_V1: u16 = 1;

// SHA256 fingerprint (DER bytes) of the AWS Nitro Enclaves Root CA (G1).
// This matches the AWS-provided root.pem and is treated as the trust anchor.
// Reference: https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
const AWS_NITRO_ROOT_CA_DER_SHA256: [u8; 32] = [
    0x64, 0x1a, 0x03, 0x21, 0xa3, 0xe2, 0x44, 0xef, 0xe4, 0x56, 0x46, 0x31, 0x95, 0xd6,
    0x06, 0x31, 0x7e, 0xd7, 0xcd, 0xcc, 0x3c, 0x17, 0x56, 0xe0, 0x98, 0x93, 0xf3, 0xc6,
    0x8f, 0x79, 0xbb, 0x5b,
];

#[derive(Debug, Error)]
pub enum AttestationVerifyError {
    #[error("invalid witness length")]
    InvalidWitnessLen,
    #[error("unsupported witness version")]
    UnsupportedWitnessVersion,
    #[error("invalid attestation document")]
    InvalidAttestationDoc,
    #[error("attestation payload missing")]
    AttestationPayloadMissing,
    #[error("attestation payload invalid")]
    AttestationPayloadInvalid,
    #[error("attestation signature invalid")]
    AttestationSignatureInvalid,
    #[error("certificate missing")]
    CertificateMissing,
    #[error("certificate chain invalid")]
    CertificateChainInvalid,
    #[error("certificate signature algorithm unsupported")]
    CertificateSignatureAlgUnsupported,
    #[error("certificate signature invalid")]
    CertificateSignatureInvalid,
    #[error("certificate validity invalid at attestation timestamp")]
    CertificateValidityInvalid,
    #[error("aws nitro root certificate not found")]
    RootCertificateNotFound,
    #[error("aws nitro root fingerprint mismatch")]
    RootFingerprintMismatch,
    #[error("public key missing")]
    PublicKeyMissing,
    #[error("public key invalid")]
    PublicKeyInvalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationJournalV1 {
    pub deployment_id: [u8; 32],
    pub junocash_chain_id: u8,
    pub junocash_genesis_hash: [u8; 32],
    pub operator_pubkey: [u8; 32],
    pub measurement: [u8; 32],
}

fn prefix_bytes(purpose: &str) -> Vec<u8> {
    // ASCII(domain) || 0x00 || ASCII(purpose) || 0x00 || u16_le(version)
    let mut out = Vec::with_capacity(DOMAIN_SEPARATOR.len() + 1 + purpose.len() + 1 + 2);
    out.extend_from_slice(DOMAIN_SEPARATOR.as_bytes());
    out.push(0);
    out.extend_from_slice(purpose.as_bytes());
    out.push(0);
    out.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    out
}

#[derive(Debug, Deserialize, Serialize)]
struct AttestationPayload {
    #[serde(default)]
    pcrs: BTreeMap<u16, ByteBuf>,
    #[serde(default)]
    certificate: Option<ByteBuf>,
    #[serde(default)]
    cabundle: Option<Vec<ByteBuf>>,
    #[serde(default)]
    public_key: Option<ByteBuf>,
    #[serde(default)]
    timestamp: Option<u64>,
}

fn sha256(b: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b);
    h.finalize().into()
}

fn measurement_digest(pcrs: &BTreeMap<u16, ByteBuf>) -> [u8; 32] {
    // Stable, domain-separated digest over the (index, value) pairs.
    // input = prefix || for each sorted key: key_u16_le || len_u16_le || bytes
    let mut h = Sha256::new();
    h.update(prefix_bytes(PURPOSE_OPERATOR_MEASUREMENT));
    for (idx, v) in pcrs.iter() {
        h.update(idx.to_le_bytes());
        let len = u16::try_from(v.len()).unwrap_or(u16::MAX);
        h.update(len.to_le_bytes());
        h.update(v.as_ref());
    }
    h.finalize().into()
}

fn parse_x509_cert(der: &[u8]) -> Result<X509Certificate<'_>, AttestationVerifyError> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|_| AttestationVerifyError::InvalidAttestationDoc)?;
    Ok(cert)
}

fn cert_is_valid_at(cert: &X509Certificate<'_>, unix_ts: u64) -> Result<(), AttestationVerifyError> {
    // The attestation doc includes its own timestamp. We validate certificate time bounds
    // against that timestamp, not "now", so old attestations remain verifiable.
    let ts = i64::try_from(unix_ts).map_err(|_| AttestationVerifyError::AttestationPayloadInvalid)?;
    let t = x509_parser::time::ASN1Time::from_timestamp(ts).map_err(|_| AttestationVerifyError::AttestationPayloadInvalid)?;
    let nb = cert.validity().not_before;
    let na = cert.validity().not_after;
    if t < nb || t > na {
        return Err(AttestationVerifyError::CertificateValidityInvalid);
    }
    Ok(())
}

fn verifying_key_from_x509(cert: &X509Certificate<'_>) -> Result<VerifyingKey, AttestationVerifyError> {
    let spki = cert.public_key();
    let pk_bytes = spki.subject_public_key.data.as_ref();
    let vk = VerifyingKey::from_sec1_bytes(pk_bytes)
        .map_err(|_| AttestationVerifyError::InvalidAttestationDoc)?;
    Ok(vk)
}

fn verify_cert_sig(
    cert: &X509Certificate<'_>,
    issuer: &X509Certificate<'_>,
) -> Result<(), AttestationVerifyError> {
    let alg = &cert.signature_algorithm.algorithm;
    if alg != &OID_SIG_ECDSA_WITH_SHA384 {
        return Err(AttestationVerifyError::CertificateSignatureAlgUnsupported);
    }

    let issuer_vk = verifying_key_from_x509(issuer)?;
    let tbs = cert.tbs_certificate.as_ref();
    let sig_der = cert.signature_value.data.as_ref();
    let sig =
        Signature::from_der(sig_der).map_err(|_| AttestationVerifyError::CertificateSignatureInvalid)?;
    issuer_vk
        .verify(tbs, &sig)
        .map_err(|_| AttestationVerifyError::CertificateSignatureInvalid)?;
    Ok(())
}

fn parse_operator_pubkey_from_public_key_der(der: &[u8]) -> Result<[u8; 32], AttestationVerifyError> {
    let spki = SubjectPublicKeyInfoRef::try_from(der).map_err(|_| AttestationVerifyError::PublicKeyInvalid)?;
    // OID for Ed25519 is 1.3.101.112.
    // We accept only that algorithm.
    const ED25519_OID: spki::ObjectIdentifier = spki::ObjectIdentifier::new_unwrap("1.3.101.112");
    if spki.algorithm.oid != ED25519_OID {
        return Err(AttestationVerifyError::PublicKeyInvalid);
    }
    let bytes = spki
        .subject_public_key
        .as_bytes()
        .ok_or(AttestationVerifyError::PublicKeyInvalid)?;
    if bytes.len() != 32 {
        return Err(AttestationVerifyError::PublicKeyInvalid);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn verify_attestation_doc_and_extract(
    doc: &[u8],
) -> Result<(AttestationPayload, [u8; 32], [u8; 32]), AttestationVerifyError> {
    let cose = CoseSign1::from_slice(doc).map_err(|_| AttestationVerifyError::InvalidAttestationDoc)?;
    let payload = cose.payload.as_ref().ok_or(AttestationVerifyError::AttestationPayloadMissing)?;
    let payload_val: AttestationPayload =
        serde_cbor::from_slice(payload).map_err(|_| AttestationVerifyError::AttestationPayloadInvalid)?;

    let leaf_cert_der = payload_val
        .certificate
        .as_ref()
        .ok_or(AttestationVerifyError::CertificateMissing)?
        .as_ref();
    let cabundle = payload_val.cabundle.clone().unwrap_or_default();

    // Parse certificates.
    let leaf_cert = parse_x509_cert(leaf_cert_der)?;
    let mut chain: Vec<Vec<u8>> = Vec::with_capacity(1 + cabundle.len());
    chain.push(leaf_cert_der.to_vec());
    for c in cabundle {
        chain.push(c.into_vec());
    }

    // Find AWS root by fingerprint.
    let mut root_der: Option<Vec<u8>> = None;
    for c in chain.iter() {
        if sha256(c.as_ref()) == AWS_NITRO_ROOT_CA_DER_SHA256 {
            root_der = Some(c.clone());
            break;
        }
    }
    let root_der = root_der.ok_or(AttestationVerifyError::RootCertificateNotFound)?;
    if sha256(root_der.as_ref()) != AWS_NITRO_ROOT_CA_DER_SHA256 {
        return Err(AttestationVerifyError::RootFingerprintMismatch);
    }
    let root_cert = parse_x509_cert(root_der.as_ref())?;

    let ts_ms = payload_val
        .timestamp
        .ok_or(AttestationVerifyError::AttestationPayloadInvalid)?;
    let ts_sec = ts_ms / 1000;
    cert_is_valid_at(&leaf_cert, ts_sec)?;
    cert_is_valid_at(&root_cert, ts_sec)?;

    // Build a subject->cert map for chain validation.
    let mut parsed = Vec::with_capacity(chain.len());
    parsed.push(leaf_cert);
    for der in chain.iter().skip(1) {
        parsed.push(parse_x509_cert(der.as_ref())?);
    }

    // Identify root in parsed list.
    let root_idx = chain
        .iter()
        .position(|c| sha256(c.as_ref()) == AWS_NITRO_ROOT_CA_DER_SHA256)
        .ok_or(AttestationVerifyError::RootCertificateNotFound)?;

    // Verify chain signatures up to the root by following issuer->subject links.
    // We accept the chain as valid if we can reach the AWS root cert.
    let mut cur_idx = 0usize; // leaf is at index 0
    let mut visited = 0usize;
    while cur_idx != root_idx {
        visited += 1;
        if visited > parsed.len() {
            return Err(AttestationVerifyError::CertificateChainInvalid);
        }
        let issuer_name = parsed[cur_idx].issuer();
        let mut next: Option<usize> = None;
        for (i, c) in parsed.iter().enumerate() {
            if i == cur_idx {
                continue;
            }
            if c.subject() == issuer_name {
                next = Some(i);
                break;
            }
        }
        let parent_idx = next.ok_or(AttestationVerifyError::CertificateChainInvalid)?;
        cert_is_valid_at(&parsed[parent_idx], ts_sec)?;
        verify_cert_sig(&parsed[cur_idx], &parsed[parent_idx])?;
        cur_idx = parent_idx;
    }

    // Verify COSE signature (ES384) using the leaf cert's public key.
    let leaf_vk = verifying_key_from_x509(&parsed[0])?;
    let sig_bytes = cose.signature.as_slice();
    let sig = Signature::from_slice(sig_bytes).map_err(|_| AttestationVerifyError::AttestationSignatureInvalid)?;
    let tbs = cose.tbs_data(&[]);
    leaf_vk
        .verify(&tbs, &sig)
        .map_err(|_| AttestationVerifyError::AttestationSignatureInvalid)?;

    let operator_pk_der = payload_val
        .public_key
        .as_ref()
        .ok_or(AttestationVerifyError::PublicKeyMissing)?
        .as_ref();
    let operator_pubkey = parse_operator_pubkey_from_public_key_der(operator_pk_der)?;
    let measurement = measurement_digest(&payload_val.pcrs);
    Ok((payload_val, operator_pubkey, measurement))
}

pub fn attestation_journal_from_witness_v1(witness: &[u8]) -> Result<Vec<u8>, AttestationVerifyError> {
    // witness encoding:
    //   version_u16_le ||
    //   deployment_id (32) ||
    //   junocash_chain_id (1) ||
    //   junocash_genesis_hash (32) ||
    //   attestation_doc_len_u32_le ||
    //   attestation_doc_bytes
    if witness.len() < 2 + 32 + 1 + 32 + 4 {
        return Err(AttestationVerifyError::InvalidWitnessLen);
    }
    let version = u16::from_le_bytes([witness[0], witness[1]]);
    if version != ATTESTATION_WITNESS_VERSION_V1 {
        return Err(AttestationVerifyError::UnsupportedWitnessVersion);
    }
    let mut off = 2;
    let mut deployment_id = [0u8; 32];
    deployment_id.copy_from_slice(&witness[off..off + 32]);
    off += 32;
    let chain_id = witness[off];
    off += 1;
    let mut genesis_hash = [0u8; 32];
    genesis_hash.copy_from_slice(&witness[off..off + 32]);
    off += 32;
    let doc_len = u32::from_le_bytes(witness[off..off + 4].try_into().unwrap()) as usize;
    off += 4;
    if witness.len() != off + doc_len {
        return Err(AttestationVerifyError::InvalidWitnessLen);
    }
    let doc = &witness[off..];

    let (_payload, operator_pubkey, measurement) = verify_attestation_doc_and_extract(doc)?;

    let mut journal = Vec::with_capacity(2 + 32 + 1 + 32 + 32 + 32);
    journal.extend_from_slice(&ATTESTATION_JOURNAL_VERSION_V1.to_le_bytes());
    journal.extend_from_slice(&deployment_id);
    journal.push(chain_id);
    journal.extend_from_slice(&genesis_hash);
    journal.extend_from_slice(&operator_pubkey);
    journal.extend_from_slice(&measurement);
    Ok(journal)
}

pub fn attestation_journal_decode_v1(journal: &[u8]) -> Result<AttestationJournalV1, AttestationVerifyError> {
    if journal.len() != 2 + 32 + 1 + 32 + 32 + 32 {
        return Err(AttestationVerifyError::InvalidWitnessLen);
    }
    if u16::from_le_bytes([journal[0], journal[1]]) != ATTESTATION_JOURNAL_VERSION_V1 {
        return Err(AttestationVerifyError::AttestationPayloadInvalid);
    }
    let mut off = 2;
    let mut deployment_id = [0u8; 32];
    deployment_id.copy_from_slice(&journal[off..off + 32]);
    off += 32;
    let chain_id = journal[off];
    off += 1;
    let mut genesis = [0u8; 32];
    genesis.copy_from_slice(&journal[off..off + 32]);
    off += 32;
    let mut op = [0u8; 32];
    op.copy_from_slice(&journal[off..off + 32]);
    off += 32;
    let mut meas = [0u8; 32];
    meas.copy_from_slice(&journal[off..off + 32]);
    off += 32;
    if off != journal.len() {
        return Err(AttestationVerifyError::AttestationPayloadInvalid);
    }
    Ok(AttestationJournalV1 {
        deployment_id,
        junocash_chain_id: chain_id,
        junocash_genesis_hash: genesis,
        operator_pubkey: op,
        measurement: meas,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn witness_roundtrip_fixture_attestation() {
        let hex_doc = include_str!("../testdata/attestation.cose.hex");
        let doc = hex::decode(hex_doc.trim()).expect("decode fixture hex");
        let deployment_id = [0x11u8; 32];
        let chain_id = 2u8;
        let genesis_hash = [0x22u8; 32];

        let mut witness = Vec::with_capacity(2 + 32 + 1 + 32 + 4 + doc.len());
        witness.extend_from_slice(&ATTESTATION_WITNESS_VERSION_V1.to_le_bytes());
        witness.extend_from_slice(&deployment_id);
        witness.push(chain_id);
        witness.extend_from_slice(&genesis_hash);
        witness.extend_from_slice(&(doc.len() as u32).to_le_bytes());
        witness.extend_from_slice(&doc);

        // This AWS fixture uses an RSA public key (for KMS), so it should pass the
        // cert-chain + COSE signature checks but fail operator key extraction.
        let err = attestation_journal_from_witness_v1(&witness).unwrap_err();
        assert!(matches!(err, AttestationVerifyError::PublicKeyInvalid));
    }

    #[test]
    fn journal_decode_roundtrip() {
        let deployment_id = [0x11u8; 32];
        let chain_id = 2u8;
        let genesis_hash = [0x22u8; 32];
        let operator_pubkey = hex!("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        let measurement = [0x33u8; 32];

        let mut journal = Vec::with_capacity(2 + 32 + 1 + 32 + 32 + 32);
        journal.extend_from_slice(&ATTESTATION_JOURNAL_VERSION_V1.to_le_bytes());
        journal.extend_from_slice(&deployment_id);
        journal.push(chain_id);
        journal.extend_from_slice(&genesis_hash);
        journal.extend_from_slice(&operator_pubkey);
        journal.extend_from_slice(&measurement);

        let decoded = attestation_journal_decode_v1(&journal).unwrap();
        assert_eq!(decoded.deployment_id, deployment_id);
        assert_eq!(decoded.junocash_chain_id, chain_id);
        assert_eq!(decoded.junocash_genesis_hash, genesis_hash);
        assert_eq!(decoded.operator_pubkey, operator_pubkey);
        assert_eq!(decoded.measurement, measurement);
    }
}
