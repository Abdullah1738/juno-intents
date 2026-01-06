use risc0_zkvm::guest::env;
use sha2::{Digest, Sha256};

const DOMAIN_SEPARATOR: &str = "JUNO_INTENTS";
const PROTOCOL_VERSION: u16 = 1;

const RECEIPT_WITNESS_VERSION_V1: u16 = 1;
const RECEIPT_JOURNAL_VERSION_V1: u16 = 1;

const ORCHARD_RECEIVER_BYTES_LEN: usize = 43;
const ORCHARD_MERKLE_DEPTH: usize = 32;

const PURPOSE_IEP_RECEIVER_TAG: &str = "iep_receiver_tag";

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

fn receiver_tag(deployment_id: &[u8; 32], fill_id: &[u8; 32], receiver_bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(prefix_bytes(PURPOSE_IEP_RECEIVER_TAG));
    h.update(deployment_id);
    h.update(fill_id);
    h.update(receiver_bytes);
    h.finalize().into()
}

fn main() {
    // Input is the Go-defined ReceiptWitnessV1.MarshalBinary() bytes.
    let witness: Vec<u8> = env::read();

    // Minimal parsing scaffold: validate length and witness version, then emit the
    // canonical receipt journal bytes (without yet verifying Orchard membership).
    //
    // Full verification is implemented in later steps.
    let min_len = 2
        + 32 // deployment_id
        + 32 // fill_id
        + 32 // orchard_root
        + 32 // cmx
        + ORCHARD_RECEIVER_BYTES_LEN
        + 8 // value_u64_le
        + 32 // rho
        + 32 // rseed
        + 4 // merkle_index_u32_le
        + ORCHARD_MERKLE_DEPTH * 32; // merkle siblings
    if witness.len() != min_len {
        panic!("invalid witness length");
    }

    let version = u16::from_le_bytes([witness[0], witness[1]]);
    if version != RECEIPT_WITNESS_VERSION_V1 {
        panic!("unsupported witness version");
    }

    let mut offset = 2;

    let mut deployment_id = [0u8; 32];
    deployment_id.copy_from_slice(&witness[offset..offset + 32]);
    offset += 32;

    let mut fill_id = [0u8; 32];
    fill_id.copy_from_slice(&witness[offset..offset + 32]);
    offset += 32;

    let mut orchard_root = [0u8; 32];
    orchard_root.copy_from_slice(&witness[offset..offset + 32]);
    offset += 32;

    let mut cmx = [0u8; 32];
    cmx.copy_from_slice(&witness[offset..offset + 32]);
    offset += 32;

    let receiver_bytes = &witness[offset..offset + ORCHARD_RECEIVER_BYTES_LEN];
    offset += ORCHARD_RECEIVER_BYTES_LEN;

    let amount_u64_le = &witness[offset..offset + 8];
    offset += 8;

    // Skip the rest for now (rho, rseed, path).
    let _ = &witness[offset..];

    let tag = receiver_tag(&deployment_id, &fill_id, receiver_bytes);

    // Receipt journal bytes: version_u16_le || deployment_id || orchard_root || cmx || amount_u64_le || receiver_tag || fill_id
    let mut journal = Vec::with_capacity(2 + 32 + 32 + 32 + 8 + 32 + 32);
    journal.extend_from_slice(&RECEIPT_JOURNAL_VERSION_V1.to_le_bytes());
    journal.extend_from_slice(&deployment_id);
    journal.extend_from_slice(&orchard_root);
    journal.extend_from_slice(&cmx);
    journal.extend_from_slice(amount_u64_le);
    journal.extend_from_slice(&tag);
    journal.extend_from_slice(&fill_id);

    env::commit_slice(&journal);
}
