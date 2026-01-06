use sha2::{Digest, Sha256};

use orchard::{
    note::{ExtractedNoteCommitment, Note, RandomSeed, Rho},
    tree::{Anchor, MerkleHashOrchard, MerklePath},
    value::NoteValue,
    Address,
};

const DOMAIN_SEPARATOR: &str = "JUNO_INTENTS";
const PROTOCOL_VERSION: u16 = 1;

pub const RECEIPT_WITNESS_VERSION_V1: u16 = 1;
pub const RECEIPT_JOURNAL_VERSION_V1: u16 = 1;

pub const ORCHARD_RECEIVER_BYTES_LEN: usize = 43;
pub const ORCHARD_MERKLE_DEPTH: usize = 32;

const PURPOSE_IEP_RECEIVER_TAG: &str = "iep_receiver_tag";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptVerifyError {
    InvalidWitnessLen,
    UnsupportedWitnessVersion,
    InvalidReceiverBytes,
    InvalidRho,
    InvalidRseed,
    InvalidNoteOpening,
    NonCanonicalCmx,
    CmxMismatch,
    InvalidMerkleSibling,
    OrchardRootMismatch,
    NonCanonicalOrchardRoot,
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

fn receiver_tag(deployment_id: &[u8; 32], fill_id: &[u8; 32], receiver_bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(prefix_bytes(PURPOSE_IEP_RECEIVER_TAG));
    h.update(deployment_id);
    h.update(fill_id);
    h.update(receiver_bytes);
    h.finalize().into()
}

pub fn receipt_journal_from_witness_v1(witness: &[u8]) -> Result<Vec<u8>, ReceiptVerifyError> {
    let expected_len = 2
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
    if witness.len() != expected_len {
        return Err(ReceiptVerifyError::InvalidWitnessLen);
    }

    let version = u16::from_le_bytes([witness[0], witness[1]]);
    if version != RECEIPT_WITNESS_VERSION_V1 {
        return Err(ReceiptVerifyError::UnsupportedWitnessVersion);
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

    let mut rho_bytes = [0u8; 32];
    rho_bytes.copy_from_slice(&witness[offset..offset + 32]);
    offset += 32;

    let mut rseed_bytes = [0u8; 32];
    rseed_bytes.copy_from_slice(&witness[offset..offset + 32]);
    offset += 32;

    let position = u32::from_le_bytes(witness[offset..offset + 4].try_into().unwrap());
    offset += 4;

    let default_hash =
        Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&[0u8; 32]))
            .unwrap_or_else(|| panic!("bad Merkle default"));
    let mut auth_path = [default_hash; ORCHARD_MERKLE_DEPTH];
    for i in 0..ORCHARD_MERKLE_DEPTH {
        let mut sib = [0u8; 32];
        sib.copy_from_slice(&witness[offset..offset + 32]);
        offset += 32;
        auth_path[i] = Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&sib))
            .ok_or(ReceiptVerifyError::InvalidMerkleSibling)?;
    }

    if offset != expected_len {
        return Err(ReceiptVerifyError::InvalidWitnessLen);
    }

    let mut receiver_arr = [0u8; ORCHARD_RECEIVER_BYTES_LEN];
    receiver_arr.copy_from_slice(receiver_bytes);

    let recipient = Option::<Address>::from(Address::from_raw_address_bytes(&receiver_arr))
        .ok_or(ReceiptVerifyError::InvalidReceiverBytes)?;

    let rho = Option::<Rho>::from(Rho::from_bytes(&rho_bytes)).ok_or(ReceiptVerifyError::InvalidRho)?;
    let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(rseed_bytes, &rho))
        .ok_or(ReceiptVerifyError::InvalidRseed)?;

    let amount = u64::from_le_bytes(amount_u64_le.try_into().unwrap());
    let value = NoteValue::from_raw(amount);

    let note = Option::<Note>::from(Note::from_parts(recipient, value, rho, rseed))
        .ok_or(ReceiptVerifyError::InvalidNoteOpening)?;

    let computed_cmx = ExtractedNoteCommitment::from(note.commitment()).to_bytes();
    if computed_cmx != cmx {
        return Err(ReceiptVerifyError::CmxMismatch);
    }

    let cmx_extracted =
        Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&cmx))
            .ok_or(ReceiptVerifyError::NonCanonicalCmx)?;

    let path = MerklePath::from_parts(position, auth_path);
    let computed_anchor = path.root(cmx_extracted).to_bytes();
    if computed_anchor != orchard_root {
        return Err(ReceiptVerifyError::OrchardRootMismatch);
    }

    let _ = Option::<Anchor>::from(Anchor::from_bytes(orchard_root))
        .ok_or(ReceiptVerifyError::NonCanonicalOrchardRoot)?;

    let tag = receiver_tag(&deployment_id, &fill_id, receiver_bytes);

    let mut journal = Vec::with_capacity(2 + 32 + 32 + 32 + 8 + 32 + 32);
    journal.extend_from_slice(&RECEIPT_JOURNAL_VERSION_V1.to_le_bytes());
    journal.extend_from_slice(&deployment_id);
    journal.extend_from_slice(&orchard_root);
    journal.extend_from_slice(&cmx);
    journal.extend_from_slice(amount_u64_le);
    journal.extend_from_slice(&tag);
    journal.extend_from_slice(&fill_id);

    Ok(journal)
}

