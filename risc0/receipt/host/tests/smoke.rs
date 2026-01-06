use sha2::{Digest, Sha256};

use juno_receipt_logic::receipt_journal_from_witness_v1;

use orchard::{
    keys::{FullViewingKey, Scope, SpendingKey},
    note::{ExtractedNoteCommitment, Note, RandomSeed, Rho},
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
    Address,
};

#[test]
fn smoke_verifies_witness_and_builds_journal() {
    // A fixed dummy witness matching the v1 encoding length.
    // Values are chosen to make it easy to compute expected journal hashes.
    const ORCHARD_RECEIVER_BYTES_LEN: usize = 43;
    const ORCHARD_MERKLE_DEPTH: usize = 32;

    let deployment_id = [0x01u8; 32];
    let fill_id = [0x02u8; 32];
    let amount = 0x0102030405060708u64;

    // Deterministically derive a valid Orchard receiver.
    let mut sk_bytes = [7u8; 32];
    let sk = loop {
        if let Some(sk) = Option::<SpendingKey>::from(SpendingKey::from_bytes(sk_bytes)) {
            break sk;
        }
        sk_bytes[0] = sk_bytes[0].wrapping_add(1);
    };
    let fvk = FullViewingKey::from(&sk);
    let recipient: Address = fvk.address_at(0u32, Scope::External);
    let receiver_bytes: [u8; ORCHARD_RECEIVER_BYTES_LEN] = recipient.to_raw_address_bytes();

    let rho_bytes = [0u8; 32];
    let rho = Option::<Rho>::from(Rho::from_bytes(&rho_bytes)).unwrap();

    let (rseed_bytes, rseed) = (0u8..=255)
        .find_map(|b| {
            let bytes = [b; 32];
            Option::<RandomSeed>::from(RandomSeed::from_bytes(bytes, &rho)).map(|rs| (bytes, rs))
        })
        .unwrap();

    let note = Option::<Note>::from(Note::from_parts(
        recipient,
        NoteValue::from_raw(amount),
        rho,
        rseed,
    ))
    .unwrap();
    let cmx = ExtractedNoteCommitment::from(note.commitment()).to_bytes();

    let cmx_extracted =
        Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&cmx))
            .unwrap();

    // Use a simple deterministic auth path (all zeros) and position 0.
    let zero_hash = Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&[0u8; 32]))
        .unwrap();
    let auth_path = [zero_hash; ORCHARD_MERKLE_DEPTH];
    let position = 0u32;
    let orchard_root = MerklePath::from_parts(position, auth_path)
        .root(cmx_extracted)
        .to_bytes();

    let mut witness = Vec::new();
    witness.extend_from_slice(&1u16.to_le_bytes()); // witness version
    witness.extend_from_slice(&deployment_id);
    witness.extend_from_slice(&fill_id);
    witness.extend_from_slice(&orchard_root);
    witness.extend_from_slice(&cmx);
    witness.extend_from_slice(&receiver_bytes);
    witness.extend_from_slice(&amount.to_le_bytes());
    witness.extend_from_slice(&rho_bytes);
    witness.extend_from_slice(&rseed_bytes);
    witness.extend_from_slice(&position.to_le_bytes());
    for _ in 0..ORCHARD_MERKLE_DEPTH {
        witness.extend_from_slice(&[0u8; 32]); // sibling bytes
    }

    // Expected journal bytes (mirrors protocol.ReceiptJournalBytesV1).
    // This stays stable even if the zkVM proof system changes.
    let mut h = Sha256::new();
    h.update(b"JUNO_INTENTS");
    h.update([0]);
    h.update(b"iep_receiver_tag");
    h.update([0]);
    h.update(1u16.to_le_bytes());
    h.update(deployment_id);
    h.update(fill_id);
    h.update(receiver_bytes);
    let receiver_tag: [u8; 32] = h.finalize().into();

    let mut expected_journal = Vec::new();
    expected_journal.extend_from_slice(&1u16.to_le_bytes()); // journal version
    expected_journal.extend_from_slice(&deployment_id);
    expected_journal.extend_from_slice(&orchard_root);
    expected_journal.extend_from_slice(&cmx);
    expected_journal.extend_from_slice(&amount.to_le_bytes());
    expected_journal.extend_from_slice(&receiver_tag);
    expected_journal.extend_from_slice(&fill_id);

    let sum: [u8; 32] = Sha256::digest(&expected_journal).into();
    let want: [u8; 32] = [
        0xf5, 0xce, 0x0f, 0xaf, 0xb1, 0xd2, 0x9d, 0x52, 0x0d, 0x70, 0x23, 0x0a, 0x99, 0xfa,
        0x46, 0xa8, 0x3a, 0x80, 0x81, 0x1c, 0x35, 0xf0, 0x73, 0x39, 0x4a, 0x8f, 0x59, 0xc5,
        0xa9, 0xd4, 0xf3, 0x5e,
    ];
    assert_eq!(sum, want, "journal sha256 mismatch");

    let journal = receipt_journal_from_witness_v1(&witness).expect("receipt_journal_from_witness_v1");
    assert_eq!(journal, expected_journal, "journal mismatch");
}

#[test]
#[ignore]
fn smoke_proves_and_commits_journal_dev_mode() {
    use juno_receipt_host::prove_receipt_journal_with_opts;
    use risc0_zkvm::ProverOpts;

    // This mirrors smoke_executes_and_commits_journal, but runs an actual proof.
    // It is ignored by default because proving can be slow and environment-dependent.
    const ORCHARD_RECEIVER_BYTES_LEN: usize = 43;
    const ORCHARD_MERKLE_DEPTH: usize = 32;

    let deployment_id = [0x01u8; 32];
    let fill_id = [0x02u8; 32];
    let amount = 0x0102030405060708u64;

    let mut sk_bytes = [7u8; 32];
    let sk = loop {
        if let Some(sk) = Option::<SpendingKey>::from(SpendingKey::from_bytes(sk_bytes)) {
            break sk;
        }
        sk_bytes[0] = sk_bytes[0].wrapping_add(1);
    };
    let fvk = FullViewingKey::from(&sk);
    let recipient: Address = fvk.address_at(0u32, Scope::External);
    let receiver_bytes: [u8; ORCHARD_RECEIVER_BYTES_LEN] = recipient.to_raw_address_bytes();

    let rho_bytes = [0u8; 32];
    let rho = Option::<Rho>::from(Rho::from_bytes(&rho_bytes)).unwrap();

    let (rseed_bytes, rseed) = (0u8..=255)
        .find_map(|b| {
            let bytes = [b; 32];
            Option::<RandomSeed>::from(RandomSeed::from_bytes(bytes, &rho)).map(|rs| (bytes, rs))
        })
        .unwrap();

    let note = Option::<Note>::from(Note::from_parts(
        recipient,
        NoteValue::from_raw(amount),
        rho,
        rseed,
    ))
    .unwrap();
    let cmx = ExtractedNoteCommitment::from(note.commitment()).to_bytes();

    let cmx_extracted =
        Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&cmx))
            .unwrap();

    let zero_hash = Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&[0u8; 32]))
        .unwrap();
    let auth_path = [zero_hash; ORCHARD_MERKLE_DEPTH];
    let position = 0u32;
    let orchard_root = MerklePath::from_parts(position, auth_path)
        .root(cmx_extracted)
        .to_bytes();

    let mut witness = Vec::new();
    witness.extend_from_slice(&1u16.to_le_bytes()); // witness version
    witness.extend_from_slice(&deployment_id);
    witness.extend_from_slice(&fill_id);
    witness.extend_from_slice(&orchard_root);
    witness.extend_from_slice(&cmx);
    witness.extend_from_slice(&receiver_bytes);
    witness.extend_from_slice(&amount.to_le_bytes());
    witness.extend_from_slice(&rho_bytes);
    witness.extend_from_slice(&rseed_bytes);
    witness.extend_from_slice(&position.to_le_bytes());
    for _ in 0..ORCHARD_MERKLE_DEPTH {
        witness.extend_from_slice(&[0u8; 32]);
    }

    let mut h = Sha256::new();
    h.update(b"JUNO_INTENTS");
    h.update([0]);
    h.update(b"iep_receiver_tag");
    h.update([0]);
    h.update(1u16.to_le_bytes());
    h.update(deployment_id);
    h.update(fill_id);
    h.update(receiver_bytes);
    let receiver_tag: [u8; 32] = h.finalize().into();

    let mut expected_journal = Vec::new();
    expected_journal.extend_from_slice(&1u16.to_le_bytes());
    expected_journal.extend_from_slice(&deployment_id);
    expected_journal.extend_from_slice(&orchard_root);
    expected_journal.extend_from_slice(&cmx);
    expected_journal.extend_from_slice(&amount.to_le_bytes());
    expected_journal.extend_from_slice(&receiver_tag);
    expected_journal.extend_from_slice(&fill_id);

    let opts = ProverOpts::default().with_dev_mode(true);
    let receipt =
        prove_receipt_journal_with_opts(witness, &opts).expect("prove_receipt_journal_with_opts");
    assert_eq!(receipt.journal.bytes, expected_journal);
}
