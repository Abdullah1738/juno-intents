use juno_receipt_host::prove_receipt_groth16_bundle_v1;
use juno_receipt_logic::receipt_journal_from_witness_v1;

use orchard::{
    keys::{FullViewingKey, Scope, SpendingKey},
    note::{ExtractedNoteCommitment, Note, RandomSeed, Rho},
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
    Address,
};

#[test]
#[ignore]
fn smoke_proves_groth16_bundle_v1() {
    // This test produces a Groth16 receipt (Docker required) and wraps it into the
    // ReceiptZKVMProofBundleV1 binary format for Solana settlement.
    if !cfg!(target_arch = "x86_64") {
        // ProverOpts::groth16() uses docker-based shrink-wrap which is only supported on x86_64.
        return;
    }

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
        witness.extend_from_slice(&[0u8; 32]);
    }

    // Selector used by the Verifier Router registry for Groth16 receipts.
    let selector = *b"JINT";
    let bundle_bytes =
        prove_receipt_groth16_bundle_v1(witness.clone(), selector).expect("prove bundle");

    // Basic decode checks (mirror Go and Solana parsing expectations).
    assert!(bundle_bytes.len() > 2 + 1 + 32 + 2 + 170 + 4);
    assert_eq!(u16::from_le_bytes([bundle_bytes[0], bundle_bytes[1]]), 1);
    assert_eq!(bundle_bytes[2], 1);

    let journal_len = u16::from_le_bytes([bundle_bytes[35], bundle_bytes[36]]) as usize;
    assert_eq!(journal_len, 170);

    let journal_off = 37;
    let journal_end = journal_off + journal_len;
    let journal = &bundle_bytes[journal_off..journal_end];

    let seal_len = u32::from_le_bytes([
        bundle_bytes[journal_end],
        bundle_bytes[journal_end + 1],
        bundle_bytes[journal_end + 2],
        bundle_bytes[journal_end + 3],
    ]) as usize;
    assert_eq!(seal_len, 260);

    let seal_off = journal_end + 4;
    let seal_end = seal_off + seal_len;
    assert_eq!(bundle_bytes.len(), seal_end);

    let seal = &bundle_bytes[seal_off..seal_end];
    assert_eq!(&seal[0..4], selector);

    // Journal bytes are deterministic from witness.
    let expected_journal = receipt_journal_from_witness_v1(&witness).expect("verify witness");
    assert_eq!(journal, expected_journal);
}
