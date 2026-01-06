use sha2::{Digest, Sha256};

use juno_receipt_methods::RECEIPT_VERIFY_ELF;

use juno_receipt_host::prove_receipt_journal_with_opts;
use risc0_zkvm::ProverOpts;

#[test]
fn smoke_proves_and_commits_journal() {
    // A fixed dummy witness matching the v1 encoding length.
    // Values are chosen to make it easy to compute expected journal hashes.
    const ORCHARD_RECEIVER_BYTES_LEN: usize = 43;
    const ORCHARD_MERKLE_DEPTH: usize = 32;

    let mut witness = Vec::new();
    witness.extend_from_slice(&1u16.to_le_bytes()); // witness version
    witness.extend_from_slice(&[0x01u8; 32]); // deployment_id
    witness.extend_from_slice(&[0x02u8; 32]); // fill_id
    witness.extend_from_slice(&[0x03u8; 32]); // orchard_root
    witness.extend_from_slice(&[0x04u8; 32]); // cmx
    witness.extend_from_slice(&[0x05u8; ORCHARD_RECEIVER_BYTES_LEN]); // receiver_bytes
    witness.extend_from_slice(&0x0102030405060708u64.to_le_bytes()); // amount
    witness.extend_from_slice(&[0x06u8; 32]); // rho
    witness.extend_from_slice(&[0x07u8; 32]); // rseed
    witness.extend_from_slice(&0xAABBCCDDu32.to_le_bytes()); // merkle index
    for i in 0..ORCHARD_MERKLE_DEPTH {
        witness.extend_from_slice(&[0x10u8 + i as u8; 32]); // siblings
    }

    // Expected journal bytes (mirrors protocol.ReceiptJournalBytesV1).
    // This stays stable even if the zkVM proof system changes.
    let mut h = Sha256::new();
    h.update(b"JUNO_INTENTS");
    h.update([0]);
    h.update(b"iep_receiver_tag");
    h.update([0]);
    h.update(1u16.to_le_bytes());
    h.update([0x01u8; 32]); // deployment_id
    h.update([0x02u8; 32]); // fill_id
    h.update([0x05u8; ORCHARD_RECEIVER_BYTES_LEN]); // receiver_bytes
    let receiver_tag: [u8; 32] = h.finalize().into();

    let mut expected_journal = Vec::new();
    expected_journal.extend_from_slice(&1u16.to_le_bytes()); // journal version
    expected_journal.extend_from_slice(&[0x01u8; 32]); // deployment_id
    expected_journal.extend_from_slice(&[0x03u8; 32]); // orchard_root
    expected_journal.extend_from_slice(&[0x04u8; 32]); // cmx
    expected_journal.extend_from_slice(&0x0102030405060708u64.to_le_bytes()); // amount
    expected_journal.extend_from_slice(&receiver_tag);
    expected_journal.extend_from_slice(&[0x02u8; 32]); // fill_id

    let sum: [u8; 32] = Sha256::digest(&expected_journal).into();
    let want: [u8; 32] = [
        0x15, 0x4c, 0xe2, 0x48, 0xfd, 0xad, 0x23, 0xaf, 0x05, 0xde, 0xce, 0x77, 0xe0, 0xc9,
        0xcb, 0x58, 0x92, 0x8d, 0x10, 0xb0, 0x4b, 0x9a, 0x47, 0x9e, 0x4f, 0xdc, 0xc9,
        0x6d, 0x4a, 0x7a, 0x9b, 0x17,
    ];
    assert_eq!(sum, want, "journal sha256 mismatch");

    // Only attempt an actual zkVM proof if methods were built (requires rzup toolchain).
    if RECEIPT_VERIFY_ELF.is_empty() {
        return;
    }

    // Use dev-mode to keep this test fast and hermetic.
    let opts = ProverOpts::default().with_dev_mode(true);
    let receipt =
        prove_receipt_journal_with_opts(witness, &opts).expect("prove_receipt_journal_with_opts");
    let journal = receipt.journal.bytes;
    assert_eq!(journal, expected_journal, "journal mismatch");
}
