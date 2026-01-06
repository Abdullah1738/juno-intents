use anyhow::Context;
use risc0_zkvm::{
    default_executor, default_prover, ExecutorEnv, ExitCode, ProverOpts, Receipt, VerifierContext,
};

use juno_receipt_methods::{RECEIPT_VERIFY_ELF, RECEIPT_VERIFY_ID};

const RECEIPT_ZKVM_PROOF_BUNDLE_VERSION_V1: u16 = 1;
const ZKVM_PROOF_SYSTEM_RISC0_GROTH16: u8 = 1;

const RECEIPT_JOURNAL_BYTES_LEN_V1: usize = 2 + 32 + 32 + 32 + 8 + 32 + 32;

// Base field modulus 'q' for BN254.
// https://docs.rs/ark-bn254/latest/ark_bn254/
const BN254_BASE_FIELD_MODULUS_Q: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81,
    0x58, 0x5d, 0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16,
    0xd8, 0x7c, 0xfd, 0x47,
];

pub fn prove_receipt_journal(witness_bytes: Vec<u8>) -> anyhow::Result<Receipt> {
    prove_receipt_journal_with_opts(witness_bytes, &ProverOpts::default())
}

pub fn execute_receipt_journal(witness_bytes: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    let env = ExecutorEnv::builder()
        .write(&witness_bytes)
        .context("failed to write witness bytes")?
        .build()
        .context("failed to build executor env")?;

    let executor = default_executor();
    let session = executor.execute(env, RECEIPT_VERIFY_ELF).context("execute failed")?;

    if session.exit_code != ExitCode::Halted(0) {
        anyhow::bail!("unexpected exit code: {:?}", session.exit_code);
    }

    Ok(session.journal.bytes)
}

pub fn prove_receipt_journal_with_opts(
    witness_bytes: Vec<u8>,
    opts: &ProverOpts,
) -> anyhow::Result<Receipt> {
    let env = ExecutorEnv::builder()
        .write(&witness_bytes)
        .context("failed to write witness bytes")?
        .build()
        .context("failed to build executor env")?;

    let prover = default_prover();
    let prove_info = prover
        .prove_with_opts(env, RECEIPT_VERIFY_ELF, opts)
        .context("prove failed")?;

    let verify_res = if opts.dev_mode() {
        let ctx = VerifierContext::default().with_dev_mode(true);
        prove_info.receipt.verify_with_context(&ctx, RECEIPT_VERIFY_ID)
    } else {
        prove_info.receipt.verify(RECEIPT_VERIFY_ID)
    };
    verify_res.context("receipt verification failed")?;

    Ok(prove_info.receipt)
}

pub fn prove_receipt_groth16_bundle_v1(
    witness_bytes: Vec<u8>,
    selector: [u8; 4],
) -> anyhow::Result<Vec<u8>> {
    let opts = ProverOpts::groth16();
    let receipt = prove_receipt_journal_with_opts(witness_bytes, &opts)?;

    let journal = receipt.journal.bytes;
    if journal.len() != RECEIPT_JOURNAL_BYTES_LEN_V1 {
        anyhow::bail!("unexpected journal length: {}", journal.len());
    }

    let image_id = method_id_bytes(RECEIPT_VERIFY_ID);

    let groth16 = receipt.inner.groth16().context("receipt is not groth16")?;
    if groth16.seal.len() != 256 {
        anyhow::bail!("unexpected groth16 seal length: {}", groth16.seal.len());
    }

    let mut pi_a = [0u8; 64];
    pi_a.copy_from_slice(&groth16.seal[0..64]);
    let pi_b = &groth16.seal[64..192];
    let pi_c = &groth16.seal[192..256];

    // RISC0's Solana verifier expects pi_a to be negated.
    let pi_a = negate_g1(&pi_a);

    let mut seal = Vec::with_capacity(4 + 256);
    seal.extend_from_slice(&selector);
    seal.extend_from_slice(&pi_a);
    seal.extend_from_slice(pi_b);
    seal.extend_from_slice(pi_c);

    encode_receipt_zkvm_proof_bundle_v1(image_id, journal, seal)
}

fn method_id_bytes(id: [u32; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, word) in id.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

fn negate_g1(point: &[u8; 64]) -> [u8; 64] {
    // Same encoding and negation as risc0-solana groth_16_verifier::negate_g1.
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&point[..32]);

    let mut y = [0u8; 32];
    y.copy_from_slice(&point[32..]);

    let mut modulus = BN254_BASE_FIELD_MODULUS_Q;
    subtract_be_bytes(&mut modulus, &y);
    out[32..].copy_from_slice(&modulus);
    out
}

fn subtract_be_bytes(a: &mut [u8; 32], b: &[u8; 32]) {
    let mut borrow: u32 = 0;
    for (ai, bi) in a.iter_mut().zip(b.iter()).rev() {
        let result = (*ai as u32).wrapping_sub(*bi as u32).wrapping_sub(borrow);
        *ai = result as u8;
        borrow = (result >> 31) & 1;
    }
}

fn encode_receipt_zkvm_proof_bundle_v1(
    image_id: [u8; 32],
    journal: Vec<u8>,
    seal: Vec<u8>,
) -> anyhow::Result<Vec<u8>> {
    if journal.len() != RECEIPT_JOURNAL_BYTES_LEN_V1 {
        anyhow::bail!("invalid journal length: {}", journal.len());
    }
    if seal.is_empty() {
        anyhow::bail!("empty seal");
    }
    if seal.len() > u32::MAX as usize {
        anyhow::bail!("seal too large");
    }

    // Canonical encoding:
    //   version_u16_le ||
    //   proof_system_u8 ||
    //   image_id (32) ||
    //   journal_len_u16_le ||
    //   journal_bytes ||
    //   seal_len_u32_le ||
    //   seal_bytes
    let mut out = Vec::with_capacity(2 + 1 + 32 + 2 + journal.len() + 4 + seal.len());
    out.extend_from_slice(&RECEIPT_ZKVM_PROOF_BUNDLE_VERSION_V1.to_le_bytes());
    out.push(ZKVM_PROOF_SYSTEM_RISC0_GROTH16);
    out.extend_from_slice(&image_id);
    out.extend_from_slice(&(journal.len() as u16).to_le_bytes());
    out.extend_from_slice(&journal);
    out.extend_from_slice(&(seal.len() as u32).to_le_bytes());
    out.extend_from_slice(&seal);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn encode_receipt_zkvm_proof_bundle_v1_golden_sha256() {
        let mut image_id = [0u8; 32];
        for (i, b) in image_id.iter_mut().enumerate() {
            *b = 0xA0u8.wrapping_add(i as u8);
        }

        let mut journal = Vec::with_capacity(RECEIPT_JOURNAL_BYTES_LEN_V1);
        journal.extend_from_slice(&1u16.to_le_bytes()); // version
        journal.extend_from_slice(&[0x01u8; 32]); // deployment_id
        journal.extend_from_slice(&[0x02u8; 32]); // orchard_root
        journal.extend_from_slice(&[0x03u8; 32]); // cmx
        journal.extend_from_slice(&42u64.to_le_bytes()); // amount_u64_le
        journal.extend_from_slice(&[0x04u8; 32]); // receiver_tag
        journal.extend_from_slice(&[0x05u8; 32]); // fill_id
        assert_eq!(journal.len(), RECEIPT_JOURNAL_BYTES_LEN_V1);

        let mut seal = vec![0u8; 257];
        for (i, b) in seal.iter_mut().enumerate() {
            *b = i as u8;
        }

        let enc = encode_receipt_zkvm_proof_bundle_v1(image_id, journal, seal).unwrap();
        let got = Sha256::digest(&enc);
        let want: [u8; 32] = [
            0x7a, 0xc0, 0x42, 0x66, 0x1c, 0x54, 0xbb, 0x82, 0x69, 0x54, 0x15, 0x9e, 0x16,
            0x60, 0xca, 0x67, 0xde, 0x7e, 0x2e, 0x92, 0x82, 0xdd, 0x10, 0x6e, 0xd7, 0x93,
            0x1d, 0x33, 0xf6, 0x52, 0xe4, 0x09,
        ];
        assert_eq!(<&[u8; 32]>::try_from(got.as_slice()).unwrap(), &want);
    }
}
