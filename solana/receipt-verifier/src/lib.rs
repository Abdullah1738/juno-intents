#![allow(unexpected_cfgs)]

#[cfg(not(feature = "no-entrypoint"))]
use solana_program::entrypoint;
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    hash::hashv,
    instruction::{AccountMeta, Instruction},
    program::invoke,
    program_error::ProgramError,
    pubkey::Pubkey,
};

const RECEIPT_ZKVM_PROOF_BUNDLE_VERSION_V1: u16 = 1;
const ZKVM_PROOF_SYSTEM_RISC0_GROTH16: u8 = 1;
const RECEIPT_JOURNAL_BYTES_LEN_V1: usize = 2 + 32 + 32 + 32 + 8 + 32 + 32;

// Current expected MethodID bytes for the RISC Zero receipt verifier guest program.
// This MUST be updated whenever the zkVM method is changed and re-embedded.
const EXPECTED_IMAGE_ID: [u8; 32] = [
    0x53, 0x65, 0xf7, 0x2c, 0x01, 0x55, 0x78, 0x8f, 0xef, 0xb7, 0x0a, 0xf0, 0x08, 0x9c,
    0x12, 0x47, 0x09, 0x0b, 0xa4, 0x1e, 0xd9, 0x0b, 0xfb, 0x92, 0xd9, 0xb5, 0xc0, 0x62,
    0x62, 0x3a, 0xf6, 0x25,
];

// Anchor discriminator for verifier_router::verify instruction:
// sha256("global:verify")[0..8]
const VERIFIER_ROUTER_VERIFY_DISCRIMINATOR: [u8; 8] = [
    0x85, 0xa1, 0x8d, 0x30, 0x78, 0xc6, 0x58, 0x96,
];

#[cfg(not(feature = "no-entrypoint"))]
entrypoint!(process_instruction);

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    input: &[u8],
) -> ProgramResult {
    let parsed = parse_receipt_zkvm_proof_bundle_v1(input)?;
    if parsed.proof_system != ZKVM_PROOF_SYSTEM_RISC0_GROTH16 {
        return Err(ProgramError::InvalidInstructionData);
    }
    if parsed.image_id != EXPECTED_IMAGE_ID {
        return Err(ProgramError::InvalidInstructionData);
    }

    // Accounts:
    // 0. verifier_router_program (executable)
    // 1. router (PDA)
    // 2. verifier_entry (PDA)
    // 3. verifier_program (groth16 verifier program)
    // 4. system_program
    let mut iter = accounts.iter();
    let verifier_router_program = next_account_info(&mut iter)?;
    let router = next_account_info(&mut iter)?;
    let verifier_entry = next_account_info(&mut iter)?;
    let verifier_program = next_account_info(&mut iter)?;
    let system_program = next_account_info(&mut iter)?;

    let journal_digest = hashv(&[parsed.journal]).to_bytes();

    // Build Anchor instruction data:
    //   discriminator(8) || seal(260) || image_id(32) || journal_digest(32)
    let mut data = Vec::with_capacity(8 + parsed.seal.len() + 32 + 32);
    data.extend_from_slice(&VERIFIER_ROUTER_VERIFY_DISCRIMINATOR);
    data.extend_from_slice(parsed.seal);
    data.extend_from_slice(&parsed.image_id);
    data.extend_from_slice(&journal_digest);

    let ix = Instruction {
        program_id: *verifier_router_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*router.key, false),
            AccountMeta::new_readonly(*verifier_entry.key, false),
            AccountMeta::new_readonly(*verifier_program.key, false),
            AccountMeta::new_readonly(*system_program.key, false),
        ],
        data,
    };

    invoke(
        &ix,
        &[
            verifier_router_program.clone(),
            router.clone(),
            verifier_entry.clone(),
            verifier_program.clone(),
            system_program.clone(),
        ],
    )
}

struct ParsedBundle<'a> {
    proof_system: u8,
    image_id: [u8; 32],
    journal: &'a [u8],
    seal: &'a [u8],
}

fn parse_receipt_zkvm_proof_bundle_v1(input: &[u8]) -> Result<ParsedBundle<'_>, ProgramError> {
    let mut offset = 0;
    if input.len() < 2 + 1 + 32 + 2 + RECEIPT_JOURNAL_BYTES_LEN_V1 + 4 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let version = u16::from_le_bytes([input[0], input[1]]);
    if version != RECEIPT_ZKVM_PROOF_BUNDLE_VERSION_V1 {
        return Err(ProgramError::InvalidInstructionData);
    }
    offset += 2;

    let proof_system = input[offset];
    offset += 1;

    let mut image_id = [0u8; 32];
    image_id.copy_from_slice(&input[offset..offset + 32]);
    offset += 32;

    let journal_len = u16::from_le_bytes([input[offset], input[offset + 1]]) as usize;
    offset += 2;
    if journal_len != RECEIPT_JOURNAL_BYTES_LEN_V1 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let journal = &input[offset..offset + journal_len];
    offset += journal_len;

    let seal_len = u32::from_le_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
    ]) as usize;
    offset += 4;
    if seal_len != 260 {
        // Router Seal selector(4) + Proof(256).
        return Err(ProgramError::InvalidInstructionData);
    }
    if input.len() != offset + seal_len {
        return Err(ProgramError::InvalidInstructionData);
    }
    let seal = &input[offset..offset + seal_len];

    Ok(ParsedBundle {
        proof_system,
        image_id,
        journal,
        seal,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn router_verify_discriminator_is_stable() {
        let got = hex::encode(VERIFIER_ROUTER_VERIFY_DISCRIMINATOR);
        assert_eq!(got, "85a18d3078c65896");
    }

    #[test]
    fn parse_receipt_zkvm_proof_bundle_v1_rejects_wrong_len() {
        assert!(
            matches!(
                parse_receipt_zkvm_proof_bundle_v1(&[0u8; 10]),
                Err(ProgramError::InvalidInstructionData)
            ),
            "expected invalid instruction data"
        );
    }
}
