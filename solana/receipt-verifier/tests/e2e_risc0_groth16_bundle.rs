use anchor_lang::{prelude::*, Discriminator};
use groth_16_verifier as risc0_groth16_verifier;
use ownable::Ownership;
use solana_program::instruction::{AccountMeta, Instruction};
use solana_program_test::{processor, ProgramTest};
use solana_sdk::{account::Account, signature::Signer, transaction::Transaction};
use verifier_router::state::{VerifierEntry, VerifierRouter};
use verifier_router as risc0_verifier_router;

fn verifier_router_entrypoint(
    program_id: &solana_program::pubkey::Pubkey,
    accounts: &[solana_program::account_info::AccountInfo],
    data: &[u8],
) -> solana_program::entrypoint::ProgramResult {
    // Anchor-generated entrypoints require the `AccountInfo` element lifetime to match the slice
    // lifetime. The runtime provides account infos with a single shared lifetime, but the
    // `ProcessInstruction` function pointer type is more generic. Coerce for tests.
    let accounts: &[solana_program::account_info::AccountInfo<'_>] =
        unsafe { std::mem::transmute(accounts) };
    risc0_verifier_router::entry(program_id, accounts, data)
}

fn groth16_verifier_entrypoint(
    program_id: &solana_program::pubkey::Pubkey,
    accounts: &[solana_program::account_info::AccountInfo],
    data: &[u8],
) -> solana_program::entrypoint::ProgramResult {
    let accounts: &[solana_program::account_info::AccountInfo<'_>] =
        unsafe { std::mem::transmute(accounts) };
    risc0_groth16_verifier::entry(program_id, accounts, data)
}

fn decode_hex_env(key: &str) -> Vec<u8> {
    let s = std::env::var(key).unwrap_or_else(|_| panic!("set {key} to hex bytes"));
    let s = s.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).unwrap_or_else(|e| panic!("invalid hex in {key}: {e}"))
}

fn parse_selector_from_bundle_v1(bundle: &[u8]) -> [u8; 4] {
    // Encoding must match risc0/receipt/host (encode_receipt_zkvm_proof_bundle_v1) and
    // solana/receipt-verifier (parse_receipt_zkvm_proof_bundle_v1).
    let min_len = 2 + 1 + 32 + 2 + 170 + 4 + 260;
    assert!(
        bundle.len() >= min_len,
        "bundle too short: {} < {}",
        bundle.len(),
        min_len
    );

    let version = u16::from_le_bytes([bundle[0], bundle[1]]);
    assert_eq!(version, 1, "unexpected bundle version");

    let proof_system = bundle[2];
    assert_eq!(proof_system, 1, "unexpected proof system");

    let journal_len = u16::from_le_bytes([bundle[35], bundle[36]]) as usize;
    assert_eq!(journal_len, 170, "unexpected journal length");

    let journal_off = 37;
    let journal_end = journal_off + journal_len;

    let seal_len = u32::from_le_bytes([
        bundle[journal_end],
        bundle[journal_end + 1],
        bundle[journal_end + 2],
        bundle[journal_end + 3],
    ]) as usize;
    assert_eq!(seal_len, 260, "unexpected seal length");

    let seal_off = journal_end + 4;
    let seal_end = seal_off + seal_len;
    assert_eq!(bundle.len(), seal_end, "bundle length mismatch");

    let seal = &bundle[seal_off..seal_end];
    let mut selector = [0u8; 4];
    selector.copy_from_slice(&seal[0..4]);
    selector
}

fn anchor_account_data<T: AnchorSerialize + Discriminator>(value: &T) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + 128);
    out.extend_from_slice(&T::DISCRIMINATOR);
    out.extend_from_slice(&value.try_to_vec().expect("serialize"));
    out
}

#[tokio::test]
#[ignore]
async fn verifies_real_risc0_groth16_bundle_v1() {
    let bundle = decode_hex_env("JUNO_RECEIPT_ZKVM_BUNDLE_HEX");
    let selector = parse_selector_from_bundle_v1(&bundle);

    let receipt_program_id = Pubkey::new_unique();
    let mut program_test = ProgramTest::new(
        "juno_intents_receipt_verifier",
        receipt_program_id,
        processor!(juno_intents_receipt_verifier::process_instruction),
    );
    program_test.add_program(
        "verifier_router",
        risc0_verifier_router::ID,
        processor!(verifier_router_entrypoint),
    );
    program_test.add_program(
        "groth_16_verifier",
        risc0_groth16_verifier::ID,
        processor!(groth16_verifier_entrypoint),
    );

    let (router_pda, _router_bump) =
        Pubkey::find_program_address(&[b"router"], &risc0_verifier_router::ID);
    let (verifier_entry_pda, _entry_bump) = Pubkey::find_program_address(
        &[b"verifier", selector.as_ref()],
        &risc0_verifier_router::ID,
    );

    let router = VerifierRouter {
        ownership: Ownership::new(Pubkey::new_unique()).expect("ownership new"),
    };
    let verifier_entry = VerifierEntry {
        selector,
        verifier: risc0_groth16_verifier::ID,
        estopped: false,
    };

    program_test.add_account(
        router_pda,
        Account {
            lamports: 1_000_000_000,
            data: anchor_account_data(&router),
            owner: risc0_verifier_router::ID,
            executable: false,
            rent_epoch: 0,
        },
    );
    program_test.add_account(
        verifier_entry_pda,
        Account {
            lamports: 1_000_000_000,
            data: anchor_account_data(&verifier_entry),
            owner: risc0_verifier_router::ID,
            executable: false,
            rent_epoch: 0,
        },
    );

    let (mut banks_client, payer, recent_blockhash) = program_test.start().await;

    let ix = Instruction {
        program_id: receipt_program_id,
        accounts: vec![
            AccountMeta::new_readonly(risc0_verifier_router::ID, false),
            AccountMeta::new_readonly(router_pda, false),
            AccountMeta::new_readonly(verifier_entry_pda, false),
            AccountMeta::new_readonly(risc0_groth16_verifier::ID, false),
            AccountMeta::new_readonly(solana_program::system_program::ID, false),
        ],
        data: bundle,
    };

    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    banks_client.process_transaction(tx).await.unwrap();
}
