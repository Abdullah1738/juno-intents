use anchor_lang::{prelude::*, Discriminator};
use groth_16_verifier as risc0_groth16_verifier;
use ownable::Ownership;
use solana_program::instruction::{AccountMeta, Instruction};
use solana_program_test::{processor, ProgramTest};
use solana_sdk::{account::Account, signature::Signer, transaction::Transaction};
use verifier_router as risc0_verifier_router;
use verifier_router::state::{VerifierEntry, VerifierRouter};

use juno_intents_operator_registry::{
    config_pda, operator_pda, OperatorRecordV1, OrpConfigV1, OrpInstruction,
};

fn verifier_router_entrypoint(
    program_id: &solana_program::pubkey::Pubkey,
    accounts: &[solana_program::account_info::AccountInfo],
    data: &[u8],
) -> solana_program::entrypoint::ProgramResult {
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

fn anchor_account_data<T: AnchorSerialize + Discriminator>(value: &T) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + 128);
    out.extend_from_slice(&T::DISCRIMINATOR);
    out.extend_from_slice(&value.try_to_vec().expect("serialize"));
    out
}

#[derive(Debug, Clone)]
struct ParsedAttestationBundleV1 {
    selector: [u8; 4],
    journal: [u8; 131],
}

fn parse_attestation_bundle_v1(bundle: &[u8]) -> ParsedAttestationBundleV1 {
    // Encoding must match risc0/attestation/host (encode_attestation_zkvm_proof_bundle_v1) and
    // solana/operator-registry (parse_attestation_bundle_v1).
    let min_len = 2 + 1 + 32 + 2 + 131 + 4 + 260;
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
    assert_eq!(journal_len, 131, "unexpected journal length");

    let journal_off = 37;
    let journal_end = journal_off + journal_len;
    let mut journal = [0u8; 131];
    journal.copy_from_slice(&bundle[journal_off..journal_end]);

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

    ParsedAttestationBundleV1 { selector, journal }
}

fn parse_journal_v1(journal: &[u8; 131]) -> ([u8; 32], u8, [u8; 32], Pubkey, [u8; 32]) {
    let journal_version = u16::from_le_bytes([journal[0], journal[1]]);
    assert_eq!(journal_version, 1, "unexpected journal version");

    let mut off = 2;
    let mut deployment_id = [0u8; 32];
    deployment_id.copy_from_slice(&journal[off..off + 32]);
    off += 32;

    let chain_id = journal[off];
    off += 1;

    let mut genesis_hash = [0u8; 32];
    genesis_hash.copy_from_slice(&journal[off..off + 32]);
    off += 32;

    let operator_pubkey = Pubkey::new_from_array(journal[off..off + 32].try_into().unwrap());
    off += 32;

    let mut measurement = [0u8; 32];
    measurement.copy_from_slice(&journal[off..off + 32]);
    off += 32;

    assert_eq!(off, 131, "journal length mismatch");
    (
        deployment_id,
        chain_id,
        genesis_hash,
        operator_pubkey,
        measurement,
    )
}

#[tokio::test]
#[ignore]
async fn registers_real_risc0_groth16_attestation_bundle_v1() {
    let bundle = decode_hex_env("JUNO_ATTESTATION_ZKVM_BUNDLE_HEX");
    let parsed = parse_attestation_bundle_v1(&bundle);
    let (deployment_id, chain_id, genesis_hash, operator_pubkey, measurement) =
        parse_journal_v1(&parsed.journal);

    let orp_program_id = Pubkey::new_unique();

    let (router_pda, _router_bump) =
        Pubkey::find_program_address(&[b"router"], &risc0_verifier_router::ID);
    let (verifier_entry_pda, _entry_bump) = Pubkey::find_program_address(
        &[b"verifier", parsed.selector.as_ref()],
        &risc0_verifier_router::ID,
    );

    let router = VerifierRouter {
        ownership: Ownership::new(Pubkey::new_unique()).expect("ownership new"),
    };
    let verifier_entry = VerifierEntry {
        selector: parsed.selector,
        verifier: risc0_groth16_verifier::ID,
        estopped: false,
    };

    let mut pt = ProgramTest::new(
        "juno_intents_operator_registry",
        orp_program_id,
        processor!(juno_intents_operator_registry::process_instruction),
    );
    pt.add_program(
        "verifier_router",
        risc0_verifier_router::ID,
        processor!(verifier_router_entrypoint),
    );
    pt.add_program(
        "groth_16_verifier",
        risc0_groth16_verifier::ID,
        processor!(groth16_verifier_entrypoint),
    );

    pt.add_account(
        router_pda,
        Account {
            lamports: 1_000_000_000,
            data: anchor_account_data(&router),
            owner: risc0_verifier_router::ID,
            executable: false,
            rent_epoch: 0,
        },
    );
    pt.add_account(
        verifier_entry_pda,
        Account {
            lamports: 1_000_000_000,
            data: anchor_account_data(&verifier_entry),
            owner: risc0_verifier_router::ID,
            executable: false,
            rent_epoch: 0,
        },
    );

    let (banks_client, payer, recent_blockhash) = pt.start().await;

    let (config, _bump) = config_pda(&orp_program_id, &deployment_id);

    // ORP config ties the chain + genesis + allowed measurement(s) to a deployment.
    let init_ix = Instruction {
        program_id: orp_program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(config, false),
            AccountMeta::new_readonly(solana_program::system_program::ID, false),
        ],
        data: OrpInstruction::Initialize {
            deployment_id,
            admin: payer.pubkey(),
            junocash_chain_id: chain_id,
            junocash_genesis_hash: genesis_hash,
            verifier_router_program: risc0_verifier_router::ID,
            router: router_pda,
            verifier_entry: verifier_entry_pda,
            verifier_program: risc0_groth16_verifier::ID,
            allowed_measurements: vec![measurement],
        }
        .try_to_vec()
        .expect("borsh encode"),
    };
    let tx = Transaction::new_signed_with_payer(
        &[init_ix],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    banks_client.process_transaction(tx).await.unwrap();

    let cfg_ai = banks_client.get_account(config).await.unwrap().unwrap();
    let cfg = OrpConfigV1::try_from_slice(&cfg_ai.data).unwrap();
    assert_eq!(cfg.deployment_id, deployment_id);
    assert_eq!(cfg.admin, payer.pubkey());
    assert_eq!(cfg.junocash_chain_id, chain_id);
    assert_eq!(cfg.junocash_genesis_hash, genesis_hash);

    let (operator_record, _bump) = operator_pda(&orp_program_id, &deployment_id, &operator_pubkey);

    let recent_blockhash = banks_client.get_latest_blockhash().await.unwrap();
    let reg_ix = Instruction {
        program_id: orp_program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(config, false),
            AccountMeta::new(operator_record, false),
            AccountMeta::new_readonly(solana_program::system_program::ID, false),
            AccountMeta::new_readonly(risc0_verifier_router::ID, false),
            AccountMeta::new_readonly(router_pda, false),
            AccountMeta::new_readonly(verifier_entry_pda, false),
            AccountMeta::new_readonly(risc0_groth16_verifier::ID, false),
        ],
        data: OrpInstruction::RegisterOperator {
            bundle: bundle.clone(),
        }
        .try_to_vec()
        .expect("borsh encode"),
    };
    let tx = Transaction::new_signed_with_payer(
        &[reg_ix],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    banks_client.process_transaction(tx).await.unwrap();

    let rec_ai = banks_client
        .get_account(operator_record)
        .await
        .unwrap()
        .unwrap();
    let rec = OperatorRecordV1::try_from_slice(&rec_ai.data).unwrap();
    assert_eq!(rec.deployment_id, deployment_id);
    assert_eq!(rec.operator_pubkey, operator_pubkey);
    assert_eq!(rec.measurement, measurement);
    assert!(rec.enabled);
}
