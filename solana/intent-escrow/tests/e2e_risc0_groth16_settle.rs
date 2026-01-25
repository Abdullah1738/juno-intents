use anchor_lang::{prelude::*, Discriminator};
use borsh::{BorshDeserialize, BorshSerialize};
use groth_16_verifier as risc0_groth16_verifier;
use ownable::Ownership;
use solana_program::instruction::{AccountMeta, Instruction};
use solana_program_test::{processor, ProgramTest};
use solana_sdk::{
    account::Account,
    ed25519_instruction::new_ed25519_instruction_with_signature,
    signature::{Keypair, Signer},
    system_instruction, system_program,
    transaction::Transaction,
};
use spl_token::solana_program::program_pack::Pack;
use verifier_router as risc0_verifier_router;
use verifier_router::state::{VerifierEntry, VerifierRouter};

use juno_intents_checkpoint_registry::{
    checkpoint_pda as crp_checkpoint_pda, config_pda as crp_config_pda,
    height_pda as crp_height_pda, observation_signing_bytes_v1, CrpInstruction,
};
use juno_intents_operator_registry::{
    config_pda as orp_config_pda, operator_pda as orp_operator_pda, OrpInstruction,
};
use juno_intents_intent_escrow::{
    config_pda as iep_config_pda, fill_pda as iep_fill_pda, intent_pda as iep_intent_pda,
    intent_vault_pda as iep_intent_vault_pda, spent_receipt_pda as iep_spent_pda,
    vault_pda as iep_vault_pda, IepFillV2, IepInstruction, IepIntentV2,
};

const IEP_PROGRAM_ID_BYTES: [u8; 32] = [0xA1u8; 32];
const CRP_PROGRAM_ID_BYTES: [u8; 32] = [0xA2u8; 32];
const RECEIPT_VERIFIER_PROGRAM_ID_BYTES: [u8; 32] = [0xA3u8; 32];
const OPERATOR_REGISTRY_PROGRAM_ID_BYTES: [u8; 32] = [0xA4u8; 32];

const INTENT_NONCE: [u8; 32] = [0x33u8; 32];

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

fn mock_verifier_router(
    _program_id: &solana_program::pubkey::Pubkey,
    _accounts: &[solana_program::account_info::AccountInfo],
    _data: &[u8],
) -> solana_program::entrypoint::ProgramResult {
    Ok(())
}

fn decode_hex_env(key: &str) -> Vec<u8> {
    let s = std::env::var(key).unwrap_or_else(|_| panic!("set {key} to hex bytes"));
    let s = s.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).unwrap_or_else(|e| panic!("invalid hex in {key}: {e}"))
}

// Must match solana/operator-registry EXPECTED_IMAGE_ID.
const ATTESTATION_IMAGE_ID: [u8; 32] = [
    0x75, 0xd1, 0x4b, 0xd3, 0x6f, 0x7b, 0x8a, 0x31, 0x00, 0x47, 0xc7, 0xe8, 0xef, 0xff,
    0x7d, 0xac, 0xab, 0x7e, 0x9e, 0x9c, 0xf2, 0x26, 0x1e, 0xc1, 0x02, 0x96, 0xe7,
    0x25, 0x01, 0xe2, 0x27, 0x15,
];
const ATTESTATION_JOURNAL_LEN_V1: usize = 2 + 32 + 1 + 32 + 32 + 32;
const ATTESTATION_SEAL_LEN_V1: usize = 260;

fn att_journal_bytes(
    deployment_id: [u8; 32],
    chain_id: u8,
    genesis_hash: [u8; 32],
    operator_pubkey: Pubkey,
    measurement: [u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(ATTESTATION_JOURNAL_LEN_V1);
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(deployment_id.as_ref());
    out.push(chain_id);
    out.extend_from_slice(genesis_hash.as_ref());
    out.extend_from_slice(operator_pubkey.as_ref());
    out.extend_from_slice(measurement.as_ref());
    assert_eq!(out.len(), ATTESTATION_JOURNAL_LEN_V1);
    out
}

fn att_bundle_bytes(journal: &[u8]) -> Vec<u8> {
    assert_eq!(journal.len(), ATTESTATION_JOURNAL_LEN_V1);
    let mut out = Vec::with_capacity(2 + 1 + 32 + 2 + journal.len() + 4 + ATTESTATION_SEAL_LEN_V1);
    out.extend_from_slice(&1u16.to_le_bytes());
    out.push(1u8);
    out.extend_from_slice(&ATTESTATION_IMAGE_ID);
    out.extend_from_slice(&(journal.len() as u16).to_le_bytes());
    out.extend_from_slice(journal);
    let seal = vec![0u8; ATTESTATION_SEAL_LEN_V1];
    out.extend_from_slice(&(seal.len() as u32).to_le_bytes());
    out.extend_from_slice(&seal);
    out
}

#[derive(Debug, Clone)]
struct ReceiptJournalV1 {
    deployment_id: [u8; 32],
    orchard_root: [u8; 32],
    cmx: [u8; 32],
    amount: u64,
    receiver_tag: [u8; 32],
    fill_id: [u8; 32],
}

fn parse_bundle_v1(bundle: &[u8]) -> (ReceiptJournalV1, [u8; 4]) {
    // Encoding must match:
    // - risc0/receipt/host (encode_receipt_zkvm_proof_bundle_v1)
    // - solana/intent-escrow (parse_receipt_bundle_and_journal_v1)
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
    let journal = &bundle[journal_off..journal_end];

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

    // Parse the v1 journal bytes.
    let journal_version = u16::from_le_bytes([journal[0], journal[1]]);
    assert_eq!(journal_version, 1, "unexpected journal version");

    let mut deployment_id = [0u8; 32];
    deployment_id.copy_from_slice(&journal[2..34]);
    let mut orchard_root = [0u8; 32];
    orchard_root.copy_from_slice(&journal[34..66]);
    let mut cmx = [0u8; 32];
    cmx.copy_from_slice(&journal[66..98]);

    let amount = u64::from_le_bytes(journal[98..106].try_into().unwrap());

    let mut receiver_tag = [0u8; 32];
    receiver_tag.copy_from_slice(&journal[106..138]);
    let mut fill_id = [0u8; 32];
    fill_id.copy_from_slice(&journal[138..170]);

    (
        ReceiptJournalV1 {
            deployment_id,
            orchard_root,
            cmx,
            amount,
            receiver_tag,
            fill_id,
        },
        selector,
    )
}

fn anchor_account_data<T: AnchorSerialize + Discriminator>(value: &T) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + 128);
    out.extend_from_slice(&T::DISCRIMINATOR);
    out.extend_from_slice(&value.try_to_vec().expect("serialize"));
    out
}

fn iep_ix(
    program_id: solana_sdk::pubkey::Pubkey,
    accounts: Vec<AccountMeta>,
    data: IepInstruction,
) -> Instruction {
    Instruction {
        program_id,
        accounts,
        data: data.try_to_vec().expect("borsh encode"),
    }
}

fn crp_ix(
    program_id: solana_sdk::pubkey::Pubkey,
    accounts: Vec<AccountMeta>,
    data: CrpInstruction,
) -> Instruction {
    Instruction {
        program_id,
        accounts,
        data: data.try_to_vec().expect("borsh encode"),
    }
}

fn orp_ix(
    program_id: solana_sdk::pubkey::Pubkey,
    accounts: Vec<AccountMeta>,
    data: OrpInstruction,
) -> Instruction {
    Instruction {
        program_id,
        accounts,
        data: data.try_to_vec().expect("borsh encode"),
    }
}

fn ed25519_ix(signer: &Keypair, msg: &[u8]) -> Instruction {
    let sig: [u8; 64] = signer.sign_message(msg).into();
    let pk = signer.pubkey().to_bytes();
    new_ed25519_instruction_with_signature(msg, &sig, &pk)
}

fn create_mint_instructions(
    payer: &solana_sdk::pubkey::Pubkey,
    mint: &solana_sdk::pubkey::Pubkey,
    mint_authority: &solana_sdk::pubkey::Pubkey,
    decimals: u8,
    lamports: u64,
) -> Vec<Instruction> {
    let space = spl_token::state::Mint::LEN as u64;
    vec![
        system_instruction::create_account(payer, mint, lamports, space, &spl_token::ID),
        spl_token::instruction::initialize_mint2(
            &spl_token::ID,
            mint,
            mint_authority,
            None,
            decimals,
        )
        .expect("initialize_mint2"),
    ]
}

fn create_token_account_instructions(
    payer: &solana_sdk::pubkey::Pubkey,
    token_account: &solana_sdk::pubkey::Pubkey,
    mint: &solana_sdk::pubkey::Pubkey,
    owner: &solana_sdk::pubkey::Pubkey,
    lamports: u64,
) -> Vec<Instruction> {
    let space = spl_token::state::Account::LEN as u64;
    vec![
        system_instruction::create_account(payer, token_account, lamports, space, &spl_token::ID),
        spl_token::instruction::initialize_account3(&spl_token::ID, token_account, mint, owner)
            .expect("initialize_account3"),
    ]
}

fn mint_to_ix(
    mint: &solana_sdk::pubkey::Pubkey,
    dest: &solana_sdk::pubkey::Pubkey,
    mint_authority: &solana_sdk::pubkey::Pubkey,
    amount: u64,
) -> Instruction {
    spl_token::instruction::mint_to(&spl_token::ID, mint, dest, mint_authority, &[], amount)
        .expect("mint_to")
}

fn token_amount(account: &Account) -> u64 {
    spl_token::state::Account::unpack(&account.data)
        .expect("unpack token account")
        .amount
}

fn spent_receipt_id(deployment_id: &[u8; 32], cmx: &[u8; 32]) -> [u8; 32] {
    let mut prefix = Vec::new();
    prefix.extend_from_slice(b"JUNO_INTENTS");
    prefix.push(0);
    prefix.extend_from_slice(b"iep_spent_receipt_id");
    prefix.push(0);
    prefix.extend_from_slice(&1u16.to_le_bytes());
    solana_sdk::hash::hashv(&[&prefix, deployment_id.as_ref(), cmx.as_ref()]).to_bytes()
}

#[tokio::test]
#[ignore]
async fn settles_real_risc0_groth16_bundle_v1() {
    let bundle = decode_hex_env("JUNO_RECEIPT_ZKVM_BUNDLE_HEX");
    let (journal, selector) = parse_bundle_v1(&bundle);

    let iep_program_id = solana_sdk::pubkey::Pubkey::new_from_array(IEP_PROGRAM_ID_BYTES);
    let crp_program_id = solana_sdk::pubkey::Pubkey::new_from_array(CRP_PROGRAM_ID_BYTES);
    let receipt_verifier_program_id =
        solana_sdk::pubkey::Pubkey::new_from_array(RECEIPT_VERIFIER_PROGRAM_ID_BYTES);
    let orp_program_id =
        solana_sdk::pubkey::Pubkey::new_from_array(OPERATOR_REGISTRY_PROGRAM_ID_BYTES);
    let orp_verifier_router_program_id = Pubkey::new_unique();
    let orp_verifier_program_id = Pubkey::new_unique();

    // Ensure the bundle's fill_id matches the deterministic Fill PDA we use in tests.
    let (intent, _bump) = iep_intent_pda(&iep_program_id, &journal.deployment_id, &INTENT_NONCE);
    let (fill, _bump) = iep_fill_pda(&iep_program_id, &intent);
    assert_eq!(
        fill.to_bytes(),
        journal.fill_id,
        "bundle fill_id does not match expected Fill PDA; regenerate witness with --fill-id={}",
        hex::encode(fill.to_bytes())
    );

    // Configure the Verifier Router registry accounts for the selector used by this bundle.
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

    // Configure a mock verifier router stack for operator attestation registration.
    let (orp_router_pda, _bump) =
        Pubkey::find_program_address(&[b"router"], &orp_verifier_router_program_id);
    let (orp_verifier_entry_pda, _bump) = Pubkey::find_program_address(
        &[b"verifier", b"JINT".as_ref()],
        &orp_verifier_router_program_id,
    );

    let mut pt = ProgramTest::new(
        "juno_intents_intent_escrow",
        iep_program_id,
        processor!(juno_intents_intent_escrow::process_instruction),
    );
    pt.add_program(
        "juno_intents_checkpoint_registry",
        crp_program_id,
        processor!(juno_intents_checkpoint_registry::process_instruction),
    );
    pt.add_program(
        "spl_token",
        spl_token::ID,
        processor!(spl_token::processor::Processor::process),
    );
    pt.add_program(
        "juno_intents_receipt_verifier",
        receipt_verifier_program_id,
        processor!(juno_intents_receipt_verifier::process_instruction),
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
    pt.add_program(
        "juno_intents_operator_registry",
        orp_program_id,
        processor!(juno_intents_operator_registry::process_instruction),
    );
    pt.add_program(
        "mock_verifier_router",
        orp_verifier_router_program_id,
        processor!(mock_verifier_router),
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
    pt.add_account(
        orp_router_pda,
        Account {
            lamports: 1,
            data: vec![],
            owner: system_program::ID,
            executable: false,
            rent_epoch: 0,
        },
    );
    pt.add_account(
        orp_verifier_entry_pda,
        Account {
            lamports: 1,
            data: vec![],
            owner: system_program::ID,
            executable: false,
            rent_epoch: 0,
        },
    );
    pt.add_account(
        orp_verifier_program_id,
        Account {
            lamports: 1,
            data: vec![],
            owner: system_program::ID,
            executable: true,
            rent_epoch: 0,
        },
    );

    let (mut banks_client, payer, recent_blockhash) = pt.start().await;

    // Create mint + token accounts.
    let mint = Keypair::new();
    let solver = Keypair::new();
    let recipient_owner = Keypair::new();
    let fee_owner = Keypair::new();
    let solver_ta = Keypair::new();
    let recipient_ta = Keypair::new();
    let fee_ta = Keypair::new();

    let mut ixs = vec![];
    ixs.push(system_instruction::transfer(
        &payer.pubkey(),
        &solver.pubkey(),
        5_000_000_000,
    ));
    ixs.extend(create_mint_instructions(
        &payer.pubkey(),
        &mint.pubkey(),
        &payer.pubkey(),
        6,
        10_000_000_000,
    ));
    ixs.extend(create_token_account_instructions(
        &payer.pubkey(),
        &solver_ta.pubkey(),
        &mint.pubkey(),
        &solver.pubkey(),
        10_000_000_000,
    ));
    ixs.extend(create_token_account_instructions(
        &payer.pubkey(),
        &recipient_ta.pubkey(),
        &mint.pubkey(),
        &recipient_owner.pubkey(),
        10_000_000_000,
    ));
    ixs.extend(create_token_account_instructions(
        &payer.pubkey(),
        &fee_ta.pubkey(),
        &mint.pubkey(),
        &fee_owner.pubkey(),
        10_000_000_000,
    ));
    ixs.push(mint_to_ix(
        &mint.pubkey(),
        &solver_ta.pubkey(),
        &payer.pubkey(),
        1_000_000_000,
    ));

    let tx = Transaction::new_signed_with_payer(
        &ixs,
        Some(&payer.pubkey()),
        &[&payer, &mint, &solver_ta, &recipient_ta, &fee_ta],
        recent_blockhash,
    );
    banks_client.process_transaction(tx).await.unwrap();

    // Initialize Operator Registry (mock verifier router, measurement allowlist enforced).
    let (orp_config, _bump) = orp_config_pda(&orp_program_id, &journal.deployment_id);
    let chain_id = 2u8;
    let genesis_hash = [0x02u8; 32];
    let allowed_measurement = [0x11u8; 32];
    let init_orp = orp_ix(
        orp_program_id,
        vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(orp_config, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        OrpInstruction::Initialize {
            deployment_id: journal.deployment_id,
            admin: payer.pubkey(),
            junocash_chain_id: chain_id,
            junocash_genesis_hash: genesis_hash,
            verifier_router_program: orp_verifier_router_program_id,
            router: orp_router_pda,
            verifier_entry: orp_verifier_entry_pda,
            verifier_program: orp_verifier_program_id,
            allowed_measurements: vec![allowed_measurement],
        },
    );
    let recent_blockhash = banks_client.get_latest_blockhash().await.unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[init_orp],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    banks_client.process_transaction(tx).await.unwrap();

    // Initialize CRP.
    let (crp_config, _bump) = crp_config_pda(&crp_program_id, &journal.deployment_id);
    let op1 = Keypair::new();
    let op2 = Keypair::new();
    let (op1_rec, _bump) = orp_operator_pda(&orp_program_id, &journal.deployment_id, &op1.pubkey());
    let (op2_rec, _bump) = orp_operator_pda(&orp_program_id, &journal.deployment_id, &op2.pubkey());

    let reg_op1 = {
        let j = att_journal_bytes(
            journal.deployment_id,
            chain_id,
            genesis_hash,
            op1.pubkey(),
            allowed_measurement,
        );
        let bundle = att_bundle_bytes(&j);
        orp_ix(
            orp_program_id,
            vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(orp_config, false),
                AccountMeta::new(op1_rec, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(orp_verifier_router_program_id, false),
                AccountMeta::new_readonly(orp_router_pda, false),
                AccountMeta::new_readonly(orp_verifier_entry_pda, false),
                AccountMeta::new_readonly(orp_verifier_program_id, false),
            ],
            OrpInstruction::RegisterOperator { bundle },
        )
    };
    let reg_op2 = {
        let j = att_journal_bytes(
            journal.deployment_id,
            chain_id,
            genesis_hash,
            op2.pubkey(),
            allowed_measurement,
        );
        let bundle = att_bundle_bytes(&j);
        orp_ix(
            orp_program_id,
            vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(orp_config, false),
                AccountMeta::new(op2_rec, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(orp_verifier_router_program_id, false),
                AccountMeta::new_readonly(orp_router_pda, false),
                AccountMeta::new_readonly(orp_verifier_entry_pda, false),
                AccountMeta::new_readonly(orp_verifier_program_id, false),
            ],
            OrpInstruction::RegisterOperator { bundle },
        )
    };
    let recent_blockhash = banks_client.get_latest_blockhash().await.unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[reg_op1, reg_op2],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    banks_client.process_transaction(tx).await.unwrap();

    let init_crp = crp_ix(
        crp_program_id,
        vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(crp_config, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        CrpInstruction::InitializeV2 {
            deployment_id: journal.deployment_id,
            admin: payer.pubkey(),
            threshold: 1,
            conflict_threshold: 2,
            finalization_delay_slots: 0,
            operator_registry_program: orp_program_id,
            operators: vec![op1.pubkey(), op2.pubkey()],
        },
    );
    let recent_blockhash = banks_client.get_latest_blockhash().await.unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[init_crp],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    banks_client.process_transaction(tx).await.unwrap();

    // Finalize checkpoint for this Orchard root.
    let (crp_checkpoint, _bump) =
        crp_checkpoint_pda(&crp_program_id, &crp_config, &journal.orchard_root);
    let block_hash = [0x23u8; 32];
    let prev_hash = [0x24u8; 32];
    let obs_msg = observation_signing_bytes_v1(
        &journal.deployment_id,
        1,
        &block_hash,
        &journal.orchard_root,
        &prev_hash,
    );
    let ed_ix = ed25519_ix(&op1, obs_msg.as_ref());
    let submit_ix = crp_ix(
        crp_program_id,
        vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(crp_config, false),
            AccountMeta::new(crp_checkpoint, false),
            AccountMeta::new_readonly(system_program::ID, false),
            AccountMeta::new_readonly(solana_program::sysvar::instructions::ID, false),
            AccountMeta::new_readonly(op1_rec, false),
        ],
        CrpInstruction::SubmitObservation {
            height: 1,
            block_hash,
            orchard_root: journal.orchard_root,
            prev_hash,
        },
    );
    let recent_blockhash = banks_client.get_latest_blockhash().await.unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[ed_ix, submit_ix],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    banks_client.process_transaction(tx).await.unwrap();

    let (crp_height, _bump) = crp_height_pda(&crp_program_id, &crp_config, 1);
    let recent_blockhash = banks_client.get_latest_blockhash().await.unwrap();
    let ed_ix = ed25519_ix(&op1, obs_msg.as_ref());
    let finalize_ix = crp_ix(
        crp_program_id,
        vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(crp_config, false),
            AccountMeta::new(crp_checkpoint, false),
            AccountMeta::new(crp_height, false),
            AccountMeta::new_readonly(system_program::ID, false),
            AccountMeta::new_readonly(solana_program::sysvar::instructions::ID, false),
            AccountMeta::new_readonly(op1_rec, false),
        ],
        CrpInstruction::FinalizeCheckpoint { sig_count: 1 },
    );
    let tx = Transaction::new_signed_with_payer(
        &[ed_ix, finalize_ix],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    banks_client.process_transaction(tx).await.unwrap();

    // Initialize IEP config.
    let (iep_config, _bump) = iep_config_pda(&iep_program_id, &journal.deployment_id);
    let init_iep = iep_ix(
        iep_program_id,
        vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(iep_config, false),
            AccountMeta::new_readonly(mint.pubkey(), false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        IepInstruction::Initialize {
            deployment_id: journal.deployment_id,
            fee_bps: 25, // 0.25%
            fee_collector: fee_owner.pubkey(),
            checkpoint_registry_program: crp_program_id,
            receipt_verifier_program: receipt_verifier_program_id,
            verifier_router_program: risc0_verifier_router::ID,
            router: router_pda,
            verifier_entry: verifier_entry_pda,
            verifier_program: risc0_groth16_verifier::ID,
        },
    );
    let recent_blockhash = banks_client.get_latest_blockhash().await.unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[init_iep],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    banks_client.process_transaction(tx).await.unwrap();

    // Create intent.
    let (intent_vault, _bump) = iep_intent_vault_pda(&iep_program_id, &intent);
    let create_intent = iep_ix(
        iep_program_id,
        vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(iep_config, false),
            AccountMeta::new(intent, false),
            AccountMeta::new(intent_vault, false),
            AccountMeta::new(solver_ta.pubkey(), false), // unused for direction A
            AccountMeta::new_readonly(mint.pubkey(), false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        IepInstruction::CreateIntent {
            intent_nonce: INTENT_NONCE,
            direction: 1,
            mint: mint.pubkey(),
            solana_recipient: recipient_owner.pubkey(),
            net_amount: 100_000,
            expiry_slot: 10_000_000,
        },
    );
    let recent_blockhash = banks_client.get_latest_blockhash().await.unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[create_intent],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    banks_client.process_transaction(tx).await.unwrap();

    // Fill intent (lock escrow).
    let (vault, _bump) = iep_vault_pda(&iep_program_id, &fill);
    let fill_ix = iep_ix(
        iep_program_id,
        vec![
            AccountMeta::new(solver.pubkey(), true),
            AccountMeta::new_readonly(iep_config, false),
            AccountMeta::new(intent, false),
            AccountMeta::new(fill, false),
            AccountMeta::new(vault, false),
            AccountMeta::new(solver_ta.pubkey(), false),
            AccountMeta::new_readonly(solver_ta.pubkey(), false), // unused for direction A
            AccountMeta::new_readonly(mint.pubkey(), false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        IepInstruction::FillIntent {
            receiver_tag: journal.receiver_tag,
            junocash_amount_required: journal.amount,
        },
    );
    let recent_blockhash = banks_client.get_latest_blockhash().await.unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[fill_ix],
        Some(&payer.pubkey()),
        &[&payer, &solver],
        recent_blockhash,
    );
    banks_client.process_transaction(tx).await.unwrap();

    // Settle.
    let spent_id = spent_receipt_id(&journal.deployment_id, &journal.cmx);
    let (spent, _bump) = iep_spent_pda(&iep_program_id, &spent_id);

    let settle_ix = iep_ix(
        iep_program_id,
        vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(iep_config, false),
            AccountMeta::new(intent, false),
            AccountMeta::new(fill, false),
            AccountMeta::new(vault, false),
            AccountMeta::new(recipient_ta.pubkey(), false),
            AccountMeta::new(fee_ta.pubkey(), false),
            AccountMeta::new_readonly(mint.pubkey(), false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new(spent, false),
            AccountMeta::new_readonly(system_program::ID, false),
            AccountMeta::new_readonly(crp_program_id, false),
            AccountMeta::new_readonly(crp_config, false),
            AccountMeta::new_readonly(crp_checkpoint, false),
            AccountMeta::new_readonly(receipt_verifier_program_id, false),
            AccountMeta::new_readonly(risc0_verifier_router::ID, false),
            AccountMeta::new_readonly(router_pda, false),
            AccountMeta::new_readonly(verifier_entry_pda, false),
            AccountMeta::new_readonly(risc0_groth16_verifier::ID, false),
        ],
        IepInstruction::Settle { bundle },
    );
    let recent_blockhash = banks_client.get_latest_blockhash().await.unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[settle_ix],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    banks_client.process_transaction(tx).await.unwrap();

    // Check token balances.
    let solver_acc = banks_client
        .get_account(solver_ta.pubkey())
        .await
        .unwrap()
        .unwrap();
    let recipient_acc = banks_client
        .get_account(recipient_ta.pubkey())
        .await
        .unwrap()
        .unwrap();
    let fee_acc = banks_client
        .get_account(fee_ta.pubkey())
        .await
        .unwrap()
        .unwrap();
    let vault_acc = banks_client.get_account(vault).await.unwrap().unwrap();

    assert_eq!(token_amount(&recipient_acc), 100_000);
    assert_eq!(token_amount(&fee_acc), 250); // floor(100_000 * 25 / 10_000)
    assert_eq!(token_amount(&vault_acc), 0);
    assert_eq!(token_amount(&solver_acc), 1_000_000_000 - 100_250);

    // Check state updated.
    let intent_ai = banks_client.get_account(intent).await.unwrap().unwrap();
    let intent_state = IepIntentV2::try_from_slice(&intent_ai.data).unwrap();
    assert_eq!(intent_state.status, 3);

    let fill_ai = banks_client.get_account(fill).await.unwrap().unwrap();
    let fill_state = IepFillV2::try_from_slice(&fill_ai.data).unwrap();
    assert_eq!(fill_state.status, 2);

    // Spent receipt marker exists.
    assert!(banks_client.get_account(spent).await.unwrap().is_some());
}
