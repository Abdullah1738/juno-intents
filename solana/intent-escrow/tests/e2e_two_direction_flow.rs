use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::instruction::{AccountMeta, Instruction};
use solana_program_test::{processor, ProgramTest};
use solana_sdk::{
    account::Account,
    ed25519_instruction::new_ed25519_instruction_with_signature,
    instruction::InstructionError,
    signature::{Keypair, Signer},
    system_instruction, system_program,
    transaction::{Transaction, TransactionError},
};
use spl_token::solana_program::program_pack::Pack as _;

use juno_intents_checkpoint_registry::{
    checkpoint_pda as crp_checkpoint_pda, config_pda as crp_config_pda,
    height_pda as crp_height_pda, observation_signing_bytes_v1, CrpInstruction,
};
use juno_intents_intent_escrow::{
    config_pda as iep_config_pda, fill_pda as iep_fill_pda, intent_pda as iep_intent_pda,
    intent_vault_pda as iep_intent_vault_pda, spent_receipt_pda as iep_spent_pda,
    vault_pda as iep_vault_pda, IepFillV2, IepInstruction, IepIntentV3,
    DEV_FEE_BPS, DEV_FEE_COLLECTOR,
};
use juno_intents_operator_registry::{
    config_pda as orp_config_pda, operator_pda as orp_operator_pda, OrpInstruction,
};

const IEP_PROGRAM_ID_BYTES: [u8; 32] = [0xA1u8; 32];
const CRP_PROGRAM_ID_BYTES: [u8; 32] = [0xA2u8; 32];
const RECEIPT_VERIFIER_PROGRAM_ID_BYTES: [u8; 32] = [0xA3u8; 32];
const OPERATOR_REGISTRY_PROGRAM_ID_BYTES: [u8; 32] = [0xA4u8; 32];
const VERIFIER_ROUTER_PROGRAM_ID_BYTES: [u8; 32] = [0xA5u8; 32];
const VERIFIER_PROGRAM_ID_BYTES: [u8; 32] = [0xA6u8; 32];

const DEPLOYMENT_ID: [u8; 32] = [0x11u8; 32];
const INTENT_NONCE_A: [u8; 32] = [0x22u8; 32];
const INTENT_NONCE_B: [u8; 32] = [0x33u8; 32];

// Must match solana/operator-registry EXPECTED_IMAGE_ID.
const ATTESTATION_IMAGE_ID: [u8; 32] = [
    0x75, 0xd1, 0x4b, 0xd3, 0x6f, 0x7b, 0x8a, 0x31, 0x00, 0x47, 0xc7, 0xe8, 0xef, 0xff,
    0x7d, 0xac, 0xab, 0x7e, 0x9e, 0x9c, 0xf2, 0x26, 0x1e, 0xc1, 0x02, 0x96, 0xe7,
    0x25, 0x01, 0xe2, 0x27, 0x15,
];

// Must match solana/receipt-verifier EXPECTED_IMAGE_ID.
const RECEIPT_IMAGE_ID: [u8; 32] = [
    0x56, 0xbd, 0x5a, 0x78, 0xb2, 0x2d, 0xf0, 0x54, 0x1e, 0xa2, 0x83, 0x9e, 0x08, 0xfc,
    0x2f, 0x30, 0xaa, 0xda, 0x49, 0x2e, 0x17, 0x00, 0x4e, 0x33, 0x03, 0xaf, 0xf7,
    0x0a, 0xbd, 0xad, 0x3c, 0x3e,
];

const ATTESTATION_JOURNAL_LEN_V1: usize = 2 + 32 + 1 + 32 + 32 + 32;
const ATTESTATION_SEAL_LEN_V1: usize = 260;

fn mock_verifier_router(
    _program_id: &solana_program::pubkey::Pubkey,
    _accounts: &[solana_program::account_info::AccountInfo],
    _data: &[u8],
) -> solana_program::entrypoint::ProgramResult {
    Ok(())
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

fn att_journal_bytes(
    deployment_id: [u8; 32],
    chain_id: u8,
    genesis_hash: [u8; 32],
    operator_pubkey: solana_sdk::pubkey::Pubkey,
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
    let mut seal = vec![0u8; ATTESTATION_SEAL_LEN_V1];
    seal[0..4].copy_from_slice(b"JINT");
    out.extend_from_slice(&(seal.len() as u32).to_le_bytes());
    out.extend_from_slice(&seal);
    out
}

fn receipt_bundle_bytes_v1(
    deployment_id: [u8; 32],
    orchard_root: [u8; 32],
    cmx: [u8; 32],
    amount: u64,
    receiver_tag: [u8; 32],
    fill_id: [u8; 32],
) -> Vec<u8> {
    // Matches risc0/receipt/host encoding.
    let mut journal = Vec::with_capacity(170);
    journal.extend_from_slice(&1u16.to_le_bytes());
    journal.extend_from_slice(&deployment_id);
    journal.extend_from_slice(&orchard_root);
    journal.extend_from_slice(&cmx);
    journal.extend_from_slice(&amount.to_le_bytes());
    journal.extend_from_slice(&receiver_tag);
    journal.extend_from_slice(&fill_id);
    assert_eq!(journal.len(), 170);

    let mut out = Vec::with_capacity(2 + 1 + 32 + 2 + journal.len() + 4 + 260);
    out.extend_from_slice(&1u16.to_le_bytes());
    out.push(1u8);
    out.extend_from_slice(&RECEIPT_IMAGE_ID);
    out.extend_from_slice(&(journal.len() as u16).to_le_bytes());
    out.extend_from_slice(&journal);

    let mut seal = vec![0u8; 260];
    seal[0..4].copy_from_slice(b"JINT");
    out.extend_from_slice(&(seal.len() as u32).to_le_bytes());
    out.extend_from_slice(&seal);
    out
}

fn assert_unauthorized(err: solana_program_test::BanksClientError) {
    match err {
        solana_program_test::BanksClientError::TransactionError(
            TransactionError::InstructionError(_, InstructionError::Custom(code)),
        ) => {
            assert_eq!(code, 12, "expected IepError::Unauthorized (12), got {code}");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[tokio::test]
async fn two_direction_bridge_flow_with_solver_binding_and_checkpoints() {
    let iep_program_id = solana_sdk::pubkey::Pubkey::new_from_array(IEP_PROGRAM_ID_BYTES);
    let crp_program_id = solana_sdk::pubkey::Pubkey::new_from_array(CRP_PROGRAM_ID_BYTES);
    let receipt_verifier_program_id =
        solana_sdk::pubkey::Pubkey::new_from_array(RECEIPT_VERIFIER_PROGRAM_ID_BYTES);
    let orp_program_id =
        solana_sdk::pubkey::Pubkey::new_from_array(OPERATOR_REGISTRY_PROGRAM_ID_BYTES);
    let verifier_router_program_id =
        solana_sdk::pubkey::Pubkey::new_from_array(VERIFIER_ROUTER_PROGRAM_ID_BYTES);
    let verifier_program_id = solana_sdk::pubkey::Pubkey::new_from_array(VERIFIER_PROGRAM_ID_BYTES);

    let (router_pda, _bump) =
        solana_sdk::pubkey::Pubkey::find_program_address(&[b"router"], &verifier_router_program_id);
    let (verifier_entry_pda, _bump) = solana_sdk::pubkey::Pubkey::find_program_address(
        &[b"verifier", b"JINT"],
        &verifier_router_program_id,
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
        "juno_intents_operator_registry",
        orp_program_id,
        processor!(juno_intents_operator_registry::process_instruction),
    );
    pt.add_program(
        "juno_intents_receipt_verifier",
        receipt_verifier_program_id,
        processor!(juno_intents_receipt_verifier::process_instruction),
    );
    pt.add_program(
        "spl_token",
        spl_token::ID,
        processor!(spl_token::processor::Processor::process),
    );
    pt.add_program(
        "mock_verifier_router",
        verifier_router_program_id,
        processor!(mock_verifier_router),
    );

    // The ORP requires these accounts to exist and be executable, but the mock verifier router
    // ignores their contents.
    pt.add_account(
        router_pda,
        Account {
            lamports: 1,
            data: vec![],
            owner: system_program::ID,
            executable: false,
            rent_epoch: 0,
        },
    );
    pt.add_account(
        verifier_entry_pda,
        Account {
            lamports: 1,
            data: vec![],
            owner: system_program::ID,
            executable: false,
            rent_epoch: 0,
        },
    );
    pt.add_account(
        verifier_program_id,
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
    let solver1 = Keypair::new();
    let solver2 = Keypair::new();
    let user = Keypair::new();
    let fee_collector = DEV_FEE_COLLECTOR;
    let solver1_ta = Keypair::new();
    let solver2_ta = Keypair::new();
    let user_ta = Keypair::new();
    let fee_ta = Keypair::new();

    let mut ixs = vec![
        system_instruction::transfer(&payer.pubkey(), &solver1.pubkey(), 5_000_000_000),
        system_instruction::transfer(&payer.pubkey(), &solver2.pubkey(), 5_000_000_000),
        system_instruction::transfer(&payer.pubkey(), &user.pubkey(), 5_000_000_000),
    ];
    ixs.extend(create_mint_instructions(
        &payer.pubkey(),
        &mint.pubkey(),
        &payer.pubkey(),
        6,
        10_000_000_000,
    ));
    ixs.extend(create_token_account_instructions(
        &payer.pubkey(),
        &solver1_ta.pubkey(),
        &mint.pubkey(),
        &solver1.pubkey(),
        10_000_000_000,
    ));
    ixs.extend(create_token_account_instructions(
        &payer.pubkey(),
        &solver2_ta.pubkey(),
        &mint.pubkey(),
        &solver2.pubkey(),
        10_000_000_000,
    ));
    ixs.extend(create_token_account_instructions(
        &payer.pubkey(),
        &user_ta.pubkey(),
        &mint.pubkey(),
        &user.pubkey(),
        10_000_000_000,
    ));
    ixs.extend(create_token_account_instructions(
        &payer.pubkey(),
        &fee_ta.pubkey(),
        &mint.pubkey(),
        &fee_collector,
        10_000_000_000,
    ));
    ixs.push(mint_to_ix(
        &mint.pubkey(),
        &solver1_ta.pubkey(),
        &payer.pubkey(),
        1_000_000_000,
    ));
    ixs.push(mint_to_ix(
        &mint.pubkey(),
        &solver2_ta.pubkey(),
        &payer.pubkey(),
        1_000_000_000,
    ));

    let tx = Transaction::new_signed_with_payer(
        &ixs,
        Some(&payer.pubkey()),
        &[&payer, &mint, &solver1_ta, &solver2_ta, &user_ta, &fee_ta],
        recent_blockhash,
    );
    banks_client.process_transaction(tx).await.unwrap();

    // Initialize Operator Registry.
    let (orp_config, _bump) = orp_config_pda(&orp_program_id, &DEPLOYMENT_ID);
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
            deployment_id: DEPLOYMENT_ID,
            admin: payer.pubkey(),
            junocash_chain_id: chain_id,
            junocash_genesis_hash: genesis_hash,
            verifier_router_program: verifier_router_program_id,
            router: router_pda,
            verifier_entry: verifier_entry_pda,
            verifier_program: verifier_program_id,
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

    // Register 2 TEE operators.
    let op1 = Keypair::new();
    let op2 = Keypair::new();
    let (op1_rec, _bump) = orp_operator_pda(&orp_program_id, &DEPLOYMENT_ID, &op1.pubkey());
    let (op2_rec, _bump) = orp_operator_pda(&orp_program_id, &DEPLOYMENT_ID, &op2.pubkey());

    for (op, rec) in [(&op1, op1_rec), (&op2, op2_rec)] {
        let journal =
            att_journal_bytes(DEPLOYMENT_ID, chain_id, genesis_hash, op.pubkey(), allowed_measurement);
        let bundle = att_bundle_bytes(&journal);
        let ix = orp_ix(
            orp_program_id,
            vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(orp_config, false),
                AccountMeta::new(rec, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(verifier_router_program_id, false),
                AccountMeta::new_readonly(router_pda, false),
                AccountMeta::new_readonly(verifier_entry_pda, false),
                AccountMeta::new_readonly(verifier_program_id, false),
            ],
            OrpInstruction::RegisterOperator { bundle },
        );
        let recent_blockhash = banks_client.get_latest_blockhash().await.unwrap();
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[&payer],
            recent_blockhash,
        );
        banks_client.process_transaction(tx).await.unwrap();
    }

    // Initialize CRP v2 (threshold=2).
    let (crp_config, _bump) = crp_config_pda(&crp_program_id, &DEPLOYMENT_ID);
    let init_crp = crp_ix(
        crp_program_id,
        vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(crp_config, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        CrpInstruction::InitializeV2 {
            deployment_id: DEPLOYMENT_ID,
            admin: payer.pubkey(),
            threshold: 2,
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

    // Create and finalize a checkpoint with 2 operator signatures.
    let orchard_root = [0xAAu8; 32];
    let block_hash = [0xBBu8; 32];
    let prev_hash = [0xCCu8; 32];
    let (crp_checkpoint, _bump) = crp_checkpoint_pda(&crp_program_id, &crp_config, &orchard_root);
    let (crp_height, _bump) = crp_height_pda(&crp_program_id, &crp_config, 1);

    let obs_msg =
        observation_signing_bytes_v1(&DEPLOYMENT_ID, 1, &block_hash, &orchard_root, &prev_hash);

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
            orchard_root,
            prev_hash,
        },
    );

    let recent_blockhash = banks_client.get_latest_blockhash().await.unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[ed25519_ix(&op1, obs_msg.as_ref()), submit_ix],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    banks_client.process_transaction(tx).await.unwrap();

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
            AccountMeta::new_readonly(op2_rec, false),
        ],
        CrpInstruction::FinalizeCheckpoint { sig_count: 2 },
    );
    let recent_blockhash = banks_client.get_latest_blockhash().await.unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[
            ed25519_ix(&op1, obs_msg.as_ref()),
            ed25519_ix(&op2, obs_msg.as_ref()),
            finalize_ix,
        ],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    banks_client.process_transaction(tx).await.unwrap();

    // Initialize IEP config.
    let (iep_config, _bump) = iep_config_pda(&iep_program_id, &DEPLOYMENT_ID);
    let init_iep = iep_ix(
        iep_program_id,
        vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(iep_config, false),
            AccountMeta::new_readonly(mint.pubkey(), false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        IepInstruction::Initialize {
            deployment_id: DEPLOYMENT_ID,
            fee_bps: DEV_FEE_BPS, // 0.25%
            fee_collector,
            checkpoint_registry_program: crp_program_id,
            receipt_verifier_program: receipt_verifier_program_id,
            verifier_router_program: verifier_router_program_id,
            router: router_pda,
            verifier_entry: verifier_entry_pda,
            verifier_program: verifier_program_id,
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

    // Direction A: JunoCash -> Solana (solver pays wJUNO).
    // Two solvers "compete": choose solver1.
    let receiver_tag_a = [0xA1u8; 32];
    let junocash_amount_a = 123_456u64;
    let net_amount_a = 100_000u64;

    let (intent_a, _bump) = iep_intent_pda(&iep_program_id, &DEPLOYMENT_ID, &INTENT_NONCE_A);
    let (fill_a, _bump) = iep_fill_pda(&iep_program_id, &intent_a);
    let (vault_a, _bump) = iep_vault_pda(&iep_program_id, &fill_a);

    let create_intent_a = iep_ix(
        iep_program_id,
        vec![
            AccountMeta::new(user.pubkey(), true),
            AccountMeta::new_readonly(iep_config, false),
            AccountMeta::new(intent_a, false),
            AccountMeta::new(solver1_ta.pubkey(), false), // unused for direction A
            AccountMeta::new(user_ta.pubkey(), false),     // unused for direction A
            AccountMeta::new_readonly(mint.pubkey(), false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        IepInstruction::CreateIntentV3 {
            intent_nonce: INTENT_NONCE_A,
            direction: 1,
            mint: mint.pubkey(),
            solana_recipient: user.pubkey(),
            net_amount: net_amount_a,
            expiry_slot: 10_000_000,
            solver: solver1.pubkey(),
            receiver_tag: receiver_tag_a,
            junocash_amount_required: junocash_amount_a,
        },
    );
    let recent_blockhash = banks_client.get_latest_blockhash().await.unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[create_intent_a],
        Some(&payer.pubkey()),
        &[&payer, &user],
        recent_blockhash,
    );
    banks_client.process_transaction(tx).await.unwrap();

    // Losing solver cannot fill.
    let fill_attempt = iep_ix(
        iep_program_id,
        vec![
            AccountMeta::new(solver2.pubkey(), true),
            AccountMeta::new_readonly(iep_config, false),
            AccountMeta::new(intent_a, false),
            AccountMeta::new(fill_a, false),
            AccountMeta::new(vault_a, false),
            AccountMeta::new(solver2_ta.pubkey(), false),
            AccountMeta::new_readonly(solver2_ta.pubkey(), false),
            AccountMeta::new_readonly(mint.pubkey(), false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        IepInstruction::FillIntent {
            receiver_tag: receiver_tag_a,
            junocash_amount_required: junocash_amount_a,
        },
    );
    let recent_blockhash = banks_client.get_latest_blockhash().await.unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[fill_attempt],
        Some(&payer.pubkey()),
        &[&payer, &solver2],
        recent_blockhash,
    );
    assert_unauthorized(banks_client.process_transaction(tx).await.unwrap_err());

    // Winning solver fills.
    let fill_ix = iep_ix(
        iep_program_id,
        vec![
            AccountMeta::new(solver1.pubkey(), true),
            AccountMeta::new_readonly(iep_config, false),
            AccountMeta::new(intent_a, false),
            AccountMeta::new(fill_a, false),
            AccountMeta::new(vault_a, false),
            AccountMeta::new(solver1_ta.pubkey(), false),
            AccountMeta::new_readonly(solver1_ta.pubkey(), false), // unused for direction A
            AccountMeta::new_readonly(mint.pubkey(), false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        IepInstruction::FillIntent {
            receiver_tag: receiver_tag_a,
            junocash_amount_required: junocash_amount_a,
        },
    );
    let recent_blockhash = banks_client.get_latest_blockhash().await.unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[fill_ix],
        Some(&payer.pubkey()),
        &[&payer, &solver1],
        recent_blockhash,
    );
    banks_client.process_transaction(tx).await.unwrap();

    // Settle direction A with a receipt bound to the Fill PDA.
    let cmx_a = [0x01u8; 32];
    let spent_id_a = spent_receipt_id(&DEPLOYMENT_ID, &cmx_a);
    let (spent_a, _bump) = iep_spent_pda(&iep_program_id, &spent_id_a);

    let bundle_a = receipt_bundle_bytes_v1(
        DEPLOYMENT_ID,
        orchard_root,
        cmx_a,
        junocash_amount_a,
        receiver_tag_a,
        fill_a.to_bytes(),
    );
    let settle_a = iep_ix(
        iep_program_id,
        vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(iep_config, false),
            AccountMeta::new(intent_a, false),
            AccountMeta::new(fill_a, false),
            AccountMeta::new(vault_a, false),
            AccountMeta::new(user_ta.pubkey(), false),
            AccountMeta::new(fee_ta.pubkey(), false),
            AccountMeta::new_readonly(mint.pubkey(), false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new(spent_a, false),
            AccountMeta::new_readonly(system_program::ID, false),
            AccountMeta::new_readonly(crp_program_id, false),
            AccountMeta::new_readonly(crp_config, false),
            AccountMeta::new_readonly(crp_checkpoint, false),
            AccountMeta::new_readonly(receipt_verifier_program_id, false),
            AccountMeta::new_readonly(verifier_router_program_id, false),
            AccountMeta::new_readonly(router_pda, false),
            AccountMeta::new_readonly(verifier_entry_pda, false),
            AccountMeta::new_readonly(verifier_program_id, false),
        ],
        IepInstruction::Settle { bundle: bundle_a },
    );
    let recent_blockhash = banks_client.get_latest_blockhash().await.unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[settle_a],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    banks_client.process_transaction(tx).await.unwrap();

    // Direction B: Solana -> JunoCash (user locks wJUNO, solver pays JunoCash).
    // Two solvers "compete": choose solver2.
    let receiver_tag_b = [0xB1u8; 32];
    let junocash_amount_b = 654_321u64;
    let net_amount_b = 50_000u64;

    let (intent_b, _bump) = iep_intent_pda(&iep_program_id, &DEPLOYMENT_ID, &INTENT_NONCE_B);
    let (fill_b, _bump) = iep_fill_pda(&iep_program_id, &intent_b);
    let (vault_b, _bump) = iep_intent_vault_pda(&iep_program_id, &intent_b);

    let create_intent_b = iep_ix(
        iep_program_id,
        vec![
            AccountMeta::new(user.pubkey(), true),
            AccountMeta::new_readonly(iep_config, false),
            AccountMeta::new(intent_b, false),
            AccountMeta::new(vault_b, false),
            AccountMeta::new(user_ta.pubkey(), false),
            AccountMeta::new_readonly(mint.pubkey(), false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        IepInstruction::CreateIntentV3 {
            intent_nonce: INTENT_NONCE_B,
            direction: 2,
            mint: mint.pubkey(),
            solana_recipient: user.pubkey(),
            net_amount: net_amount_b,
            expiry_slot: 10_000_000,
            solver: solver2.pubkey(),
            receiver_tag: receiver_tag_b,
            junocash_amount_required: junocash_amount_b,
        },
    );
    let recent_blockhash = banks_client.get_latest_blockhash().await.unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[create_intent_b],
        Some(&payer.pubkey()),
        &[&payer, &user],
        recent_blockhash,
    );
    banks_client.process_transaction(tx).await.unwrap();

    // Losing solver cannot fill.
    let fill_attempt = iep_ix(
        iep_program_id,
        vec![
            AccountMeta::new(solver1.pubkey(), true),
            AccountMeta::new_readonly(iep_config, false),
            AccountMeta::new(intent_b, false),
            AccountMeta::new(fill_b, false),
            AccountMeta::new(vault_b, false),
            AccountMeta::new(solver1_ta.pubkey(), false),
            AccountMeta::new_readonly(solver1_ta.pubkey(), false),
            AccountMeta::new_readonly(mint.pubkey(), false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        IepInstruction::FillIntent {
            receiver_tag: receiver_tag_b,
            junocash_amount_required: junocash_amount_b,
        },
    );
    let recent_blockhash = banks_client.get_latest_blockhash().await.unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[fill_attempt],
        Some(&payer.pubkey()),
        &[&payer, &solver1],
        recent_blockhash,
    );
    assert_unauthorized(banks_client.process_transaction(tx).await.unwrap_err());

    // Winning solver fills.
    let fill_ix = iep_ix(
        iep_program_id,
        vec![
            AccountMeta::new(solver2.pubkey(), true),
            AccountMeta::new_readonly(iep_config, false),
            AccountMeta::new(intent_b, false),
            AccountMeta::new(fill_b, false),
            AccountMeta::new(vault_b, false),
            AccountMeta::new(solver2_ta.pubkey(), false), // unused for direction B
            AccountMeta::new_readonly(solver2_ta.pubkey(), false),
            AccountMeta::new_readonly(mint.pubkey(), false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        IepInstruction::FillIntent {
            receiver_tag: receiver_tag_b,
            junocash_amount_required: junocash_amount_b,
        },
    );
    let recent_blockhash = banks_client.get_latest_blockhash().await.unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[fill_ix],
        Some(&payer.pubkey()),
        &[&payer, &solver2],
        recent_blockhash,
    );
    banks_client.process_transaction(tx).await.unwrap();

    // Settle direction B with a distinct receipt.
    let cmx_b = [0x02u8; 32];
    let spent_id_b = spent_receipt_id(&DEPLOYMENT_ID, &cmx_b);
    let (spent_b, _bump) = iep_spent_pda(&iep_program_id, &spent_id_b);

    let bundle_b = receipt_bundle_bytes_v1(
        DEPLOYMENT_ID,
        orchard_root,
        cmx_b,
        junocash_amount_b,
        receiver_tag_b,
        fill_b.to_bytes(),
    );
    let settle_b = iep_ix(
        iep_program_id,
        vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(iep_config, false),
            AccountMeta::new(intent_b, false),
            AccountMeta::new(fill_b, false),
            AccountMeta::new(vault_b, false),
            AccountMeta::new(solver2_ta.pubkey(), false),
            AccountMeta::new(fee_ta.pubkey(), false),
            AccountMeta::new_readonly(mint.pubkey(), false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new(spent_b, false),
            AccountMeta::new_readonly(system_program::ID, false),
            AccountMeta::new_readonly(crp_program_id, false),
            AccountMeta::new_readonly(crp_config, false),
            AccountMeta::new_readonly(crp_checkpoint, false),
            AccountMeta::new_readonly(receipt_verifier_program_id, false),
            AccountMeta::new_readonly(verifier_router_program_id, false),
            AccountMeta::new_readonly(router_pda, false),
            AccountMeta::new_readonly(verifier_entry_pda, false),
            AccountMeta::new_readonly(verifier_program_id, false),
        ],
        IepInstruction::Settle { bundle: bundle_b },
    );
    let recent_blockhash = banks_client.get_latest_blockhash().await.unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[settle_b],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    banks_client.process_transaction(tx).await.unwrap();

    // Check token balances for both directions.
    let solver1_acc = banks_client
        .get_account(solver1_ta.pubkey())
        .await
        .unwrap()
        .unwrap();
    let solver2_acc = banks_client
        .get_account(solver2_ta.pubkey())
        .await
        .unwrap()
        .unwrap();
    let user_acc = banks_client.get_account(user_ta.pubkey()).await.unwrap().unwrap();
    let fee_acc = banks_client.get_account(fee_ta.pubkey()).await.unwrap().unwrap();

    // Direction A:
    //   solver1 pays gross = 100_000 + floor(100_000*25/10_000)=100_250
    // Direction B:
    //   user pays gross = 50_000 + floor(50_000*25/10_000)=50_125, solver2 receives net 50_000
    assert_eq!(token_amount(&fee_acc), 250 + 125);
    assert_eq!(token_amount(&user_acc), net_amount_a - (net_amount_b + 125));
    assert_eq!(token_amount(&solver1_acc), 1_000_000_000 - (net_amount_a + 250));
    assert_eq!(token_amount(&solver2_acc), 1_000_000_000 + net_amount_b);

    // Check state updated.
    let intent_a_ai = banks_client.get_account(intent_a).await.unwrap().unwrap();
    let intent_a_state = IepIntentV3::try_from_slice(&intent_a_ai.data).unwrap();
    assert_eq!(intent_a_state.status, 3);
    let fill_a_ai = banks_client.get_account(fill_a).await.unwrap().unwrap();
    let fill_a_state = IepFillV2::try_from_slice(&fill_a_ai.data).unwrap();
    assert_eq!(fill_a_state.status, 2);

    let intent_b_ai = banks_client.get_account(intent_b).await.unwrap().unwrap();
    let intent_b_state = IepIntentV3::try_from_slice(&intent_b_ai.data).unwrap();
    assert_eq!(intent_b_state.status, 3);
    let fill_b_ai = banks_client.get_account(fill_b).await.unwrap().unwrap();
    let fill_b_state = IepFillV2::try_from_slice(&fill_b_ai.data).unwrap();
    assert_eq!(fill_b_state.status, 2);

    // Spent receipt markers exist.
    assert!(banks_client.get_account(spent_a).await.unwrap().is_some());
    assert!(banks_client.get_account(spent_b).await.unwrap().is_some());
}
