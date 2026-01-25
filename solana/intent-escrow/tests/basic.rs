use borsh::{BorshDeserialize, BorshSerialize};
use solana_program_test::{processor, ProgramTest};
use solana_sdk::{
    account::Account,
    ed25519_instruction::new_ed25519_instruction_with_signature,
    instruction::{AccountMeta, Instruction},
    signature::{Keypair, Signer},
    system_instruction, system_program,
    transaction::Transaction,
};
use spl_token::solana_program::program_pack::Pack;

use juno_intents_checkpoint_registry::{
    checkpoint_pda as crp_checkpoint_pda, config_pda as crp_config_pda,
    height_pda as crp_height_pda, observation_signing_bytes_v1, CrpInstruction,
};
use juno_intents_intent_escrow::{
    config_pda as iep_config_pda, fill_pda as iep_fill_pda, intent_pda as iep_intent_pda,
    intent_vault_pda as iep_intent_vault_pda, spent_receipt_pda as iep_spent_pda,
    vault_pda as iep_vault_pda, IepFillV2, IepInstruction, IepIntentV2,
};

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

fn ed25519_ix(signer: &Keypair, msg: &[u8]) -> Instruction {
    let sig: [u8; 64] = signer.sign_message(msg).into();
    let pk = signer.pubkey().to_bytes();
    new_ed25519_instruction_with_signature(msg, &sig, &pk)
}

fn mock_receipt_verifier(
    _program_id: &solana_sdk::pubkey::Pubkey,
    _accounts: &[solana_program::account_info::AccountInfo],
    _data: &[u8],
) -> solana_program::entrypoint::ProgramResult {
    Ok(())
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

fn fake_bundle_v1(
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
    out.extend_from_slice(&[0xAAu8; 32]); // image_id (unchecked by mock)
    out.extend_from_slice(&(journal.len() as u16).to_le_bytes());
    out.extend_from_slice(&journal);

    let seal = vec![0u8; 260];
    out.extend_from_slice(&(seal.len() as u32).to_le_bytes());
    out.extend_from_slice(&seal);
    out
}

#[tokio::test]
async fn settle_transfers_net_and_fee_and_marks_spent() {
    let iep_program_id = solana_sdk::pubkey::Pubkey::new_unique();
    let crp_program_id = solana_sdk::pubkey::Pubkey::new_unique();
    let receipt_verifier_program_id = solana_sdk::pubkey::Pubkey::new_unique();

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
        "mock_receipt_verifier",
        receipt_verifier_program_id,
        processor!(mock_receipt_verifier),
    );

    // Dummy accounts passed through to the mock receipt verifier.
    //
    // These must be self-consistent with the on-chain config checks:
    //   router PDA = PDA("router")
    //   verifier_entry PDA = PDA("verifier", "JINT")
    let verifier_router_program = solana_sdk::pubkey::Pubkey::new_unique();
    let (router, _bump) =
        solana_sdk::pubkey::Pubkey::find_program_address(&[b"router"], &verifier_router_program);
    let (verifier_entry, _bump) = solana_sdk::pubkey::Pubkey::find_program_address(
        &[b"verifier", b"JINT"],
        &verifier_router_program,
    );
    let verifier_program = solana_sdk::pubkey::Pubkey::new_unique();
    for k in [
        verifier_router_program,
        router,
        verifier_entry,
        verifier_program,
    ] {
        pt.add_account(
            k,
            Account {
                lamports: 1,
                data: vec![],
                owner: system_program::ID,
                executable: false,
                rent_epoch: 0,
            },
        );
    }

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
        1_000_000,
    ));

    let tx = Transaction::new_signed_with_payer(
        &ixs,
        Some(&payer.pubkey()),
        &[&payer, &mint, &solver_ta, &recipient_ta, &fee_ta],
        recent_blockhash,
    );
    banks_client.process_transaction(tx).await.unwrap();

    // Initialize CRP.
    let deployment_id = [0x11u8; 32];
    let (crp_config, _bump) = crp_config_pda(&crp_program_id, &deployment_id);
    let op1 = Keypair::new();
    let op2 = Keypair::new();
    let init_crp = crp_ix(
        crp_program_id,
        vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(crp_config, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        CrpInstruction::Initialize {
            deployment_id,
            admin: payer.pubkey(),
            threshold: 1,
            conflict_threshold: 2,
            finalization_delay_slots: 0,
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

    let orchard_root = [0x22u8; 32];
    let (crp_checkpoint, _bump) = crp_checkpoint_pda(&crp_program_id, &crp_config, &orchard_root);
    let block_hash = [0x23u8; 32];
    let prev_hash = [0x24u8; 32];
    let obs_msg =
        observation_signing_bytes_v1(&deployment_id, 1, &block_hash, &orchard_root, &prev_hash);
    let ed_ix = ed25519_ix(&op1, obs_msg.as_ref());
    let submit_ix = crp_ix(
        crp_program_id,
        vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(crp_config, false),
            AccountMeta::new(crp_checkpoint, false),
            AccountMeta::new_readonly(system_program::ID, false),
            AccountMeta::new_readonly(solana_program::sysvar::instructions::ID, false),
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
    let (iep_config, _bump) = iep_config_pda(&iep_program_id, &deployment_id);
    let init_iep = iep_ix(
        iep_program_id,
        vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(iep_config, false),
            AccountMeta::new_readonly(mint.pubkey(), false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        IepInstruction::Initialize {
            deployment_id,
            fee_bps: 25, // 0.25%
            fee_collector: fee_owner.pubkey(),
            checkpoint_registry_program: crp_program_id,
            receipt_verifier_program: receipt_verifier_program_id,
            verifier_router_program,
            router,
            verifier_entry,
            verifier_program,
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
    let intent_nonce = [0x33u8; 32];
    let (intent, _bump) = iep_intent_pda(&iep_program_id, &deployment_id, &intent_nonce);
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
            intent_nonce,
            direction: 1,
            mint: mint.pubkey(),
            solana_recipient: recipient_owner.pubkey(),
            net_amount: 100_000,
            expiry_slot: 10_000,
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

    // Fill intent.
    let (fill, _bump) = iep_fill_pda(&iep_program_id, &intent);
    let (vault, _bump) = iep_vault_pda(&iep_program_id, &fill);
    let receiver_tag = [0x44u8; 32];
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
            receiver_tag,
            junocash_amount_required: 555,
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

    // Build a fake receipt bundle matching the fill.
    let cmx = [0x55u8; 32];
    let bundle = fake_bundle_v1(
        deployment_id,
        orchard_root,
        cmx,
        555,
        receiver_tag,
        fill.to_bytes(),
    );
    let spent_id = spent_receipt_id(&deployment_id, &cmx);
    let (spent, _bump) = iep_spent_pda(&iep_program_id, &spent_id);

    // Settle.
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
            AccountMeta::new_readonly(verifier_router_program, false),
            AccountMeta::new_readonly(router, false),
            AccountMeta::new_readonly(verifier_entry, false),
            AccountMeta::new_readonly(verifier_program, false),
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
    assert_eq!(token_amount(&solver_acc), 1_000_000 - 100_250);

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

#[tokio::test]
async fn settle_direction_b_transfers_to_solver_and_fee() {
    let iep_program_id = solana_sdk::pubkey::Pubkey::new_unique();
    let crp_program_id = solana_sdk::pubkey::Pubkey::new_unique();
    let receipt_verifier_program_id = solana_sdk::pubkey::Pubkey::new_unique();

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
        "mock_receipt_verifier",
        receipt_verifier_program_id,
        processor!(mock_receipt_verifier),
    );

    // Dummy accounts passed through to the mock receipt verifier.
    //
    // These must be self-consistent with the on-chain config checks:
    //   router PDA = PDA("router")
    //   verifier_entry PDA = PDA("verifier", "JINT")
    let verifier_router_program = solana_sdk::pubkey::Pubkey::new_unique();
    let (router, _bump) =
        solana_sdk::pubkey::Pubkey::find_program_address(&[b"router"], &verifier_router_program);
    let (verifier_entry, _bump) = solana_sdk::pubkey::Pubkey::find_program_address(
        &[b"verifier", b"JINT"],
        &verifier_router_program,
    );
    let verifier_program = solana_sdk::pubkey::Pubkey::new_unique();
    for k in [
        verifier_router_program,
        router,
        verifier_entry,
        verifier_program,
    ] {
        pt.add_account(
            k,
            Account {
                lamports: 1,
                data: vec![],
                owner: system_program::ID,
                executable: false,
                rent_epoch: 0,
            },
        );
    }

    let (mut banks_client, payer, recent_blockhash) = pt.start().await;

    // Create mint + token accounts.
    let mint = Keypair::new();
    let solver = Keypair::new();
    let fee_owner = Keypair::new();
    let creator_ta = Keypair::new();
    let solver_ta = Keypair::new();
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
        &creator_ta.pubkey(),
        &mint.pubkey(),
        &payer.pubkey(),
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
        &fee_ta.pubkey(),
        &mint.pubkey(),
        &fee_owner.pubkey(),
        10_000_000_000,
    ));
    ixs.push(mint_to_ix(
        &mint.pubkey(),
        &creator_ta.pubkey(),
        &payer.pubkey(),
        1_000_000,
    ));

    let tx = Transaction::new_signed_with_payer(
        &ixs,
        Some(&payer.pubkey()),
        &[&payer, &mint, &creator_ta, &solver_ta, &fee_ta],
        recent_blockhash,
    );
    banks_client.process_transaction(tx).await.unwrap();

    // Initialize CRP.
    let deployment_id = [0x11u8; 32];
    let (crp_config, _bump) = crp_config_pda(&crp_program_id, &deployment_id);
    let op1 = Keypair::new();
    let op2 = Keypair::new();
    let init_crp = crp_ix(
        crp_program_id,
        vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(crp_config, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        CrpInstruction::Initialize {
            deployment_id,
            admin: payer.pubkey(),
            threshold: 1,
            conflict_threshold: 2,
            finalization_delay_slots: 0,
            operators: vec![op1.pubkey(), op2.pubkey()],
        },
    );
    let recent_blockhash = banks_client.get_latest_blockhash().await.unwrap();
    banks_client
        .process_transaction(Transaction::new_signed_with_payer(
            &[init_crp],
            Some(&payer.pubkey()),
            &[&payer],
            recent_blockhash,
        ))
        .await
        .unwrap();

    // Submit and finalize a checkpoint.
    let orchard_root = [0x22u8; 32];
    let (checkpoint, _bump) = crp_checkpoint_pda(&crp_program_id, &crp_config, &orchard_root);
    let submit_msg =
        observation_signing_bytes_v1(&deployment_id, 1, &[0x10u8; 32], &orchard_root, &[0u8; 32]);
    let ed_ix = ed25519_ix(&op1, &submit_msg);
    let submit_ix = crp_ix(
        crp_program_id,
        vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(crp_config, false),
            AccountMeta::new(checkpoint, false),
            AccountMeta::new_readonly(system_program::ID, false),
            AccountMeta::new_readonly(solana_program::sysvar::instructions::ID, false),
        ],
        CrpInstruction::SubmitObservation {
            height: 1,
            block_hash: [0x10u8; 32],
            orchard_root,
            prev_hash: [0u8; 32],
        },
    );
    let (height_record, _bump) = crp_height_pda(&crp_program_id, &crp_config, 1);
    let finalize_ix = crp_ix(
        crp_program_id,
        vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(crp_config, false),
            AccountMeta::new(checkpoint, false),
            AccountMeta::new(height_record, false),
            AccountMeta::new_readonly(system_program::ID, false),
            AccountMeta::new_readonly(solana_program::sysvar::instructions::ID, false),
        ],
        CrpInstruction::FinalizeCheckpoint { sig_count: 1 },
    );
    let recent_blockhash = banks_client.get_latest_blockhash().await.unwrap();
    banks_client
        .process_transaction(Transaction::new_signed_with_payer(
            &[ed_ix, submit_ix],
            Some(&payer.pubkey()),
            &[&payer],
            recent_blockhash,
        ))
        .await
        .unwrap();
    let recent_blockhash = banks_client.get_latest_blockhash().await.unwrap();
    let ed_ix = ed25519_ix(&op1, &submit_msg);
    banks_client
        .process_transaction(Transaction::new_signed_with_payer(
            &[ed_ix, finalize_ix],
            Some(&payer.pubkey()),
            &[&payer],
            recent_blockhash,
        ))
        .await
        .unwrap();

    // Initialize IEP config.
    let (iep_config, _bump) = iep_config_pda(&iep_program_id, &deployment_id);
    let init_iep = iep_ix(
        iep_program_id,
        vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(iep_config, false),
            AccountMeta::new_readonly(mint.pubkey(), false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        IepInstruction::Initialize {
            deployment_id,
            fee_bps: 25,
            fee_collector: fee_owner.pubkey(),
            checkpoint_registry_program: crp_program_id,
            receipt_verifier_program: receipt_verifier_program_id,
            verifier_router_program,
            router,
            verifier_entry,
            verifier_program,
        },
    );
    let recent_blockhash = banks_client.get_latest_blockhash().await.unwrap();
    banks_client
        .process_transaction(Transaction::new_signed_with_payer(
            &[init_iep],
            Some(&payer.pubkey()),
            &[&payer],
            recent_blockhash,
        ))
        .await
        .unwrap();

    // Create funded (direction B) intent.
    let intent_nonce = [0x33u8; 32];
    let (intent, _bump) = iep_intent_pda(&iep_program_id, &deployment_id, &intent_nonce);
    let (intent_vault, _bump) = iep_intent_vault_pda(&iep_program_id, &intent);
    let create_intent = iep_ix(
        iep_program_id,
        vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(iep_config, false),
            AccountMeta::new(intent, false),
            AccountMeta::new(intent_vault, false),
            AccountMeta::new(creator_ta.pubkey(), false),
            AccountMeta::new_readonly(mint.pubkey(), false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        IepInstruction::CreateIntent {
            intent_nonce,
            direction: 2,
            mint: mint.pubkey(),
            solana_recipient: payer.pubkey(),
            net_amount: 100_000,
            expiry_slot: 10_000,
        },
    );
    let recent_blockhash = banks_client.get_latest_blockhash().await.unwrap();
    banks_client
        .process_transaction(Transaction::new_signed_with_payer(
            &[create_intent],
            Some(&payer.pubkey()),
            &[&payer],
            recent_blockhash,
        ))
        .await
        .unwrap();

    // Fill intent (direction B): no token transfer; commits solver destination token account.
    let (fill, _bump) = iep_fill_pda(&iep_program_id, &intent);
    let receiver_tag = [0x44u8; 32];
    let fill_ix = iep_ix(
        iep_program_id,
        vec![
            AccountMeta::new(solver.pubkey(), true),
            AccountMeta::new_readonly(iep_config, false),
            AccountMeta::new(intent, false),
            AccountMeta::new(fill, false),
            AccountMeta::new(intent_vault, false),
            AccountMeta::new(solver_ta.pubkey(), false), // unused for direction B
            AccountMeta::new_readonly(solver_ta.pubkey(), false),
            AccountMeta::new_readonly(mint.pubkey(), false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        IepInstruction::FillIntent {
            receiver_tag,
            junocash_amount_required: 555,
        },
    );
    let recent_blockhash = banks_client.get_latest_blockhash().await.unwrap();
    banks_client
        .process_transaction(Transaction::new_signed_with_payer(
            &[fill_ix],
            Some(&payer.pubkey()),
            &[&payer, &solver],
            recent_blockhash,
        ))
        .await
        .unwrap();

    // Build a fake receipt bundle matching the fill.
    let cmx = [0x55u8; 32];
    let bundle = fake_bundle_v1(
        deployment_id,
        orchard_root,
        cmx,
        555,
        receiver_tag,
        fill.to_bytes(),
    );
    let spent_id = spent_receipt_id(&deployment_id, &cmx);
    let (spent, _bump) = iep_spent_pda(&iep_program_id, &spent_id);

    // Settle: net goes to solver token account; fee goes to collector.
    let settle_ix = iep_ix(
        iep_program_id,
        vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(iep_config, false),
            AccountMeta::new(intent, false),
            AccountMeta::new(fill, false),
            AccountMeta::new(intent_vault, false),
            AccountMeta::new(solver_ta.pubkey(), false),
            AccountMeta::new(fee_ta.pubkey(), false),
            AccountMeta::new_readonly(mint.pubkey(), false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new(spent, false),
            AccountMeta::new_readonly(system_program::ID, false),
            AccountMeta::new_readonly(crp_program_id, false),
            AccountMeta::new_readonly(crp_config, false),
            AccountMeta::new_readonly(checkpoint, false),
            AccountMeta::new_readonly(receipt_verifier_program_id, false),
            AccountMeta::new_readonly(verifier_router_program, false),
            AccountMeta::new_readonly(router, false),
            AccountMeta::new_readonly(verifier_entry, false),
            AccountMeta::new_readonly(verifier_program, false),
        ],
        IepInstruction::Settle { bundle },
    );
    let recent_blockhash = banks_client.get_latest_blockhash().await.unwrap();
    banks_client
        .process_transaction(Transaction::new_signed_with_payer(
            &[settle_ix],
            Some(&payer.pubkey()),
            &[&payer],
            recent_blockhash,
        ))
        .await
        .unwrap();

    // Check balances.
    let creator_acc = banks_client
        .get_account(creator_ta.pubkey())
        .await
        .unwrap()
        .unwrap();
    let solver_acc = banks_client
        .get_account(solver_ta.pubkey())
        .await
        .unwrap()
        .unwrap();
    let fee_acc = banks_client
        .get_account(fee_ta.pubkey())
        .await
        .unwrap()
        .unwrap();
    let vault_acc = banks_client
        .get_account(intent_vault)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(token_amount(&creator_acc), 1_000_000 - 100_250);
    assert_eq!(token_amount(&solver_acc), 100_000);
    assert_eq!(token_amount(&fee_acc), 250);
    assert_eq!(token_amount(&vault_acc), 0);

    // Check state updated.
    let intent_ai = banks_client.get_account(intent).await.unwrap().unwrap();
    let intent_state = IepIntentV2::try_from_slice(&intent_ai.data).unwrap();
    assert_eq!(intent_state.status, 3);

    let fill_ai = banks_client.get_account(fill).await.unwrap().unwrap();
    let fill_state = IepFillV2::try_from_slice(&fill_ai.data).unwrap();
    assert_eq!(fill_state.status, 2);

    assert!(banks_client.get_account(spent).await.unwrap().is_some());
}
