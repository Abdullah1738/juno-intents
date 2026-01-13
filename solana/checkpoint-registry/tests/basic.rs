use borsh::{BorshDeserialize, BorshSerialize};
use solana_program_test::{processor, ProgramTest};
use solana_sdk::{
    ed25519_instruction::new_ed25519_instruction_with_signature,
    instruction::{AccountMeta, Instruction},
    signature::{Keypair, Signer},
    system_program,
    transaction::Transaction,
};

use juno_intents_checkpoint_registry::{
    checkpoint_pda, config_pda, height_pda, observation_signing_bytes_v1, CrpCheckpointV1, CrpConfigV1, CrpError,
    CrpInstruction,
};

fn ix(program_id: solana_sdk::pubkey::Pubkey, accounts: Vec<AccountMeta>, data: CrpInstruction) -> Instruction {
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

#[tokio::test]
async fn init_and_halt_on_conflict() {
    let program_id = solana_sdk::pubkey::Pubkey::new_unique();
    let mut pt = ProgramTest::new(
        "juno_intents_checkpoint_registry",
        program_id,
        processor!(juno_intents_checkpoint_registry::process_instruction),
    );

    let deployment_id = [0x01u8; 32];
    let (config, _bump) = config_pda(&program_id, &deployment_id);
    let op1 = Keypair::new();
    let op2 = Keypair::new();
    let operators = vec![op1.pubkey(), op2.pubkey()];

    let (mut banks_client, payer, recent_blockhash) = pt.start().await;

    // Initialize config.
    let init_ix = ix(
        program_id,
        vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(config, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        CrpInstruction::Initialize {
            deployment_id,
            admin: payer.pubkey(),
            threshold: 2,
            conflict_threshold: 2,
            finalization_delay_slots: 0,
            operators,
        },
    );
    let tx = Transaction::new_signed_with_payer(
        &[init_ix],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    banks_client.process_transaction(tx).await.unwrap();

    let cfg_ai = banks_client.get_account(config).await.unwrap().unwrap();
    let cfg = CrpConfigV1::try_from_slice(&cfg_ai.data).unwrap();
    assert_eq!(cfg.version, 1);
    assert_eq!(cfg.deployment_id, deployment_id);
    assert_eq!(cfg.admin, payer.pubkey());
    assert_eq!(cfg.threshold, 2);
    assert_eq!(cfg.conflict_threshold, 2);
    assert_eq!(cfg.operator_count, 2);
    assert!(!cfg.paused);

    let height = 42u64;
    let orchard_root_a = [0x02u8; 32];
    let orchard_root_b = [0x03u8; 32];
    let block_hash_a = [0x04u8; 32];
    let block_hash_b = [0x05u8; 32];
    let prev_hash_a = [0x06u8; 32];
    let prev_hash_b = [0x07u8; 32];

    // Submit two conflicting observations at the same height.
    let (checkpoint_a, _bump) = checkpoint_pda(&program_id, &config, &orchard_root_a);
    let (checkpoint_b, _bump) = checkpoint_pda(&program_id, &config, &orchard_root_b);
    let msg_a = observation_signing_bytes_v1(&deployment_id, height, &block_hash_a, &orchard_root_a, &prev_hash_a);
    let msg_b = observation_signing_bytes_v1(&deployment_id, height, &block_hash_b, &orchard_root_b, &prev_hash_b);

    let recent_blockhash = banks_client.get_latest_blockhash().await.unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[
            ed25519_ix(&op1, msg_a.as_ref()),
            ix(
                program_id,
                vec![
                    AccountMeta::new(payer.pubkey(), true),
                    AccountMeta::new(config, false),
                    AccountMeta::new(checkpoint_a, false),
                    AccountMeta::new_readonly(system_program::ID, false),
                    AccountMeta::new_readonly(solana_program::sysvar::instructions::ID, false),
                ],
                CrpInstruction::SubmitObservation {
                    height,
                    block_hash: block_hash_a,
                    orchard_root: orchard_root_a,
                    prev_hash: prev_hash_a,
                },
            ),
            ed25519_ix(&op2, msg_b.as_ref()),
            ix(
                program_id,
                vec![
                    AccountMeta::new(payer.pubkey(), true),
                    AccountMeta::new(config, false),
                    AccountMeta::new(checkpoint_b, false),
                    AccountMeta::new_readonly(system_program::ID, false),
                    AccountMeta::new_readonly(solana_program::sysvar::instructions::ID, false),
                ],
                CrpInstruction::SubmitObservation {
                    height,
                    block_hash: block_hash_b,
                    orchard_root: orchard_root_b,
                    prev_hash: prev_hash_b,
                },
            ),
        ],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    banks_client.process_transaction(tx).await.unwrap();

    // Mark the height as conflicted (halts the registry irreversibly).
    let (height_rec, _bump) = height_pda(&program_id, &config, height);
    let recent_blockhash = banks_client.get_latest_blockhash().await.unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[
            ed25519_ix(&op1, msg_a.as_ref()),
            ed25519_ix(&op2, msg_b.as_ref()),
            ix(
                program_id,
                vec![
                    AccountMeta::new(payer.pubkey(), true),
                    AccountMeta::new(config, false),
                    AccountMeta::new_readonly(checkpoint_a, false),
                    AccountMeta::new_readonly(checkpoint_b, false),
                    AccountMeta::new(height_rec, false),
                    AccountMeta::new_readonly(system_program::ID, false),
                    AccountMeta::new_readonly(solana_program::sysvar::instructions::ID, false),
                ],
                CrpInstruction::MarkConflict { sig_count: 2 },
            ),
        ],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    banks_client.process_transaction(tx).await.unwrap();

    // Further writes should fail with Paused.
    let orchard_root2 = [0x05u8; 32];
    let (checkpoint2, _bump) = checkpoint_pda(&program_id, &config, &orchard_root2);
    let recent_blockhash = banks_client.get_latest_blockhash().await.unwrap();
    let msg2 = observation_signing_bytes_v1(&deployment_id, 43, &[0x06u8; 32], &orchard_root2, &[0x07u8; 32]);
    let submit_ix = ix(
        program_id,
        vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(config, false),
            AccountMeta::new(checkpoint2, false),
            AccountMeta::new_readonly(system_program::ID, false),
            AccountMeta::new_readonly(solana_program::sysvar::instructions::ID, false),
        ],
        CrpInstruction::SubmitObservation {
            height: 43,
            block_hash: [0x06u8; 32],
            orchard_root: orchard_root2,
            prev_hash: [0x07u8; 32],
        },
    );
    let tx = Transaction::new_signed_with_payer(
        &[ed25519_ix(&op1, msg2.as_ref()), submit_ix],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    let err = banks_client.process_transaction(tx).await.unwrap_err();
    let tx_err = match err {
        solana_program_test::BanksClientError::TransactionError(tx_err) => tx_err,
        solana_program_test::BanksClientError::SimulationError { err, .. } => err,
        other => panic!("unexpected error: {other:?}"),
    };
    let solana_sdk::transaction::TransactionError::InstructionError(_, ix_err) = tx_err else {
        panic!("unexpected transaction error: {tx_err:?}");
    };
    let solana_sdk::instruction::InstructionError::Custom(code) = ix_err else {
        panic!("unexpected instruction error: {ix_err:?}");
    };
    assert_eq!(code, CrpError::Paused as u32);
}
