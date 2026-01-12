use borsh::{BorshDeserialize, BorshSerialize};
use solana_program_test::{processor, ProgramTest};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    signature::Signer,
    system_program,
    transaction::Transaction,
};

use juno_intents_checkpoint_registry::{
    checkpoint_pda, config_pda, CrpCheckpointV1, CrpConfigV1, CrpError, CrpInstruction,
};

fn ix(program_id: solana_sdk::pubkey::Pubkey, accounts: Vec<AccountMeta>, data: CrpInstruction) -> Instruction {
    Instruction {
        program_id,
        accounts,
        data: data.try_to_vec().expect("borsh encode"),
    }
}

#[tokio::test]
async fn init_and_set_checkpoint_then_pause() {
    let program_id = solana_sdk::pubkey::Pubkey::new_unique();
    let mut pt = ProgramTest::new(
        "juno_intents_checkpoint_registry",
        program_id,
        processor!(juno_intents_checkpoint_registry::process_instruction),
    );

    let deployment_id = [0x01u8; 32];
    let (config, _bump) = config_pda(&program_id, &deployment_id);

    let (mut banks_client, payer, recent_blockhash) = pt.start().await;

    // Initialize config.
    let init_ix = ix(
        program_id,
        vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(config, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        CrpInstruction::Initialize { deployment_id },
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
    assert!(!cfg.paused);

    // Set a checkpoint.
    let orchard_root = [0x02u8; 32];
    let block_hash = [0x03u8; 32];
    let prev_hash = [0x04u8; 32];
    let (checkpoint, _bump) = checkpoint_pda(&program_id, &config, &orchard_root);

    let recent_blockhash = banks_client.get_latest_blockhash().await.unwrap();
    let set_ix = ix(
        program_id,
        vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(config, false),
            AccountMeta::new(checkpoint, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        CrpInstruction::SetCheckpoint {
            height: 42,
            block_hash,
            orchard_root,
            prev_hash,
        },
    );
    let tx = Transaction::new_signed_with_payer(
        &[set_ix],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    banks_client.process_transaction(tx).await.unwrap();

    let cp_ai = banks_client.get_account(checkpoint).await.unwrap().unwrap();
    let cp = CrpCheckpointV1::try_from_slice(&cp_ai.data).unwrap();
    assert_eq!(cp.version, 1);
    assert_eq!(cp.height, 42);
    assert_eq!(cp.block_hash, block_hash);
    assert_eq!(cp.orchard_root, orchard_root);
    assert_eq!(cp.prev_hash, prev_hash);
    assert!(cp.finalized);

    // Pause.
    let recent_blockhash = banks_client.get_latest_blockhash().await.unwrap();
    let pause_ix = ix(
        program_id,
        vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(config, false),
        ],
        CrpInstruction::SetPaused { paused: true },
    );
    let tx = Transaction::new_signed_with_payer(
        &[pause_ix],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    banks_client.process_transaction(tx).await.unwrap();

    // Further writes should fail with Paused.
    let orchard_root2 = [0x05u8; 32];
    let (checkpoint2, _bump) = checkpoint_pda(&program_id, &config, &orchard_root2);
    let recent_blockhash = banks_client.get_latest_blockhash().await.unwrap();
    let set_ix = ix(
        program_id,
        vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(config, false),
            AccountMeta::new(checkpoint2, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        CrpInstruction::SetCheckpoint {
            height: 43,
            block_hash: [0x06u8; 32],
            orchard_root: orchard_root2,
            prev_hash: [0x07u8; 32],
        },
    );
    let tx = Transaction::new_signed_with_payer(
        &[set_ix],
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
