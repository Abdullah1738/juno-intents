#![allow(unexpected_cfgs)]

use borsh::{BorshDeserialize, BorshSerialize};
#[cfg(not(feature = "no-entrypoint"))]
use solana_program::entrypoint;
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction,
    sysvar::Sysvar,
};

const CONFIG_SEED: &[u8] = b"config";
const CHECKPOINT_SEED: &[u8] = b"checkpoint";

const CONFIG_VERSION_V1: u8 = 1;
const CHECKPOINT_VERSION_V1: u8 = 1;

const CONFIG_LEN_V1: usize = 1 + 32 + 32 + 1;
const CHECKPOINT_LEN_V1: usize = 1 + 8 + 32 + 32 + 32 + 1;

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum CrpInstruction {
    Initialize { deployment_id: [u8; 32] },
    SetPaused { paused: bool },
    SetCheckpoint {
        height: u64,
        block_hash: [u8; 32],
        orchard_root: [u8; 32],
        prev_hash: [u8; 32],
    },
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct CrpConfigV1 {
    pub version: u8,
    pub deployment_id: [u8; 32],
    pub admin: Pubkey,
    pub paused: bool,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct CrpCheckpointV1 {
    pub version: u8,
    pub height: u64,
    pub block_hash: [u8; 32],
    pub orchard_root: [u8; 32],
    pub prev_hash: [u8; 32],
    pub finalized: bool,
}

#[repr(u32)]
pub enum CrpError {
    InvalidInstruction = 1,
    InvalidSystemProgram = 2,
    InvalidConfigPda = 3,
    InvalidCheckpointPda = 4,
    InvalidConfigOwner = 5,
    InvalidCheckpointOwner = 6,
    Unauthorized = 7,
    AlreadyInitialized = 8,
    InvalidAccountData = 9,
    Paused = 10,
}

impl From<CrpError> for ProgramError {
    fn from(e: CrpError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

#[cfg(not(feature = "no-entrypoint"))]
entrypoint!(process_instruction);

pub fn process_instruction(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let ix = CrpInstruction::try_from_slice(data).map_err(|_| CrpError::InvalidInstruction)?;
    match ix {
        CrpInstruction::Initialize { deployment_id } => {
            process_initialize(program_id, accounts, deployment_id)
        }
        CrpInstruction::SetPaused { paused } => process_set_paused(program_id, accounts, paused),
        CrpInstruction::SetCheckpoint {
            height,
            block_hash,
            orchard_root,
            prev_hash,
        } => process_set_checkpoint(program_id, accounts, height, block_hash, orchard_root, prev_hash),
    }
}

fn process_initialize(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    deployment_id: [u8; 32],
) -> ProgramResult {
    // Accounts:
    // 0. payer (signer, writable)
    // 1. config (PDA, writable)
    // 2. system_program
    let mut iter = accounts.iter();
    let payer = next_account_info(&mut iter)?;
    let config_ai = next_account_info(&mut iter)?;
    let system_program = next_account_info(&mut iter)?;

    if *system_program.key != solana_program::system_program::ID {
        return Err(CrpError::InvalidSystemProgram.into());
    }
    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let (expected_config, bump) = config_pda(program_id, &deployment_id);
    if expected_config != *config_ai.key {
        return Err(CrpError::InvalidConfigPda.into());
    }
    if !config_ai.data_is_empty() || config_ai.owner != &solana_program::system_program::ID {
        return Err(CrpError::AlreadyInitialized.into());
    }

    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(CONFIG_LEN_V1);

    invoke_signed(
        &system_instruction::create_account(payer.key, config_ai.key, lamports, CONFIG_LEN_V1 as u64, program_id),
        &[payer.clone(), config_ai.clone(), system_program.clone()],
        &[&[CONFIG_SEED, deployment_id.as_ref(), &[bump]]],
    )?;

    let cfg = CrpConfigV1 {
        version: CONFIG_VERSION_V1,
        deployment_id,
        admin: *payer.key,
        paused: false,
    };
    cfg.serialize(&mut &mut config_ai.data.borrow_mut()[..])
        .map_err(|_| ProgramError::from(CrpError::InvalidAccountData))
}

fn process_set_paused(program_id: &Pubkey, accounts: &[AccountInfo], paused: bool) -> ProgramResult {
    // Accounts:
    // 0. admin (signer)
    // 1. config (PDA, writable)
    let mut iter = accounts.iter();
    let admin = next_account_info(&mut iter)?;
    let config_ai = next_account_info(&mut iter)?;

    if !admin.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if config_ai.owner != program_id {
        return Err(CrpError::InvalidConfigOwner.into());
    }

    let mut cfg = CrpConfigV1::try_from_slice(&config_ai.data.borrow())
        .map_err(|_| ProgramError::from(CrpError::InvalidAccountData))?;
    if cfg.version != CONFIG_VERSION_V1 {
        return Err(CrpError::InvalidAccountData.into());
    }
    let (expected_config, _bump) = config_pda(program_id, &cfg.deployment_id);
    if expected_config != *config_ai.key {
        return Err(CrpError::InvalidConfigPda.into());
    }
    if cfg.admin != *admin.key {
        return Err(CrpError::Unauthorized.into());
    }

    cfg.paused = paused;
    cfg.serialize(&mut &mut config_ai.data.borrow_mut()[..])
        .map_err(|_| ProgramError::from(CrpError::InvalidAccountData))
}

fn process_set_checkpoint(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    height: u64,
    block_hash: [u8; 32],
    orchard_root: [u8; 32],
    prev_hash: [u8; 32],
) -> ProgramResult {
    // Accounts:
    // 0. admin (signer, writable payer if checkpoint needs init)
    // 1. config (PDA)
    // 2. checkpoint (PDA, writable)
    // 3. system_program
    let mut iter = accounts.iter();
    let admin = next_account_info(&mut iter)?;
    let config_ai = next_account_info(&mut iter)?;
    let checkpoint_ai = next_account_info(&mut iter)?;
    let system_program = next_account_info(&mut iter)?;

    if *system_program.key != solana_program::system_program::ID {
        return Err(CrpError::InvalidSystemProgram.into());
    }
    if !admin.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if config_ai.owner != program_id {
        return Err(CrpError::InvalidConfigOwner.into());
    }

    let cfg = CrpConfigV1::try_from_slice(&config_ai.data.borrow())
        .map_err(|_| ProgramError::from(CrpError::InvalidAccountData))?;
    if cfg.version != CONFIG_VERSION_V1 {
        return Err(CrpError::InvalidAccountData.into());
    }
    let (expected_config, _bump) = config_pda(program_id, &cfg.deployment_id);
    if expected_config != *config_ai.key {
        return Err(CrpError::InvalidConfigPda.into());
    }
    if cfg.paused {
        return Err(CrpError::Paused.into());
    }
    if cfg.admin != *admin.key {
        return Err(CrpError::Unauthorized.into());
    }

    let (expected_checkpoint, bump) = checkpoint_pda(program_id, config_ai.key, &orchard_root);
    if expected_checkpoint != *checkpoint_ai.key {
        return Err(CrpError::InvalidCheckpointPda.into());
    }

    if checkpoint_ai.data_is_empty() {
        let rent = Rent::get()?;
        let lamports = rent.minimum_balance(CHECKPOINT_LEN_V1);

        invoke_signed(
            &system_instruction::create_account(
                admin.key,
                checkpoint_ai.key,
                lamports,
                CHECKPOINT_LEN_V1 as u64,
                program_id,
            ),
            &[admin.clone(), checkpoint_ai.clone(), system_program.clone()],
            &[&[
                CHECKPOINT_SEED,
                config_ai.key.as_ref(),
                orchard_root.as_ref(),
                &[bump],
            ]],
        )?;
    } else if checkpoint_ai.owner != program_id {
        return Err(CrpError::InvalidCheckpointOwner.into());
    }

    let cp = CrpCheckpointV1 {
        version: CHECKPOINT_VERSION_V1,
        height,
        block_hash,
        orchard_root,
        prev_hash,
        finalized: true,
    };
    cp.serialize(&mut &mut checkpoint_ai.data.borrow_mut()[..])
        .map_err(|_| ProgramError::from(CrpError::InvalidAccountData))
}

pub fn config_pda(program_id: &Pubkey, deployment_id: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[CONFIG_SEED, deployment_id.as_ref()], program_id)
}

pub fn checkpoint_pda(program_id: &Pubkey, config: &Pubkey, orchard_root: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[CHECKPOINT_SEED, config.as_ref(), orchard_root.as_ref()],
        program_id,
    )
}
