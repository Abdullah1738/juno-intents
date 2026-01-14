#![allow(unexpected_cfgs)]

use borsh::{BorshDeserialize, BorshSerialize};
#[cfg(not(feature = "no-entrypoint"))]
use solana_program::entrypoint;
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    clock::Clock,
    entrypoint::ProgramResult,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction,
    sysvar::instructions::{load_current_index_checked, load_instruction_at_checked},
    sysvar::Sysvar,
};

const CONFIG_SEED: &[u8] = b"config";
const CHECKPOINT_SEED: &[u8] = b"checkpoint";
const HEIGHT_SEED: &[u8] = b"height";

const CONFIG_VERSION_V1: u8 = 1;
const CHECKPOINT_VERSION_V1: u8 = 1;
const HEIGHT_VERSION_V1: u8 = 1;

const MAX_OPERATORS: usize = 32;

// Canonical signing prefix: "JUNO_INTENTS\0crp_observation\0" + u16_le(version=1)
const OBS_PREFIX: &[u8] = b"JUNO_INTENTS\0crp_observation\0\x01\x00";
const OBS_SIGNING_BYTES_LEN: usize = 167;

pub const CONFIG_LEN_V1: usize = 1 + 32 + 32 + 1 + 1 + 8 + 1 + (32 * MAX_OPERATORS) + 1;
pub const CHECKPOINT_LEN_V1: usize = 1 + 8 + 32 + 32 + 32 + 8 + 1;
pub const HEIGHT_LEN_V1: usize = 1 + 8 + 32 + 1 + 1;

const ED25519_PROGRAM_ID: Pubkey = solana_program::ed25519_program::ID;
const ED25519_SIGNATURE_OFFSETS_START: usize = 2;
const ED25519_SIGNATURE_OFFSETS_LEN: usize = 14;
const ED25519_DATA_START: usize = ED25519_SIGNATURE_OFFSETS_START + ED25519_SIGNATURE_OFFSETS_LEN;
const ED25519_PUBKEY_LEN: usize = 32;
const ED25519_SIGNATURE_LEN: usize = 64;

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum CrpInstruction {
    Initialize {
        deployment_id: [u8; 32],
        admin: Pubkey,
        threshold: u8,
        conflict_threshold: u8,
        finalization_delay_slots: u64,
        operators: Vec<Pubkey>,
    },
    SetOperators { operators: Vec<Pubkey> },
    SubmitObservation {
        height: u64,
        block_hash: [u8; 32],
        orchard_root: [u8; 32],
        prev_hash: [u8; 32],
    },
    FinalizeCheckpoint { sig_count: u8 },
    MarkConflict { sig_count: u8 },
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct CrpConfigV1 {
    pub version: u8,
    pub deployment_id: [u8; 32],
    pub admin: Pubkey,
    pub threshold: u8,
    pub conflict_threshold: u8,
    pub finalization_delay_slots: u64,
    pub operator_count: u8,
    pub operators: [Pubkey; MAX_OPERATORS],
    pub paused: bool,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct CrpCheckpointV1 {
    pub version: u8,
    pub height: u64,
    pub block_hash: [u8; 32],
    pub orchard_root: [u8; 32],
    pub prev_hash: [u8; 32],
    pub first_seen_slot: u64,
    pub finalized: bool,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct CrpHeightV1 {
    pub version: u8,
    pub height: u64,
    pub orchard_root: [u8; 32],
    pub finalized: bool,
    pub conflicted: bool,
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
    InvalidHeightPda = 11,
    InvalidOperatorSet = 12,
    InvalidEd25519Instruction = 13,
    InvalidOperatorSignature = 14,
    DuplicateOperatorSignature = 15,
    InsufficientSignatures = 16,
    FinalizationDelayNotMet = 17,
}

impl From<CrpError> for ProgramError {
    fn from(e: CrpError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

#[cfg(not(feature = "no-entrypoint"))]
entrypoint!(process_instruction);

#[inline(never)]
pub fn process_instruction(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let ix = CrpInstruction::try_from_slice(data).map_err(|_| CrpError::InvalidInstruction)?;
    match ix {
        CrpInstruction::Initialize {
            deployment_id,
            admin,
            threshold,
            conflict_threshold,
            finalization_delay_slots,
            operators,
        } => process_initialize(
            program_id,
            accounts,
            deployment_id,
            admin,
            threshold,
            conflict_threshold,
            finalization_delay_slots,
            operators,
        ),
        CrpInstruction::SetOperators { operators } => process_set_operators(program_id, accounts, operators),
        CrpInstruction::SubmitObservation {
            height,
            block_hash,
            orchard_root,
            prev_hash,
        } => process_submit_observation(program_id, accounts, height, block_hash, orchard_root, prev_hash),
        CrpInstruction::FinalizeCheckpoint { sig_count } => process_finalize_checkpoint(program_id, accounts, sig_count),
        CrpInstruction::MarkConflict { sig_count } => process_mark_conflict(program_id, accounts, sig_count),
    }
}

#[inline(never)]
fn process_initialize(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    deployment_id: [u8; 32],
    admin: Pubkey,
    threshold: u8,
    conflict_threshold: u8,
    finalization_delay_slots: u64,
    operators: Vec<Pubkey>,
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

    let (operator_count, operator_array) =
        validate_and_fill_operator_set(threshold, conflict_threshold, &operators)?;

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
        admin,
        threshold,
        conflict_threshold,
        finalization_delay_slots,
        operator_count,
        operators: operator_array,
        paused: false,
    };
    cfg.serialize(&mut &mut config_ai.data.borrow_mut()[..])
        .map_err(|_| ProgramError::from(CrpError::InvalidAccountData))
}

#[inline(never)]
fn process_set_operators(program_id: &Pubkey, accounts: &[AccountInfo], operators: Vec<Pubkey>) -> ProgramResult {
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
    validate_config_pda(program_id, config_ai, &cfg)?;
    if cfg.admin != *admin.key {
        return Err(CrpError::Unauthorized.into());
    }

    let (operator_count, operator_array) =
        validate_and_fill_operator_set(cfg.threshold, cfg.conflict_threshold, &operators)?;
    cfg.operator_count = operator_count;
    cfg.operators = operator_array;

    cfg.serialize(&mut &mut config_ai.data.borrow_mut()[..])
        .map_err(|_| ProgramError::from(CrpError::InvalidAccountData))
}

#[inline(never)]
fn process_submit_observation(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    height: u64,
    block_hash: [u8; 32],
    orchard_root: [u8; 32],
    prev_hash: [u8; 32],
) -> ProgramResult {
    // Accounts:
    // 0. payer (signer, writable)
    // 1. config (PDA)
    // 2. checkpoint (PDA, writable)
    // 3. system_program
    // 4. instructions_sysvar
    let mut iter = accounts.iter();
    let payer = next_account_info(&mut iter)?;
    let config_ai = next_account_info(&mut iter)?;
    let checkpoint_ai = next_account_info(&mut iter)?;
    let system_program = next_account_info(&mut iter)?;
    let instructions_sysvar = next_account_info(&mut iter)?;

    if *system_program.key != solana_program::system_program::ID {
        return Err(CrpError::InvalidSystemProgram.into());
    }
    if *instructions_sysvar.key != solana_program::sysvar::instructions::ID {
        return Err(ProgramError::InvalidArgument);
    }
    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if config_ai.owner != program_id {
        return Err(CrpError::InvalidConfigOwner.into());
    }

    let cfg = CrpConfigV1::try_from_slice(&config_ai.data.borrow())
        .map_err(|_| ProgramError::from(CrpError::InvalidAccountData))?;
    validate_config_pda(program_id, config_ai, &cfg)?;
    if cfg.paused {
        return Err(CrpError::Paused.into());
    }

    let (expected_checkpoint, bump) = checkpoint_pda(program_id, config_ai.key, &orchard_root);
    if expected_checkpoint != *checkpoint_ai.key {
        return Err(CrpError::InvalidCheckpointPda.into());
    }

    let message = observation_signing_bytes_v1(&cfg.deployment_id, height, &block_hash, &orchard_root, &prev_hash);
    let signer = verify_single_ed25519_signature(instructions_sysvar, &message)?;
    if operator_bit(&cfg, &signer).is_none() {
        return Err(CrpError::InvalidOperatorSignature.into());
    }

    if checkpoint_ai.data_is_empty() {
        let rent = Rent::get()?;
        let lamports = rent.minimum_balance(CHECKPOINT_LEN_V1);
        invoke_signed(
            &system_instruction::create_account(
                payer.key,
                checkpoint_ai.key,
                lamports,
                CHECKPOINT_LEN_V1 as u64,
                program_id,
            ),
            &[payer.clone(), checkpoint_ai.clone(), system_program.clone()],
            &[&[
                CHECKPOINT_SEED,
                config_ai.key.as_ref(),
                orchard_root.as_ref(),
                &[bump],
            ]],
        )?;

        let now = Clock::get()?.slot;
        let cp = CrpCheckpointV1 {
            version: CHECKPOINT_VERSION_V1,
            height,
            block_hash,
            orchard_root,
            prev_hash,
            first_seen_slot: now,
            finalized: false,
        };
        return cp
            .serialize(&mut &mut checkpoint_ai.data.borrow_mut()[..])
            .map_err(|_| ProgramError::from(CrpError::InvalidAccountData));
    }

    if checkpoint_ai.owner != program_id {
        return Err(CrpError::InvalidCheckpointOwner.into());
    }
    let cp = CrpCheckpointV1::try_from_slice(&checkpoint_ai.data.borrow())
        .map_err(|_| ProgramError::from(CrpError::InvalidAccountData))?;
    if cp.version != CHECKPOINT_VERSION_V1
        || cp.height != height
        || cp.block_hash != block_hash
        || cp.orchard_root != orchard_root
        || cp.prev_hash != prev_hash
    {
        return Err(CrpError::InvalidAccountData.into());
    }
    Ok(())
}

#[inline(never)]
fn process_finalize_checkpoint(program_id: &Pubkey, accounts: &[AccountInfo], sig_count: u8) -> ProgramResult {
    // Accounts:
    // 0. payer (signer, writable)
    // 1. config (PDA, writable)
    // 2. checkpoint (PDA, writable)
    // 3. height_record (PDA, writable)
    // 4. system_program
    // 5. instructions_sysvar
    let mut iter = accounts.iter();
    let payer = next_account_info(&mut iter)?;
    let config_ai = next_account_info(&mut iter)?;
    let checkpoint_ai = next_account_info(&mut iter)?;
    let height_ai = next_account_info(&mut iter)?;
    let system_program = next_account_info(&mut iter)?;
    let instructions_sysvar = next_account_info(&mut iter)?;

    if *system_program.key != solana_program::system_program::ID {
        return Err(CrpError::InvalidSystemProgram.into());
    }
    if *instructions_sysvar.key != solana_program::sysvar::instructions::ID {
        return Err(ProgramError::InvalidArgument);
    }
    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if config_ai.owner != program_id {
        return Err(CrpError::InvalidConfigOwner.into());
    }
    if checkpoint_ai.owner != program_id {
        return Err(CrpError::InvalidCheckpointOwner.into());
    }

    let mut cfg = CrpConfigV1::try_from_slice(&config_ai.data.borrow())
        .map_err(|_| ProgramError::from(CrpError::InvalidAccountData))?;
    validate_config_pda(program_id, config_ai, &cfg)?;
    if cfg.paused {
        return Err(CrpError::Paused.into());
    }

    let mut cp = CrpCheckpointV1::try_from_slice(&checkpoint_ai.data.borrow())
        .map_err(|_| ProgramError::from(CrpError::InvalidAccountData))?;
    if cp.version != CHECKPOINT_VERSION_V1 {
        return Err(CrpError::InvalidAccountData.into());
    }

    let (expected_checkpoint, _bump) = checkpoint_pda(program_id, config_ai.key, &cp.orchard_root);
    if expected_checkpoint != *checkpoint_ai.key {
        return Err(CrpError::InvalidCheckpointPda.into());
    }

    if cp.finalized {
        return Ok(());
    }

    let now = Clock::get()?.slot;
    if now < cp.first_seen_slot.saturating_add(cfg.finalization_delay_slots) {
        return Err(CrpError::FinalizationDelayNotMet.into());
    }

    if cfg.operator_count == 0 || cfg.threshold == 0 {
        return Err(CrpError::InvalidOperatorSet.into());
    }
    if (sig_count as u32) < cfg.threshold as u32 {
        return Err(CrpError::InsufficientSignatures.into());
    }

    let message = observation_signing_bytes_v1(
        &cfg.deployment_id,
        cp.height,
        &cp.block_hash,
        &cp.orchard_root,
        &cp.prev_hash,
    );
    let signer_mask = verify_ed25519_signatures(instructions_sysvar, &cfg, &message, sig_count)?;
    if signer_mask.count_ones() < cfg.threshold as u32 {
        return Err(CrpError::InsufficientSignatures.into());
    }

    let height_bytes = cp.height.to_le_bytes();
    let (expected_height, height_bump) = height_pda(program_id, config_ai.key, cp.height);
    if expected_height != *height_ai.key {
        return Err(CrpError::InvalidHeightPda.into());
    }

    if height_ai.data_is_empty() {
        let rent = Rent::get()?;
        let lamports = rent.minimum_balance(HEIGHT_LEN_V1);
        invoke_signed(
            &system_instruction::create_account(payer.key, height_ai.key, lamports, HEIGHT_LEN_V1 as u64, program_id),
            &[payer.clone(), height_ai.clone(), system_program.clone()],
            &[&[HEIGHT_SEED, config_ai.key.as_ref(), height_bytes.as_ref(), &[height_bump]]],
        )?;
        let rec = CrpHeightV1 {
            version: HEIGHT_VERSION_V1,
            height: cp.height,
            orchard_root: cp.orchard_root,
            finalized: true,
            conflicted: false,
        };
        rec.serialize(&mut &mut height_ai.data.borrow_mut()[..])
            .map_err(|_| ProgramError::from(CrpError::InvalidAccountData))?;
    } else {
        if height_ai.owner != program_id {
            return Err(CrpError::InvalidAccountData.into());
        }
        let mut rec = CrpHeightV1::try_from_slice(&height_ai.data.borrow())
            .map_err(|_| ProgramError::from(CrpError::InvalidAccountData))?;
        if rec.version != HEIGHT_VERSION_V1 || rec.height != cp.height {
            return Err(CrpError::InvalidAccountData.into());
        }
        if rec.conflicted {
            cfg.paused = true;
            cfg.serialize(&mut &mut config_ai.data.borrow_mut()[..])
                .map_err(|_| ProgramError::from(CrpError::InvalidAccountData))?;
            return Ok(());
        }
        if rec.finalized && rec.orchard_root != cp.orchard_root {
            rec.conflicted = true;
            rec.serialize(&mut &mut height_ai.data.borrow_mut()[..])
                .map_err(|_| ProgramError::from(CrpError::InvalidAccountData))?;
            cfg.paused = true;
            cfg.serialize(&mut &mut config_ai.data.borrow_mut()[..])
                .map_err(|_| ProgramError::from(CrpError::InvalidAccountData))?;
            return Ok(());
        }
        rec.orchard_root = cp.orchard_root;
        rec.finalized = true;
        rec.serialize(&mut &mut height_ai.data.borrow_mut()[..])
            .map_err(|_| ProgramError::from(CrpError::InvalidAccountData))?;
    }

    cp.finalized = true;
    cp.serialize(&mut &mut checkpoint_ai.data.borrow_mut()[..])
        .map_err(|_| ProgramError::from(CrpError::InvalidAccountData))
}

#[inline(never)]
fn process_mark_conflict(program_id: &Pubkey, accounts: &[AccountInfo], sig_count: u8) -> ProgramResult {
    // Accounts:
    // 0. payer (signer, writable)
    // 1. config (PDA, writable)
    // 2. checkpoint_a (PDA, readonly)
    // 3. checkpoint_b (PDA, readonly)
    // 4. height_record (PDA, writable)
    // 5. system_program
    // 6. instructions_sysvar
    let mut iter = accounts.iter();
    let payer = next_account_info(&mut iter)?;
    let config_ai = next_account_info(&mut iter)?;
    let a_ai = next_account_info(&mut iter)?;
    let b_ai = next_account_info(&mut iter)?;
    let height_ai = next_account_info(&mut iter)?;
    let system_program = next_account_info(&mut iter)?;
    let instructions_sysvar = next_account_info(&mut iter)?;

    if *system_program.key != solana_program::system_program::ID {
        return Err(CrpError::InvalidSystemProgram.into());
    }
    if *instructions_sysvar.key != solana_program::sysvar::instructions::ID {
        return Err(ProgramError::InvalidArgument);
    }
    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if config_ai.owner != program_id {
        return Err(CrpError::InvalidConfigOwner.into());
    }
    if a_ai.owner != program_id || b_ai.owner != program_id {
        return Err(CrpError::InvalidCheckpointOwner.into());
    }

    let mut cfg = CrpConfigV1::try_from_slice(&config_ai.data.borrow())
        .map_err(|_| ProgramError::from(CrpError::InvalidAccountData))?;
    validate_config_pda(program_id, config_ai, &cfg)?;
    if cfg.paused {
        return Ok(());
    }

    let a = CrpCheckpointV1::try_from_slice(&a_ai.data.borrow())
        .map_err(|_| ProgramError::from(CrpError::InvalidAccountData))?;
    let b = CrpCheckpointV1::try_from_slice(&b_ai.data.borrow())
        .map_err(|_| ProgramError::from(CrpError::InvalidAccountData))?;
    if a.version != CHECKPOINT_VERSION_V1 || b.version != CHECKPOINT_VERSION_V1 {
        return Err(CrpError::InvalidAccountData.into());
    }
    if a.height != b.height {
        return Err(CrpError::InvalidAccountData.into());
    }
    if a.orchard_root == b.orchard_root {
        return Err(CrpError::InvalidAccountData.into());
    }

    let (expected_a, _bump) = checkpoint_pda(program_id, config_ai.key, &a.orchard_root);
    if expected_a != *a_ai.key {
        return Err(CrpError::InvalidCheckpointPda.into());
    }
    let (expected_b, _bump) = checkpoint_pda(program_id, config_ai.key, &b.orchard_root);
    if expected_b != *b_ai.key {
        return Err(CrpError::InvalidCheckpointPda.into());
    }

    if cfg.operator_count == 0 || cfg.conflict_threshold < 2 {
        return Err(CrpError::InvalidOperatorSet.into());
    }
    if sig_count == 0 {
        return Err(CrpError::InsufficientSignatures.into());
    }

    let msg_a = observation_signing_bytes_v1(&cfg.deployment_id, a.height, &a.block_hash, &a.orchard_root, &a.prev_hash);
    let msg_b = observation_signing_bytes_v1(&cfg.deployment_id, b.height, &b.block_hash, &b.orchard_root, &b.prev_hash);
    let (mask_a, mask_b) =
        verify_ed25519_conflict_signatures(instructions_sysvar, &cfg, &msg_a, &msg_b, sig_count)?;
    if mask_a == 0 || mask_b == 0 {
        return Err(CrpError::InsufficientSignatures.into());
    }
    let total = (mask_a | mask_b).count_ones() as u8;
    if total < cfg.conflict_threshold {
        return Err(CrpError::InsufficientSignatures.into());
    }

    let height_bytes = a.height.to_le_bytes();
    let (expected_height, height_bump) = height_pda(program_id, config_ai.key, a.height);
    if expected_height != *height_ai.key {
        return Err(CrpError::InvalidHeightPda.into());
    }

    if height_ai.data_is_empty() {
        let rent = Rent::get()?;
        let lamports = rent.minimum_balance(HEIGHT_LEN_V1);
        invoke_signed(
            &system_instruction::create_account(payer.key, height_ai.key, lamports, HEIGHT_LEN_V1 as u64, program_id),
            &[payer.clone(), height_ai.clone(), system_program.clone()],
            &[&[HEIGHT_SEED, config_ai.key.as_ref(), height_bytes.as_ref(), &[height_bump]]],
        )?;
        let rec = CrpHeightV1 {
            version: HEIGHT_VERSION_V1,
            height: a.height,
            orchard_root: [0u8; 32],
            finalized: false,
            conflicted: true,
        };
        rec.serialize(&mut &mut height_ai.data.borrow_mut()[..])
            .map_err(|_| ProgramError::from(CrpError::InvalidAccountData))?;
    } else {
        let mut rec = CrpHeightV1::try_from_slice(&height_ai.data.borrow())
            .map_err(|_| ProgramError::from(CrpError::InvalidAccountData))?;
        if rec.version != HEIGHT_VERSION_V1 || rec.height != a.height {
            return Err(CrpError::InvalidAccountData.into());
        }
        rec.conflicted = true;
        rec.serialize(&mut &mut height_ai.data.borrow_mut()[..])
            .map_err(|_| ProgramError::from(CrpError::InvalidAccountData))?;
    }

    cfg.paused = true;
    cfg.serialize(&mut &mut config_ai.data.borrow_mut()[..])
        .map_err(|_| ProgramError::from(CrpError::InvalidAccountData))
}

fn validate_config_pda(program_id: &Pubkey, config_ai: &AccountInfo, cfg: &CrpConfigV1) -> ProgramResult {
    if cfg.version != CONFIG_VERSION_V1 {
        return Err(CrpError::InvalidAccountData.into());
    }
    let (expected_config, _bump) = config_pda(program_id, &cfg.deployment_id);
    if expected_config != *config_ai.key {
        return Err(CrpError::InvalidConfigPda.into());
    }
    Ok(())
}

fn validate_and_fill_operator_set(
    threshold: u8,
    conflict_threshold: u8,
    operators: &[Pubkey],
) -> Result<(u8, [Pubkey; MAX_OPERATORS]), ProgramError> {
    if operators.is_empty() || operators.len() > MAX_OPERATORS {
        return Err(CrpError::InvalidOperatorSet.into());
    }
    if threshold == 0 || threshold as usize > operators.len() {
        return Err(CrpError::InvalidOperatorSet.into());
    }
    if conflict_threshold < 2 || conflict_threshold as usize > operators.len() {
        return Err(CrpError::InvalidOperatorSet.into());
    }
    for i in 0..operators.len() {
        for j in (i + 1)..operators.len() {
            if operators[i] == operators[j] {
                return Err(CrpError::InvalidOperatorSet.into());
            }
        }
    }

    let mut out = [Pubkey::default(); MAX_OPERATORS];
    for (i, pk) in operators.iter().enumerate() {
        out[i] = *pk;
    }
    Ok((operators.len() as u8, out))
}

fn operator_bit(cfg: &CrpConfigV1, pk: &Pubkey) -> Option<u32> {
    let n = cfg.operator_count as usize;
    if n == 0 || n > MAX_OPERATORS {
        return None;
    }
    for i in 0..n {
        if cfg.operators[i] == *pk {
            return Some(1u32 << (i as u32));
        }
    }
    None
}

fn verify_single_ed25519_signature(
    instructions_sysvar: &AccountInfo,
    expected_message: &[u8; OBS_SIGNING_BYTES_LEN],
) -> Result<Pubkey, ProgramError> {
    let cur = load_current_index_checked(instructions_sysvar)? as usize;
    if cur == 0 {
        return Err(CrpError::InvalidEd25519Instruction.into());
    }
    let ix = load_instruction_at_checked(cur - 1, instructions_sysvar)?;
    if ix.program_id != ED25519_PROGRAM_ID {
        return Err(CrpError::InvalidEd25519Instruction.into());
    }
    let (pk, msg) = parse_ed25519_single(&ix.data)?;
    if msg != expected_message {
        return Err(CrpError::InvalidOperatorSignature.into());
    }
    Ok(Pubkey::new_from_array(pk))
}

fn verify_ed25519_signatures(
    instructions_sysvar: &AccountInfo,
    cfg: &CrpConfigV1,
    expected_message: &[u8; OBS_SIGNING_BYTES_LEN],
    sig_count: u8,
) -> Result<u32, ProgramError> {
    let cur = load_current_index_checked(instructions_sysvar)? as usize;
    let count = sig_count as usize;
    if cur < count {
        return Err(CrpError::InvalidEd25519Instruction.into());
    }

    let mut mask: u32 = 0;
    for i in 0..count {
        let ix = load_instruction_at_checked(cur - 1 - i, instructions_sysvar)?;
        if ix.program_id != ED25519_PROGRAM_ID {
            return Err(CrpError::InvalidEd25519Instruction.into());
        }
        let (pk, msg) = parse_ed25519_single(&ix.data)?;
        if msg != expected_message {
            return Err(CrpError::InvalidOperatorSignature.into());
        }
        let pk = Pubkey::new_from_array(pk);
        let bit = operator_bit(cfg, &pk).ok_or(CrpError::InvalidOperatorSignature)?;
        if (mask & bit) != 0 {
            return Err(CrpError::DuplicateOperatorSignature.into());
        }
        mask |= bit;
    }
    Ok(mask)
}

fn verify_ed25519_conflict_signatures(
    instructions_sysvar: &AccountInfo,
    cfg: &CrpConfigV1,
    msg_a: &[u8; OBS_SIGNING_BYTES_LEN],
    msg_b: &[u8; OBS_SIGNING_BYTES_LEN],
    sig_count: u8,
) -> Result<(u32, u32), ProgramError> {
    let cur = load_current_index_checked(instructions_sysvar)? as usize;
    let count = sig_count as usize;
    if cur < count {
        return Err(CrpError::InvalidEd25519Instruction.into());
    }

    let mut mask_a: u32 = 0;
    let mut mask_b: u32 = 0;
    for i in 0..count {
        let ix = load_instruction_at_checked(cur - 1 - i, instructions_sysvar)?;
        if ix.program_id != ED25519_PROGRAM_ID {
            return Err(CrpError::InvalidEd25519Instruction.into());
        }
        let (pk, msg) = parse_ed25519_single(&ix.data)?;
        let pk = Pubkey::new_from_array(pk);
        let bit = operator_bit(cfg, &pk).ok_or(CrpError::InvalidOperatorSignature)?;
        if msg == msg_a {
            if (mask_a & bit) != 0 {
                return Err(CrpError::DuplicateOperatorSignature.into());
            }
            mask_a |= bit;
        } else if msg == msg_b {
            if (mask_b & bit) != 0 {
                return Err(CrpError::DuplicateOperatorSignature.into());
            }
            mask_b |= bit;
        } else {
            return Err(CrpError::InvalidOperatorSignature.into());
        }
    }
    Ok((mask_a, mask_b))
}

fn parse_ed25519_single(data: &[u8]) -> Result<([u8; 32], &[u8]), ProgramError> {
    // Strictly accept the canonical single-signature format produced by
    // `solana_sdk::ed25519_instruction`.
    //
    // Layout:
    // - [0] num_signatures (u8) == 1
    // - [1] padding == 0
    // - offsets (14 bytes)
    // - pubkey (32)
    // - signature (64)
    // - message (166 bytes; this protocol version)
    if data.len() < ED25519_DATA_START {
        return Err(CrpError::InvalidEd25519Instruction.into());
    }
    if data[0] != 1 || data[1] != 0 {
        return Err(CrpError::InvalidEd25519Instruction.into());
    }

    let signature_offset = read_u16_le(data, 2)? as usize;
    let signature_ix = read_u16_le(data, 4)?;
    let pubkey_offset = read_u16_le(data, 6)? as usize;
    let pubkey_ix = read_u16_le(data, 8)?;
    let message_offset = read_u16_le(data, 10)? as usize;
    let message_size = read_u16_le(data, 12)? as usize;
    let message_ix = read_u16_le(data, 14)?;

    if signature_ix != u16::MAX || pubkey_ix != u16::MAX || message_ix != u16::MAX {
        return Err(CrpError::InvalidEd25519Instruction.into());
    }
    if pubkey_offset != ED25519_DATA_START {
        return Err(CrpError::InvalidEd25519Instruction.into());
    }
    if signature_offset != pubkey_offset + ED25519_PUBKEY_LEN {
        return Err(CrpError::InvalidEd25519Instruction.into());
    }
    if message_offset != signature_offset + ED25519_SIGNATURE_LEN {
        return Err(CrpError::InvalidEd25519Instruction.into());
    }
    if message_size != OBS_SIGNING_BYTES_LEN {
        return Err(CrpError::InvalidEd25519Instruction.into());
    }

    let end = message_offset
        .checked_add(message_size)
        .ok_or(CrpError::InvalidEd25519Instruction)?;
    if end != data.len() {
        return Err(CrpError::InvalidEd25519Instruction.into());
    }

    let mut pk = [0u8; 32];
    pk.copy_from_slice(&data[pubkey_offset..pubkey_offset + 32]);
    let msg = &data[message_offset..end];
    Ok((pk, msg))
}

fn read_u16_le(data: &[u8], off: usize) -> Result<u16, ProgramError> {
    let end = off.checked_add(2).ok_or(CrpError::InvalidEd25519Instruction)?;
    if end > data.len() {
        return Err(CrpError::InvalidEd25519Instruction.into());
    }
    Ok(u16::from_le_bytes([data[off], data[off + 1]]))
}

pub fn observation_signing_bytes_v1(
    deployment_id: &[u8; 32],
    height: u64,
    block_hash: &[u8; 32],
    orchard_root: &[u8; 32],
    prev_hash: &[u8; 32],
) -> [u8; OBS_SIGNING_BYTES_LEN] {
    let mut out = [0u8; OBS_SIGNING_BYTES_LEN];
    let mut idx = 0;

    out[idx..idx + OBS_PREFIX.len()].copy_from_slice(OBS_PREFIX);
    idx += OBS_PREFIX.len();

    out[idx..idx + 32].copy_from_slice(deployment_id);
    idx += 32;

    out[idx..idx + 8].copy_from_slice(&height.to_le_bytes());
    idx += 8;

    out[idx..idx + 32].copy_from_slice(block_hash);
    idx += 32;
    out[idx..idx + 32].copy_from_slice(orchard_root);
    idx += 32;
    out[idx..idx + 32].copy_from_slice(prev_hash);
    idx += 32;

    debug_assert_eq!(idx, OBS_SIGNING_BYTES_LEN);
    out
}

pub fn config_pda(program_id: &Pubkey, deployment_id: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[CONFIG_SEED, deployment_id.as_ref()], program_id)
}

pub fn checkpoint_pda(program_id: &Pubkey, config: &Pubkey, orchard_root: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[CHECKPOINT_SEED, config.as_ref(), orchard_root.as_ref()], program_id)
}

pub fn height_pda(program_id: &Pubkey, config: &Pubkey, height: u64) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[HEIGHT_SEED, config.as_ref(), &height.to_le_bytes()], program_id)
}
