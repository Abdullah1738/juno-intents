#![allow(unexpected_cfgs)]

use borsh::{BorshDeserialize, BorshSerialize};
use juno_intents_checkpoint_registry as crp;
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    clock::Clock,
    entrypoint,
    entrypoint::ProgramResult,
    hash::hashv,
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction,
    sysvar::Sysvar,
};
use spl_token::{
    instruction as token_ix,
    solana_program::program_pack::Pack as _,
    state::Account as TokenAccount,
};

const CONFIG_SEED: &[u8] = b"config";
const INTENT_SEED: &[u8] = b"intent";
const FILL_SEED: &[u8] = b"fill";
const VAULT_SEED: &[u8] = b"vault";
const SPENT_SEED: &[u8] = b"spent";

const PROTOCOL_DOMAIN: &[u8] = b"JUNO_INTENTS";
const PROTOCOL_VERSION_U16_LE: [u8; 2] = 1u16.to_le_bytes();
const PURPOSE_IEP_SPENT_RECEIPT_ID: &[u8] = b"iep_spent_receipt_id";

const CONFIG_VERSION_V1: u8 = 1;
const INTENT_VERSION_V1: u8 = 1;
const FILL_VERSION_V1: u8 = 1;
const SPENT_RECEIPT_VERSION_V1: u8 = 1;

const CONFIG_LEN_V1: usize = 1 + 32 + 32 + 2 + 32 + 32 + 32 + 1;
const INTENT_LEN_V1: usize = 1 + 1 + 32 + 32 + 32 + 32 + 8 + 2 + 8 + 8 + 32;
const FILL_LEN_V1: usize = 1 + 1 + 32 + 32 + 32 + 8 + 32;
const SPENT_RECEIPT_LEN_V1: usize = 1 + 32 + 32;

const FEE_BPS_DENOMINATOR: u64 = 10_000;

const RECEIPT_BUNDLE_VERSION_V1: u16 = 1;
const ZKVM_PROOF_SYSTEM_RISC0_GROTH16: u8 = 1;
const RECEIPT_JOURNAL_LEN_V1: usize = 170;
const RECEIPT_SEAL_LEN_V1: usize = 260;

const INTENT_STATUS_OPEN: u8 = 0;
const INTENT_STATUS_CANCELED: u8 = 1;
const INTENT_STATUS_FILLED: u8 = 2;
const INTENT_STATUS_SETTLED: u8 = 3;

const FILL_STATUS_LOCKED: u8 = 1;
const FILL_STATUS_SETTLED: u8 = 2;
const FILL_STATUS_REFUNDED: u8 = 3;

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum IepInstruction {
    Initialize {
        deployment_id: [u8; 32],
        fee_bps: u16,
        fee_collector: Pubkey,
        checkpoint_registry_program: Pubkey,
        receipt_verifier_program: Pubkey,
    },
    SetPaused { paused: bool },
    CreateIntent {
        intent_nonce: [u8; 32],
        mint: Pubkey,
        solana_recipient: Pubkey,
        net_amount: u64,
        expiry_slot: u64,
    },
    CancelIntent,
    FillIntent {
        receiver_tag: [u8; 32],
        junocash_amount_required: u64,
    },
    Settle { bundle: Vec<u8> },
    RefundFill,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct IepConfigV1 {
    pub version: u8,
    pub deployment_id: [u8; 32],
    pub admin: Pubkey,
    pub fee_bps: u16,
    pub fee_collector: Pubkey,
    pub checkpoint_registry_program: Pubkey,
    pub receipt_verifier_program: Pubkey,
    pub paused: bool,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct IepIntentV1 {
    pub version: u8,
    pub status: u8,
    pub deployment_id: [u8; 32],
    pub creator: Pubkey,
    pub mint: Pubkey,
    pub solana_recipient: Pubkey,
    pub net_amount: u64,
    pub fee_bps: u16,
    pub protocol_fee: u64,
    pub expiry_slot: u64,
    pub intent_nonce: [u8; 32],
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct IepFillV1 {
    pub version: u8,
    pub status: u8,
    pub intent: Pubkey,
    pub solver: Pubkey,
    pub receiver_tag: [u8; 32],
    pub junocash_amount_required: u64,
    pub vault: Pubkey,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct IepSpentReceiptV1 {
    pub version: u8,
    pub deployment_id: [u8; 32],
    pub cmx: [u8; 32],
}

#[repr(u32)]
pub enum IepError {
    InvalidInstruction = 1,
    InvalidSystemProgram = 2,
    InvalidTokenProgram = 3,
    InvalidConfigPda = 4,
    InvalidIntentPda = 5,
    InvalidFillPda = 6,
    InvalidVaultPda = 7,
    InvalidSpentReceiptPda = 8,
    InvalidConfigOwner = 9,
    InvalidIntentOwner = 10,
    InvalidFillOwner = 11,
    Unauthorized = 12,
    AlreadyInitialized = 13,
    InvalidAccountData = 14,
    Paused = 15,
    IntentNotOpen = 16,
    IntentNotFilled = 17,
    FillNotLocked = 18,
    Expired = 19,
    NotExpired = 20,
    InvalidFeeBps = 21,
    ReceiptInvalid = 22,
    ReceiptMismatch = 23,
    ReceiptAlreadySpent = 24,
    CheckpointInvalid = 25,
    CheckpointNotFinalized = 26,
    TokenAccountInvalid = 27,
    InsufficientFunds = 28,
}

impl From<IepError> for ProgramError {
    fn from(e: IepError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

entrypoint!(process_instruction);

pub fn process_instruction(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let ix = IepInstruction::try_from_slice(data).map_err(|_| IepError::InvalidInstruction)?;
    match ix {
        IepInstruction::Initialize {
            deployment_id,
            fee_bps,
            fee_collector,
            checkpoint_registry_program,
            receipt_verifier_program,
        } => process_initialize(
            program_id,
            accounts,
            deployment_id,
            fee_bps,
            fee_collector,
            checkpoint_registry_program,
            receipt_verifier_program,
        ),
        IepInstruction::SetPaused { paused } => process_set_paused(program_id, accounts, paused),
        IepInstruction::CreateIntent {
            intent_nonce,
            mint,
            solana_recipient,
            net_amount,
            expiry_slot,
        } => process_create_intent(
            program_id,
            accounts,
            intent_nonce,
            mint,
            solana_recipient,
            net_amount,
            expiry_slot,
        ),
        IepInstruction::CancelIntent => process_cancel_intent(program_id, accounts),
        IepInstruction::FillIntent {
            receiver_tag,
            junocash_amount_required,
        } => process_fill_intent(program_id, accounts, receiver_tag, junocash_amount_required),
        IepInstruction::Settle { bundle } => process_settle(program_id, accounts, bundle),
        IepInstruction::RefundFill => process_refund_fill(program_id, accounts),
    }
}

fn process_initialize(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    deployment_id: [u8; 32],
    fee_bps: u16,
    fee_collector: Pubkey,
    checkpoint_registry_program: Pubkey,
    receipt_verifier_program: Pubkey,
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
        return Err(IepError::InvalidSystemProgram.into());
    }
    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if fee_bps as u64 > FEE_BPS_DENOMINATOR {
        return Err(IepError::InvalidFeeBps.into());
    }

    let (expected_config, bump) = config_pda(program_id, &deployment_id);
    if expected_config != *config_ai.key {
        return Err(IepError::InvalidConfigPda.into());
    }
    if !config_ai.data_is_empty() || config_ai.owner != &solana_program::system_program::ID {
        return Err(IepError::AlreadyInitialized.into());
    }

    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(CONFIG_LEN_V1);
    invoke_signed(
        &system_instruction::create_account(payer.key, config_ai.key, lamports, CONFIG_LEN_V1 as u64, program_id),
        &[payer.clone(), config_ai.clone(), system_program.clone()],
        &[&[CONFIG_SEED, deployment_id.as_ref(), &[bump]]],
    )?;

    let cfg = IepConfigV1 {
        version: CONFIG_VERSION_V1,
        deployment_id,
        admin: *payer.key,
        fee_bps,
        fee_collector,
        checkpoint_registry_program,
        receipt_verifier_program,
        paused: false,
    };
    cfg.serialize(&mut &mut config_ai.data.borrow_mut()[..])
        .map_err(|_| ProgramError::from(IepError::InvalidAccountData))
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
        return Err(IepError::InvalidConfigOwner.into());
    }

    let mut cfg = IepConfigV1::try_from_slice(&config_ai.data.borrow())
        .map_err(|_| ProgramError::from(IepError::InvalidAccountData))?;
    if cfg.version != CONFIG_VERSION_V1 {
        return Err(IepError::InvalidAccountData.into());
    }
    let (expected_config, _bump) = config_pda(program_id, &cfg.deployment_id);
    if expected_config != *config_ai.key {
        return Err(IepError::InvalidConfigPda.into());
    }
    if cfg.admin != *admin.key {
        return Err(IepError::Unauthorized.into());
    }

    cfg.paused = paused;
    cfg.serialize(&mut &mut config_ai.data.borrow_mut()[..])
        .map_err(|_| ProgramError::from(IepError::InvalidAccountData))
}

fn process_create_intent(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    intent_nonce: [u8; 32],
    mint: Pubkey,
    solana_recipient: Pubkey,
    net_amount: u64,
    expiry_slot: u64,
) -> ProgramResult {
    // Accounts:
    // 0. creator (signer, writable payer)
    // 1. config (PDA)
    // 2. intent (PDA, writable)
    // 3. system_program
    let mut iter = accounts.iter();
    let creator = next_account_info(&mut iter)?;
    let config_ai = next_account_info(&mut iter)?;
    let intent_ai = next_account_info(&mut iter)?;
    let system_program = next_account_info(&mut iter)?;

    if *system_program.key != solana_program::system_program::ID {
        return Err(IepError::InvalidSystemProgram.into());
    }
    if !creator.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if config_ai.owner != program_id {
        return Err(IepError::InvalidConfigOwner.into());
    }
    if !intent_ai.data_is_empty() || intent_ai.owner != &solana_program::system_program::ID {
        return Err(IepError::AlreadyInitialized.into());
    }

    let cfg = IepConfigV1::try_from_slice(&config_ai.data.borrow())
        .map_err(|_| ProgramError::from(IepError::InvalidAccountData))?;
    if cfg.version != CONFIG_VERSION_V1 {
        return Err(IepError::InvalidAccountData.into());
    }
    let (expected_config, _bump) = config_pda(program_id, &cfg.deployment_id);
    if expected_config != *config_ai.key {
        return Err(IepError::InvalidConfigPda.into());
    }
    if cfg.paused {
        return Err(IepError::Paused.into());
    }

    let (expected_intent, bump) = intent_pda(program_id, &cfg.deployment_id, &intent_nonce);
    if expected_intent != *intent_ai.key {
        return Err(IepError::InvalidIntentPda.into());
    }

    let fee = protocol_fee_for_net_amount(net_amount, cfg.fee_bps)?;
    let intent = IepIntentV1 {
        version: INTENT_VERSION_V1,
        status: INTENT_STATUS_OPEN,
        deployment_id: cfg.deployment_id,
        creator: *creator.key,
        mint,
        solana_recipient,
        net_amount,
        fee_bps: cfg.fee_bps,
        protocol_fee: fee,
        expiry_slot,
        intent_nonce,
    };

    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(INTENT_LEN_V1);
    invoke_signed(
        &system_instruction::create_account(creator.key, intent_ai.key, lamports, INTENT_LEN_V1 as u64, program_id),
        &[creator.clone(), intent_ai.clone(), system_program.clone()],
        &[&[INTENT_SEED, cfg.deployment_id.as_ref(), intent_nonce.as_ref(), &[bump]]],
    )?;
    intent
        .serialize(&mut &mut intent_ai.data.borrow_mut()[..])
        .map_err(|_| ProgramError::from(IepError::InvalidAccountData))
}

fn process_cancel_intent(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    // Accounts:
    // 0. creator (signer)
    // 1. intent (PDA, writable)
    let mut iter = accounts.iter();
    let creator = next_account_info(&mut iter)?;
    let intent_ai = next_account_info(&mut iter)?;

    if !creator.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if intent_ai.owner != program_id {
        return Err(IepError::InvalidIntentOwner.into());
    }

    let mut intent = IepIntentV1::try_from_slice(&intent_ai.data.borrow())
        .map_err(|_| ProgramError::from(IepError::InvalidAccountData))?;
    if intent.version != INTENT_VERSION_V1 {
        return Err(IepError::InvalidAccountData.into());
    }
    if intent.creator != *creator.key {
        return Err(IepError::Unauthorized.into());
    }
    if intent.status != INTENT_STATUS_OPEN {
        return Err(IepError::IntentNotOpen.into());
    }

    intent.status = INTENT_STATUS_CANCELED;
    intent
        .serialize(&mut &mut intent_ai.data.borrow_mut()[..])
        .map_err(|_| ProgramError::from(IepError::InvalidAccountData))
}

fn process_fill_intent(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    receiver_tag: [u8; 32],
    junocash_amount_required: u64,
) -> ProgramResult {
    // Accounts:
    // 0. solver (signer, writable payer)
    // 1. config (PDA)
    // 2. intent (PDA, writable)
    // 3. fill (PDA, writable)
    // 4. vault (PDA token account, writable)
    // 5. solver_source_token_account (writable)
    // 6. mint (readonly)
    // 7. token_program
    // 8. system_program
    let mut iter = accounts.iter();
    let solver = next_account_info(&mut iter)?;
    let config_ai = next_account_info(&mut iter)?;
    let intent_ai = next_account_info(&mut iter)?;
    let fill_ai = next_account_info(&mut iter)?;
    let vault_ai = next_account_info(&mut iter)?;
    let solver_source = next_account_info(&mut iter)?;
    let mint_ai = next_account_info(&mut iter)?;
    let token_program = next_account_info(&mut iter)?;
    let system_program = next_account_info(&mut iter)?;

    if *system_program.key != solana_program::system_program::ID {
        return Err(IepError::InvalidSystemProgram.into());
    }
    if *token_program.key != spl_token::ID {
        return Err(IepError::InvalidTokenProgram.into());
    }
    if !solver.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if config_ai.owner != program_id {
        return Err(IepError::InvalidConfigOwner.into());
    }
    if intent_ai.owner != program_id {
        return Err(IepError::InvalidIntentOwner.into());
    }
    if !fill_ai.data_is_empty() || fill_ai.owner != &solana_program::system_program::ID {
        return Err(IepError::AlreadyInitialized.into());
    }

    let cfg = IepConfigV1::try_from_slice(&config_ai.data.borrow())
        .map_err(|_| ProgramError::from(IepError::InvalidAccountData))?;
    if cfg.version != CONFIG_VERSION_V1 {
        return Err(IepError::InvalidAccountData.into());
    }
    let (expected_config, _bump) = config_pda(program_id, &cfg.deployment_id);
    if expected_config != *config_ai.key {
        return Err(IepError::InvalidConfigPda.into());
    }
    if cfg.paused {
        return Err(IepError::Paused.into());
    }

    let mut intent = IepIntentV1::try_from_slice(&intent_ai.data.borrow())
        .map_err(|_| ProgramError::from(IepError::InvalidAccountData))?;
    if intent.version != INTENT_VERSION_V1 {
        return Err(IepError::InvalidAccountData.into());
    }
    if intent.deployment_id != cfg.deployment_id {
        return Err(IepError::InvalidAccountData.into());
    }
    if intent.status != INTENT_STATUS_OPEN {
        return Err(IepError::IntentNotOpen.into());
    }

    // Do not allow filling an expired intent.
    let clock = Clock::get()?;
    if clock.slot > intent.expiry_slot {
        return Err(IepError::Expired.into());
    }

    let (expected_fill, bump) = fill_pda(program_id, intent_ai.key);
    if expected_fill != *fill_ai.key {
        return Err(IepError::InvalidFillPda.into());
    }
    let (expected_vault, vault_bump) = vault_pda(program_id, fill_ai.key);
    if expected_vault != *vault_ai.key {
        return Err(IepError::InvalidVaultPda.into());
    }

    // Initialize the fill account.
    let rent = Rent::get()?;
    let fill_lamports = rent.minimum_balance(FILL_LEN_V1);
    invoke_signed(
        &system_instruction::create_account(solver.key, fill_ai.key, fill_lamports, FILL_LEN_V1 as u64, program_id),
        &[solver.clone(), fill_ai.clone(), system_program.clone()],
        &[&[FILL_SEED, intent_ai.key.as_ref(), &[bump]]],
    )?;

    // Initialize the vault token account at a PDA owned by the token program.
    if !vault_ai.data_is_empty() || vault_ai.owner != &solana_program::system_program::ID {
        return Err(IepError::AlreadyInitialized.into());
    }
    let vault_lamports = rent.minimum_balance(TokenAccount::LEN);
    invoke_signed(
        &system_instruction::create_account(
            solver.key,
            vault_ai.key,
            vault_lamports,
            TokenAccount::LEN as u64,
            token_program.key,
        ),
        &[solver.clone(), vault_ai.clone(), system_program.clone()],
        &[&[VAULT_SEED, fill_ai.key.as_ref(), &[vault_bump]]],
    )?;
    let init_vault_ix =
        token_ix::initialize_account3(token_program.key, vault_ai.key, mint_ai.key, fill_ai.key)?;
    invoke(
        &init_vault_ix,
        &[vault_ai.clone(), mint_ai.clone(), token_program.clone()],
    )?;

    let gross = intent
        .net_amount
        .checked_add(intent.protocol_fee)
        .ok_or(IepError::InvalidAccountData)?;

    // Transfer gross amount into vault.
    let transfer_ix = token_ix::transfer(
        token_program.key,
        solver_source.key,
        vault_ai.key,
        solver.key,
        &[],
        gross,
    )?;
    invoke(
        &transfer_ix,
        &[
            solver_source.clone(),
            vault_ai.clone(),
            solver.clone(),
            token_program.clone(),
        ],
    )?;

    let fill = IepFillV1 {
        version: FILL_VERSION_V1,
        status: FILL_STATUS_LOCKED,
        intent: *intent_ai.key,
        solver: *solver.key,
        receiver_tag,
        junocash_amount_required,
        vault: *vault_ai.key,
    };
    fill.serialize(&mut &mut fill_ai.data.borrow_mut()[..])
        .map_err(|_| ProgramError::from(IepError::InvalidAccountData))?;

    intent.status = INTENT_STATUS_FILLED;
    intent.serialize(&mut &mut intent_ai.data.borrow_mut()[..])
        .map_err(|_| ProgramError::from(IepError::InvalidAccountData))
}

fn process_settle(program_id: &Pubkey, accounts: &[AccountInfo], bundle: Vec<u8>) -> ProgramResult {
    // Accounts:
    // 0. payer (signer, writable)
    // 1. config (PDA)
    // 2. intent (writable)
    // 3. fill (writable)
    // 4. vault (token account, writable)
    // 5. recipient_token_account (writable)
    // 6. fee_token_account (writable)
    // 7. mint (readonly)
    // 8. token_program
    // 9. spent_receipt (PDA, writable)
    // 10. system_program
    // 11. checkpoint_registry_program (executable)
    // 12. crp_config (PDA)
    // 13. checkpoint (PDA)
    // 14. receipt_verifier_program (executable)
    // 15. verifier_router_program (executable)
    // 16. router (PDA)
    // 17. verifier_entry (PDA)
    // 18. verifier_program (groth16 verifier, executable)
    let mut iter = accounts.iter();
    let payer = next_account_info(&mut iter)?;
    let config_ai = next_account_info(&mut iter)?;
    let intent_ai = next_account_info(&mut iter)?;
    let fill_ai = next_account_info(&mut iter)?;
    let vault_ai = next_account_info(&mut iter)?;
    let recipient_ta = next_account_info(&mut iter)?;
    let fee_ta = next_account_info(&mut iter)?;
    let mint_ai = next_account_info(&mut iter)?;
    let token_program = next_account_info(&mut iter)?;
    let spent_ai = next_account_info(&mut iter)?;
    let system_program = next_account_info(&mut iter)?;
    let crp_program = next_account_info(&mut iter)?;
    let crp_config_ai = next_account_info(&mut iter)?;
    let checkpoint_ai = next_account_info(&mut iter)?;
    let receipt_verifier_program = next_account_info(&mut iter)?;
    let verifier_router_program = next_account_info(&mut iter)?;
    let router = next_account_info(&mut iter)?;
    let verifier_entry = next_account_info(&mut iter)?;
    let verifier_program = next_account_info(&mut iter)?;

    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if *system_program.key != solana_program::system_program::ID {
        return Err(IepError::InvalidSystemProgram.into());
    }
    if *token_program.key != spl_token::ID {
        return Err(IepError::InvalidTokenProgram.into());
    }
    if !receipt_verifier_program.executable {
        return Err(ProgramError::IncorrectProgramId);
    }
    if config_ai.owner != program_id {
        return Err(IepError::InvalidConfigOwner.into());
    }
    if intent_ai.owner != program_id {
        return Err(IepError::InvalidIntentOwner.into());
    }
    if fill_ai.owner != program_id {
        return Err(IepError::InvalidFillOwner.into());
    }

    let cfg = IepConfigV1::try_from_slice(&config_ai.data.borrow())
        .map_err(|_| ProgramError::from(IepError::InvalidAccountData))?;
    if cfg.version != CONFIG_VERSION_V1 {
        return Err(IepError::InvalidAccountData.into());
    }
    let (expected_config, _bump) = config_pda(program_id, &cfg.deployment_id);
    if expected_config != *config_ai.key {
        return Err(IepError::InvalidConfigPda.into());
    }
    if cfg.paused {
        return Err(IepError::Paused.into());
    }
    if cfg.receipt_verifier_program != *receipt_verifier_program.key {
        return Err(ProgramError::IncorrectProgramId);
    }
    if cfg.checkpoint_registry_program != *crp_program.key {
        return Err(ProgramError::IncorrectProgramId);
    }

    let intent = IepIntentV1::try_from_slice(&intent_ai.data.borrow())
        .map_err(|_| ProgramError::from(IepError::InvalidAccountData))?;
    if intent.version != INTENT_VERSION_V1 {
        return Err(IepError::InvalidAccountData.into());
    }
    if intent.deployment_id != cfg.deployment_id {
        return Err(IepError::InvalidAccountData.into());
    }
    if intent.status != INTENT_STATUS_FILLED {
        return Err(IepError::IntentNotFilled.into());
    }

    let mut fill = IepFillV1::try_from_slice(&fill_ai.data.borrow())
        .map_err(|_| ProgramError::from(IepError::InvalidAccountData))?;
    if fill.version != FILL_VERSION_V1 {
        return Err(IepError::InvalidAccountData.into());
    }
    if fill.intent != *intent_ai.key {
        return Err(IepError::InvalidAccountData.into());
    }
    if fill.status != FILL_STATUS_LOCKED {
        return Err(IepError::FillNotLocked.into());
    }
    if fill.vault != *vault_ai.key {
        return Err(IepError::InvalidVaultPda.into());
    }

    let clock = Clock::get()?;
    if clock.slot > intent.expiry_slot {
        return Err(IepError::Expired.into());
    }

    let journal = parse_receipt_bundle_and_journal_v1(&bundle)?;
    if journal.deployment_id != cfg.deployment_id {
        return Err(IepError::ReceiptMismatch.into());
    }
    if journal.fill_id != fill_ai.key.to_bytes() {
        return Err(IepError::ReceiptMismatch.into());
    }
    if journal.receiver_tag != fill.receiver_tag {
        return Err(IepError::ReceiptMismatch.into());
    }
    if journal.amount != fill.junocash_amount_required {
        return Err(IepError::ReceiptMismatch.into());
    }

    // Checkpoint verification: ensure the Orchard root is finalized and registry is not paused.
    if !crp_program.executable {
        return Err(ProgramError::IncorrectProgramId);
    }
    if crp_config_ai.owner != crp_program.key {
        return Err(IepError::CheckpointInvalid.into());
    }
    if checkpoint_ai.owner != crp_program.key {
        return Err(IepError::CheckpointInvalid.into());
    }
    let (expected_crp_config, _bump) = crp::config_pda(crp_program.key, &cfg.deployment_id);
    if expected_crp_config != *crp_config_ai.key {
        return Err(IepError::CheckpointInvalid.into());
    }
    let (expected_checkpoint, _bump) = crp::checkpoint_pda(crp_program.key, crp_config_ai.key, &journal.orchard_root);
    if expected_checkpoint != *checkpoint_ai.key {
        return Err(IepError::CheckpointInvalid.into());
    }

    let crp_cfg = crp::CrpConfigV1::try_from_slice(&crp_config_ai.data.borrow())
        .map_err(|_| ProgramError::from(IepError::CheckpointInvalid))?;
    if crp_cfg.version != 1 || crp_cfg.deployment_id != cfg.deployment_id || crp_cfg.paused {
        return Err(IepError::CheckpointInvalid.into());
    }
    let cp = crp::CrpCheckpointV1::try_from_slice(&checkpoint_ai.data.borrow())
        .map_err(|_| ProgramError::from(IepError::CheckpointInvalid))?;
    if cp.version != 1 || !cp.finalized || cp.orchard_root != journal.orchard_root {
        return Err(IepError::CheckpointNotFinalized.into());
    }

    // Token account sanity checks.
    let vault_state = TokenAccount::unpack(&vault_ai.data.borrow()).map_err(|_| IepError::TokenAccountInvalid)?;
    if vault_state.mint != *mint_ai.key || vault_state.owner != *fill_ai.key {
        return Err(IepError::TokenAccountInvalid.into());
    }
    let recipient_state =
        TokenAccount::unpack(&recipient_ta.data.borrow()).map_err(|_| IepError::TokenAccountInvalid)?;
    if recipient_state.mint != *mint_ai.key || recipient_state.owner != intent.solana_recipient {
        return Err(IepError::TokenAccountInvalid.into());
    }
    let fee_state = TokenAccount::unpack(&fee_ta.data.borrow()).map_err(|_| IepError::TokenAccountInvalid)?;
    if fee_state.mint != *mint_ai.key || fee_state.owner != cfg.fee_collector {
        return Err(IepError::TokenAccountInvalid.into());
    }

    let gross = intent
        .net_amount
        .checked_add(intent.protocol_fee)
        .ok_or(IepError::InvalidAccountData)?;
    if vault_state.amount < gross {
        return Err(IepError::InsufficientFunds.into());
    }

    // Replay protection (spent receipt PDA).
    let spent_id = spent_receipt_id(&cfg.deployment_id, &journal.cmx);
    let (expected_spent, bump) = spent_receipt_pda(program_id, &spent_id);
    if expected_spent != *spent_ai.key {
        return Err(IepError::InvalidSpentReceiptPda.into());
    }
    if !spent_ai.data_is_empty() {
        return Err(IepError::ReceiptAlreadySpent.into());
    }

    // Verify the ZK receipt via CPI before state mutation.
    let verify_ix = solana_program::instruction::Instruction {
        program_id: *receipt_verifier_program.key,
        accounts: vec![
            solana_program::instruction::AccountMeta::new_readonly(*verifier_router_program.key, false),
            solana_program::instruction::AccountMeta::new_readonly(*router.key, false),
            solana_program::instruction::AccountMeta::new_readonly(*verifier_entry.key, false),
            solana_program::instruction::AccountMeta::new_readonly(*verifier_program.key, false),
            solana_program::instruction::AccountMeta::new_readonly(*system_program.key, false),
        ],
        data: bundle.clone(),
    };
    invoke(
        &verify_ix,
        &[
            receipt_verifier_program.clone(),
            verifier_router_program.clone(),
            router.clone(),
            verifier_entry.clone(),
            verifier_program.clone(),
            system_program.clone(),
        ],
    )?;

    // Create spent receipt marker (payer funds).
    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(SPENT_RECEIPT_LEN_V1);
    invoke_signed(
        &system_instruction::create_account(
            payer.key,
            spent_ai.key,
            lamports,
            SPENT_RECEIPT_LEN_V1 as u64,
            program_id,
        ),
        &[payer.clone(), spent_ai.clone(), system_program.clone()],
        &[&[SPENT_SEED, spent_id.as_ref(), &[bump]]],
    )?;
    let spent = IepSpentReceiptV1 {
        version: SPENT_RECEIPT_VERSION_V1,
        deployment_id: cfg.deployment_id,
        cmx: journal.cmx,
    };
    spent.serialize(&mut &mut spent_ai.data.borrow_mut()[..])
        .map_err(|_| ProgramError::from(IepError::InvalidAccountData))?;

    // Transfer net to recipient and fee to collector.
    let (fill_key, fill_bump) = fill_pda(program_id, intent_ai.key);
    if fill_key != *fill_ai.key {
        return Err(IepError::InvalidFillPda.into());
    }
    let signer_seeds: &[&[u8]] = &[FILL_SEED, intent_ai.key.as_ref(), &[fill_bump]];

    let ix_net = token_ix::transfer(
        token_program.key,
        vault_ai.key,
        recipient_ta.key,
        fill_ai.key,
        &[],
        intent.net_amount,
    )?;
    invoke_signed(
        &ix_net,
        &[
            vault_ai.clone(),
            recipient_ta.clone(),
            fill_ai.clone(),
            token_program.clone(),
        ],
        &[signer_seeds],
    )?;
    if intent.protocol_fee != 0 {
        let ix_fee = token_ix::transfer(
            token_program.key,
            vault_ai.key,
            fee_ta.key,
            fill_ai.key,
            &[],
            intent.protocol_fee,
        )?;
        invoke_signed(
            &ix_fee,
            &[
                vault_ai.clone(),
                fee_ta.clone(),
                fill_ai.clone(),
                token_program.clone(),
            ],
            &[signer_seeds],
        )?;
    }

    fill.status = FILL_STATUS_SETTLED;
    fill.serialize(&mut &mut fill_ai.data.borrow_mut()[..])
        .map_err(|_| ProgramError::from(IepError::InvalidAccountData))?;

    let mut intent_mut = intent;
    intent_mut.status = INTENT_STATUS_SETTLED;
    intent_mut.serialize(&mut &mut intent_ai.data.borrow_mut()[..])
        .map_err(|_| ProgramError::from(IepError::InvalidAccountData))
}

fn process_refund_fill(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    // Accounts:
    // 0. solver (signer)
    // 1. intent (writable)
    // 2. fill (writable)
    // 3. vault (token account, writable)
    // 4. solver_destination_token_account (writable)
    // 5. token_program
    let mut iter = accounts.iter();
    let solver = next_account_info(&mut iter)?;
    let intent_ai = next_account_info(&mut iter)?;
    let fill_ai = next_account_info(&mut iter)?;
    let vault_ai = next_account_info(&mut iter)?;
    let solver_dest = next_account_info(&mut iter)?;
    let token_program = next_account_info(&mut iter)?;

    if *token_program.key != spl_token::ID {
        return Err(IepError::InvalidTokenProgram.into());
    }
    if !solver.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if intent_ai.owner != program_id {
        return Err(IepError::InvalidIntentOwner.into());
    }
    if fill_ai.owner != program_id {
        return Err(IepError::InvalidFillOwner.into());
    }

    let intent = IepIntentV1::try_from_slice(&intent_ai.data.borrow())
        .map_err(|_| ProgramError::from(IepError::InvalidAccountData))?;
    if intent.version != INTENT_VERSION_V1 {
        return Err(IepError::InvalidAccountData.into());
    }
    if intent.status != INTENT_STATUS_FILLED {
        return Err(IepError::IntentNotFilled.into());
    }

    let mut fill = IepFillV1::try_from_slice(&fill_ai.data.borrow())
        .map_err(|_| ProgramError::from(IepError::InvalidAccountData))?;
    if fill.version != FILL_VERSION_V1 {
        return Err(IepError::InvalidAccountData.into());
    }
    if fill.intent != *intent_ai.key {
        return Err(IepError::InvalidAccountData.into());
    }
    if fill.solver != *solver.key {
        return Err(IepError::Unauthorized.into());
    }
    if fill.status != FILL_STATUS_LOCKED {
        return Err(IepError::FillNotLocked.into());
    }
    if fill.vault != *vault_ai.key {
        return Err(IepError::InvalidVaultPda.into());
    }

    let clock = Clock::get()?;
    if clock.slot <= intent.expiry_slot {
        return Err(IepError::NotExpired.into());
    }

    let vault_state = TokenAccount::unpack(&vault_ai.data.borrow()).map_err(|_| IepError::TokenAccountInvalid)?;
    if vault_state.owner != *fill_ai.key {
        return Err(IepError::TokenAccountInvalid.into());
    }

    let (fill_key, fill_bump) = fill_pda(program_id, intent_ai.key);
    if fill_key != *fill_ai.key {
        return Err(IepError::InvalidFillPda.into());
    }
    let signer_seeds: &[&[u8]] = &[FILL_SEED, intent_ai.key.as_ref(), &[fill_bump]];

    let ix_refund = token_ix::transfer(
        token_program.key,
        vault_ai.key,
        solver_dest.key,
        fill_ai.key,
        &[],
        vault_state.amount,
    )?;
    invoke_signed(
        &ix_refund,
        &[
            vault_ai.clone(),
            solver_dest.clone(),
            fill_ai.clone(),
            token_program.clone(),
        ],
        &[signer_seeds],
    )?;

    fill.status = FILL_STATUS_REFUNDED;
    fill.serialize(&mut &mut fill_ai.data.borrow_mut()[..])
        .map_err(|_| ProgramError::from(IepError::InvalidAccountData))
}

fn protocol_fee_for_net_amount(net_amount: u64, fee_bps: u16) -> Result<u64, ProgramError> {
    if fee_bps as u64 > FEE_BPS_DENOMINATOR {
        return Err(IepError::InvalidFeeBps.into());
    }
    if net_amount == 0 || fee_bps == 0 {
        return Ok(0);
    }
    let fee = (net_amount as u128)
        .saturating_mul(fee_bps as u128)
        / (FEE_BPS_DENOMINATOR as u128);
    Ok(fee as u64)
}

#[derive(Clone, Copy)]
struct ReceiptJournalV1 {
    deployment_id: [u8; 32],
    orchard_root: [u8; 32],
    cmx: [u8; 32],
    amount: u64,
    receiver_tag: [u8; 32],
    fill_id: [u8; 32],
}

fn parse_receipt_bundle_and_journal_v1(bundle: &[u8]) -> Result<ReceiptJournalV1, ProgramError> {
    if bundle.len() < 2 + 1 + 32 + 2 + RECEIPT_JOURNAL_LEN_V1 + 4 + RECEIPT_SEAL_LEN_V1 {
        return Err(IepError::ReceiptInvalid.into());
    }
    let version = u16::from_le_bytes([bundle[0], bundle[1]]);
    if version != RECEIPT_BUNDLE_VERSION_V1 {
        return Err(IepError::ReceiptInvalid.into());
    }
    if bundle[2] != ZKVM_PROOF_SYSTEM_RISC0_GROTH16 {
        return Err(IepError::ReceiptInvalid.into());
    }

    // image_id: bundle[3..35]
    let journal_len = u16::from_le_bytes([bundle[35], bundle[36]]) as usize;
    if journal_len != RECEIPT_JOURNAL_LEN_V1 {
        return Err(IepError::ReceiptInvalid.into());
    }
    let journal_off = 37;
    let journal_end = journal_off + journal_len;
    let journal = &bundle[journal_off..journal_end];

    let seal_len = u32::from_le_bytes([
        bundle[journal_end],
        bundle[journal_end + 1],
        bundle[journal_end + 2],
        bundle[journal_end + 3],
    ]) as usize;
    if seal_len != RECEIPT_SEAL_LEN_V1 {
        return Err(IepError::ReceiptInvalid.into());
    }
    if bundle.len() != journal_end + 4 + seal_len {
        return Err(IepError::ReceiptInvalid.into());
    }

    // Journal bytes:
    // version_u16_le || deployment_id(32) || orchard_root(32) || cmx(32) || amount_u64_le || receiver_tag(32) || fill_id(32)
    if journal.len() != RECEIPT_JOURNAL_LEN_V1 {
        return Err(IepError::ReceiptInvalid.into());
    }
    if u16::from_le_bytes([journal[0], journal[1]]) != 1 {
        return Err(IepError::ReceiptInvalid.into());
    }
    let mut off = 2;
    let mut deployment_id = [0u8; 32];
    deployment_id.copy_from_slice(&journal[off..off + 32]);
    off += 32;
    let mut orchard_root = [0u8; 32];
    orchard_root.copy_from_slice(&journal[off..off + 32]);
    off += 32;
    let mut cmx = [0u8; 32];
    cmx.copy_from_slice(&journal[off..off + 32]);
    off += 32;
    let amount = u64::from_le_bytes(journal[off..off + 8].try_into().unwrap());
    off += 8;
    let mut receiver_tag = [0u8; 32];
    receiver_tag.copy_from_slice(&journal[off..off + 32]);
    off += 32;
    let mut fill_id = [0u8; 32];
    fill_id.copy_from_slice(&journal[off..off + 32]);
    off += 32;
    if off != RECEIPT_JOURNAL_LEN_V1 {
        return Err(IepError::ReceiptInvalid.into());
    }

    Ok(ReceiptJournalV1 {
        deployment_id,
        orchard_root,
        cmx,
        amount,
        receiver_tag,
        fill_id,
    })
}

fn spent_receipt_id(deployment_id: &[u8; 32], cmx: &[u8; 32]) -> [u8; 32] {
    let prefix = prefix_bytes(PURPOSE_IEP_SPENT_RECEIPT_ID);
    hashv(&[&prefix, deployment_id.as_ref(), cmx.as_ref()]).to_bytes()
}

fn prefix_bytes(purpose: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PROTOCOL_DOMAIN.len() + 1 + purpose.len() + 1 + 2);
    out.extend_from_slice(PROTOCOL_DOMAIN);
    out.push(0);
    out.extend_from_slice(purpose);
    out.push(0);
    out.extend_from_slice(&PROTOCOL_VERSION_U16_LE);
    out
}

pub fn config_pda(program_id: &Pubkey, deployment_id: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[CONFIG_SEED, deployment_id.as_ref()], program_id)
}

pub fn intent_pda(program_id: &Pubkey, deployment_id: &[u8; 32], intent_nonce: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[INTENT_SEED, deployment_id.as_ref(), intent_nonce.as_ref()],
        program_id,
    )
}

pub fn fill_pda(program_id: &Pubkey, intent: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[FILL_SEED, intent.as_ref()], program_id)
}

pub fn vault_pda(program_id: &Pubkey, fill: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[VAULT_SEED, fill.as_ref()], program_id)
}

pub fn spent_receipt_pda(program_id: &Pubkey, spent_id: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[SPENT_SEED, spent_id.as_ref()], program_id)
}
