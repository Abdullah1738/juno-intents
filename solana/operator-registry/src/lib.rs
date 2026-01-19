#![allow(unexpected_cfgs)]

use borsh::{BorshDeserialize, BorshSerialize};
#[cfg(not(feature = "no-entrypoint"))]
use solana_program::entrypoint;
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    hash::hashv,
    instruction::{AccountMeta, Instruction},
    program::invoke,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction,
    sysvar::Sysvar,
};

const CONFIG_SEED: &[u8] = b"config";
const OPERATOR_SEED: &[u8] = b"operator";

const CONFIG_VERSION_V1: u8 = 1;
const OPERATOR_VERSION_V1: u8 = 1;

const MAX_MEASUREMENTS: usize = 16;

// Attestation ZKVM bundle (same outer framing as receipt bundles, but with a different journal).
const ATTESTATION_ZKVM_PROOF_BUNDLE_VERSION_V1: u16 = 1;
const ZKVM_PROOF_SYSTEM_RISC0_GROTH16: u8 = 1;
const ATTESTATION_JOURNAL_LEN_V1: usize = 2 + 32 + 1 + 32 + 32 + 32;
const ATTESTATION_SEAL_LEN_V1: usize = 260;

// Current expected MethodID bytes for the RISC Zero operator attestation verifier guest program.
//
// IMPORTANT: This value must match the MethodID produced by the production prover build
// environment (linux/amd64). If you regenerate zkVM methods on a different host/toolchain,
// you may get a different MethodID and must NOT update this constant without updating the
// production build inputs (or rebuilding all on-chain programs to match).
const EXPECTED_IMAGE_ID: [u8; 32] = [
    0x75, 0xd1, 0x4b, 0xd3, 0x6f, 0x7b, 0x8a, 0x31, 0x00, 0x47, 0xc7, 0xe8, 0xef, 0xff, 0x7d, 0xac,
    0xab, 0x7e, 0x9e, 0x9c, 0xf2, 0x26, 0x1e, 0xc1, 0x02, 0x96, 0xe7, 0x25, 0x01, 0xe2, 0x27, 0x15,
];

// Anchor discriminator for verifier_router::verify instruction:
// sha256("global:verify")[0..8]
const VERIFIER_ROUTER_VERIFY_DISCRIMINATOR: [u8; 8] =
    [0x85, 0xa1, 0x8d, 0x30, 0x78, 0xc6, 0x58, 0x96];

// Fixed selector for the RISC0 verifier router.
const RISC0_VERIFIER_SELECTOR: [u8; 4] = *b"JINT";

pub const CONFIG_LEN_V1: usize = 1 + 32 + 32 + 1 + 32 + 1 + (32 * MAX_MEASUREMENTS) + (32 * 4);
pub const OPERATOR_LEN_V1: usize = 1 + 32 + 32 + 32 + 1;

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum OrpInstruction {
    Initialize {
        deployment_id: [u8; 32],
        admin: Pubkey,
        junocash_chain_id: u8,
        junocash_genesis_hash: [u8; 32],
        verifier_router_program: Pubkey,
        router: Pubkey,
        verifier_entry: Pubkey,
        verifier_program: Pubkey,
        allowed_measurements: Vec<[u8; 32]>,
    },
    RegisterOperator {
        bundle: Vec<u8>,
    },
    SetOperatorEnabled {
        enabled: bool,
    },
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct OrpConfigV1 {
    pub version: u8,
    pub deployment_id: [u8; 32],
    pub admin: Pubkey,
    pub junocash_chain_id: u8,
    pub junocash_genesis_hash: [u8; 32],
    pub measurement_count: u8,
    pub measurements: [[u8; 32]; MAX_MEASUREMENTS],
    pub verifier_router_program: Pubkey,
    pub router: Pubkey,
    pub verifier_entry: Pubkey,
    pub verifier_program: Pubkey,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct OperatorRecordV1 {
    pub version: u8,
    pub deployment_id: [u8; 32],
    pub operator_pubkey: Pubkey,
    pub measurement: [u8; 32],
    pub enabled: bool,
}

#[repr(u32)]
pub enum OrpError {
    InvalidInstruction = 1,
    InvalidSystemProgram = 2,
    InvalidConfigPda = 3,
    InvalidOperatorPda = 4,
    InvalidConfigOwner = 5,
    InvalidOperatorOwner = 6,
    Unauthorized = 7,
    AlreadyInitialized = 8,
    AlreadyRegistered = 9,
    InvalidAccountData = 10,
    InvalidVerifierRouter = 11,
    InvalidVerifierEntry = 12,
    InvalidZkvmBundle = 13,
    InvalidZkvmImageId = 14,
    InvalidZkvmJournal = 15,
    MeasurementNotAllowed = 16,
}

impl From<OrpError> for ProgramError {
    fn from(e: OrpError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

#[cfg(not(feature = "no-entrypoint"))]
entrypoint!(process_instruction);

#[inline(never)]
pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let ix = OrpInstruction::try_from_slice(data).map_err(|_| OrpError::InvalidInstruction)?;
    match ix {
        OrpInstruction::Initialize {
            deployment_id,
            admin,
            junocash_chain_id,
            junocash_genesis_hash,
            verifier_router_program,
            router,
            verifier_entry,
            verifier_program,
            allowed_measurements,
        } => process_initialize(
            program_id,
            accounts,
            deployment_id,
            admin,
            junocash_chain_id,
            junocash_genesis_hash,
            verifier_router_program,
            router,
            verifier_entry,
            verifier_program,
            allowed_measurements,
        ),
        OrpInstruction::RegisterOperator { bundle } => {
            process_register(program_id, accounts, &bundle)
        }
        OrpInstruction::SetOperatorEnabled { enabled } => {
            process_set_enabled(program_id, accounts, enabled)
        }
    }
}

#[inline(never)]
fn process_initialize(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    deployment_id: [u8; 32],
    admin: Pubkey,
    junocash_chain_id: u8,
    junocash_genesis_hash: [u8; 32],
    verifier_router_program: Pubkey,
    router: Pubkey,
    verifier_entry: Pubkey,
    verifier_program: Pubkey,
    allowed_measurements: Vec<[u8; 32]>,
) -> ProgramResult {
    // Accounts:
    // 0. payer (signer, writable)
    // 1. config (PDA, writable)
    // 2. system_program
    let mut iter = accounts.iter();
    let payer_ai = next_account_info(&mut iter)?;
    let config_ai = next_account_info(&mut iter)?;
    let system_program = next_account_info(&mut iter)?;

    if *system_program.key != solana_program::system_program::ID {
        return Err(OrpError::InvalidSystemProgram.into());
    }
    if !payer_ai.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if allowed_measurements.len() > MAX_MEASUREMENTS {
        return Err(OrpError::InvalidAccountData.into());
    }

    let (expected_config, bump) = config_pda(program_id, &deployment_id);
    if expected_config != *config_ai.key {
        return Err(OrpError::InvalidConfigPda.into());
    }
    if !config_ai.data_is_empty() || config_ai.owner != &solana_program::system_program::ID {
        return Err(OrpError::AlreadyInitialized.into());
    }

    let (expected_router, _bump) =
        Pubkey::find_program_address(&[b"router"], &verifier_router_program);
    if expected_router != router {
        return Err(OrpError::InvalidVerifierRouter.into());
    }
    let (expected_entry, _bump) = Pubkey::find_program_address(
        &[b"verifier", RISC0_VERIFIER_SELECTOR.as_ref()],
        &verifier_router_program,
    );
    if expected_entry != verifier_entry {
        return Err(OrpError::InvalidVerifierEntry.into());
    }

    let mut measurements = [[0u8; 32]; MAX_MEASUREMENTS];
    for (i, m) in allowed_measurements.iter().enumerate() {
        measurements[i] = *m;
    }

    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(CONFIG_LEN_V1);
    invoke_signed(
        &system_instruction::create_account(
            payer_ai.key,
            config_ai.key,
            lamports,
            CONFIG_LEN_V1 as u64,
            program_id,
        ),
        &[payer_ai.clone(), config_ai.clone(), system_program.clone()],
        &[&[CONFIG_SEED, deployment_id.as_ref(), &[bump]]],
    )?;

    let cfg = OrpConfigV1 {
        version: CONFIG_VERSION_V1,
        deployment_id,
        admin,
        junocash_chain_id,
        junocash_genesis_hash,
        measurement_count: allowed_measurements.len() as u8,
        measurements,
        verifier_router_program,
        router,
        verifier_entry,
        verifier_program,
    };
    cfg.serialize(&mut &mut config_ai.data.borrow_mut()[..])
        .map_err(|_| ProgramError::from(OrpError::InvalidAccountData))
}

#[inline(never)]
fn process_register(program_id: &Pubkey, accounts: &[AccountInfo], bundle: &[u8]) -> ProgramResult {
    // Accounts:
    // 0. admin (signer, writable payer)
    // 1. config (PDA)
    // 2. operator_record (PDA, writable)
    // 3. system_program
    // 4. verifier_router_program (executable)
    // 5. router (PDA)
    // 6. verifier_entry (PDA)
    // 7. verifier_program (groth16 verifier, executable)
    let mut iter = accounts.iter();
    let admin_ai = next_account_info(&mut iter)?;
    let config_ai = next_account_info(&mut iter)?;
    let operator_ai = next_account_info(&mut iter)?;
    let system_program = next_account_info(&mut iter)?;
    let verifier_router_program_ai = next_account_info(&mut iter)?;
    let router_ai = next_account_info(&mut iter)?;
    let verifier_entry_ai = next_account_info(&mut iter)?;
    let verifier_program_ai = next_account_info(&mut iter)?;

    if *system_program.key != solana_program::system_program::ID {
        return Err(OrpError::InvalidSystemProgram.into());
    }
    if !admin_ai.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if config_ai.owner != program_id {
        return Err(OrpError::InvalidConfigOwner.into());
    }
    if !verifier_router_program_ai.executable {
        return Err(ProgramError::IncorrectProgramId);
    }
    if !verifier_program_ai.executable {
        return Err(ProgramError::IncorrectProgramId);
    }

    let cfg = OrpConfigV1::try_from_slice(&config_ai.data.borrow())
        .map_err(|_| ProgramError::from(OrpError::InvalidAccountData))?;
    validate_config_pda(program_id, config_ai, &cfg)?;
    if cfg.admin != *admin_ai.key {
        return Err(OrpError::Unauthorized.into());
    }
    if cfg.verifier_router_program != *verifier_router_program_ai.key {
        return Err(ProgramError::IncorrectProgramId);
    }
    if cfg.router != *router_ai.key {
        return Err(OrpError::InvalidAccountData.into());
    }
    if cfg.verifier_entry != *verifier_entry_ai.key {
        return Err(OrpError::InvalidAccountData.into());
    }
    if cfg.verifier_program != *verifier_program_ai.key {
        return Err(ProgramError::InvalidAccountData);
    }

    let parsed = parse_attestation_bundle_v1(bundle)?;
    if parsed.image_id != EXPECTED_IMAGE_ID {
        return Err(OrpError::InvalidZkvmImageId.into());
    }

    // Verify the ZK receipt via CPI before state mutation.
    let journal_digest = hashv(&[parsed.journal]).to_bytes();

    // Build Anchor instruction data:
    //   discriminator(8) || seal(260) || image_id(32) || journal_digest(32)
    let mut data = Vec::with_capacity(8 + parsed.seal.len() + 32 + 32);
    data.extend_from_slice(&VERIFIER_ROUTER_VERIFY_DISCRIMINATOR);
    data.extend_from_slice(parsed.seal);
    data.extend_from_slice(&parsed.image_id);
    data.extend_from_slice(&journal_digest);

    let ix = Instruction {
        program_id: *verifier_router_program_ai.key,
        accounts: vec![
            AccountMeta::new_readonly(*router_ai.key, false),
            AccountMeta::new_readonly(*verifier_entry_ai.key, false),
            AccountMeta::new_readonly(*verifier_program_ai.key, false),
            AccountMeta::new_readonly(*system_program.key, false),
        ],
        data,
    };

    invoke(
        &ix,
        &[
            verifier_router_program_ai.clone(),
            router_ai.clone(),
            verifier_entry_ai.clone(),
            verifier_program_ai.clone(),
            system_program.clone(),
        ],
    )?;

    let journal = parse_attestation_journal_v1(parsed.journal)?;
    if journal.deployment_id != cfg.deployment_id {
        return Err(OrpError::InvalidZkvmJournal.into());
    }
    if journal.junocash_chain_id != cfg.junocash_chain_id
        || journal.junocash_genesis_hash != cfg.junocash_genesis_hash
    {
        return Err(OrpError::InvalidZkvmJournal.into());
    }
    if !measurement_allowed(&cfg, &journal.measurement) {
        return Err(OrpError::MeasurementNotAllowed.into());
    }

    let (expected_operator, bump) =
        operator_pda(program_id, &cfg.deployment_id, &journal.operator_pubkey);
    if expected_operator != *operator_ai.key {
        return Err(OrpError::InvalidOperatorPda.into());
    }
    if !operator_ai.data_is_empty() {
        return Err(OrpError::AlreadyRegistered.into());
    }

    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(OPERATOR_LEN_V1);
    invoke_signed(
        &system_instruction::create_account(
            admin_ai.key,
            operator_ai.key,
            lamports,
            OPERATOR_LEN_V1 as u64,
            program_id,
        ),
        &[
            admin_ai.clone(),
            operator_ai.clone(),
            system_program.clone(),
        ],
        &[&[
            OPERATOR_SEED,
            cfg.deployment_id.as_ref(),
            journal.operator_pubkey.as_ref(),
            &[bump],
        ]],
    )?;

    let rec = OperatorRecordV1 {
        version: OPERATOR_VERSION_V1,
        deployment_id: cfg.deployment_id,
        operator_pubkey: journal.operator_pubkey,
        measurement: journal.measurement,
        enabled: true,
    };
    rec.serialize(&mut &mut operator_ai.data.borrow_mut()[..])
        .map_err(|_| ProgramError::from(OrpError::InvalidAccountData))
}

#[inline(never)]
fn process_set_enabled(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    enabled: bool,
) -> ProgramResult {
    // Accounts:
    // 0. admin (signer)
    // 1. config (PDA)
    // 2. operator_record (PDA, writable)
    let mut iter = accounts.iter();
    let admin_ai = next_account_info(&mut iter)?;
    let config_ai = next_account_info(&mut iter)?;
    let operator_ai = next_account_info(&mut iter)?;

    if !admin_ai.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if config_ai.owner != program_id {
        return Err(OrpError::InvalidConfigOwner.into());
    }
    if operator_ai.owner != program_id {
        return Err(OrpError::InvalidOperatorOwner.into());
    }

    let cfg = OrpConfigV1::try_from_slice(&config_ai.data.borrow())
        .map_err(|_| ProgramError::from(OrpError::InvalidAccountData))?;
    validate_config_pda(program_id, config_ai, &cfg)?;
    if cfg.admin != *admin_ai.key {
        return Err(OrpError::Unauthorized.into());
    }

    let mut rec = OperatorRecordV1::try_from_slice(&operator_ai.data.borrow())
        .map_err(|_| ProgramError::from(OrpError::InvalidAccountData))?;
    if rec.version != OPERATOR_VERSION_V1 || rec.deployment_id != cfg.deployment_id {
        return Err(OrpError::InvalidAccountData.into());
    }
    let (expected_operator, _bump) =
        operator_pda(program_id, &cfg.deployment_id, &rec.operator_pubkey);
    if expected_operator != *operator_ai.key {
        return Err(OrpError::InvalidOperatorPda.into());
    }
    rec.enabled = enabled;
    rec.serialize(&mut &mut operator_ai.data.borrow_mut()[..])
        .map_err(|_| ProgramError::from(OrpError::InvalidAccountData))
}

fn measurement_allowed(cfg: &OrpConfigV1, m: &[u8; 32]) -> bool {
    for i in 0..(cfg.measurement_count as usize) {
        if &cfg.measurements[i] == m {
            return true;
        }
    }
    false
}

fn validate_config_pda(
    program_id: &Pubkey,
    config_ai: &AccountInfo,
    cfg: &OrpConfigV1,
) -> ProgramResult {
    if cfg.version != CONFIG_VERSION_V1 {
        return Err(OrpError::InvalidAccountData.into());
    }
    let (expected_config, _bump) = config_pda(program_id, &cfg.deployment_id);
    if expected_config != *config_ai.key {
        return Err(OrpError::InvalidConfigPda.into());
    }
    Ok(())
}

struct ParsedBundle<'a> {
    image_id: [u8; 32],
    journal: &'a [u8],
    seal: &'a [u8],
}

fn parse_attestation_bundle_v1(input: &[u8]) -> Result<ParsedBundle<'_>, ProgramError> {
    let min_len = 2 + 1 + 32 + 2 + ATTESTATION_JOURNAL_LEN_V1 + 4 + ATTESTATION_SEAL_LEN_V1;
    if input.len() < min_len {
        return Err(OrpError::InvalidZkvmBundle.into());
    }

    let version = u16::from_le_bytes([input[0], input[1]]);
    if version != ATTESTATION_ZKVM_PROOF_BUNDLE_VERSION_V1 {
        return Err(OrpError::InvalidZkvmBundle.into());
    }
    if input[2] != ZKVM_PROOF_SYSTEM_RISC0_GROTH16 {
        return Err(OrpError::InvalidZkvmBundle.into());
    }

    let mut image_id = [0u8; 32];
    image_id.copy_from_slice(&input[3..35]);

    let journal_len = u16::from_le_bytes([input[35], input[36]]) as usize;
    if journal_len != ATTESTATION_JOURNAL_LEN_V1 {
        return Err(OrpError::InvalidZkvmBundle.into());
    }
    let journal_off = 37;
    let journal_end = journal_off + journal_len;
    let journal = &input[journal_off..journal_end];

    let seal_len = u32::from_le_bytes([
        input[journal_end],
        input[journal_end + 1],
        input[journal_end + 2],
        input[journal_end + 3],
    ]) as usize;
    if seal_len != ATTESTATION_SEAL_LEN_V1 {
        return Err(OrpError::InvalidZkvmBundle.into());
    }
    if input.len() != journal_end + 4 + seal_len {
        return Err(OrpError::InvalidZkvmBundle.into());
    }
    let seal = &input[journal_end + 4..];

    Ok(ParsedBundle {
        image_id,
        journal,
        seal,
    })
}

struct AttestationJournalV1 {
    deployment_id: [u8; 32],
    junocash_chain_id: u8,
    junocash_genesis_hash: [u8; 32],
    operator_pubkey: Pubkey,
    measurement: [u8; 32],
}

fn parse_attestation_journal_v1(journal: &[u8]) -> Result<AttestationJournalV1, ProgramError> {
    if journal.len() != ATTESTATION_JOURNAL_LEN_V1 {
        return Err(OrpError::InvalidZkvmJournal.into());
    }
    if u16::from_le_bytes([journal[0], journal[1]]) != 1 {
        return Err(OrpError::InvalidZkvmJournal.into());
    }

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

    if off != ATTESTATION_JOURNAL_LEN_V1 {
        return Err(OrpError::InvalidZkvmJournal.into());
    }

    Ok(AttestationJournalV1 {
        deployment_id,
        junocash_chain_id: chain_id,
        junocash_genesis_hash: genesis_hash,
        operator_pubkey,
        measurement,
    })
}

pub fn config_pda(program_id: &Pubkey, deployment_id: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[CONFIG_SEED, deployment_id.as_ref()], program_id)
}

pub fn operator_pda(
    program_id: &Pubkey,
    deployment_id: &[u8; 32],
    operator: &Pubkey,
) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[OPERATOR_SEED, deployment_id.as_ref(), operator.as_ref()],
        program_id,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use solana_program_test::{processor, ProgramTest};
    use solana_sdk::{
        account::Account, instruction::Instruction, signature::Signer, system_program,
        transaction::Transaction,
    };

    fn ix(program_id: Pubkey, accounts: Vec<AccountMeta>, data: OrpInstruction) -> Instruction {
        Instruction {
            program_id,
            accounts,
            data: data.try_to_vec().expect("borsh encode"),
        }
    }

    fn mock_verifier_router(
        _program_id: &Pubkey,
        _accounts: &[AccountInfo],
        _data: &[u8],
    ) -> ProgramResult {
        Ok(())
    }

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
        let mut out =
            Vec::with_capacity(2 + 1 + 32 + 2 + journal.len() + 4 + ATTESTATION_SEAL_LEN_V1);
        out.extend_from_slice(&ATTESTATION_ZKVM_PROOF_BUNDLE_VERSION_V1.to_le_bytes());
        out.push(ZKVM_PROOF_SYSTEM_RISC0_GROTH16);
        out.extend_from_slice(&EXPECTED_IMAGE_ID);
        out.extend_from_slice(&(journal.len() as u16).to_le_bytes());
        out.extend_from_slice(journal);
        let seal = vec![0u8; ATTESTATION_SEAL_LEN_V1];
        out.extend_from_slice(&(seal.len() as u32).to_le_bytes());
        out.extend_from_slice(&seal);
        out
    }

    #[tokio::test]
    async fn init_register_and_disable_operator() {
        let orp_program_id = Pubkey::new_unique();
        let verifier_router_program_id = Pubkey::new_unique();
        let verifier_program_id = Pubkey::new_unique();

        let mut pt = ProgramTest::new(
            "juno_intents_operator_registry",
            orp_program_id,
            processor!(crate::process_instruction),
        );
        pt.add_program(
            "mock_verifier_router",
            verifier_router_program_id,
            processor!(mock_verifier_router),
        );

        // Router PDAs are derived from the verifier_router_program_id.
        let (router, _bump) =
            Pubkey::find_program_address(&[b"router"], &verifier_router_program_id);
        let (verifier_entry, _bump) = Pubkey::find_program_address(
            &[b"verifier", RISC0_VERIFIER_SELECTOR.as_ref()],
            &verifier_router_program_id,
        );
        for k in [router, verifier_entry, verifier_program_id] {
            pt.add_account(
                k,
                Account {
                    lamports: 1,
                    data: vec![],
                    owner: system_program::ID,
                    executable: k == verifier_program_id,
                    rent_epoch: 0,
                },
            );
        }

        let (banks_client, payer, recent_blockhash) = pt.start().await;

        let deployment_id = [0x01u8; 32];
        let (config, _bump) = config_pda(&orp_program_id, &deployment_id);

        let chain_id = 2u8;
        let genesis_hash = [0x02u8; 32];
        let allowed = vec![[0x11u8; 32]];

        // Initialize config.
        let init_ix = ix(
            orp_program_id,
            vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(config, false),
                AccountMeta::new_readonly(system_program::ID, false),
            ],
            OrpInstruction::Initialize {
                deployment_id,
                admin: payer.pubkey(),
                junocash_chain_id: chain_id,
                junocash_genesis_hash: genesis_hash,
                verifier_router_program: verifier_router_program_id,
                router,
                verifier_entry,
                verifier_program: verifier_program_id,
                allowed_measurements: allowed.clone(),
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
        let cfg = OrpConfigV1::try_from_slice(&cfg_ai.data).unwrap();
        assert_eq!(cfg.version, 1);
        assert_eq!(cfg.deployment_id, deployment_id);
        assert_eq!(cfg.admin, payer.pubkey());
        assert_eq!(cfg.junocash_chain_id, chain_id);
        assert_eq!(cfg.junocash_genesis_hash, genesis_hash);
        assert_eq!(cfg.measurement_count, 1);
        assert_eq!(cfg.measurements[0], allowed[0]);

        // Register an operator.
        let operator_pubkey = Pubkey::new_unique();
        let (operator_pda_key, _bump) =
            operator_pda(&orp_program_id, &deployment_id, &operator_pubkey);
        let journal = att_journal_bytes(
            deployment_id,
            chain_id,
            genesis_hash,
            operator_pubkey,
            allowed[0],
        );
        let bundle = att_bundle_bytes(&journal);

        let recent_blockhash = banks_client.get_latest_blockhash().await.unwrap();
        let reg_ix = ix(
            orp_program_id,
            vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(config, false),
                AccountMeta::new(operator_pda_key, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(verifier_router_program_id, false),
                AccountMeta::new_readonly(router, false),
                AccountMeta::new_readonly(verifier_entry, false),
                AccountMeta::new_readonly(verifier_program_id, false),
            ],
            OrpInstruction::RegisterOperator { bundle },
        );
        let tx = Transaction::new_signed_with_payer(
            &[reg_ix],
            Some(&payer.pubkey()),
            &[&payer],
            recent_blockhash,
        );
        banks_client.process_transaction(tx).await.unwrap();

        let rec_ai = banks_client
            .get_account(operator_pda_key)
            .await
            .unwrap()
            .unwrap();
        let rec = OperatorRecordV1::try_from_slice(&rec_ai.data).unwrap();
        assert_eq!(rec.version, 1);
        assert_eq!(rec.deployment_id, deployment_id);
        assert_eq!(rec.operator_pubkey, operator_pubkey);
        assert_eq!(rec.measurement, allowed[0]);
        assert!(rec.enabled);

        // Disable operator.
        let recent_blockhash = banks_client.get_latest_blockhash().await.unwrap();
        let disable_ix = ix(
            orp_program_id,
            vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(config, false),
                AccountMeta::new(operator_pda_key, false),
            ],
            OrpInstruction::SetOperatorEnabled { enabled: false },
        );
        let tx = Transaction::new_signed_with_payer(
            &[disable_ix],
            Some(&payer.pubkey()),
            &[&payer],
            recent_blockhash,
        );
        banks_client.process_transaction(tx).await.unwrap();

        let rec_ai = banks_client
            .get_account(operator_pda_key)
            .await
            .unwrap()
            .unwrap();
        let rec = OperatorRecordV1::try_from_slice(&rec_ai.data).unwrap();
        assert!(!rec.enabled);
    }
}
