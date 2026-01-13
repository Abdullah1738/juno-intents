use anyhow::{bail, Context, Result};
use clap::Parser;
use juno_receipt_logic::receipt_journal_from_witness_v1;
use orchard::{
    keys::{FullViewingKey, Scope, SpendingKey},
    note::{ExtractedNoteCommitment, Note, RandomSeed, Rho},
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
    Address,
};

const ORCHARD_RECEIVER_BYTES_LEN: usize = 43;
const ORCHARD_MERKLE_DEPTH: usize = 32;
const RECEIPT_WITNESS_VERSION_V1: u16 = 1;

#[derive(Parser, Debug)]
#[command(name = "synthetic-witness-v1")]
struct Args {
    /// 32-byte hex deployment_id. Defaults to 0x11 repeated 32 times.
    #[arg(long)]
    deployment_id: Option<String>,

    /// 32-byte hex fill_id.
    #[arg(long)]
    fill_id: String,

    /// Orchard note value (u64, zatoshis).
    #[arg(long, default_value_t = 1_000_000u64)]
    amount: u64,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let deployment_id = match args.deployment_id.as_deref() {
        Some(hex32) => parse_hex_32(hex32).context("parse --deployment-id")?,
        None => [0x11u8; 32],
    };
    let fill_id = parse_hex_32(&args.fill_id).context("parse --fill-id")?;

    // Deterministically derive a valid Orchard receiver.
    let mut sk_bytes = [7u8; 32];
    let sk = loop {
        if let Some(sk) = Option::<SpendingKey>::from(SpendingKey::from_bytes(sk_bytes)) {
            break sk;
        }
        sk_bytes[0] = sk_bytes[0].wrapping_add(1);
    };
    let fvk = FullViewingKey::from(&sk);
    let recipient: Address = fvk.address_at(0u32, Scope::External);
    let receiver_bytes: [u8; ORCHARD_RECEIVER_BYTES_LEN] = recipient.to_raw_address_bytes();

    // Deterministic note opening.
    let rho_bytes = [0u8; 32];
    let rho = Option::<Rho>::from(Rho::from_bytes(&rho_bytes)).context("rho")?;
    let (rseed_bytes, rseed) = (0u8..=255)
        .find_map(|b| {
            let bytes = [b; 32];
            Option::<RandomSeed>::from(RandomSeed::from_bytes(bytes, &rho)).map(|rs| (bytes, rs))
        })
        .context("rseed")?;

    let note = Option::<Note>::from(Note::from_parts(
        recipient,
        NoteValue::from_raw(args.amount),
        rho,
        rseed,
    ))
    .context("note")?;
    let cmx = ExtractedNoteCommitment::from(note.commitment()).to_bytes();
    let cmx_extracted =
        Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&cmx))
            .context("cmx canonical")?;

    // Use a simple deterministic auth path (all zeros) and position 0.
    let zero_hash =
        Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&[0u8; 32]))
            .context("merkle zero")?;
    let auth_path = [zero_hash; ORCHARD_MERKLE_DEPTH];
    let position = 0u32;
    let orchard_root = MerklePath::from_parts(position, auth_path)
        .root(cmx_extracted)
        .to_bytes();

    let mut witness = Vec::new();
    witness.extend_from_slice(&RECEIPT_WITNESS_VERSION_V1.to_le_bytes());
    witness.extend_from_slice(&deployment_id);
    witness.extend_from_slice(&fill_id);
    witness.extend_from_slice(&orchard_root);
    witness.extend_from_slice(&cmx);
    witness.extend_from_slice(&receiver_bytes);
    witness.extend_from_slice(&args.amount.to_le_bytes());
    witness.extend_from_slice(&rho_bytes);
    witness.extend_from_slice(&rseed_bytes);
    witness.extend_from_slice(&position.to_le_bytes());
    for _ in 0..ORCHARD_MERKLE_DEPTH {
        witness.extend_from_slice(&[0u8; 32]);
    }

    // Self-check (ensures witness encoding matches receipt logic expectations).
    let _ = receipt_journal_from_witness_v1(&witness).context("verify witness")?;

    println!("{}", hex::encode(witness));
    Ok(())
}

fn parse_hex_32(s: &str) -> Result<[u8; 32]> {
    let s = s.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 64 {
        bail!("expected 32-byte hex (64 chars), got len {}", s.len());
    }
    let bytes = hex::decode(s).context("invalid hex")?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

