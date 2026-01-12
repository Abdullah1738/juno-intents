use anyhow::{bail, Context, Result};
use clap::Parser;
use juno_receipt_host::prove_receipt_groth16_bundle_v1;
use juno_receipt_logic::receipt_journal_from_witness_v1;

#[derive(Parser, Debug)]
#[command(name = "prove-bundle-v1")]
struct Args {
    /// v1 receipt witness bytes (hex).
    ///
    /// Defaults to JUNO_RECEIPT_WITNESS_HEX.
    #[arg(long)]
    witness_hex: Option<String>,

    /// 4-byte ASCII selector for the verifier router (e.g. "JINT").
    ///
    /// Defaults to JUNO_RECEIPT_SELECTOR, then "JINT".
    #[arg(long)]
    selector: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let witness_hex = args
        .witness_hex
        .or_else(|| std::env::var("JUNO_RECEIPT_WITNESS_HEX").ok())
        .context("provide --witness-hex or set JUNO_RECEIPT_WITNESS_HEX")?;
    let selector_str = args
        .selector
        .or_else(|| std::env::var("JUNO_RECEIPT_SELECTOR").ok())
        .unwrap_or_else(|| "JINT".to_string());

    let selector = parse_selector(&selector_str)?;
    let witness = decode_hex(&witness_hex).context("decode witness hex")?;
    let expected_journal =
        receipt_journal_from_witness_v1(&witness).context("receipt journal from witness")?;

    let bundle = prove_receipt_groth16_bundle_v1(witness, selector).context("prove bundle")?;
    verify_bundle_journal_matches_expected(&bundle, &expected_journal)?;
    println!("{}", hex::encode(bundle));
    Ok(())
}

fn parse_selector(s: &str) -> Result<[u8; 4]> {
    let b = s.as_bytes();
    if b.len() != 4 {
        bail!("selector must be exactly 4 bytes");
    }
    Ok([b[0], b[1], b[2], b[3]])
}

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).context("invalid hex")
}

fn verify_bundle_journal_matches_expected(bundle: &[u8], expected_journal: &[u8]) -> Result<()> {
    if bundle.len() < 2 + 1 + 32 + 2 + 170 + 4 {
        bail!("bundle too short: {}", bundle.len());
    }
    let journal_len = u16::from_le_bytes([bundle[35], bundle[36]]) as usize;
    if journal_len != 170 {
        bail!("unexpected journal length: {}", journal_len);
    }
    let journal_off = 37;
    let journal = &bundle[journal_off..journal_off + journal_len];

    if journal != expected_journal {
        bail!("bundle journal mismatch vs logic");
    }
    Ok(())
}
