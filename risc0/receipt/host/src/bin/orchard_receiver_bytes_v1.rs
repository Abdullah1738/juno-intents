use anyhow::{anyhow, bail, Context, Result};
use bech32::primitives::decode::CheckedHrpstring;
use bech32::Checksum;
use clap::Parser;
use std::io::Cursor;
use zcash_encoding::CompactSize;

#[derive(Parser, Debug)]
#[command(name = "orchard-receiver-bytes-v1")]
struct Args {
    /// Unified address (ZIP 316 / bech32m + F4Jumble).
    ///
    /// Example: jtest1...
    #[arg(long)]
    unified_address: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let receiver = orchard_receiver_bytes_from_unified_address(&args.unified_address)?;
    println!("{}", hex::encode(receiver));
    Ok(())
}

// ---- Unified address decoding (ZIP 316 / Bech32m + F4Jumble) ----

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Bech32mZip316 {}

impl Checksum for Bech32mZip316 {
    type MidstateRepr = <bech32::Bech32m as Checksum>::MidstateRepr;
    const CODE_LENGTH: usize = 4_194_368;
    const CHECKSUM_LENGTH: usize = bech32::Bech32m::CHECKSUM_LENGTH;
    const GENERATOR_SH: [u32; 5] = bech32::Bech32m::GENERATOR_SH;
    const TARGET_RESIDUE: u32 = bech32::Bech32m::TARGET_RESIDUE;
}

fn orchard_receiver_bytes_from_unified_address(addr: &str) -> Result<[u8; 43]> {
    let parsed = CheckedHrpstring::new::<Bech32mZip316>(addr)
        .map_err(|e| anyhow!("invalid unified address bech32m: {e}"))?;
    let hrp_binding = parsed.hrp();
    let hrp = hrp_binding.as_str();
    let mut data = parsed.byte_iter().collect::<Vec<u8>>();

    f4jumble::f4jumble_inv_mut(&mut data).context("f4jumble inverse")?;

    // ZIP 316: the HRP is appended as 16 bytes of padding (ASCII bytes, nul-padded).
    if hrp.len() > 16 {
        bail!("invalid HRP length for unified address: {}", hrp.len());
    }
    if data.len() < 16 {
        bail!("unified address too short");
    }
    let mut expected_padding = [0u8; 16];
    expected_padding[..hrp.len()].copy_from_slice(hrp.as_bytes());
    let (encoded, tail) = data.split_at(data.len() - 16);
    if tail != expected_padding {
        bail!("invalid unified address padding bytes");
    }

    let items = parse_unified_items(encoded)?;
    // Orchard typecode = 0x03 in ZIP 316.
    let orchard = items
        .into_iter()
        .find(|(typecode, _data)| *typecode == 0x03)
        .ok_or_else(|| anyhow!("unified address has no orchard component"))?;
    let raw: [u8; 43] = orchard
        .1
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("orchard receiver has wrong length"))?;
    Ok(raw)
}

fn parse_unified_items(mut bytes: &[u8]) -> Result<Vec<(u32, Vec<u8>)>> {
    let mut out = vec![];
    while !bytes.is_empty() {
        let mut cur = Cursor::new(bytes);
        let typecode = CompactSize::read(&mut cur).context("read typecode")? as u32;
        let len_u64 = CompactSize::read(&mut cur).context("read item length")?;
        let len: usize = len_u64
            .try_into()
            .map_err(|_| anyhow!("unified item length too large: {}", len_u64))?;
        let pos = cur.position() as usize;
        let end = pos
            .checked_add(len)
            .ok_or_else(|| anyhow!("unified item length overflow"))?;
        if end > bytes.len() {
            bail!("truncated unified item");
        }
        let data = bytes[pos..end].to_vec();
        out.push((typecode, data));
        bytes = &bytes[end..];
    }
    Ok(out)
}

// ---- Tests ----

#[cfg(test)]
mod tests {
    use super::*;
    use bech32::Hrp;

    fn encode_orchard_only_ua_with_padding(hrp: &str, padding_hrp: &str, receiver: &[u8; 43]) -> String {
        let mut payload = Vec::with_capacity(1 + 1 + 43 + 16);
        // CompactSize(typecode=3) + CompactSize(len=43)
        payload.push(0x03);
        payload.push(0x2b);
        payload.extend_from_slice(receiver);

        let mut padding = [0u8; 16];
        padding[..padding_hrp.len()].copy_from_slice(padding_hrp.as_bytes());
        payload.extend_from_slice(&padding);

        f4jumble::f4jumble_mut(&mut payload).unwrap();

        bech32::encode::<Bech32mZip316>(Hrp::parse(hrp).unwrap(), &payload).unwrap()
    }

    fn encode_orchard_only_ua(hrp: &str, receiver: &[u8; 43]) -> String {
        encode_orchard_only_ua_with_padding(hrp, hrp, receiver)
    }

    #[test]
    fn roundtrip_orchard_receiver_bytes() {
        let hrp = "jtest";
        let mut receiver = [0u8; 43];
        for (i, b) in receiver.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(3).wrapping_add(1);
        }

        let ua = encode_orchard_only_ua(hrp, &receiver);
        let decoded = orchard_receiver_bytes_from_unified_address(&ua).unwrap();
        assert_eq!(decoded, receiver);
    }

    #[test]
    fn rejects_invalid_padding() {
        let hrp = "jtest";
        let receiver = [0x42u8; 43];
        let ua = encode_orchard_only_ua_with_padding(hrp, "jtesu", &receiver);
        let err = orchard_receiver_bytes_from_unified_address(&ua).unwrap_err();
        assert!(err.to_string().contains("padding"));
    }
}
