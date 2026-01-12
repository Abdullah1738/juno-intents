use juno_receipt_host::prove_receipt_groth16_bundle_v1;
use juno_receipt_logic::receipt_journal_from_witness_v1;
use std::time::Instant;

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 {
        return Err("hex string must have even length".to_string());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = (bytes[i] as char)
            .to_digit(16)
            .ok_or_else(|| format!("invalid hex char at {i}"))?;
        let lo = (bytes[i + 1] as char)
            .to_digit(16)
            .ok_or_else(|| format!("invalid hex char at {}", i + 1))?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

fn parse_selector() -> [u8; 4] {
    // Default selector used by the Verifier Router registry for Groth16 receipts.
    // Override with JUNO_RECEIPT_SELECTOR=4 ASCII bytes, e.g. "JINT".
    let default = *b"JINT";
    let Ok(sel) = std::env::var("JUNO_RECEIPT_SELECTOR") else {
        return default;
    };
    let sel = sel.as_bytes();
    if sel.len() != 4 {
        panic!("JUNO_RECEIPT_SELECTOR must be exactly 4 bytes");
    }
    [sel[0], sel[1], sel[2], sel[3]]
}

#[test]
#[ignore]
fn proves_groth16_bundle_from_real_witness_hex() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();

    if !cfg!(target_arch = "x86_64") {
        eprintln!("skipping groth16 prove: requires x86_64 host");
        return;
    }
    if !cfg!(feature = "cuda") {
        panic!("groth16_real_witness test requires --features cuda (no docker fallback)");
    }

    let witness_hex = std::env::var("JUNO_RECEIPT_WITNESS_HEX")
        .expect("set JUNO_RECEIPT_WITNESS_HEX to the v1 witness bytes (hex)");
    let witness = decode_hex(&witness_hex).expect("decode witness hex");

    let selector = parse_selector();
    let t0 = Instant::now();
    let bundle_bytes = prove_receipt_groth16_bundle_v1(witness.clone(), selector).expect("prove");
    eprintln!("prove elapsed: {:?}", t0.elapsed());

    // Basic decode checks (mirror Go and Solana parsing expectations).
    assert!(bundle_bytes.len() > 2 + 1 + 32 + 2 + 170 + 4);
    assert_eq!(u16::from_le_bytes([bundle_bytes[0], bundle_bytes[1]]), 1);
    assert_eq!(bundle_bytes[2], 1);

    let journal_len = u16::from_le_bytes([bundle_bytes[35], bundle_bytes[36]]) as usize;
    assert_eq!(journal_len, 170);

    let journal_off = 37;
    let journal_end = journal_off + journal_len;
    let journal = &bundle_bytes[journal_off..journal_end];

    let seal_len = u32::from_le_bytes([
        bundle_bytes[journal_end],
        bundle_bytes[journal_end + 1],
        bundle_bytes[journal_end + 2],
        bundle_bytes[journal_end + 3],
    ]) as usize;
    assert_eq!(seal_len, 260);

    let seal_off = journal_end + 4;
    let seal_end = seal_off + seal_len;
    assert_eq!(bundle_bytes.len(), seal_end);

    let seal = &bundle_bytes[seal_off..seal_end];
    assert_eq!(&seal[0..4], selector);

    // Journal bytes are deterministic from witness.
    let expected_journal = receipt_journal_from_witness_v1(&witness).expect("verify witness");
    assert_eq!(journal, expected_journal);
}

