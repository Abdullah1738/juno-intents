use anyhow::{anyhow, bail, Context, Result};
use bech32::{primitives::decode::CheckedHrpstring, Checksum};
use byteorder::{LittleEndian, ReadBytesExt};
use clap::Parser;
use juno_receipt_logic::receipt_journal_from_witness_v1;
use orchard::{
    keys::{FullViewingKey, Scope},
    tree::MerkleHashOrchard,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader, Cursor, Read},
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};
use zcash_encoding::{CompactSize, Optional, Vector};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::{
    consensus::BranchId,
    TxId,
};

const ORCHARD_MERKLE_DEPTH: usize = 32;
const ORCHARD_MERKLE_DEPTH_U8: u8 = 32;
const RECEIPT_WITNESS_VERSION_V1: u16 = 1;

// Orchard wallet note commitment tree serialization.
const NOTE_STATE_V1: u8 = 1;

// Zcashd / JunoCash wallet DB record name.
const ORCHARD_NOTE_COMMITMENT_TREE_KEY: &str = "orchard_note_commitment_tree";

#[derive(Parser, Debug)]
#[command(name = "wallet-witness-v1")]
struct Args {
    /// Path to `junocash-cli` (defaults to `junocash-cli` in PATH).
    #[arg(long, default_value = "junocash-cli")]
    junocash_cli: String,

    /// Path to `db_dump` with support for newer wallet.dat versions.
    /// If omitted, will try `/opt/homebrew/opt/berkeley-db/bin/db_dump`, then `db_dump` in PATH.
    #[arg(long)]
    db_dump: Option<PathBuf>,

    /// Path to `wallet.dat`. If omitted on macOS, defaults to:
    /// `~/Library/Application Support/JunoCash/wallet.dat`.
    #[arg(long)]
    wallet: Option<PathBuf>,

    /// Optional: pick this txid (big-endian hex, as returned by RPC). If omitted, selects the
    /// first spendable Orchard note with amount > 0 from `z_listunspent`.
    #[arg(long)]
    txid: Option<String>,

    /// Optional: pick this Orchard action index. If omitted, selects from `z_listunspent`.
    #[arg(long)]
    action: Option<u32>,

    /// Optional: force using this Unified Address when exporting viewing keys.
    /// If omitted, selects the Unified Address corresponding to the selected note's account.
    #[arg(long)]
    unified_address: Option<String>,

    /// 32-byte hex deployment_id (public input binding).
    /// If omitted, uses sha256("JUNO_INTENTS_DEPLOYMENT_ID_V1").
    #[arg(long)]
    deployment_id: Option<String>,

    /// 32-byte hex fill_id (public input binding).
    /// If omitted, uses sha256("JUNO_INTENTS_FILL_ID_V1" || txid || action_u32_le).
    #[arg(long)]
    fill_id: Option<String>,

    /// If set, prints the witness hex to stdout (default: true).
    #[arg(long, default_value_t = true)]
    print_witness_hex: bool,
}

#[derive(Debug, Deserialize)]
struct ZListUnspentEntry {
    txid: String,
    pool: String,
    outindex: u32,
    spendable: bool,
    account: Option<u32>,
    amount: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct ListAddressesResp(Vec<ListAddressesSource>);

#[derive(Debug, Deserialize)]
struct ListAddressesSource {
    unified: Vec<ListAddressesUnifiedAccount>,
}

#[derive(Debug, Deserialize)]
struct ListAddressesUnifiedAccount {
    account: u32,
    addresses: Vec<ListAddressesUnifiedAddressEntry>,
}

#[derive(Debug, Deserialize)]
struct ListAddressesUnifiedAddressEntry {
    address: String,
}

#[derive(Debug, Deserialize)]
struct GetBlockTxRespV2 {
    txid: String,
    hex: String,
}

#[derive(Debug, Deserialize)]
struct GetBlockRespV2 {
    tx: Vec<GetBlockTxRespV2>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let wallet_path = args
        .wallet
        .clone()
        .or_else(default_wallet_dat_path)
        .ok_or_else(|| anyhow!("--wallet is required on this platform"))?;

    let db_dump = args
        .db_dump
        .clone()
        .or_else(default_db_dump_path)
        .unwrap_or_else(|| PathBuf::from("db_dump"));

    let (selected_txid, selected_action, selected_account) = select_outpoint(&args)?;

    let ua = match args.unified_address.clone() {
        Some(ua) => ua,
        None => unified_address_for_account(&args, selected_account)
            .context("select unified address for note account")?,
    };

    let viewkey_str = junocash_cli_string(&args, &["z_exportviewingkey", &ua])
        .context("junocash-cli z_exportviewingkey")?
        .trim()
        .to_string();

    let orchard_fvk = orchard_fvk_from_unified_viewing_key(&viewkey_str)
        .context("decode orchard fvk from unified viewing key")?;

    let (cmx_bytes, receiver_bytes, amount_u64, rho_bytes, rseed_bytes) =
        note_opening_from_tx(&args, &orchard_fvk, &selected_txid, selected_action)
            .context("extract note opening from tx")?;

    let (orchard_root, merkle_index, merkle_siblings) =
        match merkle_path_from_wallet(&wallet_path, &db_dump, &selected_txid, selected_action) {
            Ok(v) => v,
            Err(err) => {
                eprintln!(
                    "wallet merkle path extraction failed; falling back to chain scan: {:#}",
                    err
                );
                merkle_path_from_chain(&args, &selected_txid, selected_action)
                    .context("extract merkle path from chain")?
            }
        };

    let deployment_id = match args.deployment_id.as_deref() {
        Some(hex32) => parse_hex_32(hex32).context("parse --deployment-id")?,
        None => Sha256::digest(b"JUNO_INTENTS_DEPLOYMENT_ID_V1").into(),
    };

    let fill_id = match args.fill_id.as_deref() {
        Some(hex32) => parse_hex_32(hex32).context("parse --fill-id")?,
        None => {
            let mut h = Sha256::new();
            h.update(b"JUNO_INTENTS_FILL_ID_V1");
            h.update(selected_txid.as_ref());
            h.update(selected_action.to_le_bytes());
            h.finalize().into()
        }
    };

    let witness_bytes = build_receipt_witness_v1(
        deployment_id,
        fill_id,
        orchard_root,
        cmx_bytes,
        receiver_bytes,
        amount_u64,
        rho_bytes,
        rseed_bytes,
        merkle_index,
        merkle_siblings,
    )?;

    // Verify witness deterministically produces a valid journal.
    let journal = receipt_journal_from_witness_v1(&witness_bytes).context("verify witness")?;
    eprintln!("witness ok (journal_len={} bytes)", journal.len());

    if args.print_witness_hex {
        println!("{}", hex::encode(&witness_bytes));
    }

    Ok(())
}

fn default_wallet_dat_path() -> Option<PathBuf> {
    // macOS default location for junocashd.
    let home = std::env::var_os("HOME")?;
    let mut p = PathBuf::from(home);
    p.push("Library/Application Support/JunoCash/wallet.dat");
    if p.exists() {
        Some(p)
    } else {
        None
    }
}

fn default_db_dump_path() -> Option<PathBuf> {
    let p = PathBuf::from("/opt/homebrew/opt/berkeley-db/bin/db_dump");
    if p.exists() {
        Some(p)
    } else {
        None
    }
}

fn select_outpoint(args: &Args) -> Result<(TxId, u32, u32)> {
    if let (Some(txid_hex), Some(action)) = (&args.txid, args.action) {
        let txid = txid_from_rpc_hex(txid_hex)?;
        if args.unified_address.is_some() {
            // For outgoing proofs, the txid+action may not be present in z_listunspent. In that
            // case, require --unified-address (so we can derive FVK/OVK) and skip account lookup.
            return Ok((txid, action, 0));
        }
        let account = select_account_for_outpoint(args, &txid, action)?;
        return Ok((txid, action, account));
    }

    let outpoint = select_first_unspent_orchard_note(args)?;
    let txid = txid_from_rpc_hex(&outpoint.txid)?;
    let account = outpoint.account.unwrap_or(0);
    Ok((txid, outpoint.outindex, account))
}

fn select_first_unspent_orchard_note(args: &Args) -> Result<ZListUnspentEntry> {
    let raw = junocash_cli_string(args, &["z_listunspent", "1", "9999999", "false"])?;
    let notes: Vec<ZListUnspentEntry> =
        serde_json::from_str(&raw).context("parse z_listunspent JSON")?;
    notes
        .into_iter()
        .find(|n| n.pool == "orchard" && n.spendable && note_amount_nonzero(&n.amount))
        .ok_or_else(|| anyhow!("no spendable orchard notes with amount > 0 found"))
}

fn select_account_for_outpoint(args: &Args, txid: &TxId, action: u32) -> Result<u32> {
    let raw = junocash_cli_string(args, &["z_listunspent", "1", "9999999", "false"])?;
    let notes: Vec<ZListUnspentEntry> =
        serde_json::from_str(&raw).context("parse z_listunspent JSON")?;
    notes
        .into_iter()
        .find(|n| {
            n.pool == "orchard"
                && n.outindex == action
                && txid_from_rpc_hex(&n.txid).ok().as_ref() == Some(txid)
        })
        .and_then(|n| n.account)
        .ok_or_else(|| anyhow!("could not determine account for txid+action; pass --unified-address"))
}

fn unified_address_for_account(args: &Args, account: u32) -> Result<String> {
    let raw = junocash_cli_string(args, &["listaddresses"])?;
    let resp: ListAddressesResp = serde_json::from_str(&raw).context("parse listaddresses JSON")?;
    for src in resp.0 {
        for ua in src.unified {
            if ua.account != account {
                continue;
            }
            if let Some(first) = ua.addresses.first() {
                return Ok(first.address.clone());
            }
        }
    }
    bail!("no unified address found for account {}", account);
}

fn note_opening_from_tx(
    args: &Args,
    fvk: &FullViewingKey,
    txid: &TxId,
    action_idx: u32,
) -> Result<([u8; 32], [u8; 43], u64, [u8; 32], [u8; 32])> {
    let txid_rpc = txid_to_rpc_hex(txid);
    // `gettransaction` is disabled in newer JunoCash/zcashd builds; use raw tx bytes instead.
    let raw_hex = junocash_cli_string(args, &["getrawtransaction", &txid_rpc, "0"])
        .context("junocash-cli getrawtransaction")?;
    let tx_hex = raw_hex.trim().trim_matches('"');
    let tx_bytes = hex::decode(tx_hex).context("decode tx hex")?;
    let parsed = Transaction::read(Cursor::new(tx_bytes), BranchId::Nu5)
        .context("parse transaction bytes")?;
    let data = parsed.into_data();
    let bundle = data
        .orchard_bundle()
        .ok_or_else(|| anyhow!("transaction has no orchard bundle"))?;

    let action = bundle
        .actions()
        .get(action_idx as usize)
        .ok_or_else(|| anyhow!("orchard action index {} out of range", action_idx))?;

    let ivk_external = fvk.to_ivk(Scope::External);
    let ivk_internal = fvk.to_ivk(Scope::Internal);

    let ovk_external = fvk.to_ovk(Scope::External);
    let ovk_internal = fvk.to_ovk(Scope::Internal);

    let try_incoming = |ivk| {
        bundle
            .decrypt_output_with_key(action_idx as usize, ivk)
            .map(|(n, a, _m)| (n, a))
    };
    let try_outgoing = |ovk| {
        bundle
            .recover_output_with_ovk(action_idx as usize, ovk)
            .map(|(n, a, _m)| (n, a))
    };

    let (note, recipient, decrypted_kind) = try_incoming(&ivk_external)
        .or_else(|| try_incoming(&ivk_internal))
        .map(|(n, a)| (n, a, "incoming"))
        .or_else(|| {
            try_outgoing(&ovk_external)
                .or_else(|| try_outgoing(&ovk_internal))
                .map(|(n, a)| (n, a, "outgoing"))
        })
        .ok_or_else(|| anyhow!("failed to decrypt/recover orchard output at action {}", action_idx))?;
    eprintln!("decrypted orchard output via {decrypted_kind} key");

    let cmx = action.cmx().to_bytes();
    let computed_cmx = orchard::note::ExtractedNoteCommitment::from(note.commitment()).to_bytes();
    if computed_cmx != cmx {
        bail!("decrypted note commitment does not match action cmx");
    }

    let receiver_bytes = recipient.to_raw_address_bytes();
    let amount = note.value().inner();
    let rho = note.rho().to_bytes();
    let rseed = *note.rseed().as_bytes();

    Ok((cmx, receiver_bytes, amount, rho, rseed))
}

fn merkle_path_from_wallet(
    wallet_path: &Path,
    db_dump: &Path,
    txid: &TxId,
    action_idx: u32,
) -> Result<([u8; 32], u32, [[u8; 32]; ORCHARD_MERKLE_DEPTH])> {
    let record = wallet_record_bytes(wallet_path, db_dump, ORCHARD_NOTE_COMMITMENT_TREE_KEY)
        .context("extract orchard_note_commitment_tree record")?;

    let (tree, positions) = parse_orchard_note_commitment_tree(&record)
        .context("parse orchard note commitment tree record")?;

    let position = positions
        .get(&(txid_to_bytes_internal(txid), action_idx))
        .copied()
        .ok_or_else(|| anyhow!("note position not found in wallet tree for txid+action"))?;

    let merkle_index_u64: u64 = position.into();
    let merkle_index_u32: u32 = merkle_index_u64
        .try_into()
        .map_err(|_| anyhow!("note position exceeds u32: {}", merkle_index_u64))?;

    let auth_path = tree
        .witness(position, 0)
        .map_err(|e| anyhow!("witness unavailable at depth 0: {e:?}"))?;
    if auth_path.len() != ORCHARD_MERKLE_DEPTH {
        bail!(
            "unexpected orchard auth path len: got {}, want {}",
            auth_path.len(),
            ORCHARD_MERKLE_DEPTH
        );
    }

    let root = tree
        .root(0)
        .ok_or_else(|| anyhow!("wallet tree has no root at checkpoint depth 0"))?;

    let mut siblings = [[0u8; 32]; ORCHARD_MERKLE_DEPTH];
    for (i, sib) in auth_path.iter().enumerate() {
        siblings[i] = sib.to_bytes();
    }

    Ok((root.to_bytes(), merkle_index_u32, siblings))
}

fn merkle_path_from_chain(
    args: &Args,
    txid: &TxId,
    action_idx: u32,
) -> Result<([u8; 32], u32, [[u8; 32]; ORCHARD_MERKLE_DEPTH])> {
    let tip_height: u32 = junocash_cli_string(args, &["getblockcount"])
        .context("junocash-cli getblockcount")?
        .trim()
        .parse()
        .context("parse getblockcount")?;

    let mut tree: bridgetree::BridgeTree<MerkleHashOrchard, u32, ORCHARD_MERKLE_DEPTH_U8> =
        bridgetree::BridgeTree::new(1);
    let mut marked_pos: Option<incrementalmerkletree::Position> = None;

    for height in 0..=tip_height {
        let bh = junocash_cli_string(args, &["getblockhash", &height.to_string()])
            .context("junocash-cli getblockhash")?
            .trim()
            .to_string();

        let block_raw = junocash_cli_string(args, &["getblock", &bh, "2"])
            .context("junocash-cli getblock")?;
        let block: GetBlockRespV2 = serde_json::from_str(&block_raw).context("parse getblock JSON")?;

        for tx in block.tx {
            let cur_txid = txid_from_rpc_hex(&tx.txid).context("parse txid")?;
            let tx_bytes = hex::decode(tx.hex.trim()).context("decode tx hex")?;

            let parsed = Transaction::read(Cursor::new(tx_bytes), BranchId::Nu5)
                .context("parse transaction bytes")?;
            let data = parsed.into_data();
            let Some(bundle) = data.orchard_bundle() else {
                continue;
            };

            for (i, action) in bundle.actions().iter().enumerate() {
                let leaf = MerkleHashOrchard::from_cmx(action.cmx());
                if !tree.append(leaf) {
                    bail!("orchard note commitment tree overflow");
                }

                if cur_txid == *txid && i as u32 == action_idx {
                    if marked_pos.is_some() {
                        bail!("duplicate (txid, action) match while scanning chain");
                    }
                    marked_pos = tree.mark();
                }
            }
        }
    }

    let position = marked_pos.ok_or_else(|| anyhow!("target orchard action not found when scanning chain"))?;

    let merkle_index_u64: u64 = position.into();
    let merkle_index_u32: u32 = merkle_index_u64
        .try_into()
        .map_err(|_| anyhow!("note position exceeds u32: {}", merkle_index_u64))?;

    let auth_path = tree
        .witness(position, 0)
        .map_err(|e| anyhow!("witness unavailable at depth 0: {e:?}"))?;
    if auth_path.len() != ORCHARD_MERKLE_DEPTH {
        bail!(
            "unexpected orchard auth path len: got {}, want {}",
            auth_path.len(),
            ORCHARD_MERKLE_DEPTH
        );
    }

    let root = tree
        .root(0)
        .ok_or_else(|| anyhow!("chain-derived tree has no root at checkpoint depth 0"))?;

    let mut siblings = [[0u8; 32]; ORCHARD_MERKLE_DEPTH];
    for (i, sib) in auth_path.iter().enumerate() {
        siblings[i] = sib.to_bytes();
    }

    Ok((root.to_bytes(), merkle_index_u32, siblings))
}

fn build_receipt_witness_v1(
    deployment_id: [u8; 32],
    fill_id: [u8; 32],
    orchard_root: [u8; 32],
    cmx: [u8; 32],
    receiver_bytes: [u8; 43],
    amount: u64,
    rho: [u8; 32],
    rseed: [u8; 32],
    merkle_index: u32,
    merkle_siblings: [[u8; 32]; ORCHARD_MERKLE_DEPTH],
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(
        2 + 32 + 32 + 32 + 32 + 43 + 8 + 32 + 32 + 4 + ORCHARD_MERKLE_DEPTH * 32,
    );
    out.extend_from_slice(&RECEIPT_WITNESS_VERSION_V1.to_le_bytes());
    out.extend_from_slice(&deployment_id);
    out.extend_from_slice(&fill_id);
    out.extend_from_slice(&orchard_root);
    out.extend_from_slice(&cmx);
    out.extend_from_slice(&receiver_bytes);
    out.extend_from_slice(&amount.to_le_bytes());
    out.extend_from_slice(&rho);
    out.extend_from_slice(&rseed);
    out.extend_from_slice(&merkle_index.to_le_bytes());
    for sib in merkle_siblings {
        out.extend_from_slice(&sib);
    }
    Ok(out)
}

struct TempDirGuard {
    path: PathBuf,
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct WalletDumpContext {
    dump_wallet_path: PathBuf,
    dump_home: Option<PathBuf>,
    _temp_guard: Option<TempDirGuard>,
}

fn prepare_wallet_dump(wallet_path: &Path) -> Result<WalletDumpContext> {
    let wallet_dir = wallet_path
        .parent()
        .ok_or_else(|| anyhow!("wallet path has no parent dir: {}", wallet_path.display()))?;

    let log_dir = wallet_dir.join("database");
    let mut has_logs = false;
    if log_dir.is_dir() {
        if let Ok(rd) = fs::read_dir(&log_dir) {
            for e in rd.flatten() {
                let name = e.file_name();
                if name.to_string_lossy().starts_with("log.") {
                    has_logs = true;
                    break;
                }
            }
        }
    }

    if !has_logs {
        return Ok(WalletDumpContext {
            dump_wallet_path: wallet_path.to_path_buf(),
            dump_home: None,
            _temp_guard: None,
        });
    }

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tmp_home = std::env::temp_dir().join(format!("juno-walletdump-{}-{}", std::process::id(), nanos));
    let tmp_log_dir = tmp_home.join("database");
    fs::create_dir_all(&tmp_log_dir).context("create temp wallet dump dirs")?;

    let wallet_filename = wallet_path
        .file_name()
        .ok_or_else(|| anyhow!("wallet path has no filename: {}", wallet_path.display()))?;
    let tmp_wallet_path = tmp_home.join(wallet_filename);
    fs::copy(wallet_path, &tmp_wallet_path).context("copy wallet.dat to temp dir")?;

    if let Ok(rd) = fs::read_dir(&log_dir) {
        for e in rd {
            let e = e?;
            let ft = e.file_type()?;
            if !ft.is_file() {
                continue;
            }
            let name = e.file_name();
            if !name.to_string_lossy().starts_with("log.") {
                continue;
            }
            fs::copy(e.path(), tmp_log_dir.join(name)).context("copy bdb log file")?;
        }
    }

    // Ensure db_dump can locate the log directory, matching the daemon's `set_lg_dir(database)`.
    fs::write(tmp_home.join("DB_CONFIG"), b"set_lg_dir database\n").context("write DB_CONFIG")?;

    Ok(WalletDumpContext {
        dump_wallet_path: tmp_wallet_path,
        dump_home: Some(tmp_home.clone()),
        _temp_guard: Some(TempDirGuard { path: tmp_home }),
    })
}

fn wallet_record_bytes(wallet_path: &Path, db_dump: &Path, record_name: &str) -> Result<Vec<u8>> {
    let ctx = prepare_wallet_dump(wallet_path)?;

    let mut cmd = Command::new(db_dump);
    if let Some(home) = &ctx.dump_home {
        cmd.arg("-R").arg("-h").arg(home);
    }

    let mut child = cmd
        .arg(&ctx.dump_wallet_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawn db_dump at {}", db_dump.display()))?;

    let stdout = child.stdout.take().expect("stdout piped");
    let mut reader = BufReader::new(stdout);

    // Skip header.
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        if line.trim_end() == "HEADER=END" {
            break;
        }
    }

    let target = record_name.as_bytes();
    let mut key_line = String::new();
    let mut val_line = String::new();

    loop {
        key_line.clear();
        if reader.read_line(&mut key_line)? == 0 {
            break;
        }
        let key_line_trim = key_line.trim();
        if key_line_trim == "DATA=END" {
            break;
        }

        val_line.clear();
        reader.read_line(&mut val_line)?;
        let val_line_trim = val_line.trim();

        let key_bytes = hex::decode(key_line_trim).ok();
        let Some(key_bytes) = key_bytes else { continue };

        let mut cur = Cursor::new(&key_bytes);
        let len_u64 = match CompactSize::read(&mut cur) {
            Ok(n) => n,
            Err(_) => continue,
        };
        let Ok(len) = usize::try_from(len_u64) else { continue };
        let mut s = vec![0u8; len];
        if cur.read_exact(&mut s).is_err() {
            continue;
        }
        if cur.position() != key_bytes.len() as u64 {
            continue;
        }
        if s.as_slice() != target {
            continue;
        }

        let data = hex::decode(val_line_trim).context("decode record hex")?;
        // Ensure we stop db_dump quickly.
        let _ = child.kill();
        let _ = child.wait();
        return Ok(data);
    }

    let out = child.wait_with_output()?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    bail!(
        "record {} not found in wallet.dat (db_dump stderr: {})",
        record_name,
        stderr.trim()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("{}-{}", name, nanos))
    }

    #[test]
    fn prepare_wallet_dump_uses_temp_home_when_bdb_logs_present() {
        let root = mk_temp_dir("juno-walletdump-test");
        let wallet_dir = root.join("testnet3");
        let log_dir = wallet_dir.join("database");
        fs::create_dir_all(&log_dir).unwrap();
        fs::write(wallet_dir.join("wallet.dat"), b"wallet").unwrap();
        fs::write(log_dir.join("log.0000000001"), b"log").unwrap();

        let ctx = prepare_wallet_dump(&wallet_dir.join("wallet.dat")).unwrap();
        assert!(ctx.dump_home.is_some());
        let home = ctx.dump_home.as_ref().unwrap();
        assert!(home.join("DB_CONFIG").exists());
        let cfg = fs::read_to_string(home.join("DB_CONFIG")).unwrap();
        assert!(cfg.contains("set_lg_dir database"));
        assert!(home.join("database").join("log.0000000001").exists());
        assert!(ctx.dump_wallet_path.exists());

        drop(ctx);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn prepare_wallet_dump_passthrough_when_no_logs_present() {
        let root = mk_temp_dir("juno-walletdump-test-nolog");
        fs::create_dir_all(&root).unwrap();
        let wallet = root.join("wallet.dat");
        fs::write(&wallet, b"wallet").unwrap();

        let ctx = prepare_wallet_dump(&wallet).unwrap();
        assert!(ctx.dump_home.is_none());
        assert_eq!(ctx.dump_wallet_path, wallet);

        drop(ctx);
        let _ = fs::remove_dir_all(&root);
    }
}

fn parse_orchard_note_commitment_tree(
    bytes: &[u8],
) -> Result<(
    bridgetree::BridgeTree<MerkleHashOrchard, u32, ORCHARD_MERKLE_DEPTH_U8>,
    BTreeMap<([u8; 32], u32), incrementalmerkletree::Position>,
)> {
    let mut prefix_len = 0usize;
    if bytes.first().copied() != Some(NOTE_STATE_V1) && bytes.get(4).copied() == Some(NOTE_STATE_V1)
    {
        // Some wallet.dat formats prefix values with a 4-byte little-endian serialization version
        // (e.g. 0x0001627e), followed by the Rust-serialized note state.
        prefix_len = 4;
    }

    let mut cursor = Cursor::new(&bytes[prefix_len..]);
    let version = cursor.read_u8().context("read note state version")?;
    if version != NOTE_STATE_V1 {
        bail!("unsupported note state version: {}", version);
    }

    // last_checkpoint: Option<u32le> (block height)
    let _last_checkpoint: Option<u32> =
        Optional::read(&mut cursor, |r| r.read_u32::<LittleEndian>())
    .context("read last checkpoint")?;

    let tree =
        read_tree::<MerkleHashOrchard, ORCHARD_MERKLE_DEPTH_U8, _>(&mut cursor).context("read tree")?;

    // note positions
    let positions_vec: Vec<Vec<(([u8; 32], u32), incrementalmerkletree::Position)>> =
        Vector::read_collected(&mut cursor, |mut r| {
            let txid = TxId::read(&mut r)?;
            let _tx_height = r.read_u32::<LittleEndian>()?;
            let note_positions: Vec<(u32, incrementalmerkletree::Position)> =
                Vector::read_collected(&mut r, |mut rr| {
                    let action_idx = rr.read_u32::<LittleEndian>()?;
                    let pos = zcash_primitives::merkle_tree::read_position(&mut rr)?;
                    Ok((action_idx, pos))
                })?;

            let mut out = vec![];
            for (action_idx, pos) in note_positions {
                out.push(((txid_to_bytes_internal(&txid), action_idx), pos));
            }
            Ok(out)
        })
        .map_err(|e| anyhow!("read note positions: {e}"))?;

    let positions: BTreeMap<([u8; 32], u32), incrementalmerkletree::Position> =
        positions_vec.into_iter().flatten().collect();

    Ok((tree, positions))
}

// ---- Unified viewing key decoding (ZIP 316 / Bech32m + F4Jumble) ----

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Bech32mZip316 {}

impl Checksum for Bech32mZip316 {
    type MidstateRepr = <bech32::Bech32m as Checksum>::MidstateRepr;
    const CODE_LENGTH: usize = 4_194_368;
    const CHECKSUM_LENGTH: usize = bech32::Bech32m::CHECKSUM_LENGTH;
    const GENERATOR_SH: [u32; 5] = bech32::Bech32m::GENERATOR_SH;
    const TARGET_RESIDUE: u32 = bech32::Bech32m::TARGET_RESIDUE;
}

fn orchard_fvk_from_unified_viewing_key(viewkey: &str) -> Result<FullViewingKey> {
    let parsed = CheckedHrpstring::new::<Bech32mZip316>(viewkey)
        .map_err(|e| anyhow!("invalid unified viewing key bech32m: {e}"))?;
    let hrp_binding = parsed.hrp();
    let hrp = hrp_binding.as_str();
    let mut data = parsed.byte_iter().collect::<Vec<u8>>();

    f4jumble::f4jumble_inv_mut(&mut data).context("f4jumble inverse")?;

    if hrp.len() > 16 {
        bail!("invalid HRP length for unified viewing key: {}", hrp.len());
    }
    let mut expected_padding = [0u8; 16];
    expected_padding[..hrp.len()].copy_from_slice(hrp.as_bytes());
    if data.len() < 16 {
        bail!("unified viewing key too short");
    }
    let (encoded, tail) = data.split_at(data.len() - 16);
    if tail != expected_padding {
        bail!("invalid unified viewing key padding bytes");
    }

    let items = parse_unified_items(encoded)?;
    // Orchard typecode = 0x03 in ZIP 316.
    let orchard = items
        .into_iter()
        .find(|(typecode, _data)| *typecode == 0x03)
        .ok_or_else(|| anyhow!("unified viewing key has no orchard component"))?;
    let raw: [u8; 96] = orchard
        .1
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("orchard component has wrong length"))?;

    FullViewingKey::from_bytes(&raw).ok_or_else(|| anyhow!("invalid orchard full viewing key"))
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

// ---- junocash-cli helpers ----

fn junocash_cli_string(args: &Args, argv: &[&str]) -> Result<String> {
    let out = Command::new(&args.junocash_cli)
        .args(argv)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("run {} {}", args.junocash_cli, argv.join(" ")))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        bail!("junocash-cli failed: {}", stderr.trim());
    }
    Ok(String::from_utf8(out.stdout).context("junocash-cli stdout not utf8")?)
}

fn note_amount_nonzero(v: &serde_json::Value) -> bool {
    // `z_listunspent` encodes amounts as JSON numbers (decimal), but we just need to exclude 0.
    match v {
        serde_json::Value::Number(n) => n.as_f64().map(|f| f > 0.0).unwrap_or(false),
        _ => false,
    }
}

// ---- txid parsing ----

fn txid_from_rpc_hex(s: &str) -> Result<TxId> {
    let mut bytes: [u8; 32] = parse_hex_32(s).context("parse txid hex")?;
    bytes.reverse(); // RPC hex is byte-reversed relative to internal TxId bytes.
    Ok(TxId::from_bytes(bytes))
}

fn txid_to_rpc_hex(txid: &TxId) -> String {
    let mut b = txid.as_ref().to_vec();
    b.reverse();
    hex::encode(b)
}

fn txid_to_bytes_internal(txid: &TxId) -> [u8; 32] {
    *txid.as_ref()
}

fn parse_hex_32(s: &str) -> Result<[u8; 32]> {
    let s = s.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).context("decode hex")?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("expected 32 bytes, got {}", bytes.len()))?;
    Ok(arr)
}

// ---- Merkle tree parsing (compatible with zcashd/junocashd wallet format) ----

const SER_V1: u8 = 1;
const SER_V2: u8 = 2;
const SER_V3: u8 = 3;

fn read_tree<H: incrementalmerkletree::Hashable + zcash_primitives::merkle_tree::HashSer + Ord + Clone, const DEPTH: u8, R: std::io::Read>(
    mut reader: R,
) -> std::io::Result<bridgetree::BridgeTree<H, u32, DEPTH>> {
    use incrementalmerkletree::Position;
    use std::collections::BTreeMap;

    let tree_version = reader.read_u8()?;
    let prior_bridges = Vector::read(&mut reader, |r| read_bridge(r, tree_version))?;
    let current_bridge = Optional::read(&mut reader, |r| read_bridge(r, tree_version))?;
    let saved: BTreeMap<Position, usize> = Vector::read_collected(&mut reader, |mut r| {
        Ok((
            zcash_primitives::merkle_tree::read_position(&mut r)?,
            zcash_primitives::merkle_tree::read_leu64_usize(&mut r)?,
        ))
    })?;

    let checkpoints = match tree_version {
        SER_V1 => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "SER_V1 tree checkpoints not supported",
        )),
        SER_V2 => {
            let mut fake_checkpoint_id = 0u32;
            Vector::read_collected_mut(&mut reader, |r| {
                fake_checkpoint_id += 1;
                read_checkpoint_v2(r, fake_checkpoint_id)
            })
        }
        SER_V3 => Vector::read_collected(&mut reader, |r| read_checkpoint_v3(r)),
        other => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unrecognized tree serialization version: {other}"),
        )),
    }?;
    let max_checkpoints = zcash_primitives::merkle_tree::read_leu64_usize(&mut reader)?;

    bridgetree::BridgeTree::from_parts(
        prior_bridges,
        current_bridge,
        saved,
        checkpoints,
        max_checkpoints,
    )
    .map_err(|err| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("tree consistency violation: {:?}", err),
        )
    })
}

fn read_bridge<H: zcash_primitives::merkle_tree::HashSer + Ord + Clone, R: std::io::Read>(
    mut reader: R,
    tree_version: u8,
) -> std::io::Result<bridgetree::MerkleBridge<H>> {
    match tree_version {
        SER_V2 => read_bridge_v1(&mut reader),
        SER_V3 => match reader.read_u8()? {
            #[cfg(test)]
            SER_V1 => read_bridge_v1(&mut reader),
            SER_V2 => read_bridge_v2(&mut reader),
            flag => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unrecognized bridge serialization version: {:?}", flag),
            )),
        },
        other => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unrecognized tree serialization version: {:?}", other),
        )),
    }
}

fn read_auth_fragment_v1<H: zcash_primitives::merkle_tree::HashSer, R: std::io::Read>(
    mut reader: R,
) -> std::io::Result<(incrementalmerkletree::Position, usize, Vec<H>)> {
    let position = zcash_primitives::merkle_tree::read_position(&mut reader)?;
    let alts_observed = zcash_primitives::merkle_tree::read_leu64_usize(&mut reader)?;
    let values = Vector::read(&mut reader, |r| H::read(r))?;
    Ok((position, alts_observed, values))
}

fn read_bridge_v1<H: zcash_primitives::merkle_tree::HashSer + Ord + Clone, R: std::io::Read>(
    mut reader: R,
) -> std::io::Result<bridgetree::MerkleBridge<H>> {
    use incrementalmerkletree::{Address, Level, Position};
    use std::collections::{BTreeMap, BTreeSet};

    fn levels_required(pos: Position) -> impl Iterator<Item = Level> {
        (0u8..64).filter_map(move |i| {
            if u64::from(pos) == 0 || u64::from(pos) & (1 << i) == 0 {
                Some(Level::from(i))
            } else {
                None
            }
        })
    }

    let prior_position = Optional::read(&mut reader, zcash_primitives::merkle_tree::read_position)?;
    let fragments = Vector::read(&mut reader, |mut r| {
        let fragment_position = zcash_primitives::merkle_tree::read_position(&mut r)?;
        let (pos, levels_observed, values) = read_auth_fragment_v1(r)?;
        if fragment_position == pos {
            Ok((pos, levels_observed, values))
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "auth fragment position mismatch",
            ))
        }
    })?;

    let frontier = zcash_primitives::merkle_tree::read_nonempty_frontier_v1(&mut reader)?;
    let mut tracking = BTreeSet::new();
    let mut ommers = BTreeMap::new();
    for (pos, levels_observed, values) in fragments.into_iter() {
        let levels = levels_required(pos)
            .take(levels_observed + 1)
            .collect::<Vec<_>>();
        tracking.insert(Address::above_position(*levels.last().unwrap(), pos));
        for (level, ommer_value) in levels
            .into_iter()
            .rev()
            .skip(1)
            .zip(values.into_iter().rev())
        {
            let ommer_address = Address::above_position(level, pos).sibling();
            ommers.insert(ommer_address, ommer_value);
        }
    }

    Ok(bridgetree::MerkleBridge::from_parts(
        prior_position,
        tracking,
        ommers,
        frontier,
    ))
}

fn read_bridge_v2<H: zcash_primitives::merkle_tree::HashSer + Ord + Clone, R: std::io::Read>(
    mut reader: R,
) -> std::io::Result<bridgetree::MerkleBridge<H>> {
    let prior_position = Optional::read(&mut reader, zcash_primitives::merkle_tree::read_position)?;
    let tracking = Vector::read_collected(&mut reader, |r| zcash_primitives::merkle_tree::read_address(r))?;
    let ommers = Vector::read_collected(&mut reader, |mut r| {
        let addr = zcash_primitives::merkle_tree::read_address(&mut r)?;
        let value = H::read(&mut r)?;
        Ok((addr, value))
    })?;
    let frontier = zcash_primitives::merkle_tree::read_nonempty_frontier_v1(&mut reader)?;
    Ok(bridgetree::MerkleBridge::from_parts(
        prior_position,
        tracking,
        ommers,
        frontier,
    ))
}

fn read_checkpoint_v2<R: std::io::Read>(
    mut reader: R,
    checkpoint_id: u32,
) -> std::io::Result<bridgetree::Checkpoint<u32>> {
    let bridges_len = zcash_primitives::merkle_tree::read_leu64_usize(&mut reader)?;
    let _ = reader.read_u8()? == 1; // legacy is_marked flag
    let marked = Vector::read_collected(&mut reader, |r| zcash_primitives::merkle_tree::read_position(r))?;
    let forgotten = Vector::read_collected(&mut reader, |mut r| {
        let pos = zcash_primitives::merkle_tree::read_position(&mut r)?;
        let _ = zcash_primitives::merkle_tree::read_leu64_usize(&mut r)?;
        Ok(pos)
    })?;
    Ok(bridgetree::Checkpoint::from_parts(
        checkpoint_id,
        bridges_len,
        marked,
        forgotten,
    ))
}

fn read_checkpoint_v3<R: std::io::Read>(mut reader: R) -> std::io::Result<bridgetree::Checkpoint<u32>> {
    Ok(bridgetree::Checkpoint::from_parts(
        reader.read_u32::<LittleEndian>()?,
        zcash_primitives::merkle_tree::read_leu64_usize(&mut reader)?,
        Vector::read_collected(&mut reader, |r| zcash_primitives::merkle_tree::read_position(r))?,
        Vector::read_collected(&mut reader, |r| zcash_primitives::merkle_tree::read_position(r))?,
    ))
}
