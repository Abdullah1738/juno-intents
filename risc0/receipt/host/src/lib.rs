use anyhow::Context;
use risc0_zkvm::{
    default_executor, default_prover, ExecutorEnv, ExitCode, ProverOpts, Receipt, VerifierContext,
};

use juno_receipt_methods::{RECEIPT_VERIFY_ELF, RECEIPT_VERIFY_ID};

pub fn prove_receipt_journal(witness_bytes: Vec<u8>) -> anyhow::Result<Receipt> {
    prove_receipt_journal_with_opts(witness_bytes, &ProverOpts::default())
}

pub fn execute_receipt_journal(witness_bytes: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    let env = ExecutorEnv::builder()
        .write(&witness_bytes)
        .context("failed to write witness bytes")?
        .build()
        .context("failed to build executor env")?;

    let executor = default_executor();
    let session = executor.execute(env, RECEIPT_VERIFY_ELF).context("execute failed")?;

    if session.exit_code != ExitCode::Halted(0) {
        anyhow::bail!("unexpected exit code: {:?}", session.exit_code);
    }

    Ok(session.journal.bytes)
}

pub fn prove_receipt_journal_with_opts(
    witness_bytes: Vec<u8>,
    opts: &ProverOpts,
) -> anyhow::Result<Receipt> {
    let env = ExecutorEnv::builder()
        .write(&witness_bytes)
        .context("failed to write witness bytes")?
        .build()
        .context("failed to build executor env")?;

    let prover = default_prover();
    let prove_info = prover
        .prove_with_opts(env, RECEIPT_VERIFY_ELF, opts)
        .context("prove failed")?;

    let verify_res = if opts.dev_mode() {
        let ctx = VerifierContext::default().with_dev_mode(true);
        prove_info.receipt.verify_with_context(&ctx, RECEIPT_VERIFY_ID)
    } else {
        prove_info.receipt.verify(RECEIPT_VERIFY_ID)
    };
    verify_res.context("receipt verification failed")?;

    Ok(prove_info.receipt)
}
