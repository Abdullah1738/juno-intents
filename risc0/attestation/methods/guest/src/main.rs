use risc0_zkvm::guest::env;

fn main() {
    let witness: Vec<u8> = env::read();
    let journal =
        juno_attestation_logic::attestation_journal_from_witness_v1(&witness).expect("verify attestation");
    env::commit_slice(&journal);
}

