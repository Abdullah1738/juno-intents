use risc0_zkvm::guest::env;

fn main() {
    // Input is the Go-defined ReceiptWitnessV1.MarshalBinary() bytes.
    let witness: Vec<u8> = env::read();
    let journal =
        juno_receipt_logic::receipt_journal_from_witness_v1(&witness).expect("verify witness");
    env::commit_slice(&journal);
}
