# Juno Intents

Non-custodial intents bridge between JunoCash (Orchard-only) and Solana.

## High-level flow

1. TEE operators publish finalized JunoCash Orchard checkpoints to Solana.
2. A user creates an intent on Solana; a solver fills it by locking funds in escrow.
3. The required Orchard payment happens on JunoCash.
4. A prover generates a ZK receipt proving that payment exists under a finalized checkpoint.
5. The receipt settles the fill on Solana and releases escrow; otherwise funds refund after expiry.

## Testing

- Unit tests: `make test`
- E2E (Solana devnet + local JunoCash testnet): `scripts/e2e/devnet-testnet.sh --deployment <name>`
- E2E (TEE + CRP v2): run the `e2e-devnet` GitHub Action with `crp_mode=v2` and `deployment=devnet-tee-testnet-base`
