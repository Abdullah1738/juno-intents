.PHONY: test test-go test-rust test-solana witness witness-ci set-witness-secret prove-ci prove-ci-secret prove-aws prove-aws-real prove-aws-synthetic regtest-up regtest-down regtest-witness

test: test-go test-rust test-solana

test-go:
	go test ./...

test-rust:
	cargo test --manifest-path risc0/receipt/Cargo.toml

test-solana:
	cargo test --manifest-path solana/Cargo.toml

witness:
	go run ./cmd/juno-intents witness

witness-ci:
	go run ./cmd/juno-intents witness-ci

set-witness-secret:
	go run ./cmd/juno-intents set-witness-secret

prove-ci:
	go run ./cmd/juno-intents prove-ci

prove-ci-secret:
	go run ./cmd/juno-intents prove-ci --witness-source secret

prove-aws:
	scripts/aws/prove-groth16.sh

prove-aws-real:
	JUNO_PROVE_MODE=real scripts/aws/prove-groth16.sh

prove-aws-synthetic:
	JUNO_PROVE_MODE=synthetic scripts/aws/prove-groth16.sh

regtest-up:
	scripts/junocash/regtest/up.sh

regtest-down:
	scripts/junocash/regtest/down.sh

regtest-witness:
	scripts/junocash/regtest/witness-hex.sh
