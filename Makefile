.PHONY: test test-go test-rust test-solana witness prove-ci prove-aws

test: test-go test-rust test-solana

test-go:
	go test ./...

test-rust:
	cargo test --manifest-path risc0/receipt/Cargo.toml

test-solana:
	cargo test --manifest-path solana/Cargo.toml

witness:
	go run ./cmd/juno-intents witness

prove-ci:
	go run ./cmd/juno-intents prove-ci

prove-aws:
	scripts/aws/prove-groth16.sh
