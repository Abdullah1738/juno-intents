.PHONY: test test-go test-rust test-solana

test: test-go test-rust test-solana

test-go:
	go test ./...

test-rust:
	cargo test --manifest-path risc0/receipt/Cargo.toml

test-solana:
	cargo test --manifest-path solana/Cargo.toml
