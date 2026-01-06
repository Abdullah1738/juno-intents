.PHONY: test test-go test-rust

test: test-go test-rust

test-go:
	go test ./...

test-rust:
	cargo test --manifest-path risc0/receipt/Cargo.toml
