

test-unit TEST="":
	cargo test --workspace --exclude ark-testing {{TEST}}

test-integration TEST="":
	cargo test --package ark-testing {{TEST}}

test: test-unit test-integration
