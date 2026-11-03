.PHONY: check-contracts test-contracts test-go test-provenance test-runtime gate-lab gate-control gate-agent gate-subscription gate-resilience gate-security gate-dr

check-contracts:
	npm run check:contracts

test-contracts:
	npm run test:contracts

# A schema/unit-test pass must never masquerade as a real networking-lab pass.
gate-lab: check-contracts test-contracts
	npm run gate:lab

gate-control gate-agent gate-subscription gate-resilience gate-security gate-dr:
	@echo "BLOCKED: $@ has no production qualification harness yet. See docs/implementation/status.md."
	@exit 2

# Signature and structural preflight tests use synthetic keys and no networking.
test-go:
	go test -race -count=1 ./...
	go vet ./...

# Verifies the fail-closed Sigstore provenance verifier with a mocked Cosign CLI.
test-provenance:
	bash lab/runtime/verify-provenance_test.sh

# Executes a real Sing-box server/client path in isolated Linux network namespaces.
# Run as root after building the pinned runtime and installing grpcurl.
test-runtime:
	bash lab/runtime/run-local-reality.sh
