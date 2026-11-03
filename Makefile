.PHONY: check-contracts test-contracts test-go gate-lab gate-control gate-agent gate-subscription gate-resilience gate-security gate-dr

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
