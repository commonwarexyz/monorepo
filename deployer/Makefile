.PHONY: test test-unit test-localstack test-all clean-localstack help

# Default target
help:
	@echo "Available targets:"
	@echo "  test              - Run unit tests only"
	@echo "  test-localstack   - Run LocalStack integration tests"
	@echo "  test-all          - Run all tests (unit + LocalStack)"
	@echo "  clean-localstack  - Stop and remove LocalStack containers"
	@echo "  help              - Show this help message"

# Run unit tests only
test:
	cargo test --features aws --lib

# Run LocalStack integration tests
test-localstack:
	./scripts/test-localstack.sh

# Run all tests
test-all: test test-localstack

# Clean up LocalStack
clean-localstack:
	docker compose -f docker-compose.localstack.yml down -v
	rm -rf localstack-data