# Deployer Tests

This directory contains integration tests for the Commonware Deployer using LocalStack to mock AWS services.

## Overview

The tests use LocalStack to provide a local AWS environment for testing EC2 deployments without incurring costs or requiring AWS credentials. This enables comprehensive testing of:

- VPC and subnet creation
- Security group management
- EC2 instance launching
- Multi-region deployments
- Key pair management
- Full deployment lifecycle

## Prerequisites

- Docker installed and running
- Rust toolchain
- Make (optional, for convenience commands)

## Running Tests

### Quick Start

```bash
# Run all tests (unit + LocalStack integration)
make test-all

# Run only LocalStack integration tests
make test-localstack

# Run only unit tests
make test
```

### Manual Testing

1. Start LocalStack:
```bash
docker compose -f docker-compose.localstack.yml up -d
```

2. Run tests:
```bash
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_ENDPOINT_URL=http://localhost:4566
export AWS_DEFAULT_REGION=us-east-1

cargo test --features aws -- --test-threads=1
```

3. Stop LocalStack:
```bash
docker compose -f docker-compose.localstack.yml down
```

## Test Structure

### `ec2_localstack.rs`
Basic AWS resource creation tests:
- VPC creation
- Security group creation and rules
- EC2 instance launching
- Multi-region setup
- Configuration serialization

### `integration_test.rs`
Comprehensive deployment workflow tests:
- Full deployment lifecycle simulation
- Key pair management
- Network infrastructure setup
- Security group configuration
- Resource verification

## CI/CD

The tests are automatically run in GitHub Actions on:
- Push to main branch
- Pull requests

The CI pipeline:
1. Checks code formatting
2. Runs clippy linting
3. Executes unit tests
4. Starts LocalStack
5. Runs integration tests
6. Generates code coverage reports

## Troubleshooting

### LocalStack not starting
- Ensure Docker is running
- Check port 4566 is not in use
- Review logs: `docker compose -f docker-compose.localstack.yml logs`

### Tests failing
- Run tests with single thread: `cargo test -- --test-threads=1`
- Check LocalStack health: `curl http://localhost:4566/_localstack/health`
- Enable debug output: `RUST_LOG=debug cargo test`

### Cleanup
Remove LocalStack data and containers:
```bash
make clean-localstack
```

## Writing New Tests

When adding new tests:
1. Use `#[tokio::test]` for async tests
2. Add `#[serial]` attribute to prevent concurrent execution
3. Create a unique test context with `DeploymentTestContext::new("test_name")`
4. Always clean up resources in test teardown
5. Use descriptive test names that explain what is being tested

Example:
```rust
#[tokio::test]
#[serial]
async fn test_new_feature() {
    let ctx = DeploymentTestContext::new("new_feature").await;
    // Test implementation
    // Resources are automatically cleaned up when ctx is dropped
}
```