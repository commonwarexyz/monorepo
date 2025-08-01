#!/bin/bash
set -e

echo "Starting LocalStack for deployer tests..."

# Check if docker is running
if ! docker info > /dev/null 2>&1; then
    echo "Docker is not running. Please start Docker first."
    exit 1
fi

# Stop any existing LocalStack container
docker compose -f docker-compose.localstack.yml down 2>/dev/null || true

# Start LocalStack
echo "Starting LocalStack container..."
docker compose -f docker-compose.localstack.yml up -d

# Wait for LocalStack to be ready
echo "Waiting for LocalStack to be ready..."
max_attempts=30
attempt=0
while [ $attempt -lt $max_attempts ]; do
    if curl -s http://localhost:4566/_localstack/health | grep -q '"ec2".*"available"'; then
        echo "LocalStack is ready!"
        break
    fi
    echo "Waiting for LocalStack... (attempt $((attempt + 1))/$max_attempts)"
    sleep 2
    attempt=$((attempt + 1))
done

if [ $attempt -eq $max_attempts ]; then
    echo "LocalStack failed to start within timeout"
    docker compose -f docker-compose.localstack.yml logs
    exit 1
fi

# Run tests
echo "Running LocalStack tests..."
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_ENDPOINT_URL=http://localhost:4566
export AWS_DEFAULT_REGION=us-east-1

# Run tests with cargo
cargo test --features aws -- --test-threads=1 --nocapture

# Cleanup
echo "Stopping LocalStack..."
docker compose -f docker-compose.localstack.yml down

echo "Tests completed!"