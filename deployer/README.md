# commonware-deployer

[![Crates.io](https://img.shields.io/crates/v/commonware-deployer.svg)](https://crates.io/crates/commonware-deployer)
[![Docs.rs](https://docs.rs/commonware-deployer/badge.svg)](https://docs.rs/commonware-deployer)

Deploy infrastructure across cloud providers.

## Status

`commonware-deployer` is **ALPHA** software and is not yet recommended for production use. Developers should expect breaking changes and occasional instability.

## Debugging

### Missing AWS Credentials

If `commonware-deployer` can't detect your AWS credentials, you'll see a "Request has expired." error:

```
2025-03-05T01:36:47.550105Z  INFO deployer::ec2::create: created EC2 client region="eu-west-1"
2025-03-05T01:36:48.268330Z ERROR deployer: failed to create EC2 deployment error=AwsEc2(Unhandled(Unhandled { source: ErrorMetadata { code: Some("RequestExpired"), message: Some("Request has expired."), extras: Some({"aws_request_id": "006f6b92-4965-470d-8eac-7c9644744bdf"}) }, meta: ErrorMetadata { code: Some("RequestExpired"), message: Some("Request has expired."), extras: Some({"aws_request_id": "006f6b92-4965-470d-8eac-7c9644744bdf"}) } }))
```

## Profiling with Symbols

When profiling (either continuous profiling via `profiling: true` in config, or on-demand profiling via `deployer ec2 profile`), ensure your binary includes debug symbols for meaningful stack traces.

### Build Configuration

In your `Cargo.toml`, ensure the release profile (or your deployment profile) includes debug info:

```toml
[profile.release]
debug = true  # Include debug symbols
```

For best stack trace quality, also enable frame pointers:

```bash
RUSTFLAGS="-C force-frame-pointers=yes" cargo build --release
```

### Common Issues

**Problem**: Profile shows only hex addresses like `0x7f8a3b2c1000` instead of function names.

**Causes**:
1. Binary was built without `debug = true`
2. Binary was stripped after compilation (e.g., `strip` command or `strip = true` in Cargo.toml)
3. Debug symbols are in a separate file not available on the remote instance

**Solution**: Rebuild with debug symbols enabled and ensure the deployed binary is not stripped.