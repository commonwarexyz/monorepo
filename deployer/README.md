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

## Profiling

The deployer supports two profiling modes:

### Continuous Profiling (Pyroscope)

Enable continuous CPU profiling by setting `profiling: true` in your instance config. This runs Pyroscope in the background, continuously collecting profiles that are viewable in the Grafana dashboard on the monitoring instance.

### On-Demand Profiling (samply)

For detailed, on-demand CPU profiles with the Firefox Profiler UI:

```bash
deployer ec2 profile --config config.yaml --instance <name> --binary <path-to-debug-binary>
```

This captures a 30-second profile (configurable with `--duration`) using samply on the remote instance, downloads it, and opens it in Firefox Profiler with symbols resolved from your local debug binary.

### Building for Profiling

For best results with either profiling mode, build your binary with debug symbols and frame pointers:

```bash
CARGO_PROFILE_RELEASE_DEBUG=true RUSTFLAGS="-C force-frame-pointers=yes" cargo build --release
```
