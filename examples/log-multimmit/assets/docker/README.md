# Deployable binary

Build from the example directory; the recipe supplies the complete Cargo workspace as Docker's
build context:

```sh
just build
```

This produces two files:

- `deploy/commonware-log-multimmit`, the stripped binary uploaded to the deployment.
- `deploy/commonware-log-multimmit-debug`, the matching optimized binary with full debug symbols.

Use `just build linux/amd64` when the selected EC2 instance type is x86-64. The image builds the
locked `release-with-debug` profile and exports binaries rather than a runtime container image.
Keep the debug binary locally for on-demand symbolication:

```sh
cd deploy
deployer aws profile \
  --config config.yaml \
  --instance 0 \
  --binary commonware-log-multimmit-debug
```

`Dockerfile.dockerignore` keeps build outputs, generated deployment bundles, repository metadata,
and editor files out of the workspace build context.
