# syntax=docker/dockerfile:1.7
ARG RUST_IMAGE=rust:1.95-bookworm
FROM ${RUST_IMAGE} AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    cmake \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /commonware
COPY . .
ARG TARGETARCH
ARG TARGET_CPU=generic
# Frame pointers let `perf record -g` unwind the deployed binary from a stripped copy, so a
# node can be profiled in place with call chains at a cost of about one percent.
ENV RUSTFLAGS="-C force-frame-pointers=yes -C target-cpu=${TARGET_CPU}"
# An explicit target keeps deployment CPU features out of host build scripts and proc macros.
RUN case "$TARGETARCH" in \
        arm64) rust_target=aarch64-unknown-linux-gnu ;; \
        amd64) rust_target=x86_64-unknown-linux-gnu ;; \
        *) echo "Unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && cargo build --locked --target "$rust_target" --profile release-with-debug --package commonware-log-multimmit \
    && cp "target/$rust_target/release-with-debug/commonware-log-multimmit" /commonware-log-multimmit-debug \
    && strip -o /commonware-log-multimmit /commonware-log-multimmit-debug

FROM scratch AS binary
COPY --from=builder /commonware-log-multimmit /commonware-log-multimmit
COPY --from=builder /commonware-log-multimmit-debug /commonware-log-multimmit-debug
