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
RUN cargo build --locked --profile release-with-debug --package commonware-log-multimmit \
    && cp target/release-with-debug/commonware-log-multimmit /commonware-log-multimmit-debug \
    && strip -o /commonware-log-multimmit /commonware-log-multimmit-debug

FROM scratch AS binary
COPY --from=builder /commonware-log-multimmit /commonware-log-multimmit
COPY --from=builder /commonware-log-multimmit-debug /commonware-log-multimmit-debug
