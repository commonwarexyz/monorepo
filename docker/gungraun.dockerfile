FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV CARGO_HOME=/usr/local/cargo
ENV RUSTUP_HOME=/usr/local/rustup
ENV RUST_VERSION=1.96.0
ENV GUNGRAUN_VERSION=0.19.1
ENV PATH="/usr/local/cargo/bin:${PATH}"

RUN apt-get update && \
  apt-get install --assume-yes --no-install-recommends \
  build-essential \
  ca-certificates \
  clang \
  cmake \
  curl \
  git \
  libclang-dev \
  ninja-build \
  perl \
  pkg-config \
  python3 \
  valgrind && \
  rm -rf /var/lib/apt/lists/*

RUN curl https://sh.rustup.rs -sSf | \
  bash -s -- -y --default-toolchain ${RUST_VERSION} --profile minimal && \
  chmod -R a+rX "${CARGO_HOME}" "${RUSTUP_HOME}"

RUN cargo install gungraun-runner --version ${GUNGRAUN_VERSION} --locked && \
  chmod -R a+rX "${CARGO_HOME}"

WORKDIR /workspace
