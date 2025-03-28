FROM arm64v8/ubuntu

# Install necessary tools and libraries
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    curl \
    protobuf-compiler \
    git \
    pkg-config

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# Set PATH for rustup and Rust
ENV PATH="/root/.cargo/bin:${PATH}"

# Set PKG_CONFIG_PATH for OpenSSL
ENV PKG_CONFIG_PATH=/usr/lib/aarch64-linux-gnu/pkgconfig

# Install Rust target
RUN rustup default stable
RUN rustup target add aarch64-unknown-linux-gnu

# Set RUSTFLAGS to force frame pointers
ENV RUSTFLAGS="-C force-frame-pointers=yes"

# Set the working directory
WORKDIR /monorepo

# Build the binary
ENTRYPOINT ["/bin/bash", "-c"]
CMD ["cd examples/flood && cargo build --profile release-with-debug --bin flood --target aarch64-unknown-linux-gnu && cp ../../target/aarch64-unknown-linux-gnu/release-with-debug/flood assets"]