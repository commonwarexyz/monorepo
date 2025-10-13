FROM ubuntu:22.04

# Install core build dependencies
RUN apt-get update && \
  apt-get install --assume-yes --no-install-recommends \
  ca-certificates \
  autoconf \
  automake \
  autotools-dev \
  curl \
  python3 \
  python3-pip \
  python3-tomli \
  libmpc-dev \
  libmpfr-dev \
  libgmp-dev \
  gawk \
  build-essential \
  bison \
  flex \
  texinfo \
  gperf \
  libtool \
  patchutils \
  bc \
  zlib1g-dev \
  libexpat-dev \
  ninja-build \
  git \
  cmake \
  libglib2.0-dev \
  libslirp-dev

ENV RISCV=/opt/riscv
ENV RISCV_TAG=2025.09.28
ENV PATH=$PATH:$RISCV/bin

# https://github.com/riscv-collab/riscv-gnu-toolchain/issues/1669#issuecomment-2682013720
RUN git clone https://github.com/riscv/riscv-gnu-toolchain --branch $RISCV_TAG && \
  cd riscv-gnu-toolchain && \
  sed -i '/shallow = true/d' .gitmodules && \
  sed -i 's/--depth 1//g' Makefile.in && \
  ./configure --prefix=$RISCV --enable-multilib && \
  make && \
  cd .. && \
  rm -rf riscv-gnu-toolchain
