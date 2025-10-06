# Copyright 2020-2024 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

# Dockerfile with pre-compiled binary
FROM rustlang/rust:nightly-bookworm as builder

# Install dependencies including protobuf compiler for tonic
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    ca-certificates \
    git \
    protobuf-compiler \
    cmake \
    build-essential \
    libclang-dev \
    clang \
    libudev-dev \
    && rm -rf /var/lib/apt/lists/*

# Set git config for cargo (required for git dependencies)
RUN git config --global user.email "build@iota.org" && \
    git config --global user.name "Docker Build"

# Set working directory
WORKDIR /app

# Copy entire workspace
COPY . .

# Build the binary in release mode
RUN cargo build --release --package hv-iota-e2e-test --features vault

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/target/release/hv-iota-e2e-test .

# Expose port
EXPOSE 3001

# Set default environment variables
ENV RUST_LOG=info,hv_iota_e2e_test=debug
ENV API_HOST=0.0.0.0
ENV API_PORT=3001

# Run the binary
CMD ["./hv-iota-e2e-test"]