# Copyright 2020-2024 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

# Multi-stage build for IOTA Secret Storage Transaction API

# Build stage - using nightly for edition2024 support
FROM rustlang/rust:nightly-bookworm as builder

# Install build dependencies including protobuf compiler for tonic
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

# Set working directory
WORKDIR /app

# Set git config for cargo (required for git dependencies)
RUN git config --global user.email "build@iota.org" && \
    git config --global user.name "Docker Build"

# Copy workspace Cargo files first for dependency caching
COPY Cargo.toml Cargo.lock ./

# Create dummy src files for dependency caching
RUN mkdir -p core/secret-storage/src && echo "fn main() {}" > core/secret-storage/src/lib.rs
RUN mkdir -p adapters/vault-adapter/src && echo "fn main() {}" > adapters/vault-adapter/src/lib.rs
RUN mkdir -p adapters/aws-kms-adapter/src && echo "fn main() {}" > adapters/aws-kms-adapter/src/lib.rs
RUN mkdir -p applications/storage-factory/src && echo "fn main() {}" > applications/storage-factory/src/lib.rs
RUN mkdir -p applications/transaction-api/src && echo "fn main() {}" > applications/transaction-api/src/main.rs

# Copy Cargo.toml files for each package
COPY core/secret-storage/Cargo.toml ./core/secret-storage/
COPY adapters/vault-adapter/Cargo.toml ./adapters/vault-adapter/
COPY adapters/aws-kms-adapter/Cargo.toml ./adapters/aws-kms-adapter/
COPY applications/storage-factory/Cargo.toml ./applications/storage-factory/
COPY applications/transaction-api/Cargo.toml ./applications/transaction-api/

# Build dependencies (this layer will be cached if dependencies don't change)
RUN cargo build --release --package transaction-api

# Remove dummy files and copy real source code
RUN rm -rf core/ adapters/ applications/
COPY core/ ./core/
COPY adapters/ ./adapters/
COPY applications/ ./applications/

# Build the real application
RUN cargo build --release --package transaction-api

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    strace \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -s /bin/false -m -d /app iota

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/target/release/transaction-api /app/transaction-api

# Copy configuration directory (if exists) - handled in RUN to avoid copy failure
RUN touch /app/.env

# Change ownership
RUN chown -R iota:iota /app

# Switch to non-root user
USER iota

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Expose port
EXPOSE 3000

# Set default environment variables
ENV RUST_LOG=info,transaction_api=debug
ENV API_HOST=0.0.0.0
ENV API_PORT=3000

# Run the application
CMD ["./transaction-api"]