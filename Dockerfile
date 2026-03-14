# Build container for pgjwt_rs (Postgres extension shared object)
# Usage:
#   docker build -t pgjwt_rs .
#   docker run --rm -v "$PWD/out":/out pgjwt_rs

FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

# Install PostgreSQL 18 from the official PostgreSQL APT repository (Ubuntu 24.04 does not include pg18 yet)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gnupg \
    lsb-release && \
    curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor -o /usr/share/keyrings/postgresql-archive-keyring.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/postgresql-archive-keyring.gpg] http://apt.postgresql.org/pub/repos/apt/ $(lsb_release -cs)-pgdg main" \
    > /etc/apt/sources.list.d/pgdg.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    libssl-dev \
    git \
    openssl \
    postgresql-18 \
    postgresql-server-dev-18 && \
    rm -rf /var/lib/apt/lists/*

# Install Rust toolchain
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Install cargo-pgrx (must match pgrx dependency version in Cargo.toml)
RUN cargo install --locked cargo-pgrx --version 0.17.0

# Initialize pgrx for the target PG version
RUN cargo pgrx init --pg18 /usr/lib/postgresql/18/bin/pg_config

WORKDIR /workspace
COPY . .

# Generate test key pairs and run unit tests
# RUN openssl genrsa -out test_private.pem 2048 2>/dev/null && \
#     openssl rsa -in test_private.pem -pubout -out test_public.pem 2>/dev/null && \
#     openssl genpkey -algorithm Ed25519 -out test_ed25519_private.pem 2>/dev/null && \
#     openssl pkey -in test_ed25519_private.pem -pubout -out test_ed25519_public.pem 2>/dev/null && \
#     cargo test --lib

# Build the extension (produces pkg/ with the shared object)
RUN ./package.sh pg18

# Final image just holds artifacts
FROM busybox:1.37.0
COPY --from=builder /workspace/pkg /pkg

