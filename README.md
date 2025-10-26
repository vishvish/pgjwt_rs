# pgjwt_rs

PostgreSQL extension for JWT verification with RS256 and Ed25519 support.

## Overview

This extension provides cryptographically secure JWT validation at the database layer using the Rust `jsonwebtoken` crate. Unlike the pure-SQL `pgjwt` extension which only supports HMAC algorithms, `pgjwt_rs` supports asymmetric key algorithms:

- **RS256** (RSA with SHA-256)
- **Ed25519** (EdDSA)

## Why This Extension?

### The Problem
The popular `pgjwt` extension only supports HMAC-based JWT validation (HS256/384/512), which requires sharing secret keys between services. This is insecure for multi-service architectures because:
- Any service with the shared secret can forge tokens for other services
- Compromising one service compromises all services
- No way to cryptographically prove token origin

### The Solution
Asymmetric key cryptography with `pgjwt_rs`:
- Each service has a unique private key (never shared)
- Database stores only public keys
- Services sign JWTs with their private key
- Database verifies signatures with public keys
- **Mathematically impossible** to forge tokens without the private key

## Functions

### `jwt_decode_payload(token TEXT) -> JSONB`
Extract the payload from a JWT without verification. Useful for getting the issuer to look up the correct public key.

```sql
SELECT jwt_decode_payload('eyJhbGc...');
-- Returns: {"iss": "auth_guard", "sub": "...", ...}
```

### `jwt_verify_rs256(token TEXT, public_key TEXT) -> TABLE(header JSONB, payload JSONB, valid BOOLEAN)`
Verify a JWT token using RS256 algorithm.

```sql
SELECT * FROM jwt_verify_rs256(
    'eyJhbGciOiJSUzI1NiI...',
    '-----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
    -----END PUBLIC KEY-----'
);
```

### `jwt_verify_ed25519(token TEXT, public_key TEXT) -> TABLE(header JSONB, payload JSONB, valid BOOLEAN)`
Verify a JWT token using Ed25519 algorithm.

```sql
SELECT * FROM jwt_verify_ed25519(
    'eyJhbGciOiJFZERTQSI...',
    '-----BEGIN PUBLIC KEY-----
    MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=
    -----END PUBLIC KEY-----'
);
```

### `jwt_verify(token TEXT, public_key TEXT, algorithm TEXT) -> TABLE(header JSONB, payload JSONB, valid BOOLEAN)`
Verify a JWT token with the specified algorithm ('RS256' or 'EdDSA').

```sql
SELECT * FROM jwt_verify(
    'eyJhbGc...',
    '-----BEGIN PUBLIC KEY-----...',
    'RS256'
);
```

## Installation

### Prerequisites
- Rust toolchain (1.70+)
- PostgreSQL 18 (or 13-17 with appropriate feature flags)
- PostgreSQL development headers (`postgresql-server-dev` on Debian/Ubuntu, `postgresql-devel` on RHEL)
- `cargo-pgrx` version 0.16.1

### Build and Install

```bash
# Install cargo-pgrx (matching pgrx version)
cargo install --locked cargo-pgrx --version 0.16.1

# Initialize pgrx for PostgreSQL 18 (one-time setup)
cargo pgrx init --pg18 $(which pg_config)

# Build and package the extension
chmod +x package.sh
./package.sh

# Install (as superuser)
sudo cp pkg/usr/lib/postgresql/pgjwt_rs.so $(pg_config --pkglibdir)/
sudo cp pkg/usr/share/postgresql/extension/* $(pg_config --sharedir)/extension/
```

On macOS, the library extension will be `.dylib` instead of `.so`.

### Enable in Database

```sql
CREATE EXTENSION pgjwt_rs;
```

## Usage Example

```sql
-- Create a function to validate service JWTs
CREATE OR REPLACE FUNCTION validate_service_jwt(token TEXT)
RETURNS TABLE(
    service_name TEXT,
    tenant_id UUID,
    scopes TEXT[],
    valid BOOLEAN
) AS $$
DECLARE
    payload JSONB;
    jwt_result RECORD;
    public_key_pem TEXT;
    algorithm TEXT;
BEGIN
    -- Get unverified payload to find issuer
    payload := jwt_decode_payload(token);
    
    -- Look up public key for the claimed service
    SELECT pk.public_key, pk.algorithm 
    INTO public_key_pem, algorithm
    FROM auth_schema.jwt_keys pk
    WHERE pk.service_name = payload->>'iss'
      AND pk.is_active = true;
    
    IF public_key_pem IS NULL THEN
        RETURN QUERY SELECT NULL::TEXT, NULL::UUID, NULL::TEXT[], FALSE;
        RETURN;
    END IF;
    
    -- Verify JWT with correct algorithm
    SELECT * INTO jwt_result 
    FROM jwt_verify(token, public_key_pem, algorithm);
    
    IF jwt_result.valid THEN
        payload := jwt_result.payload;
        RETURN QUERY SELECT 
            (payload->>'iss')::TEXT,
            (payload->>'tenant_id')::UUID,
            ARRAY(SELECT jsonb_array_elements_text(payload->'scopes')),
            TRUE;
    ELSE
        RETURN QUERY SELECT NULL::TEXT, NULL::UUID, NULL::TEXT[], FALSE;
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
```

## Security Features

- **Signature Verification**: Always validates cryptographic signatures
- **Algorithm Enforcement**: Explicitly specify which algorithm to use
- **Public Key Validation**: Validates PEM format before use
- **Error Handling**: Safe error messages, no key material leaks
- **Memory Safety**: Built with Rust's memory safety guarantees

### Validation behavior

This extension focuses on cryptographic verification and intentionally defers claim validation to SQL so you can express policy close to data:

- Signature validation is always enforced.
- The default required JWT spec claims (like `exp`) are not enforced by the extension. Tokens without `exp` will be accepted at the cryptographic level.
- `exp`, `nbf`, and `aud` checks are disabled in Rust and can be applied in SQL, e.g. by checking `now() < to_timestamp((payload->>'exp')::bigint)` if present.

Rationale: application-specific TTLs, audiences, and clock tolerance are often best handled in database logic or service code rather than hard-coded in the extension.

## Performance

Built with Rust and compiled to native code, `pgjwt_rs` provides:
- Fast signature verification (native crypto operations)
- Minimal overhead compared to SQL-only solutions
- Efficient JSONB handling

## Development

### Running Tests

First, generate test key pairs:

```bash
# Generate RS256 test keys
openssl genrsa -out test_private.pem 2048
openssl rsa -in test_private.pem -pubout -out test_public.pem

# Generate Ed25519 test keys
openssl genpkey -algorithm ed25519 -out test_ed25519_private.pem
openssl pkey -in test_ed25519_private.pem -pubout -out test_ed25519_public.pem
```

Then run tests:

```bash
# Run Rust unit tests (with coverage)
cargo install cargo-llvm-cov
cargo llvm-cov --html

# Run PostgreSQL integration tests
cargo pgrx test pg18
```

### Building for Development

```bash
# Run with test database (opens psql with extension loaded)
cargo pgrx run pg18

# Build for specific PostgreSQL version
cargo build --release --features pg18 --no-default-features
```

## License

AGPL-3.0-only - see LICENSE file for details.

## Credits

Built with:
- [pgrx](https://github.com/pgcentralfoundation/pgrx) - Rust framework for PostgreSQL extensions
- [jsonwebtoken](https://github.com/Keats/jsonwebtoken) - JWT encoding/decoding for Rust
