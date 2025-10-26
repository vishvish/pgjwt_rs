-- pgjwt_rs--0.1.0.sql
-- PostgreSQL extension for JWT verification with RS256 and Ed25519 support

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pgjwt_rs" to load this file. \quit

-- Extract JWT payload without verification
CREATE FUNCTION jwt_decode_payload(
    token text
) RETURNS jsonb
LANGUAGE c
IMMUTABLE PARALLEL SAFE STRICT
AS 'MODULE_PATHNAME', 'jwt_decode_payload_wrapper';

-- Verify JWT with RS256 algorithm
CREATE FUNCTION jwt_verify_rs256(
    token text,
    public_key text
) RETURNS TABLE(header jsonb, payload jsonb, valid boolean)
LANGUAGE c
IMMUTABLE PARALLEL SAFE STRICT
AS 'MODULE_PATHNAME', 'jwt_verify_rs256_wrapper';

-- Verify JWT with Ed25519 algorithm  
CREATE FUNCTION jwt_verify_ed25519(
    token text,
    public_key text
) RETURNS TABLE(header jsonb, payload jsonb, valid boolean)
LANGUAGE c
IMMUTABLE PARALLEL SAFE STRICT
AS 'MODULE_PATHNAME', 'jwt_verify_ed25519_wrapper';

-- Verify JWT with specified algorithm
CREATE FUNCTION jwt_verify(
    token text,
    public_key text,
    algorithm text
) RETURNS TABLE(header jsonb, payload jsonb, valid boolean)
LANGUAGE c
IMMUTABLE PARALLEL SAFE STRICT
AS 'MODULE_PATHNAME', 'jwt_verify_wrapper';
