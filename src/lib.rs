use base64::prelude::*;
use pgrx::prelude::*;
use pgrx::JsonB;
use ring::signature;
use serde_json::Value;

use pem::parse as parse_pem;

pgrx::pg_module_magic!();

/// Called when the extension is loaded by Postgres
#[pg_guard]
#[allow(non_snake_case)]
extern "C-unwind" fn _PG_init() {
    pgrx::debug1!("pgjwt_rs extension loaded - JWT verification with RS256 and Ed25519 support");
}

/// Extract JWT payload without verification.
/// This is useful to get the issuer claim to look up the correct public key.
/// The returned JSON always contains `"_unverified": true` to signal that the
/// payload has NOT been signature-verified.
#[cfg_attr(not(test), pg_extern)]
fn jwt_decode_payload(token: String) -> JsonB {
    if token.len() > MAX_TOKEN_BYTES {
        return JsonB(serde_json::json!({"error": "Token too large"}));
    }

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return JsonB(serde_json::json!({"error": "Invalid JWT format"}));
    }

    // Decode base64 payload (URL-safe, no padding)
    match BASE64_URL_SAFE_NO_PAD.decode(parts[1]) {
        Ok(bytes) => match serde_json::from_slice::<Value>(&bytes) {
            Ok(mut payload) => {
                if let Some(map) = payload.as_object_mut() {
                    map.insert("_unverified".into(), serde_json::json!(true));
                }
                JsonB(payload)
            }
            Err(_) => JsonB(serde_json::json!({"error": "Invalid JSON in payload"})),
        },
        Err(_) => JsonB(serde_json::json!({"error": "Invalid base64 encoding"})),
    }
}

/// Verify JWT with RS256 algorithm
#[cfg_attr(not(test), pg_extern)]
fn jwt_verify_rs256(
    token: String,
    public_key: String,
) -> TableIterator<
    'static,
    (
        name!(header, JsonB),
        name!(payload, JsonB),
        name!(valid, bool),
    ),
> {
    let result = verify_jwt(&token, &public_key, JwtAlg::Rs256);
    TableIterator::once(result)
}

/// Verify JWT with Ed25519 algorithm
#[cfg_attr(not(test), pg_extern)]
fn jwt_verify_ed25519(
    token: String,
    public_key: String,
) -> TableIterator<
    'static,
    (
        name!(header, JsonB),
        name!(payload, JsonB),
        name!(valid, bool),
    ),
> {
    let result = verify_jwt(&token, &public_key, JwtAlg::EdDsa);
    TableIterator::once(result)
}

/// Verify JWT with specified algorithm
#[cfg_attr(not(test), pg_extern)]
fn jwt_verify(
    token: String,
    public_key: String,
    algorithm: String,
) -> TableIterator<
    'static,
    (
        name!(header, JsonB),
        name!(payload, JsonB),
        name!(valid, bool),
    ),
> {
    let algo = match algorithm.to_uppercase().as_str() {
        "RS256" => JwtAlg::Rs256,
        "EDDSA" | "ED25519" => JwtAlg::EdDsa,
        _ => {
            return TableIterator::once((
                JsonB(serde_json::json!({"error": "Unsupported algorithm"})),
                JsonB(serde_json::json!({})),
                false,
            ));
        }
    };

    let result = verify_jwt(&token, &public_key, algo);
    TableIterator::once(result)
}

/// Maximum accepted token size (16 KiB — generous for any real JWT)
const MAX_TOKEN_BYTES: usize = 16_384;
/// Maximum accepted PEM key size (8 KiB — generous for any real key)
const MAX_KEY_BYTES: usize = 8_192;

/// Internal function to verify JWT tokens.
fn verify_jwt(token: &str, public_key: &str, expected_alg: JwtAlg) -> (JsonB, JsonB, bool) {
    if token.len() > MAX_TOKEN_BYTES {
        return (
            JsonB(serde_json::json!({"error": "Token too large"})),
            JsonB(serde_json::json!({})),
            false,
        );
    }
    if public_key.len() > MAX_KEY_BYTES {
        return (
            JsonB(serde_json::json!({"error": "Public key too large"})),
            JsonB(serde_json::json!({})),
            false,
        );
    }

    // JWT format: header.payload.signature
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return (
            JsonB(serde_json::json!({"error": "Invalid JWT format"})),
            JsonB(serde_json::json!({})),
            false,
        );
    }

    let header_bytes = match BASE64_URL_SAFE_NO_PAD.decode(parts[0]) {
        Ok(bytes) => bytes,
        Err(_) => {
            return (
                JsonB(serde_json::json!({"error": "Invalid base64 in header"})),
                JsonB(serde_json::json!({})),
                false,
            )
        }
    };

    let header_val: Value = match serde_json::from_slice(&header_bytes) {
        Ok(v) => v,
        Err(_) => {
            return (
                JsonB(serde_json::json!({"error": "Invalid JSON in header"})),
                JsonB(serde_json::json!({})),
                false,
            )
        }
    };

    let header_obj = header_val.as_object();
    let alg = header_obj
        .and_then(|m| m.get("alg"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let typ = header_obj
        .and_then(|m| m.get("typ"))
        .and_then(|v| v.as_str())
        .unwrap_or("JWT")
        .to_string();

    let header_json = JsonB(serde_json::json!({"alg": alg, "typ": typ}));

    let expected_alg_str = match expected_alg {
        JwtAlg::Rs256 => "RS256",
        JwtAlg::EdDsa => "EdDSA",
    };

    if alg != expected_alg_str {
        return (
            header_json,
            JsonB(serde_json::json!({"error": "Algorithm mismatch"})),
            false,
        );
    }

    let payload_bytes = match BASE64_URL_SAFE_NO_PAD.decode(parts[1]) {
        Ok(bytes) => bytes,
        Err(_) => {
            return (
                header_json,
                JsonB(serde_json::json!({"error": "Invalid base64 in payload"})),
                false,
            )
        }
    };

    let payload_json = match serde_json::from_slice::<Value>(&payload_bytes) {
        Ok(v) => JsonB(v),
        Err(_) => {
            return (
                header_json,
                JsonB(serde_json::json!({"error": "Invalid JSON in payload"})),
                false,
            )
        }
    };

    let sig = match BASE64_URL_SAFE_NO_PAD.decode(parts[2]) {
        Ok(bytes) => bytes,
        Err(_) => {
            return (
                header_json,
                JsonB(serde_json::json!({"error": "Invalid base64 in signature"})),
                false,
            )
        }
    };

    let pem = match parse_pem(public_key) {
        Ok(p) => p,
        Err(_) => {
            return (
                header_json,
                JsonB(serde_json::json!({"error": "Invalid PEM public key"})),
                false,
            )
        }
    };

    // We expect a SubjectPublicKeyInfo (SPKI) public key.
    if pem.tag() != "PUBLIC KEY" {
        return (
            header_json,
            JsonB(serde_json::json!({"error": "Unsupported public key format"})),
            false,
        );
    }

    // ring expects the raw public key from inside the SPKI BIT STRING, not the
    // full SPKI DER.  Extract it with a minimal ASN.1 walk.
    let raw_key = match extract_spki_public_key(pem.contents()) {
        Some(k) => k,
        None => {
            return (
                header_json,
                JsonB(serde_json::json!({"error": "Malformed SPKI public key"})),
                false,
            )
        }
    };

    let verifying_key = match expected_alg {
        JwtAlg::Rs256 => {
            signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, raw_key)
        }
        JwtAlg::EdDsa => signature::UnparsedPublicKey::new(&signature::ED25519, raw_key),
    };

    let signing_input = [parts[0].as_bytes(), b".", parts[1].as_bytes()].concat();
    let verified = verifying_key.verify(&signing_input, &sig).is_ok();

    (header_json, payload_json, verified)
}

/// Extract the raw public key bytes from a DER-encoded SubjectPublicKeyInfo.
///
/// SPKI layout (RFC 5280):
///   SEQUENCE {
///     SEQUENCE { algorithm OID, parameters }
///     BIT STRING { unused-bits-byte, raw-key-bytes }
///   }
///
/// For RSA  the raw-key-bytes are a DER-encoded RSAPublicKey (PKCS#1).
/// For Ed25519 the raw-key-bytes are the 32-byte public key.
fn extract_spki_public_key(spki_der: &[u8]) -> Option<Vec<u8>> {
    let data = read_der_sequence(spki_der)?;
    // Skip the AlgorithmIdentifier SEQUENCE
    let (_, rest) = skip_der_element(data)?;
    // Next element must be a BIT STRING (tag 0x03)
    if rest.first()? != &0x03 {
        return None;
    }
    let bit_string_content = read_der_element_content(&rest[1..])?;
    // First byte of BIT STRING is the unused-bits count; must be 0 for keys
    if bit_string_content.first()? != &0 {
        return None;
    }
    Some(bit_string_content[1..].to_vec())
}

/// Read a DER SEQUENCE and return its content bytes.
fn read_der_sequence(data: &[u8]) -> Option<&[u8]> {
    if data.first()? != &0x30 {
        return None;
    }
    read_der_element_content(&data[1..])
}

/// Read a DER length + content and return the content slice.
fn read_der_element_content(data: &[u8]) -> Option<&[u8]> {
    let first = *data.first()?;
    if first < 0x80 {
        let len = first as usize;
        data.get(1..1 + len)
    } else {
        let num_len_bytes = (first & 0x7F) as usize;
        if num_len_bytes == 0 || num_len_bytes > 4 {
            return None;
        }
        let len_bytes = data.get(1..1 + num_len_bytes)?;
        let mut len: usize = 0;
        for &b in len_bytes {
            len = len.checked_shl(8)?.checked_add(b as usize)?;
        }
        data.get(1 + num_len_bytes..1 + num_len_bytes + len)
    }
}

/// Skip one DER element (tag + length + content) and return (element, rest).
fn skip_der_element(data: &[u8]) -> Option<(&[u8], &[u8])> {
    if data.is_empty() {
        return None;
    }
    // data[0] is the tag
    let first_len = *data.get(1)?;
    if first_len < 0x80 {
        let len = first_len as usize;
        let total = 2 + len; // tag + length-byte + content
        if data.len() < total {
            return None;
        }
        Some((&data[..total], &data[total..]))
    } else {
        let num_len_bytes = (first_len & 0x7F) as usize;
        if num_len_bytes == 0 || num_len_bytes > 4 {
            return None;
        }
        let len_bytes = data.get(2..2 + num_len_bytes)?;
        let mut len: usize = 0;
        for &b in len_bytes {
            len = len.checked_shl(8)?.checked_add(b as usize)?;
        }
        let total = 2 + num_len_bytes + len;
        if data.len() < total {
            return None;
        }
        Some((&data[..total], &data[total..]))
    }
}

/// Supported JWT algorithms
#[derive(Clone, Copy)]
enum JwtAlg {
    Rs256,
    EdDsa,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature as ring_sig;

    // ---- helpers to sign JWTs with ring (no jsonwebtoken dependency) ----

    /// Build a JWT string: base64url(header) . base64url(payload) . base64url(signature)
    fn sign_rs256(claims_json: &str, private_key_pem: &str) -> String {
        let pem_obj = pem::parse(private_key_pem).expect("valid PEM private key");
        let key_pair = ring_sig::RsaKeyPair::from_pkcs8(pem_obj.contents())
            .expect("valid PKCS8 RSA private key");
        let rng = SystemRandom::new();

        let header_b64 = BASE64_URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#.as_bytes());
        let payload_b64 = BASE64_URL_SAFE_NO_PAD.encode(claims_json.as_bytes());
        let signing_input = format!("{}.{}", header_b64, payload_b64);

        let mut sig = vec![0u8; key_pair.public().modulus_len()];
        key_pair
            .sign(
                &ring_sig::RSA_PKCS1_SHA256,
                &rng,
                signing_input.as_bytes(),
                &mut sig,
            )
            .expect("RSA sign");

        let sig_b64 = BASE64_URL_SAFE_NO_PAD.encode(&sig);
        format!("{}.{}", signing_input, sig_b64)
    }

    fn sign_eddsa(claims_json: &str, private_key_pem: &str) -> String {
        let pem_obj = pem::parse(private_key_pem).expect("valid PEM private key");
        let key_pair = ring_sig::Ed25519KeyPair::from_pkcs8_maybe_unchecked(pem_obj.contents())
            .expect("valid PKCS8 Ed25519 private key");

        let header_b64 = BASE64_URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA","typ":"JWT"}"#.as_bytes());
        let payload_b64 = BASE64_URL_SAFE_NO_PAD.encode(claims_json.as_bytes());
        let signing_input = format!("{}.{}", header_b64, payload_b64);

        let sig = key_pair.sign(signing_input.as_bytes());
        let sig_b64 = BASE64_URL_SAFE_NO_PAD.encode(sig.as_ref());
        format!("{}.{}", signing_input, sig_b64)
    }

    // ---- key loading helpers ----

    fn priv_key() -> String {
        std::fs::read_to_string("test_private.pem")
            .expect("Missing test_private.pem; run keygen step")
    }

    fn pub_key() -> String {
        std::fs::read_to_string("test_public.pem")
            .expect("Missing test_public.pem; run keygen step")
    }

    fn ed_priv_key() -> String {
        std::fs::read_to_string("test_ed25519_private.pem")
            .expect("Missing test_ed25519_private.pem; run keygen step")
    }

    fn ed_pub_key() -> String {
        std::fs::read_to_string("test_ed25519_public.pem")
            .expect("Missing test_ed25519_public.pem; run keygen step")
    }

    // ---- payload extraction tests ----

    #[test]
    fn test_decode_payload_valid() {
        let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoX2d1YXJkIiwic3ViIjoiMTIzNDU2Nzg5MCIsImlhdCI6MTUxNjIzOTAyMn0.signature";
        let result = jwt_decode_payload(token.to_string());

        assert_eq!(result.0.get("iss").unwrap().as_str(), Some("auth_guard"));
        assert_eq!(result.0.get("sub").unwrap().as_str(), Some("1234567890"));
        assert_eq!(result.0.get("_unverified").unwrap().as_bool(), Some(true));
    }

    #[test]
    fn test_decode_payload_invalid_format() {
        let result = jwt_decode_payload("invalid.token".to_string());
        assert_eq!(
            result.0.get("error").unwrap().as_str(),
            Some("Invalid JWT format")
        );
    }

    #[test]
    fn test_decode_payload_invalid_base64() {
        let result = jwt_decode_payload("header.!!!invalid_base64!!!.signature".to_string());
        assert_eq!(
            result.0.get("error").unwrap().as_str(),
            Some("Invalid base64 encoding")
        );
    }

    #[test]
    fn test_decode_payload_invalid_json() {
        let result = jwt_decode_payload("header.bm90IGpzb24.signature".to_string());
        assert_eq!(
            result.0.get("error").unwrap().as_str(),
            Some("Invalid JSON in payload")
        );
    }

    #[test]
    fn test_decode_payload_too_large() {
        let big = "a".repeat(MAX_TOKEN_BYTES + 1);
        let result = jwt_decode_payload(big);
        assert_eq!(
            result.0.get("error").unwrap().as_str(),
            Some("Token too large")
        );
    }

    // ---- algorithm selection via jwt_verify wrapper ----

    #[test]
    fn test_jwt_verify_unsupported_algorithm() {
        let mut result = jwt_verify("token".into(), "key".into(), "HS256".into());
        let (header, _payload, valid) = result.next().unwrap();

        assert!(!valid);
        assert_eq!(
            header.0.get("error").unwrap().as_str(),
            Some("Unsupported algorithm")
        );
    }

    #[test]
    fn test_jwt_verify_algorithm_rs256_dispatch() {
        // Builds a real token but we only need to prove the RS256 path is taken
        let token = sign_rs256(r#"{"test":"value"}"#, &priv_key());
        let mut result = jwt_verify(token, pub_key(), "RS256".into());
        let (_header, payload, valid) = result.next().unwrap();

        assert!(valid);
        assert_eq!(payload.0.get("test").unwrap().as_str(), Some("value"));
    }

    #[test]
    fn test_jwt_verify_eddsa_alias() {
        let token = sign_eddsa(r#"{"k":1}"#, &ed_priv_key());
        let mut result = jwt_verify(token.clone(), ed_pub_key(), "EdDSA".into());
        let (_, _, valid1) = result.next().unwrap();
        assert!(valid1);

        let mut result2 = jwt_verify(token, ed_pub_key(), "ED25519".into());
        let (_, _, valid2) = result2.next().unwrap();
        assert!(valid2);
    }

    // ---- verify_jwt internal error paths ----

    #[test]
    fn test_verify_jwt_token_too_large() {
        let big = "a".repeat(MAX_TOKEN_BYTES + 1);
        let (_, _, valid) = verify_jwt(&big, &pub_key(), JwtAlg::Rs256);
        assert!(!valid);
    }

    #[test]
    fn test_verify_jwt_key_too_large() {
        let big_key = "a".repeat(MAX_KEY_BYTES + 1);
        let token = sign_rs256(r#"{"a":1}"#, &priv_key());
        let (header, _, valid) = verify_jwt(&token, &big_key, JwtAlg::Rs256);
        assert!(!valid);
        assert_eq!(
            header.0.get("error").unwrap().as_str(),
            Some("Public key too large")
        );
    }

    #[test]
    fn test_verify_jwt_invalid_token_format() {
        let (header, _, valid) = verify_jwt("invalid", &pub_key(), JwtAlg::Rs256);
        assert!(!valid);
        assert!(header.0.get("error").is_some());
    }

    #[test]
    fn test_verify_jwt_invalid_public_key() {
        let token = sign_rs256(r#"{"t":1}"#, &priv_key());
        let (_, payload, valid) = verify_jwt(&token, "not a valid PEM key", JwtAlg::Rs256);
        assert!(!valid);
        assert!(payload
            .0
            .get("error")
            .unwrap()
            .as_str()
            .unwrap()
            .contains("Invalid PEM"));
    }

    #[test]
    fn test_verify_jwt_algorithm_mismatch() {
        // Token header says RS256 but we verify with EdDSA
        let token = sign_rs256(r#"{"t":1}"#, &priv_key());
        let (header, payload, valid) = verify_jwt(&token, &ed_pub_key(), JwtAlg::EdDsa);
        assert!(!valid);
        assert_eq!(
            payload.0.get("error").unwrap().as_str(),
            Some("Algorithm mismatch")
        );
        assert_eq!(header.0.get("alg").unwrap().as_str(), Some("RS256"));
    }

    // ---- RS256 verification ----

    #[test]
    fn test_rs256_verification_success() {
        let claims = r#"{"sub":"user123","iss":"auth_guard","exp":10000000000}"#;
        let token = sign_rs256(claims, &priv_key());

        let (_, payload, valid) = verify_jwt(&token, &pub_key(), JwtAlg::Rs256);
        assert!(valid);
        assert_eq!(payload.0.get("sub").unwrap().as_str(), Some("user123"));
        assert_eq!(payload.0.get("iss").unwrap().as_str(), Some("auth_guard"));
    }

    #[test]
    fn test_rs256_verification_invalid_signature() {
        // Construct a token with a garbage signature
        let header_b64 = BASE64_URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#.as_bytes());
        let payload_b64 = BASE64_URL_SAFE_NO_PAD.encode(r#"{"iss":"auth_guard"}"#.as_bytes());
        let token = format!("{}.{}.aW52YWxpZF9zaWduYXR1cmU", header_b64, payload_b64);

        let (_, _, valid) = verify_jwt(&token, &pub_key(), JwtAlg::Rs256);
        assert!(!valid);
    }

    #[test]
    fn test_rs256_verification_wrong_key() {
        let token = sign_rs256(r#"{"sub":"user123"}"#, &priv_key());

        let wrong_public_key = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwJJ0lGHJwRdKWLOxNI1a
j9KdP8KNLmxEKmPChBEPqGR8W4qL8xc1qsLvFTNh0r7lVxVXlAh8dPXtV7UrvGJH
oKcKKF1tPdH2ghF0Qh3PXKYX7rXBDxGZ0lLKN3IpEHjPWTX4o8mDK7AqPTqzwJlg
lvKzqGvNPqlMqR4kpxTF9G6bNTQXmGy8qPkF3W0tN0KRYqQDhN4QFvC3Y7Wplqha
7KKrFJLNDQhj3F2d5xF4N7tZNhG2YF0bHNqX3F9L1xH2M0F7cKKFLHNqXFYpQW0N
bPG2ZlCNHPFqWH3N0HGJLKLVMHNqFLqVGpHFqJLKLVMHNqFLqVGpHFqJLKLVMHNq
FwIDAQAB
-----END PUBLIC KEY-----"#;

        let (_, _, valid) = verify_jwt(&token, wrong_public_key, JwtAlg::Rs256);
        assert!(!valid);
    }

    // ---- Ed25519 verification ----

    #[test]
    fn test_eddsa_verification_success() {
        let claims = r#"{"sub":"user-eddsa","iss":"auth_guard"}"#;
        let token = sign_eddsa(claims, &ed_priv_key());

        let (_, payload, valid) = verify_jwt(&token, &ed_pub_key(), JwtAlg::EdDsa);
        assert!(valid);
        assert_eq!(payload.0.get("sub").unwrap().as_str(), Some("user-eddsa"));
    }

    #[test]
    fn test_eddsa_verification_invalid_key() {
        let token = sign_eddsa(r#"{"k":1}"#, &ed_priv_key());
        let (_, payload, valid) = verify_jwt(&token, "not valid pem", JwtAlg::EdDsa);
        assert!(!valid);
        assert!(payload.0.get("error").is_some());
    }

    // ---- wrapper function tests ----

    #[test]
    fn test_jwt_verify_rs256_wrapper() {
        let token = sign_rs256(r#"{"test":"value"}"#, &priv_key());
        let mut result = jwt_verify_rs256(token, pub_key());
        let (_, payload, valid) = result.next().unwrap();
        assert!(valid);
        assert_eq!(payload.0.get("test").unwrap().as_str(), Some("value"));
    }

    #[test]
    fn test_jwt_verify_ed25519_wrapper_invalid_key() {
        let token = "eyJhbGciOiJFZERTQSJ9.eyJ0ZXN0IjoidmFsdWUifQ.sig".to_string();
        let mut result = jwt_verify_ed25519(token, "not a valid ed25519 key".into());
        let (_, payload, valid) = result.next().unwrap();
        assert!(!valid);
        assert!(payload.0.get("error").is_some());
    }

    #[test]
    fn test_jwt_verify_ed25519_wrapper_success() {
        let token = sign_eddsa(r#"{"k":42}"#, &ed_priv_key());
        let mut result = jwt_verify_ed25519(token, ed_pub_key());
        let (_, payload, valid) = result.next().unwrap();
        assert!(valid);
        assert_eq!(payload.0.get("k").unwrap().as_u64(), Some(42));
    }

    // ---- PEM tag tests ----

    #[test]
    fn test_verify_jwt_unsupported_pem_tag() {
        let token = sign_rs256(r#"{"t":1}"#, &priv_key());
        // RSA PRIVATE KEY is not a PUBLIC KEY tag
        let bad_tag_pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n-----END RSA PRIVATE KEY-----";
        let (_, payload, valid) = verify_jwt(&token, bad_tag_pem, JwtAlg::Rs256);
        assert!(!valid);
        // Either "Invalid PEM" or "Unsupported public key format" depending on parsing
        assert!(payload.0.get("error").is_some());
    }

    // ---- pg_test module ----

    #[test]
    fn test_cover_pg_test_module() {
        crate::pg_test::setup(vec![]);
        let opts = crate::pg_test::postgresql_conf_options();
        assert!(opts.is_empty());
    }
}

/// This module is required by `cargo pgrx test` invocations.
#[cfg(test)]
pub mod pg_test {
    pub fn setup(_options: Vec<&str>) {
        // perform one-off initialization when the pg_test framework starts
    }

    pub fn postgresql_conf_options() -> Vec<&'static str> {
        // return any postgresql.conf settings that are required for your tests
        vec![]
    }
}
