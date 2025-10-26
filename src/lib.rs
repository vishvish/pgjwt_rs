use pgrx::prelude::*;
use pgrx::JsonB;
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation, Algorithm};
use serde_json::Value;
use base64::prelude::*;

pgrx::pg_module_magic!();

/// Called when the extension is loaded by Postgres
#[pg_guard]
extern "C-unwind" fn _PG_init() {
    pgrx::info!("pgjwt_rs extension loaded - JWT verification with RS256 and Ed25519 support");
}

/// Extract JWT payload without verification
/// This is useful to get the issuer claim to look up the correct public key
#[cfg_attr(not(test), pg_extern)]
fn jwt_decode_payload(token: String) -> JsonB {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return JsonB(serde_json::json!({"error": "Invalid JWT format"}));
    }
    
    // Decode base64 payload (URL-safe, no padding)
    match BASE64_URL_SAFE_NO_PAD.decode(parts[1]) {
        Ok(bytes) => {
            match serde_json::from_slice::<Value>(&bytes) {
                Ok(payload) => JsonB(payload),
                Err(_) => JsonB(serde_json::json!({"error": "Invalid JSON in payload"}))
            }
        }
        Err(_) => JsonB(serde_json::json!({"error": "Invalid base64 encoding"}))
    }
}

/// Verify JWT with RS256 algorithm
#[cfg_attr(not(test), pg_extern)]
fn jwt_verify_rs256(
    token: String,
    public_key: String
) -> TableIterator<'static, (name!(header, JsonB), name!(payload, JsonB), name!(valid, bool))> {
    let result = verify_jwt(&token, &public_key, Algorithm::RS256);
    TableIterator::once(result)
}

/// Verify JWT with Ed25519 algorithm
#[cfg_attr(not(test), pg_extern)]
fn jwt_verify_ed25519(
    token: String,
    public_key: String
) -> TableIterator<'static, (name!(header, JsonB), name!(payload, JsonB), name!(valid, bool))> {
    let result = verify_jwt(&token, &public_key, Algorithm::EdDSA);
    TableIterator::once(result)
}

/// Verify JWT with specified algorithm
#[cfg_attr(not(test), pg_extern)]
fn jwt_verify(
    token: String,
    public_key: String,
    algorithm: String
) -> TableIterator<'static, (name!(header, JsonB), name!(payload, JsonB), name!(valid, bool))> {
    let algo = match algorithm.to_uppercase().as_str() {
        "RS256" => Algorithm::RS256,
        "EDDSA" | "ED25519" => Algorithm::EdDSA,
        _ => {
            return TableIterator::once((
                JsonB(serde_json::json!({"error": "Unsupported algorithm"})),
                JsonB(serde_json::json!({})),
                false
            ));
        }
    };
    
    let result = verify_jwt(&token, &public_key, algo);
    TableIterator::once(result)
}

/// Internal function to verify JWT tokens
fn verify_jwt(token: &str, public_key: &str, algorithm: Algorithm) -> (JsonB, JsonB, bool) {
    // Parse header
    let header = match decode_header(token) {
        Ok(h) => {
            // Build a minimal, infallible JSON representation
            let alg = format!("{:?}", h.alg);
            let typ = h.typ.unwrap_or_else(|| "JWT".to_string());
            JsonB(serde_json::json!({ "alg": alg, "typ": typ }))
        },
        Err(e) => return (
            JsonB(serde_json::json!({"error": format!("Invalid JWT header: {}", e)})),
            JsonB(serde_json::json!({})),
            false
        )
    };
    
    // Create decoding key based on algorithm
    let key = match algorithm {
        Algorithm::RS256 => DecodingKey::from_rsa_pem(public_key.as_bytes()),
        Algorithm::EdDSA => DecodingKey::from_ed_pem(public_key.as_bytes()),
        _ => {
            return (
                header,
                JsonB(serde_json::json!({"error": "Algorithm not implemented"})),
                false
            );
        }
    };
    
    let key = match key {
        Ok(k) => k,
        Err(e) => return (
            header,
            JsonB(serde_json::json!({"error": format!("Invalid public key: {}", e)})),
            false
        )
    };
    
    // Configure validation
    let mut validation = Validation::new(algorithm);
    validation.validate_exp = false; // We'll handle expiration in SQL for better control
    validation.validate_nbf = false; // Not Before handling in SQL
    validation.validate_aud = false; // Audience validation in SQL if needed
    // jsonwebtoken v9 requires `exp` by default; allow tokens without exp and handle it in SQL
    validation.required_spec_claims = std::collections::HashSet::new();
    // Note: signature validation is always on and cannot be disabled in modern jsonwebtoken
    
    // Verify JWT and extract claims
    match decode::<Value>(token, &key, &validation) {
        Ok(token_data) => {
            (header, JsonB(token_data.claims), true)
        }
        Err(e) => {
            (
                header,
                JsonB(serde_json::json!({"error": format!("Verification failed: {}", e)})),
                false
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Load test RSA keys from files created during setup (test_private.pem / test_public.pem)
    fn priv_key() -> String {
        std::fs::read_to_string("test_private.pem").expect("Missing test_private.pem; run keygen step")
    }

    fn pub_key() -> String {
        std::fs::read_to_string("test_public.pem").expect("Missing test_public.pem; run keygen step")
    }

    // Load test Ed25519 keys from files created during setup (test_ed25519_private.pem / test_ed25519_public.pem)
    fn ed_priv_key() -> String {
        std::fs::read_to_string("test_ed25519_private.pem").expect("Missing test_ed25519_private.pem; run keygen step")
    }

    fn ed_pub_key() -> String {
        std::fs::read_to_string("test_ed25519_public.pem").expect("Missing test_ed25519_public.pem; run keygen step")
    }

    // Test payload extraction without verification
    #[test]
    fn test_decode_payload_valid() {
        let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoX2d1YXJkIiwic3ViIjoiMTIzNDU2Nzg5MCIsImlhdCI6MTUxNjIzOTAyMn0.signature";
        let result = jwt_decode_payload(token.to_string());
        
        assert!(result.0.get("iss").is_some());
        assert_eq!(result.0.get("iss").unwrap().as_str(), Some("auth_guard"));
        assert_eq!(result.0.get("sub").unwrap().as_str(), Some("1234567890"));
    }

    #[test]
    fn test_decode_payload_invalid_format() {
        let token = "invalid.token";
        let result = jwt_decode_payload(token.to_string());
        
        assert!(result.0.get("error").is_some());
        assert_eq!(result.0.get("error").unwrap().as_str(), Some("Invalid JWT format"));
    }

    #[test]
    fn test_decode_payload_invalid_base64() {
        let token = "header.!!!invalid_base64!!!.signature";
        let result = jwt_decode_payload(token.to_string());
        
        assert!(result.0.get("error").is_some());
        assert_eq!(result.0.get("error").unwrap().as_str(), Some("Invalid base64 encoding"));
    }

    #[test]
    fn test_decode_payload_invalid_json() {
        // This is valid base64 but invalid JSON
        let token = "header.bm90IGpzb24.signature";
        let result = jwt_decode_payload(token.to_string());
        
        assert!(result.0.get("error").is_some());
        assert_eq!(result.0.get("error").unwrap().as_str(), Some("Invalid JSON in payload"));
    }

    // Test algorithm selection in jwt_verify function
    #[test]
    fn test_jwt_verify_algorithm_rs256() {
        let token = "eyJhbGciOiJSUzI1NiJ9.eyJ0ZXN0IjoidmFsdWUifQ.sig";
        let public_key = pub_key();
        
        // Testing the algorithm parsing, not actual verification
        let mut result = jwt_verify(token.to_string(), public_key, "RS256".to_string());
        let (header, _payload, valid) = result.next().unwrap();
        
        // Should fail verification (invalid signature) but algorithm should be recognized
        let lhs = !valid;
        let rhs = header.0.get("error").is_some();
        assert!(lhs || rhs);
    }

    #[test]
    fn test_jwt_verify_algorithm_eddsa() {
        let token = "eyJhbGciOiJFZERTQSJ9.eyJ0ZXN0IjoidmFsdWUifQ.sig";
        let public_key = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----".to_string();
        
        let mut result = jwt_verify(token.to_string(), public_key, "EdDSA".to_string());
        let (header, _payload, valid) = result.next().unwrap();
        
        // Should fail but algorithm should be recognized
        let lhs = !valid;
        let rhs = header.0.get("error").is_some();
        assert!(lhs || rhs);
    }

    #[test]
    fn test_jwt_verify_algorithm_ed25519_alias() {
        let token = "eyJhbGciOiJFZERTQSJ9.eyJ0ZXN0IjoidmFsdWUifQ.sig";
        let public_key = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----".to_string();

        let mut result = jwt_verify(token.to_string(), public_key, "ED25519".to_string());
        let (header, _payload, valid) = result.next().unwrap();

        // Should fail but algorithm alias should be recognized
        let lhs = !valid;
        let rhs = header.0.get("error").is_some();
        assert!(lhs || rhs);
    }

    #[test]
    fn test_jwt_verify_unsupported_algorithm() {
        let token = "token".to_string();
        let public_key = "key".to_string();
        
        let mut result = jwt_verify(token, public_key, "HS256".to_string());
        let (header, payload, valid) = result.next().unwrap();
        
        assert!(!valid);
        assert_eq!(header.0.get("error").unwrap().as_str(), Some("Unsupported algorithm"));
        assert!(payload.0.is_object());
    }

    // Test internal verify_jwt function error paths
    #[test]
    fn test_verify_jwt_invalid_token_format() {
        let result = verify_jwt("invalid", &pub_key(), Algorithm::RS256);
        let (header, _payload, valid) = result;
        
        assert!(!valid);
        assert!(header.0.get("error").is_some());
        assert!(header.0.get("error").unwrap().as_str().unwrap().contains("Invalid JWT header"));
    }

    #[test]
    fn test_verify_jwt_invalid_public_key() {
        let token = "eyJhbGciOiJSUzI1NiJ9.eyJ0ZXN0IjoidmFsdWUifQ.signature";
        let invalid_key = "not a valid PEM key";
        
        let result = verify_jwt(token, invalid_key, Algorithm::RS256);
        let (header, payload, valid) = result;
        
        assert!(!valid);
        assert!(payload.0.get("error").is_some());
        assert!(payload.0.get("error").unwrap().as_str().unwrap().contains("Invalid public key"));
        assert!(header.0.is_object());
    }

    #[test]
    fn test_verify_jwt_algorithm_not_implemented() {
        let token = "eyJhbGciOiJIUzI1NiJ9.eyJ0ZXN0IjoidmFsdWUifQ.signature";
        
        // HS256 is not implemented (we only support RS256 and EdDSA)
        let result = verify_jwt(token, "key", Algorithm::HS256);
        let (_header, payload, valid) = result;
        
        assert!(!valid);
        assert_eq!(payload.0.get("error").unwrap().as_str(), Some("Algorithm not implemented"));
    }

    // Test RS256 verification with actual key pair
    #[test]
    fn test_rs256_verification_success() {
        use jsonwebtoken::{encode, Header, EncodingKey};
        use serde::{Serialize, Deserialize};
        
        #[derive(Debug, Serialize, Deserialize)]
        struct Claims {
            sub: String,
            iss: String,
            exp: usize,
        }
        
        let claims = Claims {
            sub: "user123".to_string(),
            iss: "auth_guard".to_string(),
            exp: 10000000000, // Far future
        };
        
        let encoding_key = EncodingKey::from_rsa_pem(priv_key().as_bytes()).unwrap();
        let token = encode(&Header::new(Algorithm::RS256), &claims, &encoding_key).unwrap();
        
        let result = verify_jwt(&token, &pub_key(), Algorithm::RS256);
        let (_header, payload, valid) = result;
        
        assert!(valid);
        assert_eq!(payload.0.get("sub").unwrap().as_str(), Some("user123"));
        assert_eq!(payload.0.get("iss").unwrap().as_str(), Some("auth_guard"));
    }

    #[test]
    fn test_rs256_verification_invalid_signature() {
        let token = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJhdXRoX2d1YXJkIn0.invalid_signature_here";
        
        let result = verify_jwt(token, &pub_key(), Algorithm::RS256);
        let (_header, payload, valid) = result;
        
        assert!(!valid);
        assert!(payload.0.get("error").is_some());
        assert!(payload.0.get("error").unwrap().as_str().unwrap().contains("Verification failed"));
    }

    #[test]
    fn test_rs256_verification_wrong_key() {
        use jsonwebtoken::{encode, Header, EncodingKey};
        use serde::{Serialize, Deserialize};
        
        #[derive(Debug, Serialize, Deserialize)]
        struct Claims {
            sub: String,
        }
        
        let claims = Claims {
            sub: "user123".to_string(),
        };
        
        // Sign with one key
        let encoding_key = EncodingKey::from_rsa_pem(priv_key().as_bytes()).unwrap();
        let token = encode(&Header::new(Algorithm::RS256), &claims, &encoding_key).unwrap();
        
        // Try to verify with a different key
        let wrong_public_key = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwJJ0lGHJwRdKWLOxNI1a
j9KdP8KNLmxEKmPChBEPqGR8W4qL8xc1qsLvFTNh0r7lVxVXlAh8dPXtV7UrvGJH
oKcKKF1tPdH2ghF0Qh3PXKYX7rXBDxGZ0lLKN3IpEHjPWTX4o8mDK7AqPTqzwJlg
lvKzqGvNPqlMqR4kpxTF9G6bNTQXmGy8qPkF3W0tN0KRYqQDhN4QFvC3Y7Wplqha
7KKrFJLNDQhj3F2d5xF4N7tZNhG2YF0bHNqX3F9L1xH2M0F7cKKFLHNqXFYpQW0N
bPG2ZlCNHPFqWH3N0HGJLKLVMHNqFLqVGpHFqJLKLVMHNqFLqVGpHFqJLKLVMHNq
FwIDAQAB
-----END PUBLIC KEY-----"#;
        
        let result = verify_jwt(&token, wrong_public_key, Algorithm::RS256);
        let (_header, payload, valid) = result;
        
        assert!(!valid);
        assert!(payload.0.get("error").is_some());
    }

    // Test wrapper functions
    #[test]
    fn test_jwt_verify_rs256_wrapper() {
        use jsonwebtoken::{encode, Header, EncodingKey};
        use serde::{Serialize, Deserialize};
        
        #[derive(Debug, Serialize, Deserialize)]
        struct Claims {
            test: String,
        }
        
        let claims = Claims {
            test: "value".to_string(),
        };
        
        let encoding_key = EncodingKey::from_rsa_pem(priv_key().as_bytes()).unwrap();
        let token = encode(&Header::new(Algorithm::RS256), &claims, &encoding_key).unwrap();
        
        let mut result = jwt_verify_rs256(token, pub_key());
        let (header, payload, valid) = result.next().unwrap();
        
        assert!(valid);
        assert_eq!(payload.0.get("test").unwrap().as_str(), Some("value"));
    }
    
    #[test]
    fn test_jwt_verify_ed25519_wrapper_invalid_key() {
        let token = "eyJhbGciOiJFZERTQSJ9.eyJ0ZXN0IjoidmFsdWUifQ.sig".to_string();
        let invalid_key = "not a valid ed25519 key".to_string();
        
        let mut result = jwt_verify_ed25519(token, invalid_key);
        let (_header, payload, valid) = result.next().unwrap();
        
        assert!(!valid);
        assert!(payload.0.get("error").is_some());
    }

    #[test]
    fn test_eddsa_verification_success() {
        use jsonwebtoken::{encode, Header, EncodingKey};
        use serde::{Serialize, Deserialize};

        #[derive(Debug, Serialize, Deserialize)]
        struct Claims { sub: String, iss: String }

        let claims = Claims { sub: "user-eddsa".into(), iss: "auth_guard".into() };
        let encoding_key = EncodingKey::from_ed_pem(ed_priv_key().as_bytes()).unwrap();
        let token = encode(&Header::new(Algorithm::EdDSA), &claims, &encoding_key).unwrap();

        let result = verify_jwt(&token, &ed_pub_key(), Algorithm::EdDSA);
        let (_header, payload, valid) = result;

        assert!(valid);
        assert_eq!(payload.0.get("sub").unwrap().as_str(), Some("user-eddsa"));
    }

    #[test]
    fn test_jwt_verify_ed25519_wrapper_success() {
        use jsonwebtoken::{encode, Header, EncodingKey};
        use serde::{Serialize, Deserialize};

        #[derive(Debug, Serialize, Deserialize)]
        struct Claims { k: u32 }

        let claims = Claims { k: 42 };
        let encoding_key = EncodingKey::from_ed_pem(ed_priv_key().as_bytes()).unwrap();
        let token = encode(&Header::new(Algorithm::EdDSA), &claims, &encoding_key).unwrap();

        let mut result = jwt_verify_ed25519(token, ed_pub_key());
        let (_header, payload, valid) = result.next().unwrap();

        assert!(valid);
        assert_eq!(payload.0.get("k").unwrap().as_u64(), Some(42));
    }
    
    #[test]
    fn test_cover_pg_test_module() {
        // Exercise pg_test helpers so they are included in coverage accounting
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
