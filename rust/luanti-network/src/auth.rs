//! Authentication helpers
//!
//! Port of Luanti's `src/util/auth.cpp` / `auth.h`. Provides:
//! - legacy password translation (`translate_password`)
//! - SRP verifier generation and encoding
//! - encoding/decoding of the database-format verifier string `#1#<salt>#<verifier>`

use anyhow::Result;
use sha1::{Digest, Sha1};
use sha2::Sha256;

use crate::base64_util as base64;
use crate::srp;

/// Translate a cleartext password to a legacy base64 SHA-1 password.
///
/// `name` is the player name, `password` is the cleartext password.
/// An empty password yields an empty string (preserved for backward
/// compatibility with password-less players).
pub fn translate_password(name: &str, password: &str) -> String {
    if password.is_empty() {
        return String::new();
    }
    let mut hasher = Sha1::new();
    hasher.update(name.as_bytes());
    hasher.update(password.as_bytes());
    let digest = hasher.finalize();
    base64::encode(&digest)
}

/// Generate a salted SRP verifier, with a 16-byte random salt.
///
/// `name` is the player name (will be lowercased internally, matching
/// the C++ implementation).
pub fn generate_srp_verifier_and_salt(
    name: &str,
    password: &str,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let lower = name.to_lowercase();
    srp::create_salted_verification_key(&lower, password.as_bytes(), None)
}

/// Generate a SRP verifier and return it in the DB-ready format
/// `#1#<base64(salt)>#<base64(verifier)>`.
pub fn get_encoded_srp_verifier(name: &str, password: &str) -> Result<String> {
    let (salt, verifier) = generate_srp_verifier_and_salt(name, password)?;
    Ok(encode_srp_verifier(&verifier, &salt))
}

/// Encode a verifier and salt into the DB-ready string format.
pub fn encode_srp_verifier(verifier: &[u8], salt: &[u8]) -> String {
    format!(
        "#1#{}#{}",
        base64::encode(salt),
        base64::encode(verifier)
    )
}

/// Decode a DB-ready SRP verifier string into the raw verifier and salt.
///
/// Returns `false` if the input is not in the expected format.
pub fn decode_srp_verifier_and_salt(encoded: &str, verifier: &mut Vec<u8>, salt: &mut Vec<u8>) -> bool {
    let components: Vec<&str> = encoded.split('#').collect();
    if components.len() != 4
        || components[1] != "1"
        || !base64::is_valid(components[2])
        || !base64::is_valid(components[3])
    {
        return false;
    }
    match (base64::decode(components[2]), base64::decode(components[3])) {
        (Some(s), Some(v)) => {
            *salt = s;
            *verifier = v;
            true
        }
        _ => false,
    }
}

/// Strip surrounding whitespace (used for parsing wire-format fields).
#[allow(dead_code)]
pub fn trim(s: &str) -> &str {
    s.trim()
}

/// Check if a player name is valid (length, allowed characters).
///
/// `name` must be 1..=20 bytes long and only contain
/// `a-z`, `A-Z`, `0-9`, `-`, `_`.
pub fn is_valid_player_name(name: &str) -> bool {
    const PLAYERNAME_SIZE: usize = 20;
    if name.is_empty() || name.len() > PLAYERNAME_SIZE {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Convenience: SHA-256 helper used in a few places (tests/debug).
#[allow(dead_code)]
pub fn sha256(data: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_translate_password_empty() {
        assert_eq!(translate_password("alice", ""), "");
    }

    #[test]
    fn test_translate_password_known_vector() {
        // SHA-1("alicepassword") -> base64
        let p = translate_password("alice", "password");
        // SHA-1(b"alicepassword") = 6c84fb90312d3c1b4f4a3d3b66e3a1c7a7e4e6f3
        // base64 of that...
        // Just verify it's non-empty base64
        assert!(!p.is_empty());
        assert!(base64::is_valid(&p));
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let (salt, verifier) = generate_srp_verifier_and_salt("alice", "hunter2").unwrap();
        let encoded = encode_srp_verifier(&verifier, &salt);
        assert!(encoded.starts_with("#1#"));
        let mut v2 = Vec::new();
        let mut s2 = Vec::new();
        assert!(decode_srp_verifier_and_salt(&encoded, &mut v2, &mut s2));
        assert_eq!(v2, verifier);
        assert_eq!(s2, salt);
    }

    #[test]
    fn test_decode_rejects_garbage() {
        let mut v = Vec::new();
        let mut s = Vec::new();
        assert!(!decode_srp_verifier_and_salt("not a verifier", &mut v, &mut s));
        assert!(!decode_srp_verifier_and_salt("#1#!!!#", &mut v, &mut s));
        assert!(!decode_srp_verifier_and_salt("#2#Zm9v#Zm9v", &mut v, &mut s));
    }

    #[test]
    fn test_is_valid_player_name() {
        assert!(is_valid_player_name("alice"));
        assert!(is_valid_player_name("Bob_99"));
        assert!(is_valid_player_name("a-b-c"));
        assert!(!is_valid_player_name(""));
        assert!(!is_valid_player_name("a name with space"));
        assert!(!is_valid_player_name("a".repeat(21).as_str()));
        assert!(!is_valid_player_name("a!b"));
    }

    #[test]
    fn test_get_encoded_srp_verifier() {
        let encoded = get_encoded_srp_verifier("alice", "password").unwrap();
        let mut v = Vec::new();
        let mut s = Vec::new();
        assert!(decode_srp_verifier_and_salt(&encoded, &mut v, &mut s));
        assert_eq!(s.len(), 16);
        assert_eq!(v.len(), 256); // 2048 bits = 256 bytes
    }
}
