//! Base64 encoding/decoding helpers
//!
//! Thin wrapper over the `base64` crate that matches Luanti's custom
//! `base64_encode` / `base64_decode` / `base64_is_valid` functions
//! (which use the standard alphabet, with `+` and `/` and `=` padding).

use base64::{engine::general_purpose::STANDARD, Engine as _};

/// Encode a byte slice to standard base64 (no line wrapping).
pub fn encode(data: &[u8]) -> String {
    STANDARD.encode(data)
}

/// Decode a base64 string to bytes.
///
/// Returns `None` if the input is not valid base64.
pub fn decode(s: &str) -> Option<Vec<u8>> {
    STANDARD.decode(s).ok()
}

/// Returns `true` if the string is valid base64 with the standard alphabet.
pub fn is_valid(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        && decode(s).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let data = b"hello world";
        let enc = encode(data);
        let dec = decode(&enc).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn test_known_vector() {
        // Base64 of "foo"
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(decode("Zm9v"), Some(b"foo".to_vec()));
    }

    #[test]
    fn test_is_valid() {
        assert!(is_valid("Zm9v"));
        assert!(!is_valid(""));
        assert!(!is_valid("not base64!"));
    }
}
