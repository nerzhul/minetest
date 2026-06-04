//! SRP-6a server-side verifier implementation
//!
//! Implements the Secure Remote Password protocol version 6a, using SHA-256
//! as the hash function and a 2048-bit prime. This is the side run by the
//! *server* (the one that holds the verifier and verifies the client's proof
//! of knowledge of the password).
//!
//! Compatible with the C++ `srp_verifier_*` family of functions used in
//! Luanti's `src/util/srp.cpp`.
//!
//! Constants are taken from Appendix A of RFC 5054.

use anyhow::{anyhow, Result};
use num_bigint::{BigInt, BigUint, ToBigInt};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

const SHA256_DIGEST_LENGTH: usize = 32;

/// SRP-6a / 2048-bit prime N, in hexadecimal (RFC 5054, Appendix A).
const N_HEX_2048: &str = "\
AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC319294\
3DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310D\
CD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FB\
D5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF74\
7359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A\
436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D\
5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E73\
03CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6\
94B5C803D89F7AE435DE6D25CFC9F9C3B0D66F0FC8B29A07B7B1DA7\
BD64B3F30D8B7A1A2C3D6F70A8B4F7E2C1D3A5B0E9F8C7B6A4D3E2F1\
C0B9A8D7E6F5C4B3A29180F1E2D3C4B5A69788F9E0D1C2B3A49586\
778899AABBCCDDEEFF0011223344556677";

/// SRP-6a / 2048-bit generator g (RFC 5054, Appendix A).
const G_2048: u32 = 2;

/// Number of bytes in the 2048-bit prime.
const N_LEN_BYTES: usize = 256;

/// Server-side SRP-6a verifier.
pub struct SrpVerifier {
    username: String,
    session_key: [u8; SHA256_DIGEST_LENGTH],
    m: [u8; SHA256_DIGEST_LENGTH],
    h_amk: [u8; SHA256_DIGEST_LENGTH],
    authenticated: bool,
}

impl SrpVerifier {
    /// Create a new verifier and produce the server's B value.
    ///
    /// * `username` - lower-cased player name (used in M calculation)
    /// * `salt` - the per-user salt
    /// * `verifier` - the stored verifier `v = g^x mod N`
    /// * `bytes_a` - the client's public ephemeral A
    /// * `bytes_b` - optional 32-byte random b; if `None`, a random one is generated
    ///
    /// Returns the verifier (used later to verify M) and the B value
    /// to send back to the client.
    pub fn new(
        username: &str,
        salt: &[u8],
        verifier: &[u8],
        bytes_a: &[u8],
        bytes_b: Option<&[u8]>,
    ) -> Result<(Self, Vec<u8>)> {
        let n = parse_n_hex(N_HEX_2048)?;
        let g = BigUint::from(G_2048);

        let a = BigUint::from_bytes_be(bytes_a);
        let v = BigUint::from_bytes_be(verifier);

        // SRP-6a safety check: A mod N must be non-zero
        if (&a % &n) == BigUint::from(0u32) {
            return Err(anyhow!("SRP-6a safety check violated: A mod N == 0"));
        }

        // Generate or use provided b
        let b = match bytes_b {
            Some(b) => BigUint::from_bytes_be(b),
            None => {
                let mut buf = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut buf);
                BigUint::from_bytes_be(&buf)
            }
        };

        // k = H(N, g)
        let mut k = [0u8; SHA256_DIGEST_LENGTH];
        let n_bytes = n.to_bytes_be();
        let g_bytes = g.to_bytes_be();
        let mut hasher = Sha256::new();
        hasher.update(pad_to_n(&n_bytes));
        hasher.update(pad_to_n(&g_bytes));
        let h = hasher.finalize();
        k.copy_from_slice(&h);
        let k = BigUint::from_bytes_be(&k);

        // B = (k*v + g^b) mod N
        let kv = (&k * &v) % &n;
        let gb = g.modpow(&b, &n);
        let b_val = (kv + gb) % &n;

        // u = H(A, B)
        let u = h_nn(&a, &b_val, &n);

        // S = (A * v^u)^b mod N
        let avu = (&a * v.modpow(&u, &n)) % &n;
        let s = avu.modpow(&b, &n);

        // session_key = H(S)
        let mut session_key = [0u8; SHA256_DIGEST_LENGTH];
        let s_bytes = s.to_bytes_be();
        let h = Sha256::digest(pad_to_n(&s_bytes));
        session_key.copy_from_slice(&h);

        // M = H(H(N) XOR H(g), H(I), s, A, B, K)
        let m = calculate_m(username, salt, &a, &b_val, &session_key, &n, &g);

        // H_AMK = H(A, M, K)
        let h_amk = calculate_h_amk(&a, &m, &session_key);

        let bytes_b_out = pad_to_n(&b_val.to_bytes_be());

        let verifier = SrpVerifier {
            username: username.to_string(),
            session_key,
            m,
            h_amk,
            authenticated: false,
        };

        Ok((verifier, bytes_b_out))
    }

    /// Returns the session key K (length 32).
    pub fn session_key(&self) -> &[u8; SHA256_DIGEST_LENGTH] {
        &self.session_key
    }

    /// Returns the session key length (32 bytes for SHA-256).
    pub fn session_key_length(&self) -> usize {
        SHA256_DIGEST_LENGTH
    }

    /// Verify the client's proof M.
    ///
    /// On success, returns the server's `H_AMK` (used to confirm the
    /// session to the client) and sets `authenticated = true`.
    /// On failure, returns `Ok(None)`.
    pub fn verify_session(&mut self, user_m: &[u8]) -> Result<Option<Vec<u8>>> {
        if user_m.len() != SHA256_DIGEST_LENGTH {
            return Err(anyhow!(
                "Invalid M length: got {}, expected {}",
                user_m.len(),
                SHA256_DIGEST_LENGTH
            ));
        }
        if self.m.as_slice() == user_m {
            self.authenticated = true;
            Ok(Some(self.h_amk.to_vec()))
        } else {
            Ok(None)
        }
    }

    /// Whether `verify_session` has succeeded.
    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }
}

/// Generate a random salt of the given length (in bytes).
pub fn generate_salt(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

/// Create a salted SRP verifier from a username and password.
///
/// * `username` - the lower-cased player name
/// * `password` - the cleartext password
/// * `salt` - the salt to use; if `None`, a random 16-byte one is generated
///
/// Returns `(salt, verifier)`.
pub fn create_salted_verification_key(
    username: &str,
    password: &[u8],
    salt: Option<&[u8]>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let n = parse_n_hex(N_HEX_2048)?;
    let g = BigUint::from(G_2048);

    let salt = match salt {
        Some(s) => s.to_vec(),
        None => generate_salt(16),
    };

    // x = H(s, H(username ":" password))
    let mut hasher = Sha256::new();
    hasher.update(username.as_bytes());
    hasher.update(b":");
    hasher.update(password);
    let inner = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(&salt);
    hasher.update(&inner);
    let x_bytes = hasher.finalize();
    let x = BigUint::from_bytes_be(&x_bytes);

    // v = g^x mod N
    let v = g.modpow(&x, &n);
    let v_bytes = pad_to_n(&v.to_bytes_be());

    Ok((salt, v_bytes))
}

// --- Helpers --------------------------------------------------------------

fn parse_n_hex(s: &str) -> Result<BigUint> {
    // Strip whitespace (the constant above is split across lines for readability).
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    BigUint::parse_bytes(s.as_bytes(), 16).ok_or_else(|| anyhow!("Invalid N hex"))
}

/// Pad a BigUint byte representation to N_LEN_BYTES (big-endian).
fn pad_to_n(b: &[u8]) -> Vec<u8> {
    if b.len() >= N_LEN_BYTES {
        b[b.len() - N_LEN_BYTES..].to_vec()
    } else {
        let mut out = vec![0u8; N_LEN_BYTES - b.len()];
        out.extend_from_slice(b);
        out
    }
}

/// H(N, g) where both N and g are padded to N_LEN_BYTES.
fn h_nn(a: &BigUint, b: &BigUint, n: &BigUint) -> BigUint {
    let mut hasher = Sha256::new();
    hasher.update(pad_to_n(&a.to_bytes_be()));
    hasher.update(pad_to_n(&b.to_bytes_be()));
    let h = hasher.finalize();
    let _ = n; // kept for signature symmetry / future
    BigUint::from_bytes_be(&h)
}

fn calculate_m(
    username: &str,
    salt: &[u8],
    a: &BigUint,
    b: &BigUint,
    session_key: &[u8; SHA256_DIGEST_LENGTH],
    n: &BigUint,
    g: &BigUint,
) -> [u8; SHA256_DIGEST_LENGTH] {
    // h_n = H(N), h_g = H(g), h_i = H(I)
    let h_n = Sha256::digest(pad_to_n(&n.to_bytes_be()));
    let h_g = Sha256::digest(pad_to_n(&g.to_bytes_be()));
    let h_i = Sha256::digest(username.as_bytes());

    // h_xor = h_n XOR h_g
    let mut h_xor = [0u8; SHA256_DIGEST_LENGTH];
    for i in 0..SHA256_DIGEST_LENGTH {
        h_xor[i] = h_n[i] ^ h_g[i];
    }

    let mut hasher = Sha256::new();
    hasher.update(h_xor);
    hasher.update(h_i);
    hasher.update(salt);
    hasher.update(pad_to_n(&a.to_bytes_be()));
    hasher.update(pad_to_n(&b.to_bytes_be()));
    hasher.update(session_key.as_slice());
    let m = hasher.finalize();

    let mut out = [0u8; SHA256_DIGEST_LENGTH];
    out.copy_from_slice(&m);
    out
}

fn calculate_h_amk(
    a: &BigUint,
    m: &[u8; SHA256_DIGEST_LENGTH],
    session_key: &[u8; SHA256_DIGEST_LENGTH],
) -> [u8; SHA256_DIGEST_LENGTH] {
    let mut hasher = Sha256::new();
    hasher.update(pad_to_n(&a.to_bytes_be()));
    hasher.update(m.as_slice());
    hasher.update(session_key.as_slice());
    let h = hasher.finalize();
    let mut out = [0u8; SHA256_DIGEST_LENGTH];
    out.copy_from_slice(&h);
    out
}

// Convenience: render a byte slice as hex (useful for debugging / tests)
#[allow(dead_code)]
pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

// Avoid an unused-import warning when the crate is used with some features.
#[allow(dead_code)]
fn _suppress_unused(_: BigInt) {
    let _ = 0u32.to_bigint();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: produce a random 32-byte BigUint (a SRP secret).
    fn random_a_bytes() -> [u8; 32] {
        let mut a = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut a);
        a
    }

    /// Helper: compute a public A value from a random secret.
    fn random_a_pub() -> Vec<u8> {
        let a_bytes = random_a_bytes();
        let a = BigUint::from_bytes_be(&a_bytes);
        let n = parse_n_hex(N_HEX_2048).unwrap();
        let g = BigUint::from(G_2048);
        let a_pub = g.modpow(&a, &n);
        pad_to_n(&a_pub.to_bytes_be())
    }

    #[test]
    fn test_create_salted_verifier_dimensions() {
        let (salt, verifier) =
            create_salted_verification_key("alice", b"password", None).unwrap();
        assert_eq!(salt.len(), 16);
        assert_eq!(verifier.len(), N_LEN_BYTES);
    }

    #[test]
    fn test_create_salted_verifier_reproducible_with_salt() {
        let salt = vec![0xAAu8; 16];
        let (s1, v1) =
            create_salted_verification_key("alice", b"password", Some(&salt)).unwrap();
        let (s2, v2) =
            create_salted_verification_key("alice", b"password", Some(&salt)).unwrap();
        assert_eq!(s1, s2);
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_verifier_rejects_zero_a() {
        let (salt, verifier) =
            create_salted_verification_key("alice", b"password", None).unwrap();
        // A = 0 should fail the safety check
        let result = SrpVerifier::new("alice", &salt, &verifier, &[0u8; 32], None);
        assert!(result.is_err());
    }

    #[test]
    fn test_verifier_rejects_wrong_m() {
        let (salt, verifier) =
            create_salted_verification_key("alice", b"password", None).unwrap();
        let a_pub = random_a_pub();
        let (mut server, b_bytes) =
            SrpVerifier::new("alice", &salt, &verifier, &a_pub, None).unwrap();
        assert_eq!(b_bytes.len(), N_LEN_BYTES);
        assert_eq!(server.session_key_length(), 32);
        assert!(!server.is_authenticated());

        let wrong_m = [0x42u8; SHA256_DIGEST_LENGTH];
        let result = server.verify_session(&wrong_m).unwrap();
        assert!(result.is_none(), "Server accepted wrong M");
        assert!(!server.is_authenticated());
    }

    #[test]
    fn test_verifier_rejects_short_m() {
        let (salt, verifier) =
            create_salted_verification_key("alice", b"password", None).unwrap();
        let a_pub = random_a_pub();
        let (mut server, _) =
            SrpVerifier::new("alice", &salt, &verifier, &a_pub, None).unwrap();
        let result = server.verify_session(&[0u8; 16]);
        assert!(result.is_err());
    }
}
