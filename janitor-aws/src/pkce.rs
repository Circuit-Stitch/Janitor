//! PKCE (RFC 7636) — code verifier + S256 challenge. Pure; the only untested
//! caller is the browser/listener shell. The verifier is secret-adjacent (it
//! proves possession of the auth code) but short-lived and not a stored secret.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::RngCore;
use sha2::{Digest, Sha256};

/// A generated PKCE pair: the verifier (sent later to `CreateToken`) and the
/// challenge (sent to `/authorize`).
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

/// base64url **without padding**, per RFC 7636 §4.2.
pub fn base64url_no_pad(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The S256 challenge for a given verifier: base64url-no-pad(SHA256(verifier)).
pub fn s256_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64url_no_pad(&digest)
}

/// Generate a fresh PKCE pair with a 32-byte (256-bit) random verifier source,
/// base64url-encoded to a 43-char verifier (within the RFC's 43–128 range).
pub fn generate() -> Pkce {
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    let verifier = base64url_no_pad(&raw);
    let challenge = s256_challenge(&verifier);
    Pkce {
        verifier,
        challenge,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7636 Appendix B known-answer vector.
    #[test]
    fn s256_matches_rfc7636_appendix_b() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(s256_challenge(verifier), expected);
    }

    #[test]
    fn base64url_is_unpadded_and_urlsafe() {
        // 0xfb bytes encode to chars that differ between standard and url-safe
        // alphabets, and any input whose length isn't a multiple of 3 would be
        // padded with '=' in the padded variant.
        let out = base64url_no_pad(&[0xfb, 0xff, 0xfe]);
        assert!(!out.contains('='), "must be unpadded");
        assert!(!out.contains('+') && !out.contains('/'), "must be url-safe");
    }

    #[test]
    fn generated_verifier_is_in_rfc_length_range() {
        let p = generate();
        assert!(
            (43..=128).contains(&p.verifier.len()),
            "verifier length {} out of RFC 7636 range",
            p.verifier.len()
        );
        // The challenge must verify against the verifier.
        assert_eq!(s256_challenge(&p.verifier), p.challenge);
    }

    #[test]
    fn two_generates_differ() {
        assert_ne!(generate().verifier, generate().verifier, "must be random");
    }
}
