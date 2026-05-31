//! CSRF `state` nonce for the Auth Code flow. Generated before the browser
//! opens, echoed on the redirect, and required to match. A mismatch means the
//! callback is forged/replayed and the Sign-in must abort (ADR 0010 §6).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::RngCore;

/// A freshly generated opaque state nonce (url-safe, ~43 chars / 256 bits).
pub fn generate() -> String {
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    URL_SAFE_NO_PAD.encode(raw)
}

/// Whether the state returned on the redirect matches what we sent. Compared in
/// length-then-content; both operands are in-process values the same user owns,
/// so there is no cross-trust timing channel to defend (cf. core's `bytes_eq`).
pub fn matches(expected: &str, returned: &str) -> bool {
    // Constant-time-ish: avoid early return on first differing byte. Not a
    // security boundary here, but cheap and signals intent.
    if expected.len() != returned.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in expected.bytes().zip(returned.bytes()) {
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_state_is_nonempty_and_random() {
        let a = generate();
        let b = generate();
        assert!(!a.is_empty());
        assert_ne!(a, b, "state must be unpredictable");
    }

    #[test]
    fn matching_state_accepted() {
        let s = generate();
        assert!(matches(&s, &s));
    }

    #[test]
    fn mismatched_state_rejected() {
        let s = generate();
        assert!(!matches(&s, "attacker-supplied-value"));
        assert!(!matches(&s, &format!("{s}x")), "length differs → reject");
    }
}
