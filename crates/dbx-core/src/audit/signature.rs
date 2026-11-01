//! HMAC-SHA256 for audit checkpoints.
//!
//! Implemented here rather than pulling in another crate: the algorithm is
//! RFC 2104 over `sha2`, which the workspace already depends on, and the
//! construction is short enough to test against the RFC 4231 vectors.

use sha2::{Digest, Sha256};

const BLOCK_SIZE: usize = 64;

/// Hex-encoded HMAC-SHA256 of `message` under `key`.
pub fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    let mut normalized_key = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let digest = Sha256::digest(key);
        normalized_key[..digest.len()].copy_from_slice(&digest);
    } else {
        normalized_key[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0x36u8; BLOCK_SIZE];
    let mut outer_pad = [0x5cu8; BLOCK_SIZE];
    for index in 0..BLOCK_SIZE {
        inner_pad[index] ^= normalized_key[index];
        outer_pad[index] ^= normalized_key[index];
    }

    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    hex(&outer.finalize())
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

/// The exact bytes a checkpoint signature covers.
pub fn checkpoint_payload(chain_id: &str, seq: i64, event_hash: &str) -> String {
    format!("dbx-audit-checkpoint:v1:{chain_id}:{seq}:{event_hash}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_rfc_4231_test_case_1() {
        let key = [0x0bu8; 20];
        assert_eq!(
            hmac_sha256_hex(&key, b"Hi There"),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn matches_rfc_4231_test_case_2() {
        assert_eq!(
            hmac_sha256_hex(b"Jefe", b"what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn a_long_key_is_hashed_first() {
        let key = [0xaau8; 131];
        let long = hmac_sha256_hex(&key, b"Test Using Larger Than Block-Size Key - Hash Key First");
        assert_eq!(long, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
    }

    #[test]
    fn the_signature_depends_on_every_field() {
        let base = checkpoint_payload("default", 7, "abc");
        assert_ne!(base, checkpoint_payload("default", 8, "abc"));
        assert_ne!(base, checkpoint_payload("default", 7, "abd"));
        assert_ne!(base, checkpoint_payload("other", 7, "abc"));
    }
}
