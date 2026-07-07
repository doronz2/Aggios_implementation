//! Domain-separated hashing to the scalar field Fr and to G1.
//!
//! Conventions (additive notation):
//! - hash_to_fr(domain_separator || canonical_serialized_data) -> Fr
//! - hash_to_g1(domain_separator || canonical_serialized_data) -> G1 (for BLS)
//!
//! All multi-part inputs are length-prefixed to make the encoding injective.

use ark_bls12_381::{Fr, G1Affine};
use ark_ec::AffineCurve;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_std::Zero;
use sha2::{Digest, Sha512};

/// Injective encoding: sep, then for each part `len_le_u64 || bytes`.
fn transcript_bytes(domain_separator: &[u8], parts: &[&[u8]]) -> Sha512 {
    let mut hasher = Sha512::new();
    hasher.update((domain_separator.len() as u64).to_le_bytes());
    hasher.update(domain_separator);
    for part in parts {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    hasher
}

/// hash_to_fr(domain_separator || parts): SHA-512 then reduction mod r.
/// The 512-bit digest makes the mod-r bias negligible.
pub fn hash_to_fr(domain_separator: &[u8], parts: &[&[u8]]) -> Fr {
    let digest = transcript_bytes(domain_separator, parts).finalize();
    Fr::from_le_bytes_mod_order(&digest)
}

/// hash_to_g1(domain_separator || parts): try-and-increment onto the curve,
/// then cofactor clearing so the result lies in the prime-order subgroup G1.
///
/// Note: this is a demo-grade hash-to-curve (not constant-time). It is only
/// used for BLS delegation signatures in this prototype.
pub fn hash_to_g1(domain_separator: &[u8], parts: &[&[u8]]) -> G1Affine {
    let mut counter: u64 = 0;
    loop {
        let mut hasher = transcript_bytes(domain_separator, parts);
        hasher.update(b"AGGIOS_H2C_CTR");
        hasher.update(counter.to_le_bytes());
        let digest = hasher.finalize(); // 64 bytes

        // G1Affine compressed encoding is 48 bytes; from_random_bytes parses a
        // candidate x coordinate (masking flag bits) and lifts it to the curve.
        if let Some(point) = G1Affine::from_random_bytes(&digest[..48]) {
            // Clear the cofactor to land in the prime-order subgroup.
            let cleared = point.mul_by_cofactor();
            if !cleared.is_zero() {
                return cleared;
            }
        }
        counter += 1;
    }
}

/// Canonical compressed serialization of any arkworks object, for hashing
/// and for public artifacts.
pub fn canonical_bytes<T: CanonicalSerialize>(t: &T) -> Vec<u8> {
    let mut buf = Vec::with_capacity(t.serialized_size());
    t.serialize(&mut buf)
        .expect("canonical serialization cannot fail on in-memory buffers");
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_to_fr_is_deterministic_and_domain_separated() {
        let a = hash_to_fr(b"SEP_A", &[b"data"]);
        let b = hash_to_fr(b"SEP_A", &[b"data"]);
        let c = hash_to_fr(b"SEP_B", &[b"data"]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn length_prefixing_is_injective() {
        // ("ab", "c") must differ from ("a", "bc")
        let a = hash_to_fr(b"SEP", &[b"ab", b"c"]);
        let b = hash_to_fr(b"SEP", &[b"a", b"bc"]);
        assert_ne!(a, b);
    }

    #[test]
    fn hash_to_g1_lands_in_subgroup() {
        let p = hash_to_g1(b"SEP", &[b"message"]);
        assert!(p.is_on_curve());
        assert!(p.is_in_correct_subgroup_assuming_on_curve());
        assert!(!p.is_zero());
        let q = hash_to_g1(b"SEP", &[b"other message"]);
        assert_ne!(p, q);
    }
}
