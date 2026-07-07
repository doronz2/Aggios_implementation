//! BLS delegation signatures (additive notation).
//!
//! Long-term voter signing key:
//!   sk_i ∈ Fr,  pk_i = sk_i · g2 ∈ G2
//! Delegation message:
//!   M_i = "AGGIOS_DELEGATION" || election_id || aggregator_id
//! Signature:
//!   σ_i = sk_i · H_M ∈ G1  where  H_M = hash_to_G1(M_i)
//! Verification:
//!   e(σ_i, g2) == e(H_M, pk_i)
//! Batch verification (all voters delegated to the same aggregator sign the
//! same message M):
//!   σ_I = Σ_i σ_i,  pk_I = Σ_i pk_i,  check  e(σ_I, g2) == e(H_M, pk_I)

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_std::rand::RngCore;
use ark_std::{UniformRand, Zero};

use crate::hash::hash_to_g1;

pub const DELEGATION_DOMAIN_SEP: &[u8] = b"AGGIOS_DELEGATION";

/// g2 generator of the prime-order group G2.
pub fn g2_generator() -> G2Affine {
    G2Affine::prime_subgroup_generator()
}

#[derive(Clone, Debug)]
pub struct SigningKeypair {
    pub sk: Fr,
    pub pk: G2Affine,
}

impl SigningKeypair {
    pub fn generate<R: RngCore>(rng: &mut R) -> Self {
        let sk = Fr::rand(rng);
        // pk = sk · g2
        let pk = g2_generator().mul(sk).into_affine();
        Self { sk, pk }
    }
}

/// H_M = hash_to_G1("AGGIOS_DELEGATION" || election_id || aggregator_id)
pub fn delegation_message_hash(election_id: &str, aggregator_id: &str) -> G1Affine {
    hash_to_g1(
        DELEGATION_DOMAIN_SEP,
        &[election_id.as_bytes(), aggregator_id.as_bytes()],
    )
}

/// σ = sk · H_M
pub fn sign_delegation(sk: &Fr, election_id: &str, aggregator_id: &str) -> G1Affine {
    let h_m = delegation_message_hash(election_id, aggregator_id);
    h_m.mul(*sk).into_affine()
}

/// Individual verification: e(σ, g2) == e(H_M, pk)
pub fn verify_delegation(
    signature: &G1Affine,
    pk: &G2Affine,
    election_id: &str,
    aggregator_id: &str,
) -> bool {
    if signature.is_zero() || pk.is_zero() {
        return false;
    }
    let h_m = delegation_message_hash(election_id, aggregator_id);
    Bls12_381::pairing(*signature, g2_generator()) == Bls12_381::pairing(h_m, *pk)
}

/// σ_I = Σ_i σ_i
pub fn aggregate_signatures(signatures: &[G1Affine]) -> G1Affine {
    signatures
        .iter()
        .fold(G1Projective::zero(), |acc, s| acc + s.into_projective())
        .into_affine()
}

/// pk_I = Σ_i pk_i
pub fn aggregate_public_keys(public_keys: &[G2Affine]) -> G2Affine {
    public_keys
        .iter()
        .fold(G2Projective::zero(), |acc, pk| acc + pk.into_projective())
        .into_affine()
}

/// Batch verification for one aggregator (same message for all voters):
/// e(σ_I, g2) == e(H_M, pk_I)
pub fn verify_aggregate_delegation(
    aggregate_signature: &G1Affine,
    public_keys: &[G2Affine],
    election_id: &str,
    aggregator_id: &str,
) -> bool {
    if public_keys.is_empty() {
        return aggregate_signature.is_zero();
    }
    let pk_agg = aggregate_public_keys(public_keys);
    if aggregate_signature.is_zero() || pk_agg.is_zero() {
        return false;
    }
    let h_m = delegation_message_hash(election_id, aggregator_id);
    Bls12_381::pairing(*aggregate_signature, g2_generator()) == Bls12_381::pairing(h_m, pk_agg)
}
