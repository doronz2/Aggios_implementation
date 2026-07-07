//! Cross-group equal-discrete-log proof (Chaum–Pedersen style, Fiat–Shamir).
//!
//! Proves that the registration token and the voting public key use the same
//! scalar skv_i (additive notation):
//!   τ_i = skv_i · B_i ∈ G1   and   pkv_i = skv_i · g2 ∈ G2
//!
//! Prove(B, τ, g2, pkv, skv, context):
//!   1. sample r ∈ Fr
//!   2. A1 = r · B ∈ G1
//!   3. A2 = r · g2 ∈ G2
//!   4. c  = hash_to_fr("AGGIOS_EQLOG" || context || B || τ || g2 || pkv || A1 || A2)
//!   5. z  = r + c · skv
//!   proof = (A1, A2, z)
//!
//! Verify: recompute c; accept iff
//!   z · B  == A1 + c · τ    and    z · g2 == A2 + c · pkv

use ark_bls12_381::{Fr, G1Affine, G2Affine};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_std::rand::RngCore;
use ark_std::UniformRand;

use crate::bls::g2_generator;
use crate::hash::{canonical_bytes, hash_to_fr};

pub const EQLOG_DOMAIN_SEP: &[u8] = b"AGGIOS_EQLOG";

/// Context binding the proof to one voter slot in one aggregator's domain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EqLogContext {
    pub election_id: String,
    pub aggregator_id: String,
    pub voter_id: String,
    pub local_index: usize,
    pub domain_size: usize,
}

impl EqLogContext {
    fn parts(&self) -> Vec<Vec<u8>> {
        vec![
            self.election_id.as_bytes().to_vec(),
            self.aggregator_id.as_bytes().to_vec(),
            self.voter_id.as_bytes().to_vec(),
            (self.local_index as u64).to_le_bytes().to_vec(),
            (self.domain_size as u64).to_le_bytes().to_vec(),
        ]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EqLogProof {
    pub a1: G1Affine,
    pub a2: G2Affine,
    pub z: Fr,
}

fn challenge(
    base_g1: &G1Affine,
    tau: &G1Affine,
    pkv: &G2Affine,
    a1: &G1Affine,
    a2: &G2Affine,
    context: &EqLogContext,
) -> Fr {
    let g2 = g2_generator();
    let mut parts: Vec<Vec<u8>> = context.parts();
    parts.push(canonical_bytes(base_g1));
    parts.push(canonical_bytes(tau));
    parts.push(canonical_bytes(&g2));
    parts.push(canonical_bytes(pkv));
    parts.push(canonical_bytes(a1));
    parts.push(canonical_bytes(a2));
    let part_refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
    hash_to_fr(EQLOG_DOMAIN_SEP, &part_refs)
}

pub fn prove<R: RngCore>(
    base_g1: &G1Affine, // B_i (Lagrange basis commitment)
    tau: &G1Affine,     // τ_i = skv · B_i
    pkv: &G2Affine,     // pkv = skv · g2
    skv: &Fr,
    context: &EqLogContext,
    rng: &mut R,
) -> EqLogProof {
    let r = Fr::rand(rng);
    // A1 = r · B, A2 = r · g2
    let a1 = base_g1.mul(r).into_affine();
    let a2 = g2_generator().mul(r).into_affine();
    let c = challenge(base_g1, tau, pkv, &a1, &a2, context);
    // z = r + c · skv
    let z = r + c * skv;
    EqLogProof { a1, a2, z }
}

pub fn verify(
    base_g1: &G1Affine,
    tau: &G1Affine,
    pkv: &G2Affine,
    proof: &EqLogProof,
    context: &EqLogContext,
) -> bool {
    let c = challenge(base_g1, tau, pkv, &proof.a1, &proof.a2, context);
    // z · B == A1 + c · τ
    let lhs_g1 = base_g1.mul(proof.z);
    let rhs_g1 = proof.a1.into_projective() + tau.mul(c);
    if lhs_g1 != rhs_g1 {
        return false;
    }
    // z · g2 == A2 + c · pkv
    let lhs_g2 = g2_generator().mul(proof.z);
    let rhs_g2 = proof.a2.into_projective() + pkv.mul(c);
    lhs_g2 == rhs_g2
}
