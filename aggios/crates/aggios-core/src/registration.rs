//! Registration flow: voter keys, registration tokens, aggregator
//! finalization, and validator-side registration checks.
//!
//! For each real voter i at local index idx_i (additive notation):
//!   B_i  = KZG commitment to the Lagrange basis polynomial L_{idx_i} in G1
//!   τ_i  = skv_i · B_i ∈ G1          (public registration token)
//! For each padding index p (public, deterministic):
//!   pad_scalar_p = hash_to_fr("AGGIOS_PAD_TOKEN" || election_id || aggregator_id || p)
//!   τ_pad_p      = pad_scalar_p · B_{real_count + p}
//! The aggregate commitment to the registered token vector is
//!   C_commit = Σ_i τ_i + Σ_p τ_pad_p

use std::collections::HashSet;
use std::sync::Arc;

use ark_bls12_381::{Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_std::rand::RngCore;
use ark_std::{UniformRand, Zero};

use crate::bls::{
    aggregate_signatures, sign_delegation, verify_aggregate_delegation, verify_delegation,
    SigningKeypair,
};
use crate::domain::{next_power_of_two, pad_scalar};
use crate::election::ElectionParams;
use crate::epa_adapter::{get_or_create_srs, SrsBundle};
use crate::eqlog::{self, EqLogContext, EqLogProof};
use crate::error::{AggiosError, Result};

/// All key material a voter holds.
#[derive(Clone, Debug)]
pub struct VoterKeys {
    /// Long-term signing key: sk ∈ Fr, pk = sk · g2 ∈ G2.
    pub signing: SigningKeypair,
    /// Voting key: skv ∈ Fr, pkv = skv · g2 ∈ G2. In basic Aggios the
    /// selected aggregator learns skv (proxy voting).
    pub skv: Fr,
    pub pkv: G2Affine,
}

impl VoterKeys {
    pub fn generate<R: RngCore>(rng: &mut R) -> Self {
        let signing = SigningKeypair::generate(rng);
        let skv = Fr::rand(rng);
        let pkv = crate::bls::g2_generator().mul(skv).into_affine();
        Self { signing, skv, pkv }
    }

    /// Delegation signature σ = sk · H("AGGIOS_DELEGATION" || election || aggregator).
    pub fn sign_delegation(&self, election_id: &str, aggregator_id: &str) -> G1Affine {
        sign_delegation(&self.signing.sk, election_id, aggregator_id)
    }
}

/// Aggregator-side record of an accepted registration. Contains skv, which
/// is PRIVATE to the aggregator and must never reach the bulletin board.
#[derive(Clone, Debug)]
pub struct RegisteredVoter {
    pub voter_id: String,
    pub pk: G2Affine,
    pub pkv: G2Affine,
    pub sigma: G1Affine,
    /// Private: the voter's voting-key scalar, sent over the (simulated)
    /// private channel.
    pub skv: Fr,
}

/// Public per-voter registration record (bulletin board).
#[derive(Clone, Debug)]
pub struct VoterRegistrationRecord {
    pub voter_id: String,
    pub idx: usize,
    pub pk: G2Affine,
    pub pkv: G2Affine,
    pub tau: G1Affine,
    pub sigma: G1Affine,
    pub eqlog: EqLogProof,
}

/// Public registration post an aggregator publishes after registration closes.
#[derive(Clone, Debug)]
pub struct FinalizedRegistration {
    pub election_id: String,
    pub aggregator_id: String,
    pub domain_size: usize,
    pub real_registered_count: usize,
    pub pad_count: usize,
    pub voters: Vec<VoterRegistrationRecord>,
    /// τ_pad_p for p in 0..pad_count (at domain indices real_count + p).
    pub pad_tokens: Vec<G1Affine>,
    /// Aggregate delegation signature σ_I = Σ_i σ_i (optimization artifact).
    pub aggregate_sigma: G1Affine,
    /// C_commit = Σ τ_i + Σ τ_pad_p.
    pub c_commit: G1Affine,
    pub srs_ref: String,
    pub timestamp_unix_ms: u64,
}

/// Domain size rule: power of two, large enough for all voters AND strictly
/// larger than the number of partitions (the EPA black box labels partitions
/// by domain-element index, so we need num_partitions distinct nonzero
/// indices).
pub fn required_domain_size(real_registered_count: usize, num_partitions: usize) -> usize {
    next_power_of_two(real_registered_count.max(num_partitions + 1))
}

/// Aggregator-side registration acceptance check for a single voter.
pub fn accept_registration(
    election_id: &str,
    aggregator_id: &str,
    voter_id: &str,
    pk: &G2Affine,
    pkv: &G2Affine,
    sigma: &G1Affine,
    skv: &Fr,
) -> Result<RegisteredVoter> {
    if !verify_delegation(sigma, pk, election_id, aggregator_id) {
        return Err(AggiosError::Registration(format!(
            "invalid delegation signature for voter {} to aggregator {}",
            voter_id, aggregator_id
        )));
    }
    // pkv must match the private skv the voter sent (proxy voting).
    let expected_pkv = crate::bls::g2_generator().mul(*skv).into_affine();
    if expected_pkv != *pkv {
        return Err(AggiosError::Registration(format!(
            "voting key mismatch for voter {}: skv does not match pkv",
            voter_id
        )));
    }
    Ok(RegisteredVoter {
        voter_id: voter_id.to_string(),
        pk: *pk,
        pkv: *pkv,
        sigma: *sigma,
        skv: *skv,
    })
}

/// Freeze the accepted voter set of one aggregator, assign local indices in
/// registration order, and produce the public registration post.
pub fn finalize_registration<R: RngCore>(
    election: &ElectionParams,
    aggregator_id: &str,
    voters: &[RegisteredVoter],
    timestamp_unix_ms: u64,
    rng: &mut R,
) -> Result<(FinalizedRegistration, Arc<SrsBundle>)> {
    let election_id = &election.election_id;
    let real_count = voters.len();
    let domain_size = required_domain_size(real_count, election.num_partitions());
    let pad_count = domain_size - real_count;

    let bundle = get_or_create_srs(domain_size)?;
    let basis = bundle.lagrange_basis();

    let mut records = Vec::with_capacity(real_count);
    let mut c_acc = G1Projective::zero();

    for (idx, voter) in voters.iter().enumerate() {
        // B_i = [L_idx(τ)]_1, τ_i = skv · B_i
        let b_i = basis[idx];
        let tau = b_i.mul(voter.skv).into_affine();
        let context = EqLogContext {
            election_id: election_id.clone(),
            aggregator_id: aggregator_id.to_string(),
            voter_id: voter.voter_id.clone(),
            local_index: idx,
            domain_size,
        };
        let eqlog = eqlog::prove(&b_i, &tau, &voter.pkv, &voter.skv, &context, rng);
        c_acc += tau.into_projective();
        records.push(VoterRegistrationRecord {
            voter_id: voter.voter_id.clone(),
            idx,
            pk: voter.pk,
            pkv: voter.pkv,
            tau,
            sigma: voter.sigma,
            eqlog,
        });
    }

    let mut pad_tokens = Vec::with_capacity(pad_count);
    for p in 0..pad_count {
        let scalar = pad_scalar(election_id, aggregator_id, p);
        let tau_pad = basis[real_count + p].mul(scalar).into_affine();
        c_acc += tau_pad.into_projective();
        pad_tokens.push(tau_pad);
    }

    let sigmas: Vec<G1Affine> = voters.iter().map(|v| v.sigma).collect();
    let aggregate_sigma = aggregate_signatures(&sigmas);

    Ok((
        FinalizedRegistration {
            election_id: election_id.clone(),
            aggregator_id: aggregator_id.to_string(),
            domain_size,
            real_registered_count: real_count,
            pad_count,
            voters: records,
            pad_tokens,
            aggregate_sigma,
            c_commit: c_acc.into_affine(),
            srs_ref: bundle.srs_ref.clone(),
            timestamp_unix_ms,
        },
        bundle,
    ))
}

#[derive(Clone, Debug, Default)]
pub struct ValidationReport {
    pub errors: Vec<String>,
}

impl ValidationReport {
    pub fn ok(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Validator-side checks for one aggregator's registration post.
///
/// `use_aggregate_bls = false` verifies each delegation signature
/// individually; `true` uses the batched check e(σ_I, g2) == e(H_M, Σ pk_i).
pub fn validate_finalized_registration(
    election: &ElectionParams,
    post: &FinalizedRegistration,
    use_aggregate_bls: bool,
) -> Result<ValidationReport> {
    let mut report = ValidationReport::default();
    let election_id = &election.election_id;
    let aggregator_id = &post.aggregator_id;

    if !election.aggregators.contains(aggregator_id) {
        report
            .errors
            .push(format!("unknown aggregator {}", aggregator_id));
        return Ok(report);
    }

    let expected_domain =
        required_domain_size(post.real_registered_count, election.num_partitions());
    if post.domain_size != expected_domain {
        report.errors.push(format!(
            "domain size {} does not match expected {}",
            post.domain_size, expected_domain
        ));
        return Ok(report);
    }
    if post.voters.len() != post.real_registered_count
        || post.pad_tokens.len() != post.pad_count
        || post.real_registered_count + post.pad_count != post.domain_size
    {
        report.errors.push("inconsistent registration counts".into());
        return Ok(report);
    }

    let bundle = get_or_create_srs(post.domain_size)?;
    let basis = bundle.lagrange_basis();

    // Local indices must be dense 0..count-1 in registration order.
    for (position, record) in post.voters.iter().enumerate() {
        if record.idx != position {
            report.errors.push(format!(
                "voter {} has index {} but position {}",
                record.voter_id, record.idx, position
            ));
        }
    }

    // Duplicate voter within the post.
    let mut seen = HashSet::new();
    for record in &post.voters {
        if !seen.insert(record.voter_id.clone()) {
            report
                .errors
                .push(format!("duplicate voter {} in post", record.voter_id));
        }
    }

    // BLS delegation signatures.
    if use_aggregate_bls {
        let pks: Vec<G2Affine> = post.voters.iter().map(|v| v.pk).collect();
        if !verify_aggregate_delegation(&post.aggregate_sigma, &pks, election_id, aggregator_id) {
            report
                .errors
                .push("aggregate delegation signature invalid".into());
        }
    } else {
        for record in &post.voters {
            if !verify_delegation(&record.sigma, &record.pk, election_id, aggregator_id) {
                report.errors.push(format!(
                    "delegation signature invalid for voter {}",
                    record.voter_id
                ));
            }
        }
        // The aggregate signature artifact must also be consistent.
        let sigmas: Vec<G1Affine> = post.voters.iter().map(|v| v.sigma).collect();
        if aggregate_signatures(&sigmas) != post.aggregate_sigma {
            report
                .errors
                .push("aggregate signature does not match individual signatures".into());
        }
    }

    // EqLog: τ_i and pkv_i use the same scalar, with B_i recomputed from
    // idx/domain.
    for record in &post.voters {
        let context = EqLogContext {
            election_id: election_id.clone(),
            aggregator_id: aggregator_id.clone(),
            voter_id: record.voter_id.clone(),
            local_index: record.idx,
            domain_size: post.domain_size,
        };
        let b_i = basis[record.idx];
        if !eqlog::verify(&b_i, &record.tau, &record.pkv, &record.eqlog, &context) {
            report
                .errors
                .push(format!("EqLog proof invalid for voter {}", record.voter_id));
        }
    }

    // Padding tokens must match the deterministic public derivation.
    for (p, tau_pad) in post.pad_tokens.iter().enumerate() {
        let scalar = pad_scalar(election_id, aggregator_id, p);
        let expected = basis[post.real_registered_count + p]
            .mul(scalar)
            .into_affine();
        if *tau_pad != expected {
            report
                .errors
                .push(format!("padding token {} does not match derivation", p));
        }
    }

    // C_commit must equal Σ τ_i + Σ τ_pad_p.
    let mut c_acc = G1Projective::zero();
    for record in &post.voters {
        c_acc += record.tau.into_projective();
    }
    for tau_pad in &post.pad_tokens {
        c_acc += tau_pad.into_projective();
    }
    if c_acc.into_affine() != post.c_commit {
        report
            .errors
            .push("C_commit does not equal the sum of registration tokens".into());
    }

    Ok(report)
}

/// Election-level check: a voter_id may appear under at most one aggregator.
pub fn check_no_duplicate_voters(posts: &[&FinalizedRegistration]) -> Vec<String> {
    let mut errors = Vec::new();
    let mut seen: HashSet<&str> = HashSet::new();
    for post in posts {
        for record in &post.voters {
            if !seen.insert(record.voter_id.as_str()) {
                errors.push(format!(
                    "voter {} registered under more than one aggregator",
                    record.voter_id
                ));
            }
        }
    }
    errors
}
