//! Tally construction (aggregator side) and tally verification (validator
//! side), around the black-box EPA prover/verifier.

use std::collections::HashMap;

use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_std::Zero;

use crate::election::ElectionParams;
use crate::epa_adapter::{
    self, get_or_create_srs, EpaProof, EpaPublicInput, EpaWitness,
};
use crate::error::{AggiosError, Result};
use crate::labels::ElectionLabels;
use crate::registration::{FinalizedRegistration, RegisteredVoter};

/// Everything an aggregator publishes with its tally.
#[derive(Clone, Debug)]
pub struct TallyPost {
    pub election_id: String,
    pub aggregator_id: String,
    /// Vote counts per candidate, in candidate display order.
    pub candidate_counts: Vec<usize>,
    pub no_vote_count: usize,
    pub pad_count: usize,
    pub domain_size: usize,
    pub c_commit: G1Affine,
    /// Aggios hash labels w_j per partition (candidates, NO_VOTE, PAD).
    pub labels: Vec<Fr>,
    /// EPA-level label indices (see epa_adapter docs).
    pub label_indices: Vec<usize>,
    /// Partition sizes, same order as labels.
    pub sizes: Vec<usize>,
    /// Serialized EPA proof (canonical compressed encoding).
    pub proof_bytes: Vec<u8>,
    pub proving_time_ms: u128,
    pub proof_size_bytes: usize,
}

/// Build the tally witness for one aggregator and call the black-box EPA
/// prover. `votes` maps voter_id -> candidate_id; registered voters missing
/// from `votes` are counted in the NO_VOTE partition.
pub fn build_and_prove_tally(
    election: &ElectionParams,
    labels: &ElectionLabels,
    finalized: &FinalizedRegistration,
    registered: &[RegisteredVoter],
    votes: &HashMap<String, String>,
) -> Result<TallyPost> {
    let n = finalized.domain_size;
    let num_candidates = election.candidates.len();
    let num_partitions = election.num_partitions();

    let candidate_position: HashMap<&str, usize> = election
        .candidates
        .iter()
        .enumerate()
        .map(|(j, c)| (c.id.as_str(), j))
        .collect();

    // skv values are aggregator-private; match them to public records by id.
    let skv_by_voter: HashMap<&str, &Fr> = registered
        .iter()
        .map(|v| (v.voter_id.as_str(), &v.skv))
        .collect();

    // values_by_index: skv_i at each real voter index, pad_scalar_p at each
    // padding index.
    let mut values_by_index = vec![Fr::from(0u64); n];
    // partitions in deterministic order: candidates (display order), NO_VOTE, PAD.
    let mut partition_indices: Vec<Vec<usize>> = vec![Vec::new(); num_partitions];

    for record in &finalized.voters {
        let skv = skv_by_voter.get(record.voter_id.as_str()).ok_or_else(|| {
            AggiosError::Tally(format!(
                "aggregator has no private skv for voter {}",
                record.voter_id
            ))
        })?;
        values_by_index[record.idx] = **skv;

        match votes.get(&record.voter_id) {
            Some(candidate_id) => {
                let j = *candidate_position.get(candidate_id.as_str()).ok_or_else(|| {
                    AggiosError::Tally(format!("unknown candidate {}", candidate_id))
                })?;
                partition_indices[j].push(record.idx);
            }
            None => partition_indices[num_candidates].push(record.idx), // NO_VOTE
        }
    }

    for p in 0..finalized.pad_count {
        let idx = finalized.real_registered_count + p;
        values_by_index[idx] = crate::domain::pad_scalar(
            &election.election_id,
            &finalized.aggregator_id,
            p,
        );
        partition_indices[num_candidates + 1].push(idx); // PAD
    }

    let sizes: Vec<usize> = partition_indices.iter().map(|p| p.len()).collect();
    let candidate_counts = sizes[..num_candidates].to_vec();
    let no_vote_count = sizes[num_candidates];
    let pad_count = sizes[num_candidates + 1];

    // Pre-prove sanity checks (the adapter re-validates coverage/duplicates).
    if sizes.iter().sum::<usize>() != n {
        return Err(AggiosError::Tally("partition sizes do not sum to domain".into()));
    }
    if pad_count != finalized.pad_count {
        return Err(AggiosError::Tally("pad partition size mismatch".into()));
    }

    let public_input = EpaPublicInput {
        election_id: election.election_id.clone(),
        aggregator_id: finalized.aggregator_id.clone(),
        domain_size: n,
        commitment_c: finalized.c_commit,
        labels: labels.partition_labels(),
        label_indices: EpaPublicInput::canonical_label_indices(num_partitions),
        sizes: sizes.clone(),
        srs_ref: finalized.srs_ref.clone(),
    };
    let witness = EpaWitness {
        values_by_index,
        partition_indices,
    };

    let bundle = get_or_create_srs(n)?;
    let proof_result = epa_adapter::prove(&bundle, &public_input, &witness)?;

    Ok(TallyPost {
        election_id: election.election_id.clone(),
        aggregator_id: finalized.aggregator_id.clone(),
        candidate_counts,
        no_vote_count,
        pad_count,
        domain_size: n,
        c_commit: finalized.c_commit,
        labels: public_input.labels,
        label_indices: public_input.label_indices,
        sizes,
        proof_bytes: proof_result.proof.to_bytes()?,
        proving_time_ms: proof_result.proving_time_ms,
        proof_size_bytes: proof_result.proof_size_bytes,
    })
}

/// Validator outcome for one aggregator tally.
#[derive(Clone, Debug)]
pub struct AggregatorVerification {
    pub aggregator_id: String,
    pub valid: bool,
    pub errors: Vec<String>,
    pub verification_time_ms: u128,
}

/// Validator flow for one aggregator result (spec section 13):
/// recompute labels and C_commit from public data, cross-check the posted
/// tally, then call the black-box EPA verifier.
pub fn verify_aggregator_tally(
    election: &ElectionParams,
    labels: &ElectionLabels,
    finalized: &FinalizedRegistration,
    post: &TallyPost,
) -> AggregatorVerification {
    let mut errors: Vec<String> = Vec::new();
    let num_candidates = election.candidates.len();
    let num_partitions = election.num_partitions();

    // Recompute C_commit from the public registration tokens.
    let mut c_acc = G1Projective::zero();
    for record in &finalized.voters {
        c_acc += record.tau.into_projective();
    }
    for tau_pad in &finalized.pad_tokens {
        c_acc += tau_pad.into_projective();
    }
    let c_recomputed = c_acc.into_affine();
    if c_recomputed != post.c_commit {
        errors.push("posted C_commit does not match registration tokens".into());
    }

    if post.domain_size != finalized.domain_size {
        errors.push("tally domain size does not match registration post".into());
    }
    if post.sizes.len() != num_partitions {
        errors.push("wrong number of partitions".into());
    } else {
        if post.sizes.iter().sum::<usize>() != post.domain_size {
            errors.push("partition sizes do not sum to domain size".into());
        }
        // Candidate tally must equal the candidate partition sizes and must
        // exclude NO_VOTE and PAD.
        if post.candidate_counts != post.sizes[..num_candidates] {
            errors.push("candidate tally does not match partition sizes".into());
        }
        if post.no_vote_count != post.sizes[num_candidates] {
            errors.push("NO_VOTE count does not match partition size".into());
        }
        if post.pad_count != post.sizes[num_candidates + 1] {
            errors.push("PAD count does not match partition size".into());
        }
        if post.pad_count != finalized.pad_count {
            errors.push("PAD count does not match registration post".into());
        }
    }

    // Recompute labels and the canonical EPA label indices.
    let expected_labels = labels.partition_labels();
    if post.labels != expected_labels {
        errors.push("posted labels do not match recomputed labels".into());
    }
    if post.label_indices != EpaPublicInput::canonical_label_indices(num_partitions) {
        errors.push("posted label indices are not canonical".into());
    }

    if !errors.is_empty() {
        return AggregatorVerification {
            aggregator_id: post.aggregator_id.clone(),
            valid: false,
            errors,
            verification_time_ms: 0,
        };
    }

    // Build the EPA public input from recomputed data and verify.
    let public_input = EpaPublicInput {
        election_id: election.election_id.clone(),
        aggregator_id: post.aggregator_id.clone(),
        domain_size: post.domain_size,
        commitment_c: c_recomputed,
        labels: expected_labels,
        label_indices: EpaPublicInput::canonical_label_indices(num_partitions),
        sizes: post.sizes.clone(),
        srs_ref: finalized.srs_ref.clone(),
    };

    let result = (|| -> Result<crate::epa_adapter::VerificationResult> {
        let bundle = get_or_create_srs(post.domain_size)?;
        let proof = EpaProof::from_bytes(&post.proof_bytes)?;
        epa_adapter::verify(&bundle, &public_input, &proof)
    })();

    match result {
        Ok(v) => AggregatorVerification {
            aggregator_id: post.aggregator_id.clone(),
            valid: v.valid,
            errors: if v.valid {
                vec![]
            } else {
                vec!["EPA proof rejected".into()]
            },
            verification_time_ms: v.verification_time_ms,
        },
        Err(e) => AggregatorVerification {
            aggregator_id: post.aggregator_id.clone(),
            valid: false,
            errors: vec![format!("verification failed: {}", e)],
            verification_time_ms: 0,
        },
    }
}

/// Global tally over VERIFIED aggregators only; NO_VOTE and PAD excluded.
pub fn global_tally(
    election: &ElectionParams,
    posts: &[TallyPost],
    verifications: &[AggregatorVerification],
) -> HashMap<String, usize> {
    let verified: std::collections::HashSet<&str> = verifications
        .iter()
        .filter(|v| v.valid)
        .map(|v| v.aggregator_id.as_str())
        .collect();

    let mut totals: HashMap<String, usize> = election
        .candidates
        .iter()
        .map(|c| (c.id.clone(), 0))
        .collect();

    for post in posts {
        if !verified.contains(post.aggregator_id.as_str()) {
            continue;
        }
        for (j, candidate) in election.candidates.iter().enumerate() {
            if let Some(count) = post.candidate_counts.get(j) {
                *totals.get_mut(&candidate.id).unwrap() += count;
            }
        }
    }
    totals
}
