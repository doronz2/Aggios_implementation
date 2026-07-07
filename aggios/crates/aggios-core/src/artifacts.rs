//! Canonical JSON artifacts for the public bulletin board.
//!
//! All group/field elements use canonical compressed serialization, hex
//! encoded. Every public object carries version, object type, election id
//! and the curve/backend identifier.

use ark_bls12_381::{Fr, G1Affine, G2Affine};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};

use crate::election::ARTIFACT_VERSION;
use crate::epa_adapter::EPA_BACKEND_ID;
use crate::eqlog::EqLogProof;
use crate::error::{AggiosError, Result};
use crate::registration::{FinalizedRegistration, VoterRegistrationRecord};
use crate::tally::{AggregatorVerification, TallyPost};

fn to_hex<T: CanonicalSerialize>(t: &T) -> String {
    hex::encode(crate::hash::canonical_bytes(t))
}

fn from_hex<T: CanonicalDeserialize>(s: &str) -> Result<T> {
    let bytes = hex::decode(s).map_err(|e| AggiosError::Serialization(e.to_string()))?;
    T::deserialize(&bytes[..]).map_err(|e| AggiosError::Serialization(format!("{:?}", e)))
}

pub fn g1_to_hex(p: &G1Affine) -> String {
    to_hex(p)
}
pub fn g1_from_hex(s: &str) -> Result<G1Affine> {
    from_hex(s)
}
pub fn g2_to_hex(p: &G2Affine) -> String {
    to_hex(p)
}
pub fn g2_from_hex(s: &str) -> Result<G2Affine> {
    from_hex(s)
}
pub fn fr_to_hex(x: &Fr) -> String {
    to_hex(x)
}
pub fn fr_from_hex(s: &str) -> Result<Fr> {
    from_hex(s)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EqLogProofArtifact {
    pub a1: String,
    pub a2: String,
    pub z: String,
}

impl EqLogProofArtifact {
    pub fn from_proof(p: &EqLogProof) -> Self {
        Self {
            a1: g1_to_hex(&p.a1),
            a2: g2_to_hex(&p.a2),
            z: fr_to_hex(&p.z),
        }
    }
    pub fn to_proof(&self) -> Result<EqLogProof> {
        Ok(EqLogProof {
            a1: g1_from_hex(&self.a1)?,
            a2: g2_from_hex(&self.a2)?,
            z: fr_from_hex(&self.z)?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VoterRegistrationArtifact {
    pub voter_id: String,
    pub idx: usize,
    pub pk: String,
    pub pkv: String,
    pub tau: String,
    pub sigma: String,
    pub eqlog: EqLogProofArtifact,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistrationPostArtifact {
    pub version: u32,
    pub object_type: String,
    pub curve: String,
    pub election_id: String,
    pub aggregator_id: String,
    pub domain_size: usize,
    pub real_registered_count: usize,
    pub pad_count: usize,
    pub voters: Vec<VoterRegistrationArtifact>,
    pub pad_tokens: Vec<String>,
    pub aggregate_sigma: String,
    pub c_commit: String,
    pub srs_ref: String,
    pub timestamp_unix_ms: u64,
}

impl RegistrationPostArtifact {
    pub fn from_post(post: &FinalizedRegistration) -> Self {
        Self {
            version: ARTIFACT_VERSION,
            object_type: "aggios_registration_post".into(),
            curve: EPA_BACKEND_ID.into(),
            election_id: post.election_id.clone(),
            aggregator_id: post.aggregator_id.clone(),
            domain_size: post.domain_size,
            real_registered_count: post.real_registered_count,
            pad_count: post.pad_count,
            voters: post
                .voters
                .iter()
                .map(|v| VoterRegistrationArtifact {
                    voter_id: v.voter_id.clone(),
                    idx: v.idx,
                    pk: g2_to_hex(&v.pk),
                    pkv: g2_to_hex(&v.pkv),
                    tau: g1_to_hex(&v.tau),
                    sigma: g1_to_hex(&v.sigma),
                    eqlog: EqLogProofArtifact::from_proof(&v.eqlog),
                })
                .collect(),
            pad_tokens: post.pad_tokens.iter().map(g1_to_hex).collect(),
            aggregate_sigma: g1_to_hex(&post.aggregate_sigma),
            c_commit: g1_to_hex(&post.c_commit),
            srs_ref: post.srs_ref.clone(),
            timestamp_unix_ms: post.timestamp_unix_ms,
        }
    }

    pub fn to_post(&self) -> Result<FinalizedRegistration> {
        let voters = self
            .voters
            .iter()
            .map(|v| {
                Ok(VoterRegistrationRecord {
                    voter_id: v.voter_id.clone(),
                    idx: v.idx,
                    pk: g2_from_hex(&v.pk)?,
                    pkv: g2_from_hex(&v.pkv)?,
                    tau: g1_from_hex(&v.tau)?,
                    sigma: g1_from_hex(&v.sigma)?,
                    eqlog: v.eqlog.to_proof()?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let pad_tokens = self
            .pad_tokens
            .iter()
            .map(|s| g1_from_hex(s))
            .collect::<Result<Vec<_>>>()?;
        Ok(FinalizedRegistration {
            election_id: self.election_id.clone(),
            aggregator_id: self.aggregator_id.clone(),
            domain_size: self.domain_size,
            real_registered_count: self.real_registered_count,
            pad_count: self.pad_count,
            voters,
            pad_tokens,
            aggregate_sigma: g1_from_hex(&self.aggregate_sigma)?,
            c_commit: g1_from_hex(&self.c_commit)?,
            srs_ref: self.srs_ref.clone(),
            timestamp_unix_ms: self.timestamp_unix_ms,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TallyPostArtifact {
    pub version: u32,
    pub object_type: String,
    pub curve: String,
    pub election_id: String,
    pub aggregator_id: String,
    pub candidate_counts: Vec<usize>,
    pub no_vote_count: usize,
    pub pad_count: usize,
    pub domain_size: usize,
    pub c_commit: String,
    /// Aggios hash labels w_j (hex Fr), candidates then NO_VOTE then PAD.
    pub labels: Vec<String>,
    /// EPA black-box label indices (label scalar = ω^index).
    pub label_indices: Vec<usize>,
    pub sizes: Vec<usize>,
    /// Serialized EPA proof, hex.
    pub proof: String,
    pub proving_time_ms: u64,
    pub proof_size_bytes: usize,
}

impl TallyPostArtifact {
    pub fn from_post(post: &TallyPost) -> Self {
        Self {
            version: ARTIFACT_VERSION,
            object_type: "aggios_tally_post".into(),
            curve: EPA_BACKEND_ID.into(),
            election_id: post.election_id.clone(),
            aggregator_id: post.aggregator_id.clone(),
            candidate_counts: post.candidate_counts.clone(),
            no_vote_count: post.no_vote_count,
            pad_count: post.pad_count,
            domain_size: post.domain_size,
            c_commit: g1_to_hex(&post.c_commit),
            labels: post.labels.iter().map(fr_to_hex).collect(),
            label_indices: post.label_indices.clone(),
            sizes: post.sizes.clone(),
            proof: hex::encode(&post.proof_bytes),
            proving_time_ms: post.proving_time_ms as u64,
            proof_size_bytes: post.proof_size_bytes,
        }
    }

    pub fn to_post(&self) -> Result<TallyPost> {
        Ok(TallyPost {
            election_id: self.election_id.clone(),
            aggregator_id: self.aggregator_id.clone(),
            candidate_counts: self.candidate_counts.clone(),
            no_vote_count: self.no_vote_count,
            pad_count: self.pad_count,
            domain_size: self.domain_size,
            c_commit: g1_from_hex(&self.c_commit)?,
            labels: self
                .labels
                .iter()
                .map(|s| fr_from_hex(s))
                .collect::<Result<Vec<_>>>()?,
            label_indices: self.label_indices.clone(),
            sizes: self.sizes.clone(),
            proof_bytes: hex::decode(&self.proof)
                .map_err(|e| AggiosError::Serialization(e.to_string()))?,
            proving_time_ms: self.proving_time_ms as u128,
            proof_size_bytes: self.proof_size_bytes,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationArtifact {
    pub version: u32,
    pub object_type: String,
    pub election_id: String,
    pub aggregator_id: String,
    pub valid: bool,
    pub errors: Vec<String>,
    pub verification_time_ms: u64,
}

impl VerificationArtifact {
    pub fn from_verification(election_id: &str, v: &AggregatorVerification) -> Self {
        Self {
            version: ARTIFACT_VERSION,
            object_type: "aggios_verification_result".into(),
            election_id: election_id.to_string(),
            aggregator_id: v.aggregator_id.clone(),
            valid: v.valid,
            errors: v.errors.clone(),
            verification_time_ms: v.verification_time_ms as u64,
        }
    }
}

/// The full public election artifact (bulletin-board export).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicElectionArtifact {
    pub version: u32,
    pub object_type: String,
    pub curve: String,
    pub election: crate::election::ElectionParams,
    /// Candidate labels w_j (hex Fr) plus NO_VOTE and PAD labels.
    pub candidate_labels: Vec<String>,
    pub no_vote_label: String,
    pub pad_label: String,
    pub registration_posts: Vec<RegistrationPostArtifact>,
    pub tally_posts: Vec<TallyPostArtifact>,
    pub verifications: Vec<VerificationArtifact>,
    /// Final tally over verified aggregators only (NO_VOTE/PAD excluded).
    pub verified_global_tally: std::collections::HashMap<String, usize>,
}
