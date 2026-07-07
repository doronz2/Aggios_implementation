//! Election parameters and built-in templates.

use serde::{Deserialize, Serialize};

pub const ARTIFACT_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Candidate {
    pub id: String,
    pub name: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ElectionPhase {
    Setup,
    Registration,
    Voting,
    Tally,
    Closed,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ElectionParams {
    pub version: u32,
    pub object_type: String,
    pub curve: String,
    pub election_id: String,
    pub title: String,
    pub description: String,
    pub candidates: Vec<Candidate>,
    pub aggregators: Vec<String>,
    pub max_voters: usize,
    /// Reference to the deterministic demo SRS family; the concrete instance
    /// (domain size) is chosen per aggregator at registration finalization.
    pub srs_ref: String,
    pub phase: ElectionPhase,
}

impl ElectionParams {
    pub fn new(
        election_id: String,
        title: String,
        description: String,
        candidates: Vec<Candidate>,
        aggregators: Vec<String>,
        max_voters: usize,
    ) -> Self {
        Self {
            version: ARTIFACT_VERSION,
            object_type: "aggios_election_params".into(),
            curve: crate::epa_adapter::EPA_BACKEND_ID.into(),
            election_id,
            title,
            description,
            candidates,
            aggregators,
            max_voters,
            srs_ref: "epa-kzg10-bls12-381;deterministic-test-rng;n=per-aggregator".into(),
            phase: ElectionPhase::Setup,
        }
    }

    pub fn candidate_pairs(&self) -> Vec<(String, String)> {
        self.candidates
            .iter()
            .map(|c| (c.id.clone(), c.name.clone()))
            .collect()
    }

    /// Partitions = candidates + NO_VOTE + PAD.
    pub fn num_partitions(&self) -> usize {
        self.candidates.len() + 2
    }
}

pub const DEFAULT_AGGREGATORS: [&str; 3] = ["A1", "A2", "A3"];

pub fn default_aggregators() -> Vec<String> {
    DEFAULT_AGGREGATORS.iter().map(|s| s.to_string()).collect()
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ElectionTemplate {
    Representative,
    CrimeReform,
    Custom,
}

pub fn template_candidates(template: ElectionTemplate) -> Vec<Candidate> {
    match template {
        ElectionTemplate::Representative => vec![
            Candidate { id: "alice".into(), name: "Alice".into() },
            Candidate { id: "bob".into(), name: "Bob".into() },
            Candidate { id: "charlie".into(), name: "Charlie".into() },
        ],
        ElectionTemplate::CrimeReform => vec![
            Candidate {
                id: "increase-sentencing".into(),
                name: "Increase sentencing for violent crime".into(),
            },
            Candidate {
                id: "rehabilitation-first".into(),
                name: "Rehabilitation-first reform".into(),
            },
            Candidate {
                id: "keep-current".into(),
                name: "Keep the current policy".into(),
            },
            Candidate {
                id: "balanced-reform".into(),
                name: "Balanced reform: targeted sentencing + rehabilitation".into(),
            },
        ],
        ElectionTemplate::Custom => vec![],
    }
}

pub fn template_title(template: ElectionTemplate) -> &'static str {
    match template {
        ElectionTemplate::Representative => "Representative election",
        ElectionTemplate::CrimeReform => "Crime reform policy vote",
        ElectionTemplate::Custom => "Custom election",
    }
}
