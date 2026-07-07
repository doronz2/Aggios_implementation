//! Host-independent demo election state machine.
//!
//! This module implements the full basic-Aggios demo flow (elections, demo
//! voters, registration, voting, finalization, proving, verification,
//! bulletin board, public artifact) as plain synchronous methods returning
//! JSON values. It is shared by:
//!   - the axum backend (aggios-server), and
//!   - the in-browser WASM build (aggios-wasm) used on the static website.

use std::collections::HashMap;

use serde::Deserialize;
use serde_json::{json, Value};

use crate::artifacts::{
    fr_to_hex, g1_to_hex, g2_to_hex, PublicElectionArtifact, RegistrationPostArtifact,
    TallyPostArtifact, VerificationArtifact,
};
use crate::election::{
    default_aggregators, template_candidates, template_title, Candidate, ElectionParams,
    ElectionPhase, ElectionTemplate, ARTIFACT_VERSION,
};
use crate::epa_adapter::EPA_BACKEND_ID;
use crate::labels::{derive_election_labels, ElectionLabels};
use crate::registration::{
    accept_registration, check_no_duplicate_voters, finalize_registration,
    validate_finalized_registration, FinalizedRegistration, RegisteredVoter, VoterKeys,
};
use crate::tally::{
    build_and_prove_tally, global_tally, verify_aggregator_tally, AggregatorVerification,
    TallyPost,
};

/// (http-like status, message)
#[derive(Debug, Clone)]
pub struct DemoError {
    pub status: u16,
    pub message: String,
}

impl DemoError {
    pub fn bad(msg: impl Into<String>) -> Self {
        DemoError { status: 400, message: msg.into() }
    }
    pub fn not_found(msg: impl Into<String>) -> Self {
        DemoError { status: 404, message: msg.into() }
    }
}

impl From<crate::AggiosError> for DemoError {
    fn from(e: crate::AggiosError) -> Self {
        DemoError { status: 422, message: e.to_string() }
    }
}

pub type DemoResult = Result<Value, DemoError>;

pub struct DemoVoter {
    pub voter_id: String,
    pub keys: VoterKeys,
    pub registered_with: Option<String>,
    pub vote: Option<String>,
}

#[derive(Default)]
pub struct AggregatorState {
    pub registered: Vec<RegisteredVoter>,
    pub finalized: Option<FinalizedRegistration>,
    pub registration_valid: Option<bool>,
    pub registration_errors: Vec<String>,
    pub tally_post: Option<TallyPost>,
    pub verification: Option<AggregatorVerification>,
}

pub struct BulletinEvent {
    pub seq: u64,
    pub timestamp_unix_ms: u64,
    pub kind: String,
    pub payload: Value,
}

pub struct ElectionState {
    pub params: ElectionParams,
    pub labels: ElectionLabels,
    pub voters: HashMap<String, DemoVoter>,
    pub voter_order: Vec<String>,
    pub aggregators: HashMap<String, AggregatorState>,
    pub bulletin: Vec<BulletinEvent>,
    pub next_voter: u64,
}

impl ElectionState {
    fn post_bulletin(&mut self, now_ms: u64, kind: &str, payload: Value) {
        let seq = self.bulletin.len() as u64;
        self.bulletin.push(BulletinEvent {
            seq,
            timestamp_unix_ms: now_ms,
            kind: kind.to_string(),
            payload,
        });
    }
}

#[derive(Default)]
pub struct DemoState {
    pub elections: HashMap<String, ElectionState>,
    pub election_order: Vec<String>,
    counter: u64,
}

#[derive(Deserialize)]
pub struct CreateElectionRequest {
    pub template: ElectionTemplate,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub custom_options: Vec<String>,
    #[serde(default)]
    pub aggregators: Vec<String>,
    #[serde(default)]
    pub max_voters: Option<usize>,
}

fn phase_str(phase: ElectionPhase) -> &'static str {
    match phase {
        ElectionPhase::Setup => "setup",
        ElectionPhase::Registration => "registration",
        ElectionPhase::Voting => "voting",
        ElectionPhase::Tally => "tally",
        ElectionPhase::Closed => "closed",
    }
}

fn election_summary(e: &ElectionState) -> Value {
    let per_aggregator: Vec<Value> = e
        .params
        .aggregators
        .iter()
        .map(|aid| {
            let a = &e.aggregators[aid];
            let candidate_counts: HashMap<&str, usize> = e
                .params
                .candidates
                .iter()
                .enumerate()
                .map(|(j, c)| {
                    (
                        c.id.as_str(),
                        a.tally_post
                            .as_ref()
                            .map(|p| p.candidate_counts[j])
                            .unwrap_or(0),
                    )
                })
                .collect();
            json!({
                "aggregator_id": aid,
                "registered_voters": a.registered.len(),
                "votes_received": e.voters.values()
                    .filter(|v| v.registered_with.as_deref() == Some(aid.as_str()) && v.vote.is_some())
                    .count(),
                "finalized": a.finalized.is_some(),
                "domain_size": a.finalized.as_ref().map(|f| f.domain_size),
                "pad_count": a.finalized.as_ref().map(|f| f.pad_count),
                "registration_valid": a.registration_valid,
                "registration_errors": a.registration_errors,
                "proof_status": if a.tally_post.is_some() {
                    match &a.verification {
                        Some(v) if v.valid => "verified",
                        Some(_) => "rejected",
                        None => "proved",
                    }
                } else if a.finalized.is_some() { "ready" } else { "pending" },
                "candidate_counts": candidate_counts,
                "no_vote_count": a.tally_post.as_ref().map(|p| p.no_vote_count),
                "proving_time_ms": a.tally_post.as_ref().map(|p| p.proving_time_ms as u64),
                "proof_size_bytes": a.tally_post.as_ref().map(|p| p.proof_size_bytes),
                "verification_time_ms": a.verification.as_ref().map(|v| v.verification_time_ms as u64),
                "verification_errors": a.verification.as_ref().map(|v| v.errors.clone()),
            })
        })
        .collect();

    let verifications: Vec<_> = e
        .params
        .aggregators
        .iter()
        .filter_map(|aid| e.aggregators[aid].verification.clone())
        .collect();
    let posts: Vec<_> = e
        .params
        .aggregators
        .iter()
        .filter_map(|aid| e.aggregators[aid].tally_post.clone())
        .collect();
    let verified_tally = global_tally(&e.params, &posts, &verifications);
    let any_verified = verifications.iter().any(|v| v.valid);

    json!({
        "election": e.params,
        "phase": phase_str(e.params.phase),
        "num_voters": e.voters.len(),
        "voters": e.voter_order.iter().map(|vid| {
            let v = &e.voters[vid];
            json!({
                "voter_id": v.voter_id,
                "registered_with": v.registered_with,
                "has_voted": v.vote.is_some(),
                "vote": v.vote, // demo UI shows it; the aggregator knows it in basic Aggios
            })
        }).collect::<Vec<_>>(),
        "aggregators": per_aggregator,
        "verified_global_tally": if any_verified { Some(verified_tally) } else { None },
        "candidate_labels": e.labels.candidate_labels.iter().map(fr_to_hex).collect::<Vec<_>>(),
        "no_vote_label": fr_to_hex(&e.labels.no_vote_label),
        "pad_label": fr_to_hex(&e.labels.pad_label),
    })
}

impl DemoState {
    fn next_id(&mut self, prefix: &str, now_ms: u64) -> String {
        self.counter += 1;
        format!("{}-{}-{:04x}", prefix, now_ms % 1_000_000, self.counter)
    }

    fn election(&self, eid: &str) -> Result<&ElectionState, DemoError> {
        self.elections
            .get(eid)
            .ok_or_else(|| DemoError::not_found("election not found"))
    }

    fn election_mut(&mut self, eid: &str) -> Result<&mut ElectionState, DemoError> {
        self.elections
            .get_mut(eid)
            .ok_or_else(|| DemoError::not_found("election not found"))
    }

    pub fn create_election(&mut self, req: CreateElectionRequest, now_ms: u64) -> DemoResult {
        let candidates: Vec<Candidate> = match req.template {
            ElectionTemplate::Custom => {
                if req.custom_options.len() < 2 {
                    return Err(DemoError::bad("custom election needs at least 2 options"));
                }
                req.custom_options
                    .iter()
                    .enumerate()
                    .map(|(i, name)| Candidate {
                        id: format!("opt-{}", i),
                        name: name.clone(),
                    })
                    .collect()
            }
            t => template_candidates(t),
        };

        let aggregators = if req.aggregators.is_empty() {
            default_aggregators()
        } else {
            req.aggregators.clone()
        };

        let election_id = self.next_id("elec", now_ms);
        let params = ElectionParams::new(
            election_id.clone(),
            req.title
                .filter(|t| !t.is_empty())
                .unwrap_or_else(|| template_title(req.template).to_string()),
            req.description.unwrap_or_default(),
            candidates,
            aggregators.clone(),
            req.max_voters.unwrap_or(10_000),
        );
        let labels = derive_election_labels(&election_id, &params.candidate_pairs());

        let mut election = ElectionState {
            params: params.clone(),
            labels,
            voters: HashMap::new(),
            voter_order: vec![],
            aggregators: aggregators
                .iter()
                .map(|a| (a.clone(), AggregatorState::default()))
                .collect(),
            bulletin: vec![],
            next_voter: 0,
        };
        election.post_bulletin(now_ms, "election_created", json!({ "election": params }));

        let summary = election_summary(&election);
        self.elections.insert(election_id.clone(), election);
        self.election_order.push(election_id);
        Ok(summary)
    }

    pub fn list_elections(&self) -> Value {
        let list: Vec<Value> = self
            .election_order
            .iter()
            .filter_map(|id| self.elections.get(id))
            .map(|e| {
                json!({
                    "election_id": e.params.election_id,
                    "title": e.params.title,
                    "phase": phase_str(e.params.phase),
                    "candidates": e.params.candidates.len(),
                    "aggregators": e.params.aggregators.len(),
                    "voters": e.voters.len(),
                })
            })
            .collect();
        json!({ "elections": list })
    }

    pub fn get_election(&self, eid: &str) -> DemoResult {
        Ok(election_summary(self.election(eid)?))
    }

    pub fn set_phase(&mut self, eid: &str, phase: &str, now_ms: u64) -> DemoResult {
        let phase = match phase {
            "setup" => ElectionPhase::Setup,
            "registration" => ElectionPhase::Registration,
            "voting" => ElectionPhase::Voting,
            "tally" => ElectionPhase::Tally,
            "closed" => ElectionPhase::Closed,
            other => return Err(DemoError::bad(format!("unknown phase {}", other))),
        };
        let election = self.election_mut(eid)?;
        election.params.phase = phase;
        election.post_bulletin(now_ms, "phase_changed", json!({ "phase": phase_str(phase) }));
        Ok(election_summary(election))
    }

    pub fn demo_create_voters<R: ark_std::rand::RngCore>(
        &mut self,
        eid: &str,
        count: usize,
        rng: &mut R,
    ) -> DemoResult {
        if count == 0 || count > 500 {
            return Err(DemoError::bad("count must be between 1 and 500 (demo)"));
        }
        let election = self.election_mut(eid)?;
        let mut created = vec![];
        for _ in 0..count {
            election.next_voter += 1;
            let voter_id = format!("voter-{}", election.next_voter);
            let keys = VoterKeys::generate(rng);
            created.push(voter_id.clone());
            election.voter_order.push(voter_id.clone());
            election.voters.insert(
                voter_id.clone(),
                DemoVoter {
                    voter_id,
                    keys,
                    registered_with: None,
                    vote: None,
                },
            );
        }
        Ok(json!({ "created": created }))
    }

    pub fn register_voter(
        &mut self,
        eid: &str,
        voter_id: &str,
        aggregator_id: &str,
        now_ms: u64,
    ) -> DemoResult {
        let election = self.election_mut(eid)?;
        if election.params.phase != ElectionPhase::Registration {
            return Err(DemoError::bad("registration is not open"));
        }
        if !election.aggregators.contains_key(aggregator_id) {
            return Err(DemoError::bad("unknown aggregator"));
        }
        let voter = election
            .voters
            .get(voter_id)
            .ok_or_else(|| DemoError::not_found("voter not found"))?;
        if voter.registered_with.is_some() {
            return Err(DemoError::bad(
                "voter already registered with an aggregator (exactly one allowed)",
            ));
        }
        if election.aggregators[aggregator_id].finalized.is_some() {
            return Err(DemoError::bad("aggregator registration already finalized"));
        }

        let election_id = election.params.election_id.clone();
        // Voter signs the delegation message for the selected aggregator.
        let sigma = voter.keys.sign_delegation(&election_id, aggregator_id);
        let pk = voter.keys.signing.pk;
        let pkv = voter.keys.pkv;
        let skv = voter.keys.skv;

        // Aggregator-side acceptance: verifies the BLS delegation and that
        // skv (simulated private channel) matches pkv.
        let registered =
            accept_registration(&election_id, aggregator_id, voter_id, &pk, &pkv, &sigma, &skv)
                .map_err(DemoError::from)?;

        election
            .aggregators
            .get_mut(aggregator_id)
            .unwrap()
            .registered
            .push(registered);
        election.voters.get_mut(voter_id).unwrap().registered_with =
            Some(aggregator_id.to_string());

        // Public bulletin event: no skv here.
        election.post_bulletin(
            now_ms,
            "voter_registered",
            json!({
                "voter_id": voter_id,
                "aggregator_id": aggregator_id,
                "pk": g2_to_hex(&pk),
                "pkv": g2_to_hex(&pkv),
                "delegation_signature": g1_to_hex(&sigma),
            }),
        );
        Ok(json!({ "ok": true }))
    }

    pub fn cast_vote(&mut self, eid: &str, voter_id: &str, candidate_id: &str) -> DemoResult {
        let election = self.election_mut(eid)?;
        if election.params.phase != ElectionPhase::Voting {
            return Err(DemoError::bad("voting is not open"));
        }
        if !election
            .params
            .candidates
            .iter()
            .any(|c| c.id == candidate_id)
        {
            return Err(DemoError::bad("unknown candidate"));
        }
        let voter = election
            .voters
            .get_mut(voter_id)
            .ok_or_else(|| DemoError::not_found("voter not found"))?;
        if voter.registered_with.is_none() {
            return Err(DemoError::bad("voter is not registered with any aggregator"));
        }
        // Basic Aggios: the vote goes to the aggregator (proxy voting), NOT
        // to the public bulletin board.
        voter.vote = Some(candidate_id.to_string());
        Ok(json!({ "ok": true }))
    }

    pub fn voter_receipt(&self, eid: &str, voter_id: &str) -> DemoResult {
        let election = self.election(eid)?;
        if !election.voters.contains_key(voter_id) {
            return Err(DemoError::not_found("voter not found"));
        }
        Ok(json!({
            "available": false,
            "reason": "receipt support requires an EPA opening API; the existing EPA \
                       implementation only exposes blinded partition commitments with \
                       no opening hooks",
        }))
    }

    pub fn finalize_aggregator<R: ark_std::rand::RngCore>(
        &mut self,
        eid: &str,
        aid: &str,
        now_ms: u64,
        rng: &mut R,
    ) -> DemoResult {
        let (params, registered) = {
            let election = self.election(eid)?;
            let agg = election
                .aggregators
                .get(aid)
                .ok_or_else(|| DemoError::not_found("aggregator not found"))?;
            if agg.finalized.is_some() {
                return Err(DemoError::bad("registration already finalized"));
            }
            if election.params.phase == ElectionPhase::Registration {
                return Err(DemoError::bad(
                    "close registration before finalizing (set phase to voting)",
                ));
            }
            (election.params.clone(), agg.registered.clone())
        };

        let (finalized, _bundle) = finalize_registration(&params, aid, &registered, now_ms, rng)
            .map_err(DemoError::from)?;
        // Validator-side registration checks (individual BLS + EqLog).
        let report =
            validate_finalized_registration(&params, &finalized, false).map_err(DemoError::from)?;

        let artifact = RegistrationPostArtifact::from_post(&finalized);
        let election = self.election_mut(eid)?;
        {
            let agg = election.aggregators.get_mut(aid).unwrap();
            agg.finalized = Some(finalized);
            agg.registration_valid = Some(report.ok());
            agg.registration_errors = report.errors.clone();
        }
        election.post_bulletin(
            now_ms,
            "registration_post",
            serde_json::to_value(&artifact).unwrap(),
        );
        election.post_bulletin(
            now_ms,
            "registration_validated",
            json!({
                "aggregator_id": aid,
                "valid": report.ok(),
                "errors": report.errors,
            }),
        );
        Ok(json!({ "ok": report.ok(), "errors": report.errors }))
    }

    pub fn prove_aggregator(&mut self, eid: &str, aid: &str, now_ms: u64) -> DemoResult {
        let (params, labels, finalized, registered, votes) = {
            let election = self.election(eid)?;
            let agg = election
                .aggregators
                .get(aid)
                .ok_or_else(|| DemoError::not_found("aggregator not found"))?;
            let finalized = agg
                .finalized
                .clone()
                .ok_or_else(|| DemoError::bad("finalize registration first"))?;
            let votes: HashMap<String, String> = election
                .voters
                .values()
                .filter(|v| v.registered_with.as_deref() == Some(aid))
                .filter_map(|v| v.vote.clone().map(|c| (v.voter_id.clone(), c)))
                .collect();
            (
                election.params.clone(),
                election.labels.clone(),
                finalized,
                agg.registered.clone(),
                votes,
            )
        };

        let post = build_and_prove_tally(&params, &labels, &finalized, &registered, &votes)
            .map_err(DemoError::from)?;
        let artifact = TallyPostArtifact::from_post(&post);

        let election = self.election_mut(eid)?;
        let response = json!({
            "ok": true,
            "proving_time_ms": post.proving_time_ms as u64,
            "proof_size_bytes": post.proof_size_bytes,
            "candidate_counts": post.candidate_counts,
            "no_vote_count": post.no_vote_count,
            "pad_count": post.pad_count,
        });
        election.aggregators.get_mut(aid).unwrap().tally_post = Some(post);
        election.post_bulletin(now_ms, "tally_post", serde_json::to_value(&artifact).unwrap());
        Ok(response)
    }

    pub fn verify_aggregator(&mut self, eid: &str, aid: &str, now_ms: u64) -> DemoResult {
        let (params, labels, finalized, post) = {
            let election = self.election(eid)?;
            let agg = election
                .aggregators
                .get(aid)
                .ok_or_else(|| DemoError::not_found("aggregator not found"))?;
            (
                election.params.clone(),
                election.labels.clone(),
                agg.finalized
                    .clone()
                    .ok_or_else(|| DemoError::bad("no finalized registration"))?,
                agg.tally_post
                    .clone()
                    .ok_or_else(|| DemoError::bad("no proof to verify; run prove first"))?,
            )
        };

        let verification = verify_aggregator_tally(&params, &labels, &finalized, &post);
        let election = self.election_mut(eid)?;
        let eid_owned = eid.to_string();
        election.post_bulletin(
            now_ms,
            "verification_result",
            serde_json::to_value(VerificationArtifact::from_verification(
                &eid_owned,
                &verification,
            ))
            .unwrap(),
        );
        let response = json!({
            "valid": verification.valid,
            "errors": verification.errors,
            "verification_time_ms": verification.verification_time_ms as u64,
        });
        election.aggregators.get_mut(aid).unwrap().verification = Some(verification);
        Ok(response)
    }

    pub fn aggregator_proof_json(&self, eid: &str, aid: &str) -> DemoResult {
        let election = self.election(eid)?;
        let agg = election
            .aggregators
            .get(aid)
            .ok_or_else(|| DemoError::not_found("aggregator not found"))?;
        let post = agg
            .tally_post
            .as_ref()
            .ok_or_else(|| DemoError::not_found("no proof yet"))?;
        Ok(serde_json::to_value(TallyPostArtifact::from_post(post)).unwrap())
    }

    pub fn verify_all(&mut self, eid: &str, now_ms: u64) -> DemoResult {
        let (params, labels, per_agg) = {
            let election = self.election(eid)?;
            let per_agg: Vec<_> = election
                .params
                .aggregators
                .iter()
                .map(|aid| {
                    let a = &election.aggregators[aid];
                    (aid.clone(), a.finalized.clone(), a.tally_post.clone())
                })
                .collect();
            (election.params.clone(), election.labels.clone(), per_agg)
        };

        // Cross-aggregator duplicate-voter check over all posts.
        let posts: Vec<&FinalizedRegistration> =
            per_agg.iter().filter_map(|(_, f, _)| f.as_ref()).collect();
        let duplicate_errors = check_no_duplicate_voters(&posts);

        let mut registration_results = Vec::new();
        let mut verifications = Vec::new();
        let mut tally_posts = Vec::new();
        for (aid, finalized, post) in &per_agg {
            let reg_ok = match finalized {
                Some(f) => match validate_finalized_registration(&params, f, false) {
                    Ok(report) => (report.ok(), report.errors),
                    Err(e) => (false, vec![e.to_string()]),
                },
                None => (false, vec!["registration not finalized".into()]),
            };
            registration_results.push(json!({
                "aggregator_id": aid,
                "registration_valid": reg_ok.0,
                "errors": reg_ok.1,
            }));

            if let (Some(f), Some(p)) = (finalized, post) {
                let mut v = verify_aggregator_tally(&params, &labels, f, p);
                if !reg_ok.0 {
                    v.valid = false;
                    v.errors.push("registration post invalid".into());
                }
                verifications.push(v);
                tally_posts.push(p.clone());
            }
        }
        let tally = global_tally(&params, &tally_posts, &verifications);

        let eid_owned = eid.to_string();
        let election = self.election_mut(eid)?;
        for v in &verifications {
            election.post_bulletin(
                now_ms,
                "verification_result",
                serde_json::to_value(VerificationArtifact::from_verification(&eid_owned, v))
                    .unwrap(),
            );
            if let Some(agg) = election.aggregators.get_mut(&v.aggregator_id) {
                agg.verification = Some(v.clone());
            }
        }
        election.post_bulletin(
            now_ms,
            "global_tally",
            json!({ "verified_global_tally": tally, "duplicate_voter_errors": duplicate_errors }),
        );

        Ok(json!({
            "duplicate_voter_errors": duplicate_errors,
            "registration": registration_results,
            "verifications": verifications.iter().map(|v| json!({
                "aggregator_id": v.aggregator_id,
                "valid": v.valid,
                "errors": v.errors,
                "verification_time_ms": v.verification_time_ms as u64,
            })).collect::<Vec<_>>(),
            "verified_global_tally": tally,
        }))
    }

    pub fn bulletin_board(&self, eid: &str) -> DemoResult {
        let election = self.election(eid)?;
        Ok(json!({
            "events": election.bulletin.iter().map(|ev| json!({
                "seq": ev.seq,
                "timestamp_unix_ms": ev.timestamp_unix_ms,
                "kind": ev.kind,
                "payload": ev.payload,
            })).collect::<Vec<_>>()
        }))
    }

    pub fn public_artifact(&self, eid: &str) -> DemoResult {
        let e = self.election(eid)?;
        let registration_posts: Vec<_> = e
            .params
            .aggregators
            .iter()
            .filter_map(|aid| e.aggregators[aid].finalized.as_ref())
            .map(RegistrationPostArtifact::from_post)
            .collect();
        let tally_posts_runtime: Vec<_> = e
            .params
            .aggregators
            .iter()
            .filter_map(|aid| e.aggregators[aid].tally_post.clone())
            .collect();
        let verifications_runtime: Vec<_> = e
            .params
            .aggregators
            .iter()
            .filter_map(|aid| e.aggregators[aid].verification.clone())
            .collect();
        let tally = global_tally(&e.params, &tally_posts_runtime, &verifications_runtime);

        let artifact = PublicElectionArtifact {
            version: ARTIFACT_VERSION,
            object_type: "aggios_public_election_artifact".into(),
            curve: EPA_BACKEND_ID.into(),
            election: e.params.clone(),
            candidate_labels: e.labels.candidate_labels.iter().map(fr_to_hex).collect(),
            no_vote_label: fr_to_hex(&e.labels.no_vote_label),
            pad_label: fr_to_hex(&e.labels.pad_label),
            registration_posts,
            tally_posts: tally_posts_runtime
                .iter()
                .map(TallyPostArtifact::from_post)
                .collect(),
            verifications: verifications_runtime
                .iter()
                .map(|v| VerificationArtifact::from_verification(&e.params.election_id, v))
                .collect(),
            verified_global_tally: tally,
        };
        Ok(serde_json::to_value(artifact).unwrap())
    }
}
