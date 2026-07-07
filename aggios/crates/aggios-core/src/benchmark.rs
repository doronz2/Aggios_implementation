//! Benchmark engine, used by both the CLI and the web UI.
//!
//! Two modes:
//! - real crypto: runs the full basic-Aggios pipeline (keys, delegation,
//!   registration tokens, EqLog, EPA prove/verify) and records honest
//!   timings. Failures (memory, time, SRS limits) are recorded, never
//!   silently downsampled.
//! - simulation: counting only, clearly labeled NON-CRYPTOGRAPHIC. No keys,
//!   no proofs; it only streams voters through assignment/vote sampling, so
//!   it works for 10^6 voters without materializing them.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use ark_std::rand::SeedableRng;
use rand::rngs::StdRng;
use rand::Rng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::election::{
    template_candidates, template_title, Candidate, ElectionParams, ElectionTemplate,
};
use crate::labels::derive_election_labels;
use crate::registration::{
    accept_registration, finalize_registration, required_domain_size,
    validate_finalized_registration, RegisteredVoter, VoterKeys,
};
use crate::tally::{build_and_prove_tally, global_tally, verify_aggregator_tally};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AssignmentStrategy {
    RoundRobin,
    Uniform,
    Weighted,
    Skewed,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum VoteDistributionKind {
    Uniform,
    Fixed,
    Skewed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BenchmarkConfig {
    pub voters: usize,
    pub aggregators: usize,
    pub template: ElectionTemplate,
    /// Used when template == Custom.
    #[serde(default)]
    pub custom_candidates: Vec<Candidate>,
    pub assignment: AssignmentStrategy,
    /// Aggregator weights for `Weighted` assignment (normalized internally).
    #[serde(default)]
    pub assignment_weights: Vec<f64>,
    pub vote_distribution: VoteDistributionKind,
    /// Candidate percentages for `Fixed` vote distribution.
    #[serde(default)]
    pub vote_percentages: Vec<f64>,
    pub seed: u64,
    pub real_crypto: bool,
    /// Voter receipts are not available with the current EPA API; this flag
    /// is accepted but reported as unavailable.
    #[serde(default)]
    pub receipts: bool,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            voters: 100,
            aggregators: 3,
            template: ElectionTemplate::Representative,
            custom_candidates: vec![],
            assignment: AssignmentStrategy::Uniform,
            assignment_weights: vec![],
            vote_distribution: VoteDistributionKind::Uniform,
            vote_percentages: vec![],
            seed: 42,
            real_crypto: true,
            receipts: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProgressEvent {
    pub stage: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregator: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fraction: Option<f64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AggregatorBenchResult {
    pub aggregator_id: String,
    pub voters: usize,
    pub domain_size: usize,
    pub pad_count: usize,
    pub registration_ms: u64,
    pub finalization_ms: u64,
    pub registration_validation_ms: u64,
    pub tally_and_proving_ms: u64,
    pub epa_proving_ms: u64,
    pub epa_verification_ms: u64,
    pub proof_size_bytes: usize,
    pub verified: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BenchmarkResult {
    pub config: BenchmarkConfig,
    /// "real-crypto" or "simulation (NON-CRYPTOGRAPHIC)"
    pub mode: String,
    pub voter_count: usize,
    pub num_aggregators: usize,
    pub num_candidates: usize,
    pub voters_per_aggregator: Vec<usize>,
    pub per_aggregator: Vec<AggregatorBenchResult>,
    pub candidate_tally: HashMap<String, usize>,
    pub expected_tally: HashMap<String, usize>,
    pub tally_matches_expected: bool,
    pub voter_generation_ms: u64,
    pub registration_time_ms: u64,
    pub tally_construction_and_proving_ms: u64,
    pub epa_proving_time_ms: u64,
    pub epa_verification_time_ms: u64,
    pub proof_size_bytes_total: usize,
    pub public_artifact_size_bytes: usize,
    pub max_rss_bytes: Option<u64>,
    pub total_ms: u64,
    pub receipts: String,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Peak resident set size, if the platform exposes it.
pub fn max_rss_bytes() -> Option<u64> {
    #[cfg(unix)]
    unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        if libc::getrusage(libc::RUSAGE_SELF, &mut usage) == 0 {
            let raw = usage.ru_maxrss as u64;
            // macOS reports bytes, Linux reports kilobytes.
            #[cfg(target_os = "macos")]
            return Some(raw);
            #[cfg(not(target_os = "macos"))]
            return Some(raw * 1024);
        }
        None
    }
    #[cfg(not(unix))]
    {
        None
    }
}

fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E3779B97F4A7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D049BB133111EB);
    x ^ (x >> 31)
}

fn candidates_for(config: &BenchmarkConfig) -> Vec<Candidate> {
    match config.template {
        ElectionTemplate::Custom => config.custom_candidates.clone(),
        t => template_candidates(t),
    }
}

fn aggregator_weights(config: &BenchmarkConfig) -> Vec<f64> {
    let m = config.aggregators;
    let weights = match config.assignment {
        AssignmentStrategy::RoundRobin | AssignmentStrategy::Uniform => vec![1.0; m],
        AssignmentStrategy::Weighted => {
            if config.assignment_weights.len() == m
                && config.assignment_weights.iter().all(|w| *w > 0.0)
            {
                config.assignment_weights.clone()
            } else {
                vec![1.0; m]
            }
        }
        // Skewed 80/15/5: first three aggregators get 80/15/5; any further
        // aggregators share the tail of a geometric decay.
        AssignmentStrategy::Skewed => {
            let base = [80.0, 15.0, 5.0];
            (0..m)
                .map(|i| {
                    if i < 3 {
                        base[i]
                    } else {
                        5.0 / (1 << (i - 2)) as f64
                    }
                })
                .collect()
        }
    };
    let total: f64 = weights.iter().sum();
    weights.into_iter().map(|w| w / total).collect()
}

fn vote_weights(config: &BenchmarkConfig, num_candidates: usize) -> Vec<f64> {
    let weights = match config.vote_distribution {
        VoteDistributionKind::Uniform => vec![1.0; num_candidates],
        VoteDistributionKind::Fixed => {
            if config.vote_percentages.len() == num_candidates
                && config.vote_percentages.iter().all(|w| *w >= 0.0)
                && config.vote_percentages.iter().sum::<f64>() > 0.0
            {
                config.vote_percentages.clone()
            } else {
                vec![1.0; num_candidates]
            }
        }
        // Skewed: geometric decay, first candidate strongest.
        VoteDistributionKind::Skewed => (0..num_candidates)
            .map(|j| 1.0 / (1 << j.min(30)) as f64)
            .collect(),
    };
    let total: f64 = weights.iter().sum();
    weights.into_iter().map(|w| w / total).collect()
}

fn sample_weighted<R: Rng>(weights: &[f64], rng: &mut R) -> usize {
    let x: f64 = rng.gen();
    let mut acc = 0.0;
    for (i, w) in weights.iter().enumerate() {
        acc += w;
        if x < acc {
            return i;
        }
    }
    weights.len() - 1
}

/// Deterministic assignment/vote sampling for voter `i` (no storage needed).
fn assign_voter(
    config: &BenchmarkConfig,
    agg_weights: &[f64],
    cand_weights: &[f64],
    i: usize,
) -> (usize, usize) {
    let mut rng = StdRng::seed_from_u64(splitmix64(config.seed ^ (i as u64)));
    let agg = match config.assignment {
        AssignmentStrategy::RoundRobin => i % config.aggregators,
        _ => sample_weighted(agg_weights, &mut rng),
    };
    let cand = sample_weighted(cand_weights, &mut rng);
    (agg, cand)
}

pub fn run_benchmark(
    config: &BenchmarkConfig,
    progress: &(dyn Fn(ProgressEvent) + Sync),
    cancel: &AtomicBool,
) -> BenchmarkResult {
    let started = Instant::now();
    let candidates = candidates_for(config);
    let mode = if config.real_crypto {
        "real-crypto".to_string()
    } else {
        "simulation (NON-CRYPTOGRAPHIC)".to_string()
    };

    let mut result = BenchmarkResult {
        config: config.clone(),
        mode,
        voter_count: config.voters,
        num_aggregators: config.aggregators,
        num_candidates: candidates.len(),
        voters_per_aggregator: vec![],
        per_aggregator: vec![],
        candidate_tally: HashMap::new(),
        expected_tally: HashMap::new(),
        tally_matches_expected: false,
        voter_generation_ms: 0,
        registration_time_ms: 0,
        tally_construction_and_proving_ms: 0,
        epa_proving_time_ms: 0,
        epa_verification_time_ms: 0,
        proof_size_bytes_total: 0,
        public_artifact_size_bytes: 0,
        max_rss_bytes: None,
        total_ms: 0,
        receipts: "not available with current EPA API".into(),
        success: false,
        error: None,
    };

    if candidates.is_empty() {
        result.error = Some("no candidates configured".into());
        return result;
    }
    if config.aggregators == 0 || config.voters == 0 {
        result.error = Some("need at least one aggregator and one voter".into());
        return result;
    }

    let agg_weights = aggregator_weights(config);
    let cand_weights = vote_weights(config, candidates.len());

    // Streamed deterministic assignment (works for 10^6 without storing
    // voters): tallies + per-aggregator counts.
    let mut per_agg_count = vec![0usize; config.aggregators];
    let mut expected_tally: Vec<usize> = vec![0; candidates.len()];
    for i in 0..config.voters {
        let (agg, cand) = assign_voter(config, &agg_weights, &cand_weights, i);
        per_agg_count[agg] += 1;
        expected_tally[cand] += 1;
    }
    result.voters_per_aggregator = per_agg_count.clone();
    result.expected_tally = candidates
        .iter()
        .zip(&expected_tally)
        .map(|(c, n)| (c.id.clone(), *n))
        .collect();

    if !config.real_crypto {
        // Simulation: counting only. Explicitly non-cryptographic.
        for (i, agg_id) in (0..config.aggregators).enumerate() {
            let voters = per_agg_count[i];
            let domain = required_domain_size(voters, candidates.len() + 2);
            result.per_aggregator.push(AggregatorBenchResult {
                aggregator_id: format!("A{}", agg_id + 1),
                voters,
                domain_size: domain,
                pad_count: domain - voters,
                verified: false,
                ..Default::default()
            });
        }
        result.candidate_tally = result.expected_tally.clone();
        result.tally_matches_expected = true;
        result.max_rss_bytes = max_rss_bytes();
        result.total_ms = started.elapsed().as_millis() as u64;
        result.success = true;
        progress(ProgressEvent {
            stage: "done".into(),
            message: "simulation complete (no cryptography executed)".into(),
            aggregator: None,
            fraction: Some(1.0),
        });
        return result;
    }

    // ---- Real crypto pipeline ----
    let election_id = format!("bench-{}-{}", config.voters, config.seed);
    let aggregator_ids: Vec<String> = (1..=config.aggregators).map(|i| format!("A{}", i)).collect();
    let election = ElectionParams::new(
        election_id.clone(),
        format!("Benchmark: {}", template_title(config.template)),
        "benchmark election".into(),
        candidates.clone(),
        aggregator_ids.clone(),
        config.voters,
        );
    let labels = derive_election_labels(&election_id, &election.candidate_pairs());

    macro_rules! bail_if_cancelled {
        () => {
            if cancel.load(Ordering::Relaxed) {
                result.error = Some("cancelled".into());
                result.total_ms = started.elapsed().as_millis() as u64;
                result.max_rss_bytes = max_rss_bytes();
                return result;
            }
        };
    }

    progress(ProgressEvent {
        stage: "voters".into(),
        message: format!("generating {} voters with real keys", config.voters),
        aggregator: None,
        fraction: Some(0.0),
    });

    // Generate voters (keys + delegation signatures) in parallel with
    // per-voter deterministic seeds.
    let gen_start = Instant::now();
    struct BenchVoter {
        registered: RegisteredVoter,
        aggregator: usize,
        candidate: usize,
    }
    let voters: Vec<BenchVoter> = (0..config.voters)
        .into_par_iter()
        .map(|i| {
            let mut rng = StdRng::seed_from_u64(splitmix64(
                config.seed.wrapping_mul(0x5851F42D4C957F2D) ^ (i as u64),
            ));
            let keys = VoterKeys::generate(&mut rng);
            let (agg, cand) = assign_voter(config, &agg_weights, &cand_weights, i);
            let aggregator_id = &aggregator_ids[agg];
            let sigma = keys.sign_delegation(&election_id, aggregator_id);
            BenchVoter {
                registered: RegisteredVoter {
                    voter_id: format!("v{}", i),
                    pk: keys.signing.pk,
                    pkv: keys.pkv,
                    sigma,
                    skv: keys.skv,
                },
                aggregator: agg,
                candidate: cand,
            }
        })
        .collect();
    result.voter_generation_ms = gen_start.elapsed().as_millis() as u64;
    bail_if_cancelled!();

    let run = (|| -> crate::error::Result<()> {
        let mut posts = Vec::new();
        let mut verifications = Vec::new();

        for (agg_idx, aggregator_id) in aggregator_ids.iter().enumerate() {
            if cancel.load(Ordering::Relaxed) {
                return Err(crate::error::AggiosError::Benchmark("cancelled".into()));
            }
            let mine: Vec<&BenchVoter> =
                voters.iter().filter(|v| v.aggregator == agg_idx).collect();
            progress(ProgressEvent {
                stage: "registration".into(),
                message: format!("aggregator {}: registering {} voters", aggregator_id, mine.len()),
                aggregator: Some(aggregator_id.clone()),
                fraction: Some(agg_idx as f64 / aggregator_ids.len() as f64),
            });

            // Aggregator-side acceptance: real BLS verification per voter.
            let reg_start = Instant::now();
            let accepted: Vec<RegisteredVoter> = mine
                .par_iter()
                .map(|v| {
                    accept_registration(
                        &election_id,
                        aggregator_id,
                        &v.registered.voter_id,
                        &v.registered.pk,
                        &v.registered.pkv,
                        &v.registered.sigma,
                        &v.registered.skv,
                    )
                })
                .collect::<crate::error::Result<Vec<_>>>()?;
            let registration_ms = reg_start.elapsed().as_millis() as u64;

            progress(ProgressEvent {
                stage: "finalize".into(),
                message: format!(
                    "aggregator {}: finalizing registration (tokens + EqLog)",
                    aggregator_id
                ),
                aggregator: Some(aggregator_id.clone()),
                fraction: None,
            });
            let fin_start = Instant::now();
            let mut rng = StdRng::seed_from_u64(splitmix64(config.seed ^ 0xA66_u64 ^ agg_idx as u64));
            let (finalized, _bundle) =
                finalize_registration(&election, aggregator_id, &accepted, 0, &mut rng)?;
            let finalization_ms = fin_start.elapsed().as_millis() as u64;

            progress(ProgressEvent {
                stage: "validate-registration".into(),
                message: format!("validator: checking registration post of {}", aggregator_id),
                aggregator: Some(aggregator_id.clone()),
                fraction: None,
            });
            let val_start = Instant::now();
            // Aggregate BLS check + per-voter EqLog checks.
            let report = validate_finalized_registration(&election, &finalized, true)?;
            if !report.ok() {
                return Err(crate::error::AggiosError::Benchmark(format!(
                    "registration validation failed: {:?}",
                    report.errors
                )));
            }
            let registration_validation_ms = val_start.elapsed().as_millis() as u64;

            progress(ProgressEvent {
                stage: "prove".into(),
                message: format!(
                    "aggregator {}: building tally and running EPA prover (domain {})",
                    aggregator_id, finalized.domain_size
                ),
                aggregator: Some(aggregator_id.clone()),
                fraction: None,
            });
            let votes: HashMap<String, String> = mine
                .iter()
                .map(|v| {
                    (
                        v.registered.voter_id.clone(),
                        candidates[v.candidate].id.clone(),
                    )
                })
                .collect();
            let tally_start = Instant::now();
            let post = build_and_prove_tally(&election, &labels, &finalized, &accepted, &votes)?;
            let tally_and_proving_ms = tally_start.elapsed().as_millis() as u64;

            progress(ProgressEvent {
                stage: "verify".into(),
                message: format!("validator: verifying EPA proof of {}", aggregator_id),
                aggregator: Some(aggregator_id.clone()),
                fraction: None,
            });
            let verification = verify_aggregator_tally(&election, &labels, &finalized, &post);
            if !verification.valid {
                return Err(crate::error::AggiosError::Benchmark(format!(
                    "tally verification failed for {}: {:?}",
                    aggregator_id, verification.errors
                )));
            }

            result.per_aggregator.push(AggregatorBenchResult {
                aggregator_id: aggregator_id.clone(),
                voters: mine.len(),
                domain_size: finalized.domain_size,
                pad_count: finalized.pad_count,
                registration_ms,
                finalization_ms,
                registration_validation_ms,
                tally_and_proving_ms,
                epa_proving_ms: post.proving_time_ms as u64,
                epa_verification_ms: verification.verification_time_ms as u64,
                proof_size_bytes: post.proof_size_bytes,
                verified: verification.valid,
            });

            // Public-artifact size accounting.
            posts.push(post);
            verifications.push(verification);
        }

        let tally = global_tally(&election, &posts, &verifications);
        result.candidate_tally = tally;

        let artifact = crate::artifacts::PublicElectionArtifact {
            version: crate::election::ARTIFACT_VERSION,
            object_type: "aggios_public_election_artifact".into(),
            curve: crate::epa_adapter::EPA_BACKEND_ID.into(),
            election: election.clone(),
            candidate_labels: labels
                .candidate_labels
                .iter()
                .map(crate::artifacts::fr_to_hex)
                .collect(),
            no_vote_label: crate::artifacts::fr_to_hex(&labels.no_vote_label),
            pad_label: crate::artifacts::fr_to_hex(&labels.pad_label),
            registration_posts: vec![], // omitted from benchmark artifact sizing of posts below
            tally_posts: posts
                .iter()
                .map(crate::artifacts::TallyPostArtifact::from_post)
                .collect(),
            verifications: verifications
                .iter()
                .map(|v| crate::artifacts::VerificationArtifact::from_verification(&election_id, v))
                .collect(),
            verified_global_tally: result.candidate_tally.clone(),
        };
        result.public_artifact_size_bytes = serde_json::to_vec(&artifact)
            .map(|v| v.len())
            .unwrap_or(0);
        Ok(())
    })();

    result.registration_time_ms = result
        .per_aggregator
        .iter()
        .map(|a| a.registration_ms + a.finalization_ms + a.registration_validation_ms)
        .sum();
    result.tally_construction_and_proving_ms = result
        .per_aggregator
        .iter()
        .map(|a| a.tally_and_proving_ms)
        .sum();
    result.epa_proving_time_ms = result.per_aggregator.iter().map(|a| a.epa_proving_ms).sum();
    result.epa_verification_time_ms = result
        .per_aggregator
        .iter()
        .map(|a| a.epa_verification_ms)
        .sum();
    result.proof_size_bytes_total = result
        .per_aggregator
        .iter()
        .map(|a| a.proof_size_bytes)
        .sum();
    result.max_rss_bytes = max_rss_bytes();
    result.total_ms = started.elapsed().as_millis() as u64;

    match run {
        Ok(()) => {
            result.tally_matches_expected = result.candidate_tally == result.expected_tally;
            result.success = result.tally_matches_expected;
            if !result.tally_matches_expected {
                result.error = Some("verified tally does not match expected tally".into());
            }
            progress(ProgressEvent {
                stage: "done".into(),
                message: "benchmark complete".into(),
                aggregator: None,
                fraction: Some(1.0),
            });
        }
        Err(e) => {
            result.success = false;
            result.error = Some(e.to_string());
            progress(ProgressEvent {
                stage: "failed".into(),
                message: e.to_string(),
                aggregator: None,
                fraction: None,
            });
        }
    }
    result
}

/// Run a benchmark, converting panics from the underlying stack (e.g. EPA
/// internals or allocation failures) into an honest failure record.
pub fn run_benchmark_catching(
    config: &BenchmarkConfig,
    progress: &(dyn Fn(ProgressEvent) + Sync),
    cancel: &AtomicBool,
) -> BenchmarkResult {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_benchmark(config, progress, cancel)
    }));
    match outcome {
        Ok(result) => result,
        Err(panic) => {
            let msg = panic
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "unknown panic".into());
            BenchmarkResult {
                config: config.clone(),
                mode: if config.real_crypto {
                    "real-crypto".into()
                } else {
                    "simulation (NON-CRYPTOGRAPHIC)".into()
                },
                voter_count: config.voters,
                num_aggregators: config.aggregators,
                num_candidates: candidates_for(config).len(),
                voters_per_aggregator: vec![],
                per_aggregator: vec![],
                candidate_tally: HashMap::new(),
                expected_tally: HashMap::new(),
                tally_matches_expected: false,
                voter_generation_ms: 0,
                registration_time_ms: 0,
                tally_construction_and_proving_ms: 0,
                epa_proving_time_ms: 0,
                epa_verification_time_ms: 0,
                proof_size_bytes_total: 0,
                public_artifact_size_bytes: 0,
                max_rss_bytes: max_rss_bytes(),
                total_ms: 0,
                receipts: "not available with current EPA API".into(),
                success: false,
                error: Some(format!("panic during benchmark: {}", msg)),
            }
        }
    }
}

/// CSV export: one row per aggregator plus a TOTAL row.
pub fn result_to_csv(result: &BenchmarkResult) -> String {
    let mut out = String::from(
        "aggregator,voters,domain_size,pad_count,registration_ms,finalization_ms,\
         registration_validation_ms,tally_and_proving_ms,epa_proving_ms,\
         epa_verification_ms,proof_size_bytes,verified\n",
    );
    for a in &result.per_aggregator {
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{},{},{}\n",
            a.aggregator_id,
            a.voters,
            a.domain_size,
            a.pad_count,
            a.registration_ms,
            a.finalization_ms,
            a.registration_validation_ms,
            a.tally_and_proving_ms,
            a.epa_proving_ms,
            a.epa_verification_ms,
            a.proof_size_bytes,
            a.verified
        ));
    }
    out.push_str(&format!(
        "TOTAL,{},,,{},,,{},{},{},{},{}\n",
        result.voter_count,
        result.registration_time_ms,
        result.tally_construction_and_proving_ms,
        result.epa_proving_time_ms,
        result.epa_verification_time_ms,
        result.proof_size_bytes_total,
        result.success
    ));
    out
}
